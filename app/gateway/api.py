"""Private Gateway application. Only the TLS proxy is an external entry point."""

import hmac
import ipaddress
import json
import logging
import os
import re
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from uuid import uuid4
from zoneinfo import ZoneInfo

import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import Field

from app.gateway.database import Database, ViewPlan
from app.gateway.provider import GatewayProvider
from app.gateway.security import decode_token, issue_token, verify_password, hash_password
from app.gateway.sessions import Sessions
from app.jsonio import strict_json_loads
from app.models import AccessRequest, StrictModel, Subject
from app.services import DecisionService, ROOT

LOG = logging.getLogger("gateway.audit")
LOG.setLevel(logging.INFO)
if not LOG.handlers:
    LOG.addHandler(logging.StreamHandler())
LOG.propagate = False


class Login(StrictModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


def load_registry(path):
    registry = strict_json_loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(registry, dict) or set(registry) != {"accounts", "devices"}:
        raise ValueError("Invalid registry structure")
    if not isinstance(registry["accounts"], dict) or not isinstance(registry["devices"], dict):
        raise ValueError("Invalid registry collections")
    for name, row in registry["accounts"].items():
        if not isinstance(row, dict) or set(row) != {
            "subject",
            "password_hash",
            "enabled",
            "auth_version",
        }:
            raise ValueError("Invalid account contract")
        if not isinstance(row["password_hash"], str) or not re.fullmatch(
            r"pbkdf2_sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}", row["password_hash"]
        ):
            raise ValueError("Invalid password hash contract")
        subject = Subject.model_validate(row["subject"])
        if subject.id != name or type(row["enabled"]) is not bool:
            raise ValueError("Invalid account registry")
        if type(row["auth_version"]) is not int or row["auth_version"] < 1:
            raise ValueError("Invalid authorization version")
    for serial, device in registry["devices"].items():
        if (
            not re.fullmatch(r"[0-9A-F]{1,64}", serial)
            or not isinstance(device, dict)
            or set(device) != {"id", "enabled"}
            or type(device["enabled"]) is not bool
            or not isinstance(device["id"], str)
            or not 1 <= len(device["id"]) <= 100
        ):
            raise ValueError("Invalid device registry")
    return registry


class LoginLimiter:
    def __init__(self):
        self.attempts = defaultdict(deque)
        self.lock = threading.Lock()

    def check(self, address):
        with self.lock:
            now = time.monotonic()
            # Bound memory; evict only expired entries, never active restrictions.
            for key in list(self.attempts):
                while self.attempts[key] and self.attempts[key][0] < now - 60:
                    self.attempts[key].popleft()
                if not self.attempts[key]:
                    del self.attempts[key]
            if address not in self.attempts and len(self.attempts) >= 4096:
                raise HTTPException(429, "Login capacity exceeded")
            attempts = self.attempts[address]
            if len(attempts) >= 10:
                raise HTTPException(429, "Too many login attempts; retry after one minute")
            attempts.append(now)


def create_app(config=None, database=None, clock=None):
    config = config or {
        "secret": os.environ["GATEWAY_JWT_SECRET"],
        "proxy_secret": os.environ["GATEWAY_PROXY_SECRET"],
        "registry": os.environ["GATEWAY_REGISTRY"],
        "database_url": os.environ["DATABASE_URL"],
        "office_networks": os.getenv("OFFICE_NETWORKS", "127.0.0.0/8,::1/128"),
        "timezone": os.getenv("BUSINESS_TIMEZONE", "Asia/Bangkok"),
        "policy_file": os.getenv("GATEWAY_POLICY_FILE", str(ROOT / "policies/policies.json")),
    }
    if len(config["secret"]) < 32 or len(config["proxy_secret"]) < 32:
        raise ValueError("Gateway secrets must be independently generated, at least 32 characters")
    networks = [
        ipaddress.ip_network(value.strip()) for value in config["office_networks"].split(",")
    ]
    ZoneInfo(config["timezone"])
    load_registry(config["registry"])
    sessions = Sessions(
        config.get("session_file")
        or os.getenv("GATEWAY_SESSION_FILE")
        or str(Path(config["registry"]).parent / "sessions.sqlite")
    )
    db = database or Database(config["database_url"])
    # Every request gets a provider; HTTP client/catalogue repository remain shared.
    core = DecisionService()
    core.simulation = False
    core.dev_failures = False
    core.policy_path = Path(config["policy_file"])
    get_now = clock or (lambda: datetime.now(timezone.utc))
    limiter = LoginLimiter()
    dummy_hash = hash_password("nonexistent-account-dummy-password")

    @asynccontextmanager
    async def lifespan(app):
        yield
        core.opa.client.close()
        db.close()

    app = FastAPI(
        title="ABAC Data Gateway", version="4.0.0", lifespan=lifespan, docs_url=None, redoc_url=None
    )
    app.state.database = db
    app.state.core = core
    app.state.sessions = sessions

    @app.middleware("http")
    async def private_ingress(request, call_next):
        request_id = str(uuid4())
        request.state.request_id = request_id
        if request.url.path != "/health" and not hmac.compare_digest(
            request.headers.get("x-gateway-proxy-secret", "").encode(),
            config["proxy_secret"].encode(),
        ):
            response = JSONResponse(
                status_code=403, content={"decision": "DENY", "reason_code": "UNTRUSTED_PROXY"}
            )
        else:
            try:
                response = await call_next(request)
            except Exception:
                response = JSONResponse(
                    status_code=503,
                    content={
                        "request_id": request_id,
                        "decision": "DENY",
                        "reason_code": "GATEWAY_FAILURE",
                    },
                )
        if response.status_code >= 400:
            LOG.error(
                "%s",
                json.dumps(
                    {
                        "request_id": request_id,
                        "decision": "DENY",
                        "http_status": response.status_code,
                        "event": "request_rejected",
                    }
                ),
            )
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'"
        )
        return response

    @app.exception_handler(HTTPException)
    async def rejected(request, exc):
        code = {
            401: "AUTHENTICATION_FAILED",
            403: "UNTRUSTED_CONTEXT",
            404: "UNKNOWN_RESOURCE",
            422: "INVALID_REQUEST",
            429: "RATE_LIMITED",
        }.get(exc.status_code, "REQUEST_REJECTED")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "request_id": request.state.request_id,
                "decision": "DENY",
                "reason_code": code,
                "detail": exc.detail,
                "db_queried": False,
            },
        )

    def peer(request):
        try:
            # Proxy overwrites this header with its actual TCP peer, not X-Forwarded-For.
            return ipaddress.ip_address(request.headers["x-gateway-client-ip"])
        except (KeyError, ValueError):
            raise HTTPException(403, "Invalid trusted client address") from None

    @app.get("/health")
    def health():
        try:
            engine = core.opa.client.get("/v1/data/capstone/engine_version").json()
            view = core.opa.client.get("/v1/data/gateway/resource_columns").json()
            ready = engine.get("result") == "2.0.0" and set(view.get("result", {})) == {
                "customers",
                "financial",
                "production",
            }
            database_ready = db.ready()
        except Exception:
            ready = False
            database_ready = False
        return JSONResponse(
            status_code=200 if ready and database_ready else 503,
            content={"version": "4.0.0", "opa_ready": ready, "database_ready": database_ready},
        )

    @app.get("/")
    def home():
        return FileResponse(ROOT / "ui/gateway/index.html")

    @app.get("/gateway.js")
    def javascript():
        return FileResponse(ROOT / "ui/gateway/gateway.js", media_type="application/javascript")

    @app.get("/gateway.css")
    def stylesheet():
        return FileResponse(ROOT / "ui/gateway/gateway.css", media_type="text/css")

    @app.post("/auth/login")
    def login(body: Login, request: Request):
        limiter.check(str(peer(request)))
        row = load_registry(config["registry"])["accounts"].get(body.username)
        matched = verify_password(body.password, row["password_hash"] if row else dummy_hash)
        if not row or not matched or not row["enabled"]:
            raise HTTPException(401, "Invalid credentials")
        serial = (
            request.headers.get("x-gateway-device-serial", "").upper()
            if request.headers.get("x-gateway-device-verified") == "SUCCESS"
            else None
        )
        token = issue_token(body.username, config["secret"], row["auth_version"], serial)
        sessions.add(decode_token(token, config["secret"]))
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 600,
        }

    def authenticate(request, registry):
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "Authentication required")
        try:
            claims = decode_token(authorization[7:], config["secret"])
            row = registry["accounts"][claims["sub"]]
            if not row["enabled"] or claims["auth_version"] != row["auth_version"]:
                raise ValueError("Revoked identity")
            if not sessions.active(claims):
                raise ValueError("Inactive session")
            actual_serial = (
                request.headers.get("x-gateway-device-serial", "").upper()
                if request.headers.get("x-gateway-device-verified") == "SUCCESS"
                else None
            )
            if claims["device_serial"] != actual_serial:
                raise ValueError("Token device mismatch")
            request.state.claims = claims
            return row["subject"]
        except (jwt.PyJWTError, ValueError, KeyError, TypeError):
            raise HTTPException(401, "Invalid or expired identity token") from None

    @app.post("/auth/logout")
    def logout(request: Request):
        authenticate(request, load_registry(config["registry"]))
        sessions.revoke(request.state.claims)
        return {"revoked": True}

    @app.get("/api/v1/data/{resource}")
    def protected_data(resource: str, request: Request):
        if request.query_params:
            raise HTTPException(422, "Gateway does not accept overrides or SQL parameters")
        started = perf_counter()
        registry = load_registry(config["registry"])
        subject = authenticate(request, registry)
        if resource not in {"customers", "financial", "production"}:
            raise HTTPException(404, "Unknown protected resource")
        address = peer(request)
        device = registry["devices"].get(request.headers.get("x-gateway-device-serial", "").upper())
        trusted = request.headers.get("x-gateway-device-verified") == "SUCCESS" and bool(
            device and device["enabled"]
        )
        now = get_now()
        context = {
            "device_trusted": trusted,
            "location": "office" if any(address in network for network in networks) else "external",
            "time": now.isoformat(),
            "risk_score": 10 if trusted else 50,
        }
        provider = GatewayProvider(subject, context, now, config["timezone"])
        access = AccessRequest(subject_id=subject["id"], resource_id=resource, action="read")
        result = core.evaluate(access, now=now, trusted_provider=provider)
        result["request_id"] = request.state.request_id
        audit = {
            "request_id": result["request_id"],
            "subject": subject["id"],
            "resource": resource,
            "decision": result["decision"],
            "reason_code": result["reason_code"],
            "policy_digest": result["trace"].get("catalogue_digest"),
            "db_queried": False,
        }
        if result["decision"] != "ALLOW":
            LOG.info("%s", json.dumps(audit))
            return JSONResponse(
                status_code=403 if result["decision_status"] == "DENIED_BY_POLICY" else 503,
                content={
                    "request_id": result["request_id"],
                    "decision": "DENY",
                    "reason_code": result["reason_code"],
                    "db_queried": False,
                },
            )
        try:
            plan_tick = perf_counter()
            response = core.opa.client.post(
                "/v1/data/gateway/view_plan",
                json={"input": {"decision": "ALLOW", "subject": subject, "resource": resource}},
            )
            response.raise_for_status()
            plan = ViewPlan.model_validate(strict_json_loads(response.text)["result"])
            if plan.resource != resource:
                raise ValueError("Mismatched obligation resource")
            plan_ms = (perf_counter() - plan_tick) * 1000
            db_tick = perf_counter()
            audit["db_queried"] = True
            rows = db.query(plan)
            db_ms = (perf_counter() - db_tick) * 1000
        except Exception:
            LOG.error(
                "%s",
                json.dumps({**audit, "decision": "DENY", "reason_code": "ENFORCEMENT_FAILURE"}),
            )
            return JSONResponse(
                status_code=503, content={"decision": "DENY", "reason_code": "ENFORCEMENT_FAILURE"}
            )
        audit.update(db_queried=True, row_count=len(rows), obligations=plan.model_dump())
        LOG.info("%s", json.dumps(audit))
        return {
            "request_id": result["request_id"],
            "decision": "ALLOW",
            "reason_code": result["reason_code"],
            "obligations": plan.model_dump(),
            "data": rows,
            "db_queried": True,
            "context": {
                **context,
                "business_timezone": config["timezone"],
                "device_id": device["id"] if trusted else None,
                "source": "verified TLS proxy + server clock",
                "risk_model": "demo-heuristic-v1",
            },
            "metrics": {
                **result["metrics"],
                "obligation_ms": plan_ms,
                "database_ms": db_ms,
                "gateway_ms": (perf_counter() - started) * 1000,
            },
        }

    return app
