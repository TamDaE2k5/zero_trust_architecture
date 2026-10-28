"""
Mô-đun Điểm Cổng Dịch vụ Chính (API Gateway - PEP Enforcement Point).
Chức năng chính:
1. Đóng vai trò là Điểm Thực thi Chính sách (PEP - Policy Enforcement Point) theo mô hình Zero Trust.
2. Nằm sau Nginx mTLS Proxy; chỉ chấp nhận các kết nối nội bộ có mã bí mật hợp lệ (`x-gateway-proxy-secret`).
3. Cung cấp các Endpoint:
   - `/auth/login`: Xác thực tài khoản, kiểm tra mTLS, cấp phát JWT Token ràng buộc thiết bị và lưu phiên vào Allowlist.
   - `/auth/logout`: Thu hồi phiên tức thì trong SQLite Allowlist (chống tấn công Replay).
   - `/api/v1/data/{resource}`: Endpoint bảo vệ dữ liệu nhạy cảm (Customers, Financial, Production),
     kết hợp đánh giá ABAC qua OPA và thực thi bảo vệ sâu (RLS/DDM) trong PostgreSQL.
   - `/health`: Kiểm tra sức khỏe toàn diện của OPA Engine và PostgreSQL Database.
4. Triệt để tuân thủ nguyên tắc an toàn Fail-Closed: Mọi ngoại lệ, sự cố hay từ chối truy cập đều trả về
   phán quyết DENY và bảo đảm CSDL không bị chạm tới (`db_queried = false`).
"""

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

# Thiết lập Logger chuyên dụng cho Nhật ký Kiểm toán (Audit Log)
LOG = logging.getLogger("gateway.audit")
LOG.setLevel(logging.INFO)
if not LOG.handlers:
    LOG.addHandler(logging.StreamHandler())
LOG.propagate = False


class Login(StrictModel):
    """Mô hình dữ liệu nhận vào khi người dùng đăng nhập."""
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


def load_registry(path):
    """
    Nạp và kiểm tra tính toàn vẹn của danh bạ hệ thống (`registry.json`):
    - Chứa danh sách tài khoản (accounts): quyền hạn subject, mã băm mật khẩu, trạng thái kích hoạt enabled, phiên bản auth_version.
    - Chứa danh sách thiết bị được phê duyệt (devices): số Serial chứng chỉ phần cứng X.509 và trạng thái kích hoạt.
    - Áp dụng kiểm tra hợp đồng nghiêm ngặt bằng biểu thức chính quy (Regex) và Pydantic.
    """
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
    """
    Bộ giới hạn tốc độ đăng nhập (Rate Limiter) tại Gateway:
    - Giới hạn tối đa 10 lần thử đăng nhập trong vòng 1 phút từ cùng 1 địa chỉ IP.
    - Bảo vệ hệ thống khỏi tấn công dò mật khẩu (Brute-force / Credential Stuffing).
    - Sử dụng hàng đợi Thread-safe và tự động giải phóng bộ nhớ cho các IP đã hết hạn.
    """
    def __init__(self):
        self.attempts = defaultdict(deque)
        self.lock = threading.Lock()

    def check(self, address):
        with self.lock:
            now = time.monotonic()
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
    """
    Hàm nhà máy khởi tạo ứng dụng FastAPI Gateway:
    - Nạp cấu hình từ biến môi trường (Secrets, DB URL, Registry, Timezone).
    - Khởi tạo kết nối SQLite Session Allowlist và PostgreSQL Pool.
    - Đăng ký các Middleware bảo mật, xử lý ngoại lệ và các Route dịch vụ.
    """
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
    core = DecisionService()
    core.simulation = False
    core.dev_failures = False
    core.policy_path = Path(config["policy_file"])
    get_now = clock or (lambda: datetime.now(timezone.utc))
    limiter = LoginLimiter()
    dummy_hash = hash_password("nonexistent-account-dummy-password")

    @asynccontextmanager
    async def lifespan(app):
        """Quản lý vòng đời ứng dụng: dọn dẹp kết nối OPA và DB khi tắt server."""
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
        """
        Tầng Middleware Cửa ngõ (Private Ingress Security Barrier):
        1. Gắn mã truy vết duy nhất `request_id` cho mỗi yêu cầu.
        2. Xác thực Proxy Secret: Kiểm tra header `x-gateway-proxy-secret` bằng `hmac.compare_digest`.
           Nếu không khớp => Yêu cầu không đi qua Nginx mTLS mà cố tình bypass kết nối trực tiếp => Chặn 403 ngay!
        3. Bắt mọi ngoại lệ chưa lường trước, tự động chuyển thành lỗi HTTP 503 Fail-Closed.
        4. Ghi nhật ký kiểm toán (Audit Log) cho các yêu cầu bị từ chối.
        5. Đính kèm các tiêu đề an ninh HTTP nghiêm ngặt:
           - Cache-Control: no-store (Cấm trình duyệt lưu cache dữ liệu nhạy cảm).
           - X-Content-Type-Options: nosniff (Chống tấn công MIME-sniffing).
           - Content-Security-Policy: Chặn tải script/style độc hại từ bên ngoài.
        """
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
        """Định dạng phản hồi lỗi chuẩn tắc: luôn có decision=DENY và cờ db_queried=False."""
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
        """Trích xuất địa chỉ IP thực tế của Client do Nginx chuyển tiếp (không đọc X-Forwarded-For giả)."""
        try:
            return ipaddress.ip_address(request.headers["x-gateway-client-ip"])
        except (KeyError, ValueError):
            raise HTTPException(403, "Invalid trusted client address") from None

    @app.get("/health")
    def health():
        """Endpoint kiểm tra sức khỏe hệ thống: cả OPA Engine và PostgreSQL DB phải sẵn sàng mới trả 200."""
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
        """
        Xử lý Đăng nhập & Cấp phát Phiên (Authentication & Token Issuance):
        1. Kiểm tra giới hạn tốc độ (Rate Limit) theo IP client.
        2. Thẩm định username và mật khẩu bằng PBKDF2 hash (dùng dummy_hash nếu user không tồn tại để chống Timing Attack).
        3. Kiểm tra trạng thái tài khoản (`enabled == True`).
        4. Trích xuất số Serial của chứng chỉ thiết bị nếu vượt qua mTLS (`x-gateway-device-verified == SUCCESS`).
        5. Cấp phát Token JWT (có chứa sub, auth_version, exp, và device_serial).
        6. Lưu mã băm `jti` của Token vào SQLite Session Allowlist.
        7. Trả về Token có thời hạn 600 giây (10 phút) cho người dùng.
        """
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
        """
        Hàm Xác thực Danh tính & Kiểm tra Phiên (Authentication & Token Validation):
        1. Yêu cầu Header `Authorization: Bearer <token>`.
        2. Giải mã và xác thực chữ ký số của JWT Token.
        3. Kiểm tra xem tài khoản có còn được kích hoạt không và auth_version có khớp không (chống dùng token cũ sau đổi mật khẩu).
        4. Kiểm tra Session Allowlist trong SQLite: Nếu phiên đã bị Logout hoặc hết hạn => Báo lỗi Inactive session ngay!
        5. Ràng buộc thiết bị phần cứng (Device Binding): So khớp số serial trong Token với serial từ bắt tay mTLS hiện tại.
           Nếu kẻ gian cắp token mang sang máy tính khác => Lập tức báo lỗi "Token device mismatch"!
        6. Trả về thông tin Subject của người dùng từ bản ghi nội bộ máy chủ (không lấy từ client).
        """
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
        """
        Xử lý Đăng xuất (Session Revocation):
        Xác thực danh tính người dùng và xóa ngay mã băm của phiên trong bảng SQLite Allowlist.
        Sau khi gọi lệnh này, token cũ hoàn toàn không thể tái sử dụng để truy cập dữ liệu!
        """
        authenticate(request, load_registry(config["registry"]))
        sessions.revoke(request.state.claims)
        return {"revoked": True}

    @app.get("/api/v1/data/{resource}")
    def protected_data(resource: str, request: Request):
        """
        Endpoint Truy xuất Dữ liệu Được Bảo vệ (Core Protected Data Endpoint):
        1. Tuyệt đối cấm Query Parameters trên URL (chống SQL Injection / Override bối cảnh).
        2. Xác thực danh tính và phiên qua hàm `authenticate`.
        3. Thu thập thuộc tính ngữ cảnh thực tế (Context):
           - device_trusted: Thiết bị có chứng chỉ mTLS hợp lệ và đã đăng ký trong danh bạ hay không.
           - location: Nằm trong dải mạng văn phòng ('office') hay bên ngoài ('external').
           - risk_score: Thiết bị tin cậy = 10 điểm (Low Risk); Thiết bị lạ = 50 điểm (Medium Risk).
        4. Chuyển giao toàn bộ thuộc tính sang OPA Engine để đánh giá phân quyền ABAC.
        5. Nếu OPA phán quyết DENY:
           Ghi Audit log, trả về mã lỗi HTTP 403 (bị từ chối do chính sách) hoặc 503 (lỗi hạ tầng).
           Cờ `db_queried = False` chứng minh CSDL hoàn toàn không bị chạm tới!
        6. Nếu OPA phán quyết ALLOW:
           - Gửi yêu cầu sang OPA lấy Kế hoạch hiển thị (ViewPlan / Obligations): xác định danh sách
             cột được xem, các cột bắt buộc phải che mờ (masking), và phạm vi lọc dòng (row_scope).
           - Chuyển ViewPlan xuống Database để thực thi truy vấn an toàn bằng tài khoản `gateway_reader`.
           - PostgreSQL tự động che mờ cột (DDM) và tự động lọc dòng (RLS).
        7. Ghi Audit Log thành công và trả về dữ liệu an toàn kèm theo các chỉ số đo lường hiệu năng.
        """
        # Tuyệt đối cấm tham số URL giả mạo
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
        
        # Thiết lập bối cảnh khách quan từ hạ tầng
        context = {
            "device_trusted": trusted,
            "location": "office" if any(address in network for network in networks) else "external",
            "time": now.isoformat(),
            "risk_score": 10 if trusted else 50,
        }
        
        # 1. Điểm cung cấp thuộc tính (PIP)
        provider = GatewayProvider(subject, context, now, config["timezone"])
        access = AccessRequest(subject_id=subject["id"], resource_id=resource, action="read")
        
        # 2. Điểm quyết định chính sách (PDP - OPA Engine)
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
        
        # 3. Xử lý khi bị TỪ CHỐI (DENY)
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
            
        # 4. Xử lý khi được CHO PHÉP (ALLOW) - Thực thi nghĩa vụ (Obligations)
        try:
            plan_tick = perf_counter()
            # Lấy ViewPlan từ OPA để biết cần che mờ cột nào và lọc dòng thế nào
            response = core.opa.client.post(
                "/v1/data/gateway/view_plan",
                json={"input": {"decision": "ALLOW", "subject": subject, "resource": resource}},
            )
            response.raise_for_status()
            plan = ViewPlan.model_validate(strict_json_loads(response.text)["result"])
            if plan.resource != resource:
                raise ValueError("Mismatched obligation resource")
            plan_ms = (perf_counter() - plan_tick) * 1000
            
            # Truy vấn PostgreSQL với RLS và DDM
            db_tick = perf_counter()
            audit["db_queried"] = True
            rows = db.query(plan)
            db_ms = (perf_counter() - db_tick) * 1000
        except Exception:
            # Nguyên tắc Fail-Closed: Bất kỳ lỗi thực thi nào cũng chuyển thành DENY 503
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
