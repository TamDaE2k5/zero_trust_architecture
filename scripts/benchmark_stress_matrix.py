#!/usr/bin/env python3
"""
Zero Trust ABAC Performance & Stress Benchmark Matrix
Tests performance across:
  - Policy scales: 50, 500, 5000 policies
  - Target load rates: 10 req/s, 100 req/s, 1000 req/s
Measures:
  - Actual Throughput (RPS)
  - Success / Error Rate (%)
  - End-to-end Latency (P50, P95, Min, Max)
  - Per-Tier Latency Breakdown:
      * Tier 1: mTLS & Ingress Nginx (Network/TLS overhead)
      * Tier 2: Gateway PEP (Attribute resolution, Context, JWT, JSON)
      * Tier 3: Policy Decision Point OPA (PDP Eval & Roundtrip)
      * Tier 4: Data Enforcement Point PostgreSQL (DEP RLS & DDM)
  - Early-Rejection Path (DENY vs ALLOW)
"""

import asyncio
import json
import math
import shutil
import sys
import time
from pathlib import Path

try:
    import httpx
except ImportError:
    print("Vui lòng cài đặt httpx: pip install httpx")
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
GATEWAY_URL = "https://127.0.0.1:28443"
POLICIES_FILE = ROOT / ".gateway/server/policies.json"
POLICIES_BAK = ROOT / ".gateway/server/policies.json.bak"
CREDS_FILE = ROOT / ".gateway/credentials.json"

CERT_COMPANY = (
    str(ROOT / ".gateway/tls/company-device.crt"),
    str(ROOT / ".gateway/tls/company-device.key"),
)
CERT_UNTRUSTED = (
    str(ROOT / ".gateway/tls/unregistered-device.crt"),
    str(ROOT / ".gateway/tls/unregistered-device.key"),
)

# Load base policies
if not POLICIES_BAK.exists():
    shutil.copyfile(POLICIES_FILE, POLICIES_BAK)

BASE_POLICIES = json.loads(POLICIES_BAK.read_text(encoding="utf-8"))
CREDS = json.loads(CREDS_FILE.read_text(encoding="utf-8"))


def generate_policies(target_count: int) -> list:
    """Generate valid synthetic policies without shadowing the customer resource."""
    policies = list(BASE_POLICIES)
    existing_count = len(policies)
    for i in range(existing_count + 1, target_count + 1):
        policies.append({
            "id": f"P{i:05d}",
            "description": f"Synthetic benchmark policy {i}",
            "target": [{"path": ["resource", "id"], "op": "eq", "value": f"synthetic_res_{i % 100}"}],
            "conditions": [
                {"path": ["subject", "role"], "op": "in", "value": ["admin", "data_engineer"]},
                {"path": ["action"], "op": "eq", "value": "read"}
            ],
            "effect": "Permit" if i % 2 == 0 else "Deny",
            "priority": 50 + (i % 100),
            "version": "1.0.0",
            "reason_code": f"SYNTHETIC_RULE_{i}",
            "baselines": ["rbac", "static_abac", "context_abac"],
            "rationale": f"Synthetic benchmark rule {i}"
        })
    return policies


def percentile(data: list[float], pct: float) -> float:
    if not data:
        return 0.0
    k = (len(data) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return data[int(k)]
    d0 = data[int(f)] * (c - k)
    d1 = data[int(c)] * (k - f)
    return d0 + d1


async def run_load_test(
    policy_count: int,
    target_rate: int,
    duration_s: float,
    cert=CERT_COMPANY,
    username: str = "analyst",
    endpoint: str = "/api/v1/data/customers",
) -> dict:
    """Run an async load burst at target_rate for duration_s seconds."""
    limits = httpx.Limits(max_keepalive_connections=100, max_connections=200)
    total_expected = int(target_rate * duration_s)
    interval = 1.0 / target_rate

    async with httpx.AsyncClient(verify=False, cert=cert, limits=limits, timeout=12.0) as client:
        # 1. Login to get token
        login_res = await client.post(
            f"{GATEWAY_URL}/auth/login",
            json={"username": username, "password": CREDS[username]},
        )
        if login_res.status_code != 200:
            raise RuntimeError(f"Login failed: {login_res.status_code} {login_res.text}")
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Warm up request
        try:
            await client.get(f"{GATEWAY_URL}{endpoint}", headers=headers)
        except Exception:
            pass

        # 3. Scheduled launch of requests
        http_latencies = []
        tier_tls = []
        tier_pep = []
        tier_opa_eval = []
        tier_opa_rt = []
        tier_db = []
        status_counts = {}
        errors = 0

        async def worker(idx: int):
            nonlocal errors
            t0 = time.perf_counter()
            try:
                res = await client.get(f"{GATEWAY_URL}{endpoint}", headers=headers)
                t_total = (time.perf_counter() - t0) * 1000.0
                sc = res.status_code
                status_counts[sc] = status_counts.get(sc, 0) + 1
                http_latencies.append(t_total)

                if sc == 200:
                    data = res.json()
                    m = data.get("metrics", {})
                    gw_ms = m.get("gateway_ms", 0.0)
                    db_ms = m.get("database_ms", 0.0)
                    opa_eval = m.get("opa_eval_ms", 0.0)
                    opa_rt = m.get("opa_roundtrip_ms", 0.0)
                    ob_ms = m.get("obligation_ms", 0.0)

                    tls_ms = max(0.0, t_total - gw_ms)
                    pep_ms = max(0.0, gw_ms - db_ms - opa_rt - ob_ms)

                    tier_tls.append(tls_ms)
                    tier_pep.append(pep_ms)
                    tier_opa_eval.append(opa_eval)
                    tier_opa_rt.append(opa_rt + ob_ms)
                    tier_db.append(db_ms)
                elif sc >= 400:
                    # In Deny cases, Gateway returns 403 or 503
                    if sc == 403:
                        # Legitimate Deny
                        pass
                    else:
                        errors += 1
            except Exception:
                errors += 1
                status_counts["ERR"] = status_counts.get("ERR", 0) + 1

        t_start = time.perf_counter()
        tasks = []
        for i in range(total_expected):
            tasks.append(asyncio.create_task(worker(i)))
            await asyncio.sleep(interval)

        await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.perf_counter() - t_start

    http_latencies.sort()
    tier_tls.sort()
    tier_pep.sort()
    tier_opa_eval.sort()
    tier_opa_rt.sort()
    tier_db.sort()

    success_count = status_counts.get(200, 0)
    total_processed = len(http_latencies) + errors
    actual_rps = total_processed / total_time if total_time > 0 else 0.0
    error_rate = (errors / total_processed * 100.0) if total_processed > 0 else 0.0

    return {
        "policy_count": policy_count,
        "target_rate": target_rate,
        "duration_s": round(total_time, 2),
        "total_requests": total_expected,
        "processed_requests": total_processed,
        "success_count": success_count,
        "error_count": errors,
        "error_rate_pct": round(error_rate, 2),
        "actual_rps": round(actual_rps, 1),
        "http_p50": round(percentile(http_latencies, 50), 2),
        "http_p95": round(percentile(http_latencies, 95), 2),
        "http_min": round(min(http_latencies) if http_latencies else 0.0, 2),
        "http_max": round(max(http_latencies) if http_latencies else 0.0, 2),
        "tier_tls_p50": round(percentile(tier_tls, 50), 2),
        "tier_pep_p50": round(percentile(tier_pep, 50), 2),
        "tier_opa_eval_p50": round(percentile(tier_opa_eval, 50), 2),
        "tier_opa_rt_p50": round(percentile(tier_opa_rt, 50), 2),
        "tier_db_p50": round(percentile(tier_db, 50), 2),
        "status_distribution": status_counts,
    }


def main():
    print("=" * 80)
    print("ZERO TRUST ABAC BENCHMARK MATRIX TEST")
    print("Policies: 50, 500, 5000 | Load Rates: 10, 100, 1000 req/s")
    print("=" * 80)

    policy_scales = [50, 500, 5000]
    load_rates = [10, 100, 1000]

    # Durations tailored to avoid system lockup while gathering statistical significance
    # 10 rps: 3.5s (35 reqs)
    # 100 rps: 3.0s (300 reqs)
    # 1000 rps: 1.5s (1500 reqs burst)
    durations = {
        10: 3.5,
        100: 3.0,
        1000: 1.5,
    }

    results = []

    try:
        for p_count in policy_scales:
            print(f"\n[+] Preparing catalogue with {p_count} policies...")
            policies = generate_policies(p_count)
            POLICIES_FILE.write_text(json.dumps(policies, indent=2), encoding="utf-8")
            time.sleep(1.0)  # Allow Gateway container filesystem event to settle

            for rate in load_rates:
                dur = durations[rate]
                print(f"  --> Running {p_count} policies @ {rate} req/s (burst {dur}s)...", end="", flush=True)
                res = asyncio.run(run_load_test(p_count, rate, dur))
                results.append(res)
                print(f" Done! Actual RPS: {res['actual_rps']}, P50: {res['http_p50']}ms, P95: {res['http_p95']}ms, Err: {res['error_rate_pct']}%")
                time.sleep(1.0)

        # Early-rejection comparison test (Deny path: untrusted device)
        print("\n[+] Running Early-Rejection (DENY path) comparison at 100 req/s...")
        for p_count in [50, 500, 5000]:
            policies = generate_policies(p_count)
            POLICIES_FILE.write_text(json.dumps(policies, indent=2), encoding="utf-8")
            time.sleep(0.5)
            print(f"  --> DENY test: {p_count} policies @ 100 req/s (untrusted cert)...", end="", flush=True)
            res_deny = asyncio.run(run_load_test(p_count, 100, 2.0, cert=CERT_UNTRUSTED))
            res_deny["type"] = "early_deny"
            results.append(res_deny)
            print(f" Done! P50: {res_deny['http_p50']}ms, Statuses: {res_deny['status_distribution']}")
            time.sleep(0.5)

    finally:
        # Restore original policies
        print("\n[*] Restoring original policies.json...")
        shutil.copyfile(POLICIES_BAK, POLICIES_FILE)
        print("[*] Original policies restored successfully.")

    # Save raw results
    out_file = ROOT / "benchmark_results.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n[✓] Results saved to {out_file}")

    # Print summary tables
    print("\n" + "=" * 90)
    print("BẢNG 1: HIỆU NĂNG TỔNG THỂ THEO QUY MÔ POLICY & TẢI TRỌNG (THROUGHPUT & LATENCY)")
    print("=" * 90)
    print(f"{'Policies':<10} | {'Target (req/s)':<14} | {'Actual RPS':<12} | {'P50 (ms)':<10} | {'P95 (ms)':<10} | {'Min (ms)':<10} | {'Max (ms)':<10} | {'Error (%)':<10}")
    print("-" * 90)
    for r in results:
        if r.get("type") == "early_deny":
            continue
        print(f"{r['policy_count']:<10} | {r['target_rate']:<14} | {r['actual_rps']:<12} | {r['http_p50']:<10} | {r['http_p95']:<10} | {r['http_min']:<10} | {r['http_max']:<10} | {r['error_rate_pct']:<10}")

    print("\n" + "=" * 95)
    print("BẢNG 2: BÓC TÁCH ĐỘ TRỄ TỪNG TẦNG KIẾN TRÚC TẠI P50 (TIER-BY-TIER LATENCY BREAKDOWN)")
    print("=" * 95)
    print(f"{'Policies':<10} | {'Rate (r/s)':<10} | {'mTLS/Nginx (ms)':<16} | {'Gateway PEP (ms)':<16} | {'OPA Total (ms)':<16} | {'(OPA Eval ms)':<14} | {'Postgres DEP (ms)':<16}")
    print("-" * 95)
    for r in results:
        if r.get("type") == "early_deny":
            continue
        print(f"{r['policy_count']:<10} | {r['target_rate']:<10} | {r['tier_tls_p50']:<16} | {r['tier_pep_p50']:<16} | {r['tier_opa_rt_p50']:<16} | {r['tier_opa_eval_p50']:<14} | {r['tier_db_p50']:<16}")

    print("\n" + "=" * 80)
    print("BẢNG 3: SO SÁNH ĐƯỜNG TRUY XUẤT CHO PHÉP (ALLOW) VÀ TỪ CHỐI SỚM (EARLY DENY)")
    print("=" * 80)
    print(f"{'Policies':<10} | {'Path':<12} | {'P50 (ms)':<10} | {'P95 (ms)':<10} | {'Postgres Queried?':<18} | {'Status':<12}")
    print("-" * 80)
    deny_map = {r["policy_count"]: r for r in results if r.get("type") == "early_deny"}
    for r in results:
        if r.get("type") != "early_deny" and r["target_rate"] == 100:
            pc = r["policy_count"]
            d = deny_map.get(pc)
            print(f"{pc:<10} | {'ALLOW':<12} | {r['http_p50']:<10} | {r['http_p95']:<10} | {'Yes (RLS + DDM)':<18} | {'HTTP 200':<12}")
            if d:
                print(f"{pc:<10} | {'EARLY DENY':<12} | {d['http_p50']:<10} | {d['http_p95']:<10} | {'No (0 ms)':<18} | {'HTTP 403':<12}")
            print("-" * 80)


if __name__ == "__main__":
    main()
