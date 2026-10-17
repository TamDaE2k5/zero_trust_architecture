import json
import secrets
from pathlib import Path
from app.gateway.security import hash_password

ROOT = Path(__file__).resolve().parents[1]
gateway_dir = ROOT / ".gateway"
registry_path = gateway_dir / "server/registry.json"
credentials_path = gateway_dir / "credentials.json"

registry = json.loads(registry_path.read_text(encoding="utf-8"))
credentials = json.loads(credentials_path.read_text(encoding="utf-8"))

new_accounts = {
    "intern": {
        "role": "intern",
        "department": "marketing",
        "clearance": "internal",
        "enabled": True,
        "note": "Thực tập sinh Marketing - Clearance thấp (internal)"
    },
    "risk_officer": {
        "role": "risk_analyst",
        "department": "risk",
        "clearance": "restricted",
        "enabled": True,
        "note": "Chuyên viên Risk - Phòng ban 'risk'"
    },
    "revoked_user": {
        "role": "marketing_analyst",
        "department": "marketing",
        "clearance": "confidential",
        "enabled": False,
        "note": "Nhân viên đã nghỉ việc (enabled: false) để test chặn login"
    }
}

for username, meta in new_accounts.items():
    if username not in credentials:
        password = secrets.token_urlsafe(18)
        credentials[username] = password
    else:
        password = credentials[username]
        
    registry["accounts"][username] = {
        "subject": {
            "id": username,
            "role": meta["role"],
            "department": meta["department"],
            "clearance": meta["clearance"],
        },
        "password_hash": hash_password(password),
        "enabled": meta["enabled"],
        "auth_version": 1,
    }

registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
credentials_path.write_text(json.dumps(credentials, indent=2), encoding="utf-8")

print("[+] Da them thanh cong cac tai khoan moi vao registry.json va credentials.json!")
for username, meta in new_accounts.items():
    print(f"  - User: {username:15} | Password: {credentials[username]:24} | Role: {meta['role']:15} | Dept: {meta['department']:10} | Clearance: {meta['clearance']:12} | Enabled: {meta['enabled']}")

