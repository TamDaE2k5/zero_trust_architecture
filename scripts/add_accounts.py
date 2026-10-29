"""
Kịch bản Bổ sung Tài khoản Người dùng Mẫu (Add Demo Accounts Tool).
Tệp: scripts/add_accounts.py

Chức năng chính:
1. Thêm các tài khoản đặc biệt vào danh bạ `registry.json` và tệp mật khẩu `credentials.json` để phục vụ các kịch bản kiểm thử:
   - `intern`: Thực tập sinh Marketing có mức kiểm tra an ninh thấp (`clearance: internal`). Dùng để test việc bị từ chối truy cập dữ liệu tài chính (Policy P04).
   - `risk_officer`: Chuyên viên phòng Risk (`department: risk`). Dùng để test phân vùng phòng ban và truy cập dữ liệu rủi ro.
   - `revoked_user`: Nhân viên bị khóa tài khoản (`enabled: false`). Dùng để test việc Gateway từ chối đăng nhập ngay từ đầu (HTTP 401).
2. Tự động sinh mật khẩu ngẫu nhiên an toàn nếu tài khoản chưa có mật khẩu.
3. Băm mật khẩu bằng thuật toán PBKDF2-SHA256 (600.000 vòng) trước khi lưu vào danh bạ máy chủ.
"""

import json
import secrets
from pathlib import Path
from app.gateway.security import hash_password

ROOT = Path(__file__).resolve().parents[1]
gateway_dir = ROOT / ".gateway"
registry_path = gateway_dir / "server/registry.json"
credentials_path = gateway_dir / "credentials.json"

# Nạp danh bạ và danh sách mật khẩu hiện có
registry = json.loads(registry_path.read_text(encoding="utf-8"))
credentials = json.loads(credentials_path.read_text(encoding="utf-8"))

# Định nghĩa các tài khoản thử nghiệm chuyên biệt
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
        "enabled": False,     # Cố tình đặt False để kiểm thử cơ chế chặn người dùng bị thu hồi quyền
        "note": "Nhân viên đã nghỉ việc (enabled: false) để test chặn login"
    }
}

# Xử lý sinh mật khẩu và băm mật khẩu an toàn
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

# Lưu dữ liệu cập nhật trở lại đĩa
registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
credentials_path.write_text(json.dumps(credentials, indent=2), encoding="utf-8")

print("[+] Da them thanh cong cac tai khoan moi vao registry.json va credentials.json!")
for username, meta in new_accounts.items():
    print(
        f"  - User: {username:15} | Password: {credentials[username]:24} | "
        f"Role: {meta['role']:15} | Dept: {meta['department']:10} | "
        f"Clearance: {meta['clearance']:12} | Enabled: {meta['enabled']}"
    )
