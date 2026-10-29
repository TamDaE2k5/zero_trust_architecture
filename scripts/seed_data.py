"""
Kịch bản Tạo Dữ liệu Thuộc tính & Ngữ cảnh Mẫu (Synthetic Data Seeder).
Tệp: scripts/seed_data.py

Chức năng chính:
1. Xuất bản các bản chụp thuộc tính (Synthetic Attribute Snapshots) có gắn dấu thời gian mới nhất (Fresh Timestamp).
2. Thiết lập cấu trúc bao bì hợp đồng dữ liệu chuẩn (Envelope Contract):
   - `attributes`: Thuộc tính nghiệp vụ của đối tượng.
   - `source`: Nguồn gốc minh bạch (`synthetic-server-snapshot`).
   - `timestamp`: Thời điểm quan sát (UTC ISO format).
   - `ttl_seconds`: Thời gian sống tối đa của bản chụp thuộc tính trước khi bị coi là Stale (cũ).
3. Tạo các file dữ liệu thử nghiệm trong thư mục `data/`:
   - `data/users.json`: Danh mục người dùng (admin, engineer, risk, marketing, intern).
   - `data/resources.json`: Danh mục tài nguyên dữ liệu (public_report, customer_dataset, risk_dataset, production_db, finance_records).
   - `data/contexts.json`: Ngữ cảnh truy cập mặc định cho từng người dùng (thiết bị, vị trí, rủi ro).
   - `data/scenarios.json`: Các kịch bản thử nghiệm đa dạng (ngoài giờ, thiết bị lạ, điểm rủi ro cao 90, vị trí external).
"""

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write(path: str, value: any):
    """Ghi dữ liệu JSON ra file theo đường dẫn tương đối từ thư mục gốc."""
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def seed():
    """Hàm khởi tạo toàn bộ bộ dữ liệu mẫu."""
    # Lấy thời gian hiện tại chuẩn UTC
    now = datetime.now(timezone.utc).isoformat()

    def envelope(attributes: dict, ttl: int = 86400):
        """
        Đóng gói thuộc tính theo chuẩn bao bì có nguồn gốc (Provenance Envelope):
        - attributes: Từ điển thuộc tính.
        - source: Nguồn cung cấp tin cậy.
        - timestamp: Thời điểm ghi nhận.
        - ttl_seconds: Hạn sử dụng (mặc định 24h = 86.400 giây cho thuộc tính tĩnh).
        """
        return {
            "attributes": attributes,
            "source": "synthetic-server-snapshot",
            "timestamp": now,
            "ttl_seconds": ttl,
        }

    # 1. Danh sách người dùng mẫu: (id, role, department, clearance)
    users = [
        ("admin", "admin", "data", "restricted"),
        ("engineer", "data_engineer", "data", "restricted"),
        ("risk", "risk_analyst", "risk", "confidential"),
        ("marketing", "marketing_analyst", "marketing", "internal"),
        ("intern", "intern", "data", "public"),
    ]
    
    # 2. Danh sách tài nguyên mẫu: (id, type, department, sensitivity)
    resources = [
        ("public_report", "report", "marketing", "public"),
        ("customer_dataset", "dataset", "marketing", "confidential"),
        ("risk_dataset", "dataset", "risk", "confidential"),
        ("production_db", "database", "data", "restricted"),
        ("finance_records", "records", "finance", "restricted"),
    ]
    
    # Ghi dữ liệu người dùng và tài nguyên
    write(
        "data/users.json",
        [envelope(dict(zip(("id", "role", "department", "clearance"), row))) for row in users],
    )
    write(
        "data/resources.json",
        [
            envelope(dict(zip(("id", "type", "department", "sensitivity"), row)))
            for row in resources
        ],
    )
    
    # 3. Ngữ cảnh truy cập tiêu chuẩn (Thiết bị tin cậy, văn phòng, rủi ro thấp 20 điểm)
    context = {
        "device_trusted": True,
        "location": "office",
        "time": "2026-01-15T10:00:00Z",
        "risk_score": 20,
    }
    # Gán bối cảnh này cho các tài khoản, thời hạn TTL là 1 giờ (3.600 giây)
    write("data/contexts.json", {row[0]: envelope(context.copy(), 3600) for row in users})
    
    # 4. Tạo các kịch bản kiểm thử biến thiên (Policy Evaluation Scenarios)
    scenarios = []
    variants = [
        ("Trusted low-risk workday", {}),                                            # Bình thường
        ("Untrusted device", {"device_trusted": False}),                             # Thiết bị lạ
        ("High risk", {"risk_score": 90}),                                           # Rủi ro cao 90 điểm
        ("Outside work hours", {"time": "2026-01-15T22:00:00Z"}),                    # Ngoài giờ làm việc (22h đêm)
        ("Unexpected location", {"location": "external"}),                           # Vị trí ngoài văn phòng
        ("Untrusted and high risk", {"device_trusted": False, "risk_score": 90}),    # Máy lạ + Rủi ro cao
        ("Medium risk", {"risk_score": 50}),                                         # Rủi ro trung bình 50 điểm
    ]
    
    for label, change in variants:
        scenarios.append(
            {
                "name": label,
                "request": {
                    "subject_id": "engineer",
                    "resource_id": "production_db",
                    "action": "read",
                    "baseline": "context_abac",
                    "strategy": "deny-overrides",
                    "context": {**context, **change},
                },
            }
        )
    write("data/scenarios.json", scenarios)
    print("[+] Da khoi tao thanh cong bo du lieu thuoc tinh mau trong thu muc data/!")


if __name__ == "__main__":
    seed()
