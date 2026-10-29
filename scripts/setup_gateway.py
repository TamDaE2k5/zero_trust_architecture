"""
Kịch bản Khởi tạo Hạ tầng Bảo mật Cổng Dịch vụ (Gateway Setup & PKI Bootstrapper).
Tệp: scripts/setup_gateway.py

Chức năng chính:
1. Khởi tạo Cơ quan Chứng thực Khóa công khai Nội bộ (Private Root Certificate Authority - CA) dùng thuật toán RSA 3072-bit.
2. Cấp phát chứng chỉ số X.509 (Leaf Certificates) dùng thuật toán RSA 2048-bit:
   - Server Certificate: Chứng chỉ máy chủ Nginx (hỗ trợ Subject Alternative Names - SANs cho localhost, 127.0.0.1, IP LAN).
   - Client Certificate: Chứng chỉ định danh thiết bị công ty (`company-device`) dùng cho xác thực mTLS hai chiều.
   - Unregistered Certificate: Chứng chỉ đã ký bởi CA nhưng CỐ TÌNH không đăng ký vào Registry (dùng cho kịch bản Red Team kiểm thử bị từ chối).
3. Đóng gói chứng chỉ máy khách ra định dạng PKCS#12 (`.p12`) có mã hóa mật khẩu để cài đặt trực tiếp vào Trình duyệt web.
4. Sinh các tài khoản mặc định (engineer, analyst, finance, admin) với mật khẩu ngẫu nhiên độ an toàn cao và băm bằng PBKDF2-SHA256 (600.000 vòng).
5. Tự động sinh các khóa bí mật hệ thống (Secrets) an toàn tuyệt đối:
   - `GATEWAY_JWT_SECRET`: Khóa ký số token JWT (32 bytes ngẫu nhiên).
   - `GATEWAY_PROXY_SECRET`: Mã bí mật chứng minh yêu cầu đi qua Nginx mTLS (32 bytes ngẫu nhiên).
   - Mật khẩu CSDL PostgreSQL cho superuser (`gateway_owner`) và ứng dụng (`gateway_reader`).
6. Cấu hình giờ làm việc (Business Hours) cho các chính sách OPA P10, P11 (múi giờ Asia/Bangkok).
7. Xuất cấu hình môi trường `.gateway/gateway.env`, cấu hình Nginx mTLS `nginx.conf`, và danh bạ hệ thống `registry.json`.

Lưu ý: Kịch bản được thiết kế an toàn, nếu thư mục `.gateway` đã tồn tại sẽ không ghi đè để bảo vệ các chứng chỉ và khóa riêng tư hiện hành.
"""

import argparse
import ipaddress
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.gateway.security import hash_password
from app.jsonio import strict_json_loads

# Thư mục gốc của dự án
ROOT = Path(__file__).resolve().parents[1]


def setup(directory: Path, hosts: list[str], office_networks: str, start_hour: int = 0, end_hour: int = 24):
    """
    Hàm thực thi khởi tạo toàn bộ hạ tầng Zero Trust vào thư mục đích (mặc định .gateway):
    - directory: Đường dẫn thư mục runtime (.gateway).
    - hosts: Danh sách tên miền hoặc IP bổ sung cho chứng chỉ server.
    - office_networks: Dải mạng nội bộ văn phòng (CIDR).
    - start_hour, end_hour: Khung giờ làm việc được phép truy cập hệ thống.
    """
    # 1. Kiểm tra an toàn: Nếu thư mục đã tồn tại thì không ghi đè, tránh làm mất khóa bí mật cũ
    if directory.exists():
        raise ValueError(
            "Runtime already exists; preserve credentials and certificates. Use a new directory for a new deployment."
        )
    if not 0 <= start_hour < end_hour <= 24:
        raise ValueError("Invalid business hours")
        
    # Thẩm định dải mạng văn phòng hợp lệ
    for network in office_networks.split(","):
        ipaddress.ip_network(network.strip())

    # Tạo cấu trúc thư mục lưu trữ
    tls = directory / "tls"              # Chứa khóa riêng tư (.key) và chứng chỉ (.crt)
    tls.mkdir(parents=True)
    runtime = directory / "server"       # Chứa registry.json và policies.json
    runtime.mkdir()
    state = directory / "state"          # Chứa database phiên làm việc SQLite sessions.sqlite
    state.mkdir(exist_ok=True)
    
    now = datetime.now(timezone.utc)

    # -------------------------------------------------------------------------
    # 2. KHỞI TẠO ROOT CERTIFICATE AUTHORITY (CA NỘI BỘ)
    # -------------------------------------------------------------------------
    # Sinh cặp khóa RSA 3072-bit mạnh mẽ cho CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ABAC Local Demo CA")])
    
    # Xây dựng chứng chỉ tự ký (Self-signed) cho CA, thời hạn 365 ngày
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )

    def write_pair(label, key, cert):
        """Ghi cặp khóa riêng tư và chứng chỉ công khai ra định dạng chuẩn PEM."""
        (tls / f"{label}.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (tls / f"{label}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # Lưu chứng chỉ và khóa riêng tư của Root CA
    write_pair("ca", ca_key, ca)

    # -------------------------------------------------------------------------
    # 3. HÀM KÝ CHỨNG CHỈ LÁ (LEAF CERTIFICATE: SERVER & CLIENT)
    # -------------------------------------------------------------------------
    def leaf(label, purpose, sans=None):
        """Ký một chứng chỉ mới bằng CA nội bộ với mục đích sử dụng (purpose) xác định."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(cert_name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
            .add_extension(
                x509.KeyUsage(True, False, True, False, False, False, False, False, False),
                critical=True,
            )
        )
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        write_pair(label, key, cert)
        return cert

    # -------------------------------------------------------------------------
    # 4. TẠO CHỨNG CHỈ SERVER (NGINX TLS REVERSE PROXY)
    # -------------------------------------------------------------------------
    # Bổ sung danh sách IP và tên miền SANs để trình duyệt không báo lỗi chứng chỉ sai host
    sans = [x509.DNSName("localhost")]
    for host in {"127.0.0.1", "::1", *hosts}:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            sans.append(x509.DNSName(host))
    leaf("server", ExtendedKeyUsageOID.SERVER_AUTH, sans)

    # -------------------------------------------------------------------------
    # 5. TẠO CHỨNG CHỈ MÁY KHÁCH HỢP LỆ (COMPANY-DEVICE MTLS)
    # -------------------------------------------------------------------------
    client = leaf("company-device", ExtendedKeyUsageOID.CLIENT_AUTH)
    client_key = serialization.load_pem_private_key((tls / "company-device.key").read_bytes(), None)
    p12_pw = secrets.token_urlsafe(20)
    
    # Đóng gói ra file PKCS#12 (.p12) kèm chứng chỉ Root CA để import vào trình duyệt (Chrome, Firefox, Safari)
    (directory / "company-device.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"ABAC company device",
            client_key,
            client,
            [ca],
            serialization.BestAvailableEncryption(p12_pw.encode()),
        )
    )
    # Ghi mật khẩu giải mã p12 và số Serial Number chứng chỉ ra file JSON hỗ trợ
    (directory / "device-import.json").write_text(
        json.dumps(
            {"password": p12_pw, "certificate_serial": format(client.serial_number, "X")},
            indent=2,
        ),
        encoding="utf-8",
    )

    # -------------------------------------------------------------------------
    # 6. TẠO CHỨNG CHỈ MÁY LẠ CỐ TÌNH KHÔNG ĐĂNG KÝ (UNREGISTERED-DEVICE)
    # -------------------------------------------------------------------------
    # Ký bởi CA nhưng KHÔNG ghi vào registry.json => Dùng để kiểm thử kịch bản Red Team bị Nginx chặn (403)
    leaf("unregistered-device", ExtendedKeyUsageOID.CLIENT_AUTH)

    # -------------------------------------------------------------------------
    # 7. KHỞI TẠO TÀI KHOẢN NGƯỜI DÙNG VÀ DANH BẠ HỆ THỐNG (REGISTRY.JSON)
    # -------------------------------------------------------------------------
    accounts = {
        "engineer": ("data_engineer", "data", "restricted"),
        "analyst": ("marketing_analyst", "marketing", "confidential"),
        "finance": ("risk_analyst", "finance", "restricted"),
        "admin": ("admin", "data", "restricted"),
    }
    credentials, rows = {}, {}
    for username, (role, department, clearance) in accounts.items():
        # Sinh mật khẩu ngẫu nhiên 18 ký tự an toàn tuyệt đối
        password = secrets.token_urlsafe(18)
        credentials[username] = password
        rows[username] = {
            "subject": {
                "id": username,
                "role": role,
                "department": department,
                "clearance": clearance,
            },
            # Băm mật khẩu bằng PBKDF2-SHA256 (600.000 vòng)
            "password_hash": hash_password(password),
            "enabled": True,
            "auth_version": 1,
        }
        
    registry = {
        "accounts": rows,
        # Đăng ký Serial Number của thiết bị công ty vào danh sách thiết bị tin cậy (device_trusted=true)
        "devices": {
            format(client.serial_number, "X"): {"id": "company-laptop-01", "enabled": True}
        },
    }
    (runtime / "registry.json").write_text(json.dumps(registry, indent=2), encoding="utf-8")
    (directory / "credentials.json").write_text(json.dumps(credentials, indent=2), encoding="utf-8")

    # -------------------------------------------------------------------------
    # 8. CẬP NHẬT GIỜ KINH DOANH CHO CÁC CHÍNH SÁCH OPA (POLICIES.JSON)
    # -------------------------------------------------------------------------
    policies = strict_json_loads((ROOT / "policies/policies.json").read_text(encoding="utf-8"))
    for policy in policies:
        if policy["id"] in {"P10", "P11"}:
            boundary = start_hour if policy["id"] == "P10" else end_hour
            policy["conditions"][0]["value"] = boundary
            policy["version"] = "3.0.0"
            policy["description"] = policy["rationale"] = (
                f"Gateway business hours {start_hour:02d}:00–{end_hour:02d}:00 Asia/Bangkok."
            )
    (runtime / "policies.json").write_text(json.dumps(policies, indent=2), encoding="utf-8")

    # -------------------------------------------------------------------------
    # 9. SINH CÁC KHÓA BÍ MẬT & CẤU HÌNH BIẾN MÔI TRƯỜNG (GATEWAY.ENV)
    # -------------------------------------------------------------------------
    proxy_secret = secrets.token_hex(32)
    env = {
        "POSTGRES_PASSWORD": secrets.token_hex(24),
        "GATEWAY_DB_PASSWORD": secrets.token_hex(24),
        "GATEWAY_JWT_SECRET": secrets.token_hex(32),
        "GATEWAY_PROXY_SECRET": proxy_secret,
        "OFFICE_NETWORKS": office_networks,
    }
    (directory / "gateway.env").write_text(
        "\n".join(f"{key}={value}" for key, value in env.items()) + "\n", encoding="utf-8"
    )

    # -------------------------------------------------------------------------
    # 10. TẠO FILE CẤU HÌNH NGINX MTLS REVERSE PROXY
    # -------------------------------------------------------------------------
    (directory / "nginx.conf").write_text(
        """events {}
http {
  # Giới hạn tần suất đăng nhập: tối đa 5 yêu cầu/phút từ cùng một IP (chống dò mật khẩu)
  limit_req_zone $binary_remote_addr zone=login:1m rate=5r/m;
  server {
    listen 443 ssl;
    server_name _;
    # Chứng chỉ máy chủ
    ssl_certificate /etc/gateway/tls/server.crt;
    ssl_certificate_key /etc/gateway/tls/server.key;
    # Chứng chỉ Root CA dùng để xác thực chứng chỉ máy khách mTLS
    ssl_client_certificate /etc/gateway/tls/ca.crt;
    ssl_verify_client optional;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 8k;
    error_page 497 =301 https://$http_host$request_uri;
    add_header Strict-Transport-Security "max-age=86400" always;
    
    # Endpoint đăng nhập áp dụng Rate Limiter
    location = /auth/login {
      limit_req zone=login burst=10 nodelay;
      include /etc/gateway/tls/proxy-headers.conf;
      proxy_pass http://gateway:8000;
    }
    
    # Toàn bộ các API khác chuyển tiếp vào Gateway nội bộ
    location / {
      include /etc/gateway/tls/proxy-headers.conf;
      proxy_pass http://gateway:8000;
    }
  }
}
""",
        encoding="utf-8",
    )

    # -------------------------------------------------------------------------
    # 11. TẠO PROXY-HEADERS.CONF (TRUYỀN DỮ LIỆU MTLS TỪ NGINX VÀO FASTAPI)
    # -------------------------------------------------------------------------
    (tls / "proxy-headers.conf").write_text(
        f'''# Mã bí mật chứng minh request đi qua Nginx mTLS, không phải gọi trực tiếp
proxy_set_header X-Gateway-Proxy-Secret "{proxy_secret}";
# Địa chỉ IP thật của máy khách do Nginx ghi nhận
proxy_set_header X-Gateway-Client-IP $remote_addr;
# Trạng thái xác thực mTLS: SUCCESS hoặc FAILED/NONE
proxy_set_header X-Gateway-Device-Verified $ssl_client_verify;
# Số Serial phần cứng của Client Certificate để Gateway đối soát registry
proxy_set_header X-Gateway-Device-Serial $ssl_client_serial;
# Xóa sạch header X-Forwarded-For giả mạo từ bên ngoài
proxy_set_header X-Forwarded-For "";
proxy_set_header Host $host;
proxy_connect_timeout 3s;
proxy_read_timeout 10s;
''',
        encoding="utf-8",
    )

    # Ghi metadata tổng hợp
    (directory / "setup-metadata.json").write_text(
        json.dumps(
            {
                "created_at": now.isoformat(),
                "hosts": hosts,
                "office_networks": office_networks,
                "business_hours": [start_hour, end_hour],
                "timezone": "Asia/Bangkok",
                "note": "Generated synthetic credentials/data; demo heuristic risk.",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return registry


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", nargs="*", default=[], help="Danh sách tên miền hoặc IP bổ sung cho SSL")
    parser.add_argument("--office-networks", default="127.0.0.0/8,::1/128", help="Dải mạng văn phòng hợp lệ (CIDR)")
    parser.add_argument("--start-hour", type=int, default=0, help="Giờ bắt đầu làm việc (0-24)")
    parser.add_argument("--end-hour", type=int, default=24, help="Giờ kết thúc làm việc (0-24)")
    args = parser.parse_args()
    
    setup(ROOT / ".gateway", args.hosts, args.office_networks, args.start_hour, args.end_hour)
    print("[+] Da khoi tao thanh cong ha tang Zero Trust .gateway!")
    print(f"    - Khung gio lam viec: {args.start_hour:02d}:00–{args.end_hour:02d}:00 Asia/Bangkok.")
    print("    - Xem thong tin tai khoan va mat khau tai file: .gateway/credentials.json")
