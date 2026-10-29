"""
Kịch bản Gia hạn & Bổ sung IP cho Chứng chỉ Máy chủ (Renew Gateway Server Certificate).
Tệp: scripts/renew_gateway_server.py

Chức năng chính:
1. Tái cấp phát (re-issue) CHỈ RIÊNG chứng chỉ máy chủ Nginx (`server.crt` và `server.key`) khi hệ thống đổi mạng hoặc cần mở rộng IP:
   - Thêm các địa chỉ IP mới trong mạng LAN (ví dụ: Wi-Fi văn phòng `192.168.1.15`, IP VPN).
   - Thêm các tên miền mới vào trường Subject Alternative Name (SANs).
2. Bảo toàn nguyên vẹn:
   - Root CA (`ca.crt`, `ca.key`) được giữ nguyên.
   - Toàn bộ danh sách tài khoản, mật khẩu, và thiết bị đã đăng ký trong `registry.json` không bị thay đổi.
   - Toàn bộ Client Certificates của người dùng không cần phải cấp lại.
3. Tự động lưu bản sao lưu chứng chỉ cũ (`server.previous.crt`, `server.previous.key`) để phục vụ khôi phục khẩn cấp.
4. Sau khi chạy script này, chỉ cần khởi động lại container `proxy` (Nginx) để nạp chứng chỉ mới.

Cách sử dụng:
  python scripts/renew_gateway_server.py --hosts 192.168.1.15 gateway.company.local
"""

import argparse
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]


def renew(runtime: Path, hosts: list[str]):
    """
    Gia hạn chứng chỉ Server với danh sách SANs mới:
    - runtime: Thư mục chứa hạ tầng (.gateway).
    - hosts: Danh sách IP hoặc hostname bổ sung cần đưa vào SANs.
    """
    tls = runtime / "tls"
    # 1. Nạp Root CA hiện tại để ký chứng chỉ mới
    ca = x509.load_pem_x509_certificate((tls / "ca.crt").read_bytes())
    ca_key = serialization.load_pem_private_key((tls / "ca.key").read_bytes(), None)
    
    # 2. Sinh cặp khóa RSA 2048-bit mới cho Server
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # 3. Chuẩn bị danh sách tên miền và IP SANs
    names = [x509.DNSName("localhost")]
    for host in {"127.0.0.1", "::1", *hosts}:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
            
    now = datetime.now(timezone.utc)
    
    # 4. Xây dựng và ký chứng chỉ máy chủ X.509 mới (thời hạn 90 ngày)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ABAC Gateway")]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    
    # 5. Lưu bản sao lưu chứng chỉ cũ thành `server.previous.*`
    for suffix in ("crt", "key"):
        path = tls / f"server.{suffix}"
        if path.exists():
            (tls / f"server.previous.{suffix}").write_bytes(path.read_bytes())
            
    # 6. Ghi đè cặp khóa và chứng chỉ máy chủ mới
    (tls / "server.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (tls / "server.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", nargs="+", required=True, help="Danh sách IP hoặc Domain mới cần thêm vào SSL SANs")
    args = parser.parse_args()
    
    renew(ROOT / ".gateway", args.hosts)
    print("[+] Da gia han va cap nhat thanh cong chung chi May chu (Server Certificate)!")
    print("    - Cac IP/Domains duoc bao ve:", args.hosts)
    print("    - Luu y: Chi can khoi dong lai container Nginx proxy: 'docker compose restart proxy'")
