"""
Kịch bản Cấp phát và Đăng ký Chứng chỉ Thiết bị Mới (Device Enrollment & Client PKI).
Tệp: scripts/enroll_device.py

Chức năng chính:
1. Đóng vai trò là công cụ quản trị thiết bị (Device Provisioning Tool) trong kiến trúc Zero Trust.
2. Sinh cặp khóa riêng tư RSA 2048-bit cho một thiết bị máy khách mới (ví dụ: laptop cá nhân, máy trạm nhân viên).
3. Sử dụng Root CA nội bộ (`.gateway/tls/ca.key`) để ký chứng chỉ số X.509 với mục đích xác thực máy khách (`CLIENT_AUTH`).
4. Xuất bộ chứng chỉ đầy đủ:
   - `<device_name>.key`: Khóa riêng tư PEM của thiết bị.
   - `<device_name>.crt`: Chứng chỉ công khai PEM của thiết bị.
   - `ca.crt`: Chứng chỉ công khai của Root CA.
   - `<device_name>.p12`: Gói chứng chỉ PKCS#12 có mật khẩu bảo vệ dùng để nhập (import) vào Trình duyệt web.
   - `device_info.json`: Thông tin định danh, số Serial phần cứng và mật khẩu giải mã file p12.
5. Tự động ghi số Serial Number vào danh bạ `registry.json` để đánh dấu `device_trusted = true`.
6. Hỗ trợ tùy chọn `--no-enroll`: Cấp chứng chỉ hợp lệ nhưng CỐ TÌNH không ghi vào registry
   => Dùng cho kịch bản kiểm thử Red Team: chứng minh thiết bị dù có chứng chỉ do CA cấp nhưng chưa được phê duyệt vẫn bị chặn (403 Forbidden).

Cách sử dụng:
  - Đăng ký thiết bị hợp lệ:
      python scripts/enroll_device.py --name laptop-02
  - Tạo chứng chỉ thử nghiệm chặn (không đăng ký):
      python scripts/enroll_device.py --name laptop-hacker --no-enroll
"""

import argparse
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]


def issue_client_cert(device_name: str, enroll: bool = True, output_dir: Path | None = None):
    """
    Cấp phát chứng chỉ X.509 máy khách và tùy chọn đăng ký vào hệ thống:
    - device_name: Tên định danh thiết bị (ví dụ: laptop-02, pc-ketoan).
    - enroll: Nếu True => Đăng ký số Serial vào registry.json. Nếu False => Chỉ sinh cert để test chặn.
    - output_dir: Thư mục xuất file chứng chỉ (mặc định .gateway/exported_devices/<device_name>).
    """
    gateway_dir = ROOT / ".gateway"
    tls_dir = gateway_dir / "tls"
    runtime_dir = gateway_dir / "server"
    output_dir = output_dir or (gateway_dir / "exported_devices" / device_name)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Kiểm tra sự tồn tại của CA nội bộ
    ca_key_path = tls_dir / "ca.key"
    ca_crt_path = tls_dir / "ca.crt"
    if not ca_key_path.exists() or not ca_crt_path.exists():
        raise FileNotFoundError(
            "Chưa tìm thấy Root CA trong .gateway/tls. Vui lòng chạy setup_gateway.py trước!"
        )

    # Nạp khóa riêng tư và chứng chỉ của Root CA
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), None)
    ca_cert = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())

    # 2. Sinh cặp khóa RSA 2048-bit riêng cho thiết bị mới
    device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_name)])

    # 3. Xây dựng và ký chứng chỉ X.509 cho thiết bị
    # - Mục đích: CLIENT_AUTH (Xác thực máy khách với Nginx mTLS)
    # - Thời hạn: 90 ngày
    cert = (
        x509.CertificateBuilder()
        .subject_name(cert_name)
        .issuer_name(ca_cert.subject)
        .public_key(device_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, False, False, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Định dạng số Serial thành chuỗi Hex in hoa (ví dụ: 3A5F89C...)
    serial_hex = format(cert.serial_number, "X")

    # 4. Lưu khóa và chứng chỉ ra file PEM
    key_pem = device_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    crt_pem = cert.public_bytes(serialization.Encoding.PEM)

    (output_dir / f"{device_name}.key").write_bytes(key_pem)
    (output_dir / f"{device_name}.crt").write_bytes(crt_pem)
    (output_dir / "ca.crt").write_bytes(ca_crt_path.read_bytes())

    # 5. Đóng gói ra file PKCS#12 (.p12) có mật khẩu bảo vệ để import vào Trình duyệt web
    p12_password = secrets.token_urlsafe(16)
    p12_data = pkcs12.serialize_key_and_certificates(
        device_name.encode(),
        device_key,
        cert,
        [ca_cert],
        serialization.BestAvailableEncryption(p12_password.encode()),
    )
    (output_dir / f"{device_name}.p12").write_bytes(p12_data)

    # Ghi file metadata thông tin thiết bị
    metadata = {
        "device_name": device_name,
        "serial_number": serial_hex,
        "enrolled": enroll,
        "p12_password": p12_password,
        "created_at": now.isoformat(),
    }
    (output_dir / "device_info.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    # 6. Đăng ký số Serial vào registry.json nếu có yêu cầu (enroll=True)
    registry_file = runtime_dir / "registry.json"
    if enroll and registry_file.exists():
        registry = json.loads(registry_file.read_text(encoding="utf-8"))
        registry["devices"][serial_hex] = {
            "id": device_name,
            "enabled": True,
        }
        registry_file.write_text(json.dumps(registry, indent=2), encoding="utf-8")
        print(f"[+] Da dang ky thiet bi '{device_name}' (Serial: {serial_hex}) vao danh ba registry.json!")
    else:
        print(f"[-] Thiet bi '{device_name}' (Serial: {serial_hex}) CHUA duoc dang ky vao registry (dung cho test chan)")

    print(f"[+] Files da duoc xuat ra thu muc: {output_dir}")
    print(f"    - Certificate: {device_name}.crt")
    print(f"    - Private Key: {device_name}.key")
    print(f"    - Browser P12: {device_name}.p12 (Mat khau giai ma: {p12_password})")
    print(f"    - Root CA:     ca.crt")
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="laptop-02", help="Ten dinh danh thiet bi (vi du: laptop-02, pc-ketoan)")
    parser.add_argument(
        "--no-enroll",
        action="store_true",
        help="Khong dang ky vao registry (de test kich ban thiet bi co cert hop le nhung bi Gateway tu choi)",
    )
    args = parser.parse_args()
    issue_client_cert(args.name, enroll=not args.no_enroll)
