"""
Kịch bản Xuất Chứng chỉ Thiết bị cho Trình duyệt (Export Device PKCS#12).
Tệp: scripts/export_device.py

Chức năng chính:
1. Đóng gói cặp khóa riêng tư (`company-device.key`) và chứng chỉ (`company-device.crt`)
   kèm Root CA (`ca.crt`) thành tệp định dạng chuẩn công nghiệp PKCS#12 (`.p12`).
2. Mã hóa file `.p12` bằng mật khẩu ngẫu nhiên độ an toàn cao (`secrets.token_urlsafe(20)`).
3. Cho phép người dùng hoặc quản trị viên dễ dàng nhập (import) chứng chỉ vào kho chứng chỉ cá nhân
   trên các hệ điều hành (Windows Certificate Manager, macOS Keychain, Linux NSS) hoặc trình duyệt (Chrome, Firefox).
4. Lưu mật khẩu giải mã và số Serial chứng chỉ vào tệp `.gateway/device-import.json` để tiện tra cứu.
"""

import json
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

ROOT = Path(__file__).resolve().parents[1]


def export(runtime: Path):
    """
    Xuất chứng chỉ thiết bị công ty ra file company-device.p12:
    - runtime: Thư mục chứa hạ tầng (.gateway).
    """
    destination = runtime / "company-device.p12"
    # Kiểm tra an toàn: Nếu file p12 đã tồn tại thì không ghi đè để bảo vệ khóa cũ
    if destination.exists():
        raise ValueError("Device import already exists; credentials are preserved")
        
    # Nạp khóa riêng tư và chứng chỉ công khai của thiết bị
    key = serialization.load_pem_private_key(
        (runtime / "tls/company-device.key").read_bytes(), None
    )
    certificate = x509.load_pem_x509_certificate((runtime / "tls/company-device.crt").read_bytes())
    ca = x509.load_pem_x509_certificate((runtime / "tls/ca.crt").read_bytes())
    
    # Sinh mật khẩu mã hóa ngẫu nhiên
    password = secrets.token_urlsafe(20)
    
    # Đóng gói và mã hóa theo chuẩn PKCS#12
    destination.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"ABAC company device",
            key,
            certificate,
            [ca],
            serialization.BestAvailableEncryption(password.encode()),
        )
    )
    
    # Ghi mật khẩu và Serial Number ra file JSON
    (runtime / "device-import.json").write_text(
        json.dumps(
            {"password": password, "certificate_serial": format(certificate.serial_number, "X")},
            indent=2,
        ),
        encoding="utf-8",
    )
    return destination


if __name__ == "__main__":
    p12_path = export(ROOT / ".gateway")
    print(f"[+] Da xuat thanh cong goi chung chi: {p12_path}")
    print("    - Xem mat khau nhap vao trinh duyet tai: .gateway/device-import.json")
