"""Issue and optionally enroll a new client certificate for another machine."""

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
    gateway_dir = ROOT / ".gateway"
    tls_dir = gateway_dir / "tls"
    runtime_dir = gateway_dir / "server"
    output_dir = output_dir or (gateway_dir / "exported_devices" / device_name)
    output_dir.mkdir(parents=True, exist_ok=True)

    ca_key_path = tls_dir / "ca.key"
    ca_crt_path = tls_dir / "ca.crt"
    if not ca_key_path.exists() or not ca_crt_path.exists():
        raise FileNotFoundError("CA certificate or key not found in .gateway/tls. Run setup_gateway.py first.")

    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), None)
    ca_cert = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())

    # Generate new device RSA key
    device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_name)])

    # Build certificate
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

    serial_hex = format(cert.serial_number, "X")

    # Save PEM files
    key_pem = device_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    crt_pem = cert.public_bytes(serialization.Encoding.PEM)

    (output_dir / f"{device_name}.key").write_bytes(key_pem)
    (output_dir / f"{device_name}.crt").write_bytes(crt_pem)
    (output_dir / "ca.crt").write_bytes(ca_crt_path.read_bytes())

    # Export password-protected PKCS#12 (.p12) for browser import
    p12_password = secrets.token_urlsafe(16)
    p12_data = pkcs12.serialize_key_and_certificates(
        device_name.encode(),
        device_key,
        cert,
        [ca_cert],
        serialization.BestAvailableEncryption(p12_password.encode()),
    )
    (output_dir / f"{device_name}.p12").write_bytes(p12_data)

    metadata = {
        "device_name": device_name,
        "serial_number": serial_hex,
        "enrolled": enroll,
        "p12_password": p12_password,
        "created_at": now.isoformat(),
    }
    (output_dir / "device_info.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    # Enroll in registry if requested
    registry_file = runtime_dir / "registry.json"
    if enroll and registry_file.exists():
        registry = json.loads(registry_file.read_text(encoding="utf-8"))
        registry["devices"][serial_hex] = {
            "id": device_name,
            "enabled": True,
        }
        registry_file.write_text(json.dumps(registry, indent=2), encoding="utf-8")
        print(f"[+] Da dang ky thiet bi '{device_name}' (Serial: {serial_hex}) vao registry.json")
    else:
        print(f"[-] Thiet bi '{device_name}' (Serial: {serial_hex}) CHUA duoc dang ky vao registry (dung cho test chan)")

    print(f"[+] Files da duoc xuat ra thu muc: {output_dir}")
    print(f"    - Certificate: {device_name}.crt")
    print(f"    - Private Key: {device_name}.key")
    print(f"    - Browser P12: {device_name}.p12 (Mat khau: {p12_password})")
    print(f"    - CA Root:     ca.crt")
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="laptop-02", help="Ten dinh danh thiet bi (vi du: laptop-02)")
    parser.add_argument(
        "--no-enroll",
        action="store_true",
        help="Khong dang ky vao registry (de test kich ban thiet bi co cer nhung bi tu choi)",
    )
    args = parser.parse_args()
    issue_client_cert(args.name, enroll=not args.no_enroll)
