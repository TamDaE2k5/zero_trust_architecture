"""
Mô-đun Quản lý Bảo mật & Danh tính (Security & Cryptography).
Chức năng chính:
1. Băm mật khẩu an toàn bằng thuật toán PBKDF2-SHA256 (600.000 vòng theo khuyến nghị OWASP).
2. So sánh mật khẩu bằng thời gian hằng số (Constant-time comparison) chống tấn công dò thời gian (Timing Attack).
3. Cấp phát và xác thực Token JWT ngắn hạn (1 phút), gắn chặt với số Serial của chứng chỉ thiết bị phần cứng (mTLS Device Binding).
4. Tuyệt đối không tin tưởng vai trò (Role) do Client tự gửi lên; toàn bộ bối cảnh được mã hóa vào Token do máy chủ ký.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt


def hash_password(password, salt=None):
    """
    Băm mật khẩu người dùng trước khi lưu trữ:
    - Sử dụng thuật toán PBKDF2 với hàm băm SHA-256.
    - 600.000 vòng lặp (vô hiệu hóa các cuộc tấn công Brute-force/Rainbow Table).
    - Tạo salt ngẫu nhiên 16 bytes (32 ký tự hex) cho mỗi mật khẩu.
    - Định dạng đầu ra chuẩn: pbkdf2_sha256$<vòng_lặp>$<salt>$<mã_băm>
    """
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
    return f"pbkdf2_sha256$600000${salt}${digest.hex()}"


def verify_password(password, encoded):
    """
    Kiểm tra mật khẩu đăng nhập:
    - Tách chuỗi mã băm thành 4 thành phần: thuật toán, số vòng, salt, digest.
    - Băm lại mật khẩu nhập vào với cùng salt và số vòng lặp.
    - Dùng `hmac.compare_digest` để so sánh chuỗi: bảo đảm thời gian thực thi như nhau
      bất kể chuỗi giống hay khác nhau (chống tấn công kênh bên / Timing Attack).
    """
    try:
        algorithm, rounds, salt, digest = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or rounds != "600000":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
        return hmac.compare_digest(actual.hex(), digest)
    except (ValueError, TypeError):
        return False


def issue_token(subject, secret, auth_version, device_serial=None):
    """
    Cấp phát JWT Access Token sau khi đăng nhập thành công:
    - sub (Subject): Tên tài khoản định danh người dùng.
    - iss / aud: Phạm vi phát hành và đích đến của token (abac-gateway -> abac-data).
    - exp: Thời gian sống cực ngắn (1 phút) nhằm giảm thiểu rủi ro khi token bị lộ.
    - jti (JWT ID): Mã định danh phiên ngẫu nhiên (dùng để lưu hash vào Session Allowlist SQLite).
    - auth_version: Phiên bản phân quyền của tài khoản (tự động vô hiệu hóa token cũ khi đổi mật khẩu).
    - device_serial: Số Serial của chứng chỉ X.509 trích xuất từ tầng mTLS.
      => Đây là cơ chế Ràng buộc Thiết bị (Certificate Binding): kẻ tấn công lấy được token này
         nhưng mang sang máy tính khác (serial khác) sẽ bị Gateway từ chối ngay lập tức!
    """
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": subject,
            "iss": "abac-gateway",
            "aud": "abac-data",
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=1),
            "jti": secrets.token_hex(16),
            "auth_version": auth_version,
            "device_serial": device_serial,
        },
        secret,
        algorithm="HS256",
    )


def decode_token(token, secret):
    """
    Giải mã và thẩm định tính toàn vẹn của JWT Token:
    - Xác thực chữ ký số bằng khóa bí mật bí mật (secret).
    - Kiểm tra thời hạn (exp, nbf), nhà phát hành (iss) và đối tượng sử dụng (aud).
    - Rà soát hợp đồng dữ liệu nghiêm ngặt (Strict Contract Validation):
      + auth_version phải là số nguyên dương.
      + jti phải có độ dài đúng 32 ký tự hex.
      + device_serial nếu có phải hợp lệ về mặt định dạng chuỗi.
    """
    claims = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer="abac-gateway",
        audience="abac-data",
        options={"require": ["sub", "iss", "aud", "iat", "nbf", "exp", "jti", "auth_version"]},
    )
    if (
        type(claims["auth_version"]) is not int
        or claims["auth_version"] < 1
        or not isinstance(claims["jti"], str)
        or len(claims["jti"]) != 32
        or "device_serial" not in claims
        or (
            claims["device_serial"] is not None
            and (not isinstance(claims["device_serial"], str) or len(claims["device_serial"]) > 64)
        )
    ):
        raise jwt.InvalidTokenError("Invalid identity/session contract")
    return claims
