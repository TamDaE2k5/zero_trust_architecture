"""
Mô-đun Quản lý Phiên làm việc (Session Allowlist - Stateful Token Revocation).
Chức năng chính:
1. Giải quyết điểm yếu "Stateless" cố hữu của JWT (token không thể thu hồi trước khi hết hạn).
2. Lưu trữ danh sách các phiên đang hợp lệ (Allowlist) vào cơ sở dữ liệu SQLite cục bộ.
3. Nguyên tắc bảo mật Zero Trust: Tuyệt đối KHÔNG lưu chuỗi token thô (plaintext) vào DB;
   chỉ lưu mã băm SHA-256 của `jti` (JWT ID). Kẻ trộm có đánh cắp file SQLite cũng không tái tạo được Token.
4. Hỗ trợ thu hồi phiên tức thời (Instant Revocation): Khi người dùng bấm Logout, phiên bị xóa ngay lập tức,
   chặn đứng hoàn toàn tấn công Token Replay Attack.
"""

import hashlib
from contextlib import contextmanager
import sqlite3
import time
from pathlib import Path


class Sessions:
    def __init__(self, path):
        """Khởi tạo bảng sessions nếu chưa tồn tại (chỉ gồm: id băm và thời điểm hết hạn expires)."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as database:
            database.execute(
                "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)"
            )

    @contextmanager
    def connect(self):
        """Mở kết nối SQLite an toàn với timeout 3s, tự động commit và đóng kết nối sau khi hoàn thành."""
        connection = sqlite3.connect(self.path, timeout=3)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def identifier(claims):
        """
        Tạo mã định danh phiên an toàn:
        Băm giá trị `jti` từ payload của JWT thành mã hex SHA-256 (64 ký tự).
        """
        return hashlib.sha256(claims["jti"].encode()).hexdigest()

    def add(self, claims):
        """
        Thêm một phiên mới vào Allowlist khi người dùng đăng nhập thành công:
        - Sử dụng transaction BEGIN IMMEDIATE để khóa bảng, chống race-condition.
        - Tự động dọn dẹp (clean-up) các phiên cũ đã hết hạn (`expires <= current_time`).
        - Giới hạn dung lượng tối đa 10.000 phiên đồng thời (chống tràn bộ nhớ / DoS).
        - Ghi mã băm định danh và thời gian hết hạn (`exp`).
        """
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute("DELETE FROM sessions WHERE expires <= ?", (int(time.time()),))
            if database.execute("SELECT count(*) FROM sessions").fetchone()[0] >= 10000:
                raise ValueError("Session capacity reached")
            database.execute(
                "INSERT INTO sessions VALUES (?, ?)", (self.identifier(claims), claims["exp"])
            )

    def active(self, claims):
        """
        Kiểm tra xem phiên này có đang còn hiệu lực hay không:
        - Tìm mã băm của `jti` trong bảng sessions.
        - Phiên được coi là hợp lệ (Active) khi và chỉ khi:
          1. Bản ghi tồn tại trong Allowlist (chưa bị Logout).
          2. Thời gian hết hạn vẫn lớn hơn thời gian hiện tại (`expires > now`).
        """
        with self.connect() as database:
            row = database.execute(
                "SELECT expires FROM sessions WHERE id = ?", (self.identifier(claims),)
            ).fetchone()
            return bool(row and row[0] > time.time())

    def revoke(self, claims):
        """
        Thu hồi phiên tức thì (khi người dùng gọi POST /auth/logout):
        Xóa bản ghi mã băm của phiên khỏi bảng sessions.
        Từ thời điểm này, mọi request gửi kèm token cũ sẽ bị chặn đứng với mã lỗi HTTP 401.
        """
        with self.connect() as database:
            database.execute("DELETE FROM sessions WHERE id = ?", (self.identifier(claims),))
