"""
Mô-đun Tương tác Cơ sở Dữ liệu & Thực thi Bảo mật Sâu (Database & Deep Enforcement).
Chức năng chính:
1. Quản lý Connection Pool kết nối tới PostgreSQL bằng tài khoản đặc quyền tối thiểu (`gateway_reader`).
2. Nhận kế hoạch hiển thị (ViewPlan) và nghĩa vụ bắt buộc (Obligations) do OPA Engine phê duyệt.
3. Che mờ dữ liệu động (Dynamic Data Masking - DDM) trực tiếp tại tầng câu lệnh SQL SELECT:
   Dữ liệu nhạy cảm được thay thế bằng chuỗi 'REDACTED' ngay trong PostgreSQL; dữ liệu thô tuyệt đối
   không bao giờ được nạp vào bộ nhớ RAM của tiến trình Python hay xuất hiện trong log.
4. Truyền bối cảnh người dùng an toàn vào biến phiên CSDL (`set_config(..., true)`):
   Sử dụng cờ `is_local = true` (tương đương SET LOCAL trong Transaction) để phạm vi bối cảnh
   tự động hủy ngay khi câu lệnh kết thúc, giải quyết triệt để lỗi Rò rỉ bối cảnh Connection Pool (Connection Reuse Leak).
"""

from typing import Literal

from pydantic import Field, model_validator
from psycopg import sql
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from app.models import StrictModel, Department

# Ánh xạ tên tài nguyên ảo thành tên bảng vật lý thật trong PostgreSQL
TABLES = {
    "customers": "customer_data",
    "financial": "financial_records",
    "production": "production_logs",
}

# Danh mục các cột hợp lệ của từng bảng dữ liệu
COLUMNS = {
    "customers": {"id", "department", "name", "email", "salary", "national_id"},
    "financial": {"id", "department", "period", "revenue"},
    "production": {"id", "department", "event", "severity"},
}


class RowScope(StrictModel):
    """
    Quy định phạm vi dòng dữ liệu được phép đọc (Row Scope):
    - kind = 'all': Được đọc toàn bộ các dòng (thường chỉ dành cho vai trò admin).
    - kind = 'department': Chỉ được đọc các dòng thuộc phòng ban/chi nhánh của mình (`value`).
    """
    kind: Literal["all", "department"]
    value: Department | None = None

    @model_validator(mode="after")
    def valid_scope(self):
        """Bảo đảm: nếu scope là department thì bắt buộc phải có giá trị phòng ban cụ thể."""
        if (self.kind == "department") != (self.value is not None):
            raise ValueError("Invalid row scope")
        return self


class ViewPlan(StrictModel):
    """
    Hợp đồng Kế hoạch Hiển thị (View Plan) do OPA Engine tính toán và phê duyệt:
    - version: Phiên bản hợp đồng kế hoạch (cố định = 1).
    - resource: Tên tài nguyên được truy cập (customers, financial, production).
    - columns: Danh sách các cột được phép lấy về.
    - mask: Danh sách các cột nhạy cảm BẮT BUỘC phải che mờ (ví dụ: email, salary, national_id).
    - row_scope: Phạm vi lọc dòng RLS.
    - limit: Giới hạn số dòng tối đa (1 đến 100 dòng, chống vét cạn CSDL).
    """
    version: Literal[1]
    resource: Literal["customers", "financial", "production"]
    columns: list[str] = Field(min_length=1)
    mask: list[str]
    row_scope: RowScope
    limit: int = Field(ge=1, le=100)

    @model_validator(mode="after")
    def valid_columns(self):
        """Xác thực tính hợp lệ của các cột và danh sách cột cần che mờ."""
        # Không được trùng lặp cột và các cột phải tồn tại trong bảng dữ liệu
        if (
            len(set(self.columns)) != len(self.columns)
            or not set(self.columns) <= COLUMNS[self.resource]
        ):
            raise ValueError("Unsupported columns")
        # Danh sách mask phải là tập con của các cột được truy vấn
        if len(set(self.mask)) != len(self.mask) or not set(self.mask) <= set(self.columns):
            raise ValueError("Unsupported mask")
        # Chỉ hỗ trợ che mờ 3 trường thông tin nhạy cảm định trước
        if not set(self.mask) <= {"email", "salary", "national_id"}:
            raise ValueError("Unknown masking operation")
        return self


class Database:
    def __init__(self, url):
        """
        Khởi tạo Connection Pool kết nối PostgreSQL:
        - min_size = 0, max_size = 5 (giới hạn tối đa 5 kết nối đồng thời để tiết kiệm tài nguyên).
        - row_factory = dict_row (trả về kết quả dạng Python Dictionary {cột: giá trị}).
        - connect_timeout = 3 giây.
        """
        self.pool = ConnectionPool(
            url,
            min_size=0,
            max_size=5,
            open=True,
            timeout=5,
            kwargs={"row_factory": dict_row, "connect_timeout": 3},
        )

    def query(self, plan: ViewPlan):
        """
        Thực thi truy vấn dữ liệu đã được bảo vệ sâu:
        1. Xây dựng mệnh đề SELECT với cơ chế che mờ cột (DDM):
           Nếu cột nằm trong danh sách `plan.mask`, thay thế bằng: 'REDACTED'::text AS <tên_cột>
        2. Xây dựng câu lệnh SQL tham số hóa (Parameterized Query) chống tấn công SQL Injection.
        3. Mượn một kết nối từ Pool, thiết lập timeout câu lệnh là 3 giây.
        4. Cực kỳ quan trọng: Thiết lập biến phiên bối cảnh `gateway.scope` và `gateway.department`
           với tham số `is_local = true` (SELECT set_config(..., true)). Điều này tương đương với
           SET LOCAL: giá trị bối cảnh chỉ tồn tại duy nhất trong giao dịch (transaction) này.
           Sau khi truy vấn xong, bối cảnh biến mất, bảo đảm kết nối trả về Pool hoàn toàn sạch sẽ!
        5. PostgreSQL tự động áp dụng chính sách RLS (Row-Level Security) ở tầng CSDL để lọc dòng.
        """
        # Che mờ trực tiếp trong câu lệnh SELECT ở mức Database
        fields = []
        for column in plan.columns:
            if column in plan.mask:
                fields.append(sql.SQL("'REDACTED'::text AS {} ").format(sql.Identifier(column)))
            else:
                fields.append(sql.Identifier(column))
        
        # Xây dựng câu truy vấn có điều kiện lọc theo phạm vi
        query = sql.SQL("SELECT {} FROM {} WHERE {} ORDER BY id LIMIT %s").format(
            sql.SQL(", ").join(fields),
            sql.Identifier(TABLES[plan.resource]),
            sql.SQL("department = %s") if plan.row_scope.kind == "department" else sql.SQL("TRUE"),
        )
        params = ([plan.row_scope.value] if plan.row_scope.kind == "department" else []) + [
            plan.limit
        ]
        
        with self.pool.connection() as connection:
            # Chặn câu lệnh chạy quá 3 giây (chống tấn công DoS database)
            connection.execute("SET LOCAL statement_timeout = '3s'")
            # Gán bối cảnh phạm vi có giới hạn Transaction-local (is_local=true)
            connection.execute(
                "SELECT set_config('gateway.scope', %s, true), set_config('gateway.department', %s, true)",
                (plan.row_scope.kind, plan.row_scope.value or ""),
            )
            return connection.execute(query, params).fetchall()

    def close(self):
        """Đóng toàn bộ kết nối trong Pool khi tắt dịch vụ Gateway."""
        self.pool.close()

    def ready(self):
        """Kiểm tra trạng thái sẵn sàng của Database (Health Check)."""
        with self.pool.connection() as connection:
            return connection.execute("SELECT 1").fetchone()["?column?"] == 1
