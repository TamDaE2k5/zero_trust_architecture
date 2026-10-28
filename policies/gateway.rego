# Gói chính sách thực thi tại Cổng Dịch vụ (Gateway View Plan & Data Protection Policy)
# Chức năng: Sau khi một yêu cầu đã được OPA phán quyết ALLOW, mô-đun này sẽ tính toán
# các Nghĩa vụ Bắt buộc (Obligations) cần thực thi ở tầng CSDL, bao gồm:
# 1. Che mờ dữ liệu động (Dynamic Data Masking - DDM): Xác định các cột nhạy cảm cần che giấu.
# 2. Phân vùng phạm vi dòng (Row Scope - RLS): Xác định phạm vi dòng người dùng được đọc.
package gateway

import rego.v1

# Danh mục các cột hợp lệ tương ứng với từng loại tài nguyên
resource_columns := {
    "customers": ["id", "department", "name", "email", "salary", "national_id"],
    "financial": ["id", "department", "period", "revenue"],
    "production": ["id", "department", "event", "severity"],
}

# Quy tắc che mờ cột (DDM Masking Obligation):
# Nếu truy cập bảng 'customers' và vai trò KHÔNG PHẢI là 'admin'
# => Bắt buộc phải che mờ 3 trường nhạy cảm: email, salary, national_id
# Ngược lại, nếu là admin => Không che mờ (trả về danh sách rỗng [])
mask := ["email", "salary", "national_id"] if {
    input.resource == "customers"
    input.subject.role != "admin"
} else := []

# Quy tắc phân vùng phạm vi dòng (RLS Scope Obligation):
# - Nếu vai trò là 'admin' => Được xem toàn bộ các dòng (kind = "all").
# - Nếu là nhân viên thông thường => Chỉ được xem các dòng thuộc phòng ban của mình (kind = "department").
scope := {"kind": "all"} if {
    input.subject.role == "admin"
} else := {"kind": "department", "value": input.subject.department}

# Kế hoạch hiển thị hoàn chỉnh (View Plan Envelope):
# Chỉ được sinh ra khi quyết định trước đó là ALLOW và tài nguyên nằm trong danh mục bảo vệ.
# Gateway sẽ nhận cấu trúc này để truyền xuống PostgreSQL thực thi.
view_plan := {
    "version": 1,
    "resource": input.resource,
    "columns": resource_columns[input.resource],
    "mask": mask,
    "row_scope": scope,
    "limit": 100,                                   # Giới hạn tối đa 100 dòng, chống vét cạn CSDL
} if {
    input.decision == "ALLOW"
    input.resource in {"customers", "financial", "production"}
}
