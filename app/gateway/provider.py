"""
Mô-đun Cung cấp Thuộc tính Ngữ cảnh (Attribute Provider & Provenance Resolver).
Chức năng chính:
1. Đóng vai trò là Điểm Cung cấp Thuộc tính (PIP - Policy Information Point) theo chuẩn ABAC.
2. Tập hợp và chuẩn hóa 4 nhóm thuộc tính:
   - Subject (Chủ thể: user_id, role, department, clearance).
   - Resource (Tài nguyên: customers, financial, production, sensitivity).
   - Context (Ngữ cảnh: device_trusted, location, time, risk_score, hour).
   - Action (Hành động: read).
3. Đảm bảo nguồn gốc xuất xứ minh bạch (Explicit Provenance):
   Mỗi thuộc tính đều gắn liền với nguồn gốc tin cậy trên máy chủ (server/account-registry,
   server/resource-registry, server/TLS-proxy-and-clock).
4. Kiểm tra độ tươi mới (Freshness/TTL = 30s): Loại bỏ thuộc tính đã hết hạn.
5. Tuyệt đối chặn đứng mọi nỗ lực giả mạo bối cảnh (Context Override) từ phía Client.
"""

from zoneinfo import ZoneInfo

from app.attribute_provider import AttributeProvider, DecisionError
from app.models import Context, Resource, Subject

# Danh mục định nghĩa tài nguyên và mức độ nhạy cảm dữ liệu (Data Classification)
RESOURCES = {
    "customers": {
        "id": "customers",
        "type": "dataset",
        "department": "marketing",
        "sensitivity": "confidential",      # Dữ liệu bảo mật thông thường
    },
    "financial": {
        "id": "financial",
        "type": "records",
        "department": "finance",
        "sensitivity": "restricted",        # Dữ liệu giới hạn (nhạy cảm cao)
    },
    "production": {
        "id": "production",
        "type": "database",
        "department": "data",
        "sensitivity": "restricted",        # Dữ liệu vận hành hệ thống
    },
}


class GatewayProvider:
    def __init__(self, subject, context, observed_at, business_timezone):
        """
        Khởi tạo Provider với các thông tin đã được Gateway xác thực:
        - subject: Thông tin tài khoản lấy từ registry nội bộ máy chủ (không lấy từ client).
        - context: Ngữ cảnh thực tế thu thập từ mTLS proxy và đồng hồ hệ thống.
        - observed_at: Thời điểm ghi nhận request (dùng để kiểm tra TTL).
        - business_timezone: Múi giờ kinh doanh chuẩn (mặc định Asia/Bangkok).
        """
        self.subject = subject
        self.context = context
        self.observed_at = observed_at
        self.business_timezone = business_timezone

    def resolve(self, request, now, simulation):
        """
        Phân giải và thẩm định toàn bộ thuộc tính trước khi gửi sang OPA:
        1. Chặn đứng hành vi ghi đè ngữ cảnh: Nếu client tự gửi context kèm request,
           lập tức báo lỗi UNTRUSTED_OVERRIDE.
        2. Thẩm định Subject ID và Resource ID có nằm trong danh mục hệ thống hay không.
        3. Kiểm tra tính tươi mới (Freshness/TTL = 30 giây) qua `AttributeProvider.validate`:
           Nếu thuộc tính quan sát đã cũ hơn 30 giây (age >= 30s), OPA sẽ từ chối truy cập (Fail-Closed).
        4. Chuyển đổi giờ truy cập (`hour`) sang múi giờ doanh nghiệp để kiểm tra luật giờ hành chính.
        5. Trả về cấu trúc thuộc tính hoàn chỉnh kèm nhãn nguồn gốc (provenance).
        """
        # Tuyệt đối không chấp nhận tham số can thiệp bối cảnh do client tự gửi
        if request.context is not None or request.failure_mode != "none":
            raise DecisionError("UNTRUSTED_OVERRIDE", "Gateway does not accept context overrides.")
        
        # Kiểm tra tài nguyên và danh tính hợp lệ
        if request.subject_id != self.subject["id"] or request.resource_id not in RESOURCES:
            raise DecisionError("UNKNOWN_RESOURCE", "Unknown identity or resource.", False)
            
        values, provenance = {}, {}
        # Kiểm tra hợp đồng dữ liệu Pydantic và hạn dùng TTL cho từng nhóm thuộc tính
        for name, attrs, model, source in (
            ("subject", self.subject, Subject, "server/account-registry"),
            ("resource", RESOURCES[request.resource_id], Resource, "server/resource-registry"),
            ("context", self.context, Context, "server/TLS-proxy-and-clock"),
        ):
            values[name], provenance[name] = AttributeProvider.validate(
                {"attributes": attrs, "timestamp": self.observed_at.isoformat(), "ttl_seconds": 30},
                model,
                now,
                source,
            )
            
        # Gán giờ hiện tại theo múi giờ kinh doanh của tổ chức (Asia/Bangkok)
        values["context"]["hour"] = self.observed_at.astimezone(
            ZoneInfo(self.business_timezone)
        ).hour
        values["action"] = "read"
        
        return {"attributes": values, "provenance": provenance}
