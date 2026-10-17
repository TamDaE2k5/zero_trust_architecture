# Nginx Reverse Proxy trong Kiến trúc Zero Trust

Thư mục này chứa cấu hình mẫu và giải thích kiến trúc của tầng **Nginx Reverse Proxy** — đóng vai trò là **Điểm Thực thi Chính sách Vành đai (Edge Policy Enforcement Point - Edge PEP)** trong kiến trúc Zero Trust (NIST SP 800-207).

---

## 1. Vai trò của Nginx trong Hệ thống

Trong kiến trúc Zero Trust của đồ án:
1. **Phân đoạn Mạng (Micro-segmentation):**
   - Container Nginx là dịch vụ duy nhất cắm vào mạng `edge` và mở cổng 443 ra ngoài cho người dùng / client kết nối.
   - Các dịch vụ cốt lõi: FastAPI Gateway (8000), OPA Policy Engine (8181), PostgreSQL Database (5432) hoàn toàn nằm trong mạng nội bộ cô lập (`backend: internal: true`).
2. **Xác thực Hai chiều (Mutual TLS - mTLS):**
   - Nginx chấm dứt kết nối TLS và kiểm tra tính hợp lệ của chứng chỉ máy khách x509 (`ssl_client_certificate /etc/gateway/tls/ca.crt`).
   - Nếu chứng chỉ hợp lệ, Nginx trích xuất số serial định danh phần cứng `$ssl_client_serial` và trạng thái `$ssl_client_verify`.
3. **Chống Tấn công Dò quét Mật khẩu (Rate Limiting):**
   - Cấu hình `limit_req_zone` giới hạn tốc độ truy cập endpoint `/auth/login` (tối đa 5 requests/phút trên mỗi IP, burst 10).
4. **Chống Giả mạo Địa chỉ IP (Anti-IP Spoofing):**
   - Nginx xóa trắng tiêu đề `X-Forwarded-For: ""` để ngăn chặn kẻ tấn công tự chế header IP giả mạo.
   - Thay vào đó, Nginx ghi nhận IP thật từ socket kết nối TCP thông qua biến `$remote_addr` và truyền qua header `X-Gateway-Client-IP`.
5. **Cơ chế Chống Đi tắt (Anti-Bypass via Shared Secret):**
   - Nginx tự động chèn header `X-Gateway-Proxy-Secret` mang mã bí mật 32-byte ngẫu nhiên.
   - FastAPI Gateway sẽ từ chối ngay lập tức (`HTTP 403 UNTRUSTED_PROXY`) đối với bất kỳ request nào không có header bí mật này.

---

## 2. Cách Nginx hoạt động khi khởi chạy

Khi bạn chạy lệnh:
```bash
python3 scripts/setup_gateway.py --hosts localhost 127.0.0.1
```
Hệ thống sẽ:
1. Sinh chứng chỉ Server TLS và CA trong thư mục `.gateway/tls/`.
2. Tự động sinh mã bí mật ngẫu nhiên `proxy_secret` (32 bytes hex).
3. Tự động kết xuất file cấu hình thực thi vào `.gateway/nginx.conf` và `.gateway/tls/proxy-headers.conf`.
4. File Docker Compose (`compose.gateway.yml`) mount các tệp cấu hình này trực tiếp vào container Nginx khi bạn chạy `./scripts/start.sh`.
