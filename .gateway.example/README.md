# Thư mục Mẫu: .gateway (Runtime Secrets & PKI State Blueprint)

Thư mục này là **Bản vẽ thiết kế mẫu (Blueprint & Template)** mô tả cấu trúc của thư mục runtime `.gateway/`.

Khi triển khai trên môi trường thực tế, thư mục `.gateway/` thực sự sẽ được tự động sinh ra bằng lệnh:
```bash
python3 scripts/setup_gateway.py --hosts localhost 127.0.0.1
```
hoặc tự động kích hoạt khi bạn chạy `./scripts/start.sh`.

---

## Cấu trúc thư mục `.gateway/` khi được khởi tạo:

```
.gateway/
├── company-device.p12          # Chứng chỉ mTLS đóng gói PKCS#12 (có mật khẩu) cho trình duyệt
├── device-import.json          # Mật khẩu mở khóa file .p12 và Serial của thiết bị
├── credentials.json            # Mật khẩu tài khoản người dùng được sinh ngẫu nhiên
├── gateway.env                 # Biến môi trường mật khẩu và secret truyền vào Docker Compose
├── nginx.conf                  # Cấu hình Nginx reverse proxy mTLS thực thi
├── setup-metadata.json         # Siêu dữ liệu thời gian sinh và dải mạng văn phòng
├── server/
│   ├── policies.json           # File 12 chính sách P01-P12 có áp múi giờ doanh nghiệp
│   └── registry.json           # Sổ đăng ký tài khoản (băm PBKDF2 600k) & Serial thiết bị
├── state/
│   └── sessions.sqlite         # Cơ sở dữ liệu SQLite lưu danh sách phiên còn hiệu lực
└── tls/
    ├── ca.crt / ca.key         # Root Certificate Authority (CA) nội bộ RSA 3072-bit
    ├── server.crt / server.key # Chứng chỉ Server TLS x509 có gắn SANs
    ├── company-device.crt/.key # Chứng chỉ mTLS thiết bị doanh nghiệp tin cậy
    ├── unregistered-device.*   # Chứng chỉ mTLS chưa đăng ký (dùng test phòng thủ)
    └── proxy-headers.conf      # Header bí mật X-Gateway-Proxy-Secret
```

---

## Tại sao thư mục `.gateway/` thực sự không được đưa lên GitHub?
- **Nguyên lý Zero Trust:** Khóa bí mật (`*.key`) và mật khẩu (`gateway.env`, `credentials.json`) **tuyệt đối không bao giờ được lưu vào Git**.
- Mỗi máy chủ / nhà phát triển khi tải mã nguồn về sẽ chạy `setup_gateway.py` để sinh ra một Root CA và bộ mật khẩu **hoàn toàn mới và độc lập**, đảm bảo không bao giờ bị lộ khóa bảo mật ra Internet.
