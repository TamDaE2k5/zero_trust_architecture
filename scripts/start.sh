#!/usr/bin/env sh
# Kịch bản Khởi động Hệ thống Cổng Dữ liệu Zero Trust ABAC
# Tệp: scripts/start.sh
# - Chạy an toàn với cờ: -e (dừng khi lỗi), -u (báo lỗi biến chưa gán)
set -eu

# Chuyển thư mục làm việc về thư mục gốc của dự án
cd "$(dirname "$0")/.."

# 1. Tự động kiểm tra hạ tầng bảo mật (.gateway/gateway.env)
# Nếu lần đầu chạy dự án và chưa có chứng chỉ / khóa bí mật:
if [ ! -f .gateway/gateway.env ]; then
    echo "[*] Chua tim thay .gateway/gateway.env."
    echo "[*] Dang tu dong khoi tao ha tang chung chi PKI va ma bi mat qua setup_gateway.py..."
    python3 scripts/setup_gateway.py --hosts localhost 127.0.0.1
    echo "[+] Khoi tao ha tang .gateway thanh cong!"
fi

# 2. Khởi chạy 4 container Docker trong chế độ chạy ngầm (detached mode -d):
# - Nginx mTLS Proxy (cổng 28443)
# - FastAPI Gateway (cổng nội bộ 8000)
# - OPA Policy Engine (cổng nội bộ 8181)
# - PostgreSQL Database (cổng nội bộ 5432)
echo "[*] Dang khoi dong cac container qua docker compose..."
docker compose --env-file .gateway/gateway.env -f compose.gateway.yml -p abac-v3 up -d
echo "[+] He thong da khoi dong thanh cong tai: https://127.0.0.1:28443"
