#!/bin/sh
# =============================================================================
# Kịch bản Khởi tạo Vai trò CSDL Đặc quyền Tối thiểu (Least Privilege Role)
# Tệp: scripts/init_gateway_role.sh
# Tự động thực thi bởi PostgreSQL container khi khởi động
# =============================================================================
set -eu

# Sử dụng psql để tạo user runtime riêng cho Gateway
# - Tuyệt đối không để Gateway dùng tài khoản chủ 'gateway_owner' (superuser)
# - Chỉ cấp quyền đọc SELECT; cấm hoàn toàn INSERT, UPDATE, DELETE
# - Không cấp cờ SUPERUSER và không cấp BYPASSRLS
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v app_password="$GATEWAY_DB_PASSWORD" <<'SQL'
CREATE ROLE gateway_reader LOGIN PASSWORD :'app_password';
GRANT CONNECT ON DATABASE gateway_db TO gateway_reader;
GRANT USAGE ON SCHEMA public TO gateway_reader;
GRANT SELECT ON customer_data, financial_records, production_logs TO gateway_reader;
SQL
