#!/usr/bin/env sh
# Kịch bản Dừng toàn bộ Hệ thống Docker
# Tệp: scripts/stop.sh
set -eu

cd "$(dirname "$0")/.."

echo "[*] Dang dung va giai phong toan bo container trong project abac-v3..."
docker compose --env-file .gateway/gateway.env -f compose.gateway.yml -p abac-v3 down
echo "[+] Da dung toan bo dich vu thanh cong."
