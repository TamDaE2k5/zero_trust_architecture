#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."

if [ ! -f .gateway/gateway.env ]; then
    echo "[*] Chua tim thay .gateway/gateway.env."
    echo "[*] Dang tu dong khoi tao ha tang chung chi PKI va ma bi mat qua setup_gateway.py..."
    python3 scripts/setup_gateway.py --hosts localhost 127.0.0.1
    echo "[+] Khoi tao ha tang .gateway thanh cong!"
fi

docker compose --env-file .gateway/gateway.env -f compose.gateway.yml -p abac-v3 up -d
