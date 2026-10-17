#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
docker compose --env-file .gateway/gateway.env -f compose.gateway.yml -p abac-v3 up -d
