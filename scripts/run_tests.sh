#!/usr/bin/env sh
# Kịch bản Thực thi Bộ Kiểm thử Tự động pytest
# Tệp: scripts/run_tests.sh
# - Chạy 198 test cases tự động
# - Xuất kết quả ra file chuẩn JUnit XML (tests/results.xml) phục vụ tích hợp CI/CD
set -eu

cd "$(dirname "$0")/.."

echo "[*] Dang khoi chay 198 ca kiem thu tu dong pytest..."
python -m pytest -q --junitxml=tests/results.xml
echo "[+] Hoan tat kiem thu! Ket qua luu tai: tests/results.xml"
