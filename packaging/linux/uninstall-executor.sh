#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo "run as root" >&2; exit 1; }
systemctl disable --now sparkbridge-executor 2>/dev/null || true
rm -f /etc/systemd/system/sparkbridge-executor.service /usr/local/bin/sparkbridge-executor
systemctl daemon-reload
echo "SparkBridge executor removed. Configuration and identity were retained intentionally."
