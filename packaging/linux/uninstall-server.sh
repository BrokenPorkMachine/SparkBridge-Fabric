#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo "run as root" >&2; exit 1; }
systemctl disable --now sparkbridge-server 2>/dev/null || true
rm -f /etc/systemd/system/sparkbridge-server.service /usr/local/bin/sparkbridge-server /usr/local/bin/sparkbridge
systemctl daemon-reload
echo "SparkBridge server binaries/service removed. /etc/sparkbridge and /var/lib/sparkbridge were retained intentionally."
