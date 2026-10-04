#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo "run as root" >&2; exit 1; }
install -d /etc/sparkbridge /usr/local/bin
install -m 0755 target/release/sparkbridge-executor /usr/local/bin/sparkbridge-executor
[[ -f /etc/sparkbridge/executor.toml ]] || install -m 0600 config/executor.example.toml /etc/sparkbridge/executor.toml
install -m 0644 packaging/systemd/sparkbridge-executor.service /etc/systemd/system/sparkbridge-executor.service
systemctl daemon-reload
echo "Edit /etc/sparkbridge/executor.toml and enroll before enabling: systemctl enable --now sparkbridge-executor"
