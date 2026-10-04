#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo "run as root" >&2; exit 1; }
getent group sparkbridge >/dev/null 2>&1 || groupadd --system sparkbridge
id -u sparkbridge >/dev/null 2>&1 || useradd --system --gid sparkbridge --home /var/lib/sparkbridge --shell /usr/sbin/nologin sparkbridge
install -d -o sparkbridge -g sparkbridge /var/lib/sparkbridge 2>/dev/null || true
# /etc/sparkbridge holds root-owned secret material that the server reads as the
# `sparkbridge` service account. The setgid bit makes files created here later
# (sparkbridge pki init) inherit the sparkbridge group so they can be group-readable.
install -d -o root -g sparkbridge -m 2750 /etc/sparkbridge
install -d -o root -g sparkbridge -m 2750 /etc/sparkbridge/pki
install -d /usr/local/bin
install -m 0755 target/release/sparkbridge-server /usr/local/bin/sparkbridge-server
install -m 0755 target/release/sparkbridge /usr/local/bin/sparkbridge
# The unit runs as User=sparkbridge/Group=sparkbridge, so a root:root 0640 config is unreadable.
[[ -f /etc/sparkbridge/server.toml ]] || install -m 0640 -o root -g sparkbridge config/server.example.toml /etc/sparkbridge/server.toml
chgrp sparkbridge /etc/sparkbridge/server.toml
chmod 0640 /etc/sparkbridge/server.toml
install -m 0644 packaging/systemd/sparkbridge-server.service /etc/systemd/system/sparkbridge-server.service
systemctl daemon-reload
cat <<'EOF'
Next:
  1. sparkbridge pki init --dir /etc/sparkbridge/pki
  2. Make the PKI material readable by the service account, then enable:
       chgrp -R sparkbridge /etc/sparkbridge/pki
       chmod 0640 /etc/sparkbridge/pki/*.pem /etc/sparkbridge/pki/gateway-token /etc/sparkbridge/pki/integration-token
       chmod 0600 /etc/sparkbridge/pki/ca-key.pem
  3. systemctl enable --now sparkbridge-server
EOF
