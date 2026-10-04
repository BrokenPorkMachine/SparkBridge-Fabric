#!/bin/sh
set -eu
PREFIX=${PREFIX:-/usr/local/bin}
APP_SUPPORT="/Library/Application Support/SparkBridge"
LOG_DIR="/Library/Logs/SparkBridge"
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
install -d "$PREFIX" "$APP_SUPPORT" "$LOG_DIR" /Library/LaunchDaemons
install -m 0755 target/release/sparkbridge-executor "$PREFIX/sparkbridge-executor"
[ -f "$APP_SUPPORT/executor.toml" ] || install -m 0600 config/executor.example.toml "$APP_SUPPORT/executor.toml"
install -m 0644 packaging/macos/com.sparkbridge.executor.plist /Library/LaunchDaemons/com.sparkbridge.executor.plist
launchctl bootout system/com.sparkbridge.executor 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.sparkbridge.executor.plist
