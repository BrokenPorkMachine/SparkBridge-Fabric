#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
launchctl bootout system/com.sparkbridge.executor 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.sparkbridge.executor.plist /usr/local/bin/sparkbridge-executor
echo "SparkBridge executor removed. /Library/Application Support/SparkBridge was retained intentionally."
