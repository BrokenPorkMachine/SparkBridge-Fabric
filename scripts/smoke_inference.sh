#!/usr/bin/env bash
set -euo pipefail

GATEWAY_URL="${SPARKBRIDGE_GATEWAY_URL:-https://127.0.0.1:7790}"
CA_CERT="${SPARKBRIDGE_CA_CERT:-./pki/ca.pem}"
TOKEN="${SPARKBRIDGE_GATEWAY_TOKEN:-}"
MODEL="${1:-}"

if [[ -z "$TOKEN" ]]; then
  echo "SPARKBRIDGE_GATEWAY_TOKEN is required" >&2
  exit 2
fi

curl --fail --silent --show-error \
  --cacert "$CA_CERT" \
  -H "Authorization: Bearer $TOKEN" \
  "$GATEWAY_URL/api/v1/inference/health"
echo

curl --fail --silent --show-error \
  --cacert "$CA_CERT" \
  -H "Authorization: Bearer $TOKEN" \
  "$GATEWAY_URL/api/v1/inference/models"
echo

if [[ -n "$MODEL" ]]; then
  curl --fail --no-buffer --silent --show-error \
    --cacert "$CA_CERT" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    "$GATEWAY_URL/api/v1/inference/generate" \
    --data "{\"model\":\"$MODEL\",\"prompt\":\"Reply with exactly: SparkBridge inference OK\"}"
  echo
fi
