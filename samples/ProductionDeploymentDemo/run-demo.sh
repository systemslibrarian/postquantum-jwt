#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

ISSUER_URL="${ISSUER_URL:-http://localhost:5180}"
ORDERS_URL="${ORDERS_URL:-http://localhost:5190}"

PASS_COUNT=0
FAIL_COUNT=0

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

log() {
  printf '%s\n' "$*"
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[PASS] %s\n' "$*"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '[FAIL] %s\n' "$*" >&2
  exit 1
}

json_get() {
  local file="$1"
  local expr="$2"

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$file" "$expr" <<'PY'
import json
import sys

path, expr = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

value = data
for part in expr.split("."):
    if part:
        value = value[part]

if value is True:
    print("true")
elif value is False:
    print("false")
elif value is None:
    print("")
else:
    print(value)
PY
  elif command -v jq >/dev/null 2>&1; then
    jq -r ".$expr" "$file"
  else
    fail "Need python3 or jq to parse JSON responses."
  fi
}

wait_for() {
  local name="$1"
  local url="$2"

  for _ in $(seq 1 90); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      pass "$name health check"
      return 0
    fi
    sleep 2
  done

  fail "$name did not become healthy at $url"
}

post_json() {
  local url="$1"
  local body="$2"
  local output="$3"

  curl -fsS -X POST "$url" \
    -H "Content-Type: application/json" \
    -d "$body" \
    -o "$output"
}

http_status_for_token() {
  local token="$1"
  local output="$2"

  curl -sS -o "$output" -w "%{http_code}" \
    "$ORDERS_URL/orders/123" \
    -H "Authorization: Bearer $token"
}

expect_status() {
  local label="$1"
  local expected="$2"
  local token="$3"

  local body="$tmpdir/${label// /_}.json"
  local status
  status="$(http_status_for_token "$token" "$body")"

  if [[ "$status" == "$expected" ]]; then
    pass "$label"
  else
    log "Response body:"
    cat "$body" || true
    fail "$label expected HTTP $expected but got $status"
  fi
}

token_parts() {
  awk -F'.' '{print NF}' <<< "$1"
}

log "Starting ProductionDeploymentDemo stack..."
docker compose -f "$COMPOSE_FILE" up --build -d

wait_for "issuer" "$ISSUER_URL/health"
wait_for "orders-api" "$ORDERS_URL/health"

encrypted_json="$tmpdir/encrypted-token.json"
post_json "$ISSUER_URL/token" '{"subject":"alice","role":"reader","scope":"orders.read","encrypted":true}' "$encrypted_json"
ENCRYPTED_TOKEN="$(json_get "$encrypted_json" "access_token")"
ENCRYPTED_PARTS="$(token_parts "$ENCRYPTED_TOKEN")"

if [[ "$ENCRYPTED_PARTS" == "5" ]]; then
  pass "encrypted token issued as 5-part compact token"
else
  fail "encrypted token should have 5 parts but had $ENCRYPTED_PARTS"
fi

expect_status "encrypted token accepted by orders-api" "200" "$ENCRYPTED_TOKEN"

signed_json="$tmpdir/signed-token.json"
post_json "$ISSUER_URL/token" '{"subject":"bob","role":"reader","scope":"orders.read","encrypted":false}' "$signed_json"
SIGNED_TOKEN="$(json_get "$signed_json" "access_token")"
SIGNED_PARTS="$(token_parts "$SIGNED_TOKEN")"

if [[ "$SIGNED_PARTS" == "3" ]]; then
  expect_status "signed-only token accepted by orders-api" "200" "$SIGNED_TOKEN"
else
  fail "signed-only token should have 3 parts but had $SIGNED_PARTS"
fi

replay_json="$tmpdir/replay-token.json"
post_json "$ISSUER_URL/token" '{"subject":"carol","role":"reader","scope":"orders.read","encrypted":true}' "$replay_json"
REPLAY_TOKEN="$(json_get "$replay_json" "access_token")"
expect_status "first use of replay-test token accepted" "200" "$REPLAY_TOKEN"
expect_status "replayed token rejected" "401" "$REPLAY_TOKEN"

TAMPERED_TOKEN="${ENCRYPTED_TOKEN}A"
expect_status "tampered token rejected" "401" "$TAMPERED_TOKEN"

wrong_audience_json="$tmpdir/wrong-audience-token.json"
post_json "$ISSUER_URL/token/wrong-audience" '{"subject":"dana","role":"reader","scope":"orders.read","encrypted":true}' "$wrong_audience_json"
WRONG_AUDIENCE_TOKEN="$(json_get "$wrong_audience_json" "access_token")"
expect_status "wrong-audience token rejected" "401" "$WRONG_AUDIENCE_TOKEN"

expired_json="$tmpdir/expired-token.json"
post_json "$ISSUER_URL/token/expired" '{"subject":"erin","role":"reader","scope":"orders.read","encrypted":true}' "$expired_json"
EXPIRED_TOKEN="$(json_get "$expired_json" "access_token")"
expect_status "expired token rejected" "401" "$EXPIRED_TOKEN"

old1_json="$tmpdir/old-key-token-1.json"
old2_json="$tmpdir/old-key-token-2.json"
post_json "$ISSUER_URL/token" '{"subject":"frank","role":"reader","scope":"orders.read","encrypted":true}' "$old1_json"
post_json "$ISSUER_URL/token" '{"subject":"grace","role":"reader","scope":"orders.read","encrypted":true}' "$old2_json"
OLD_TOKEN_OVERLAP="$(json_get "$old1_json" "access_token")"
OLD_TOKEN_AFTER_RETIRE="$(json_get "$old2_json" "access_token")"

rotate_json="$tmpdir/rotate.json"
post_json "$ISSUER_URL/keys/rotate" '{}' "$rotate_json"
PUBLISHED_AFTER_ROTATE="$(json_get "$rotate_json" "publishedKeyCount")"

if [[ "$PUBLISHED_AFTER_ROTATE" == "2" ]]; then
  pass "key rotation publishes active + previous keys"
else
  fail "key rotation should publish 2 keys but published $PUBLISHED_AFTER_ROTATE"
fi

sleep 3
expect_status "old-key token accepted during overlap" "200" "$OLD_TOKEN_OVERLAP"

retire_json="$tmpdir/retire.json"
post_json "$ISSUER_URL/keys/retire-previous" '{}' "$retire_json"
PUBLISHED_AFTER_RETIRE="$(json_get "$retire_json" "publishedKeyCount")"

if [[ "$PUBLISHED_AFTER_RETIRE" == "1" ]]; then
  pass "previous key retired"
else
  fail "retirement should publish 1 key but published $PUBLISHED_AFTER_RETIRE"
fi

sleep 3
expect_status "old-key token rejected after retirement" "401" "$OLD_TOKEN_AFTER_RETIRE"

log ""
log "ProductionDeploymentDemo complete: ${PASS_COUNT}/14 checks passed."
