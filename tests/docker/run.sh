#!/usr/bin/env bash
# End-to-end docker test for bifrost-socks5d.
#
# Two-phase startup because the client config needs the exit's pub key:
#   1. Build the image, bring up `exit` alone, scrape its pub key
#      from the log.
#   2. Export BIFROST_EXIT_PUBKEY, bring up `client` + `target`, run
#      curl through the SOCKS5 proxy on host:11080 and check the
#      SHA-256 matches what `target` advertises at /digest.
#
# Tear-down is unconditional via the trap.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE="$ROOT/tests/docker"
PARENT=$(cd "$ROOT/.." && pwd)  # contains both norn-rs/ and bifrost/

cleanup() {
    if [ "${BIFROST_KEEP:-}" = "1" ]; then
        echo "=== BIFROST_KEEP=1: leaving cluster up for inspection ==="
        echo "  to tear down manually: cd $HERE && BIFROST_EXIT_PUBKEY=00 docker compose down -v"
        return
    fi
    echo "=== tear down ==="
    (cd "$HERE" && BIFROST_EXIT_PUBKEY=00 docker compose down --remove-orphans -v >/dev/null 2>&1 || true)
}
trap cleanup EXIT

echo "=== build bifrost:test (context=$PARENT) ==="
DOCKER_BUILDKIT=1 docker build \
    -f "$HERE/Dockerfile.bifrost" \
    -t bifrost:test "$PARENT"

echo "=== bring up exit only ==="
(cd "$HERE" && BIFROST_EXIT_PUBKEY=deadbeef docker compose up -d --no-deps exit)

echo "=== wait for exit to publish its pub_key ==="
EXIT_PUB=""
for i in $(seq 1 30); do
    EXIT_PUB=$(docker logs bifrost-test-exit 2>&1 | grep -oE 'our pub_key=[0-9a-f]{64}' | head -1 | cut -d= -f2 || true)
    if [ -n "$EXIT_PUB" ]; then
        break
    fi
    sleep 0.5
done

if [ -z "$EXIT_PUB" ]; then
    echo "FAIL: exit never logged its pub_key" >&2
    docker logs bifrost-test-exit >&2
    exit 1
fi
echo "exit pub_key=$EXIT_PUB"
export BIFROST_EXIT_PUBKEY="$EXIT_PUB"

echo "=== bring up client + target ==="
(cd "$HERE" && docker compose up -d client target)

echo "=== wait for client SOCKS5 listener ==="
for i in $(seq 1 30); do
    if docker logs bifrost-test-client 2>&1 | grep -q 'SOCKS5 listener up'; then
        break
    fi
    sleep 0.5
done

echo "=== wait for mesh session establishment (≤10s) ==="
sleep 8

echo "=== probe: small GET through SOCKS5 ==="
# --socks5-hostname asks curl to forward the literal hostname through the
# SOCKS5 server so the exit container resolves it inside the docker network.
# Run with set +e so a curl failure dumps the live container logs before
# the EXIT trap tears the stack down.
set +e
HTTP_DIGEST=$(curl --max-time 15 --socks5-hostname 127.0.0.1:11080 -sv http://target:8080/digest 2>/tmp/bifrost-arq-curl.log)
CURL_RC=$?
set -e
if [ $CURL_RC -ne 0 ]; then
    echo "FAIL: small GET curl returned $CURL_RC"
    echo "--- curl stderr ---"; tail -30 /tmp/bifrost-arq-curl.log
    echo "--- client logs ---"; docker logs --tail 60 bifrost-test-client 2>&1
    echo "--- exit logs ---";   docker logs --tail 60 bifrost-test-exit   2>&1
    exit $CURL_RC
fi
echo "remote digest = $HTTP_DIGEST"

echo "=== probe: 1 MB download through SOCKS5 ==="
TMP=$(mktemp)
curl --max-time 30 --socks5-hostname 127.0.0.1:11080 -s -o "$TMP" \
     -w "HTTP %{http_code} bytes=%{size_download} time=%{time_total}s\n" \
     http://target:8080/

LOCAL_DIGEST=$(sha256sum "$TMP" | cut -d' ' -f1)
echo "local sha256 = $LOCAL_DIGEST"
rm -f "$TMP"

if [ "$HTTP_DIGEST" = "$LOCAL_DIGEST" ]; then
    echo "=== PASS: 1 MB through mesh, sha256 matches ==="
else
    echo "=== FAIL: digest mismatch (local=$LOCAL_DIGEST remote=$HTTP_DIGEST) ==="
    exit 1
fi

echo "=== client/exit log tail (last 30 lines each) ==="
echo "--- client ---"; docker logs --tail 30 bifrost-test-client 2>&1
echo "--- exit ---";   docker logs --tail 30 bifrost-test-exit 2>&1
