#!/usr/bin/env bash
# End-to-end docker test for bifrost-vpnd (egress NAT mode).
#
# Two-phase startup mirrors run.sh: bring exit up alone, scrape its
# pub key, then bring client + target up with BIFROST_EXIT_PUBKEY
# wired in. The probe runs `curl` *inside* the client container so
# the request goes through the client's TUN → mesh → exit's TUN →
# MASQUERADE → target. The target reports the apparent client
# address at /whoami; that should equal the exit's eth0 IP, not the
# client's, proving the NAT worked.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE="$ROOT/tests/docker"
PARENT=$(cd "$ROOT/.." && pwd)

cleanup() {
    if [ "${BIFROST_KEEP:-}" = "1" ]; then
        echo "=== BIFROST_KEEP=1: leaving cluster up for inspection ==="
        echo "  manual teardown: cd $HERE && BIFROST_EXIT_PUBKEY=00 docker compose -f docker-compose.vpn.yml down -v"
        return
    fi
    echo "=== tear down ==="
    (cd "$HERE" && BIFROST_EXIT_PUBKEY=00 docker compose -f docker-compose.vpn.yml down --remove-orphans -v >/dev/null 2>&1 || true)
}
trap cleanup EXIT

echo "=== build bifrost:test (context=$PARENT) ==="
DOCKER_BUILDKIT=1 docker build \
    -f "$HERE/Dockerfile.bifrost" \
    -t bifrost:test "$PARENT"

echo "=== bring up exit only ==="
(cd "$HERE" && BIFROST_EXIT_PUBKEY=deadbeef docker compose -f docker-compose.vpn.yml up -d --no-deps exit)

echo "=== wait for exit to publish its pub_key ==="
EXIT_PUB=""
for _ in $(seq 1 30); do
    EXIT_PUB=$(docker logs bifrost-vpn-exit 2>&1 | grep -oE 'our pub_key=[0-9a-f]{64}' | head -1 | cut -d= -f2 || true)
    if [ -n "$EXIT_PUB" ]; then
        break
    fi
    sleep 0.5
done
if [ -z "$EXIT_PUB" ]; then
    echo "FAIL: exit never logged its pub_key" >&2
    docker logs bifrost-vpn-exit >&2
    exit 1
fi
echo "exit pub_key=$EXIT_PUB"
export BIFROST_EXIT_PUBKEY="$EXIT_PUB"

echo "=== bring up client + target ==="
(cd "$HERE" && docker compose -f docker-compose.vpn.yml up -d client target)

echo "=== wait for client TUN allocation (≤90s) ==="
for _ in $(seq 1 180); do
    if docker logs bifrost-vpn-client 2>&1 | grep -q 'egress client: allocated'; then
        break
    fi
    sleep 0.5
done

ALLOCATED=$(docker logs bifrost-vpn-client 2>&1 | grep -oE 'allocated [0-9.]+' | head -1 | awk '{print $2}' || true)
if [ -z "$ALLOCATED" ]; then
    echo "FAIL: client did not log an allocated address" >&2
    echo "--- client logs ---"; docker logs --tail 80 bifrost-vpn-client 2>&1
    echo "--- exit logs ---";   docker logs --tail 80 bifrost-vpn-exit   2>&1
    exit 1
fi
echo "client allocated address: $ALLOCATED"

echo "=== force target's IP via the VPN TUN ==="
# Without this the client would reach `target` directly on the docker
# bridge (172.20.0.0/16) and bypass the VPN entirely. We add a /32
# override so just the target's traffic hops through bifrost-eg0;
# the mesh handshake (exit:9001) keeps using eth0 so we don't deadlock.
sleep 2  # let the kernel settle
TARGET_IP=$(docker inspect bifrost-vpn-target -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "target IP = $TARGET_IP"
docker exec bifrost-vpn-client ip route replace "$TARGET_IP/32" via 10.55.0.1 dev bifrost-eg0
docker exec bifrost-vpn-client ip a show bifrost-eg0 || true
docker exec bifrost-vpn-client ip route || true

echo "=== probe: /whoami via mesh-NATed path ==="
set +e
WHOAMI=$(docker exec bifrost-vpn-client curl --max-time 20 -s http://target:8080/whoami 2>&1)
RC1=$?
set -e
echo "/whoami → $WHOAMI"
if [ $RC1 -ne 0 ]; then
    echo "FAIL: /whoami curl returned $RC1"
    echo "--- client logs ---"; docker logs --tail 60 bifrost-vpn-client 2>&1
    echo "--- exit logs ---";   docker logs --tail 60 bifrost-vpn-exit   2>&1
    echo "--- target logs ---"; docker logs --tail 20 bifrost-vpn-target 2>&1
    exit $RC1
fi

EXIT_BRIDGE_IP=$(docker inspect bifrost-vpn-exit -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "exit bridge IP = $EXIT_BRIDGE_IP"
if [ "$WHOAMI" = "$EXIT_BRIDGE_IP" ]; then
    echo "PASS: target saw client as $WHOAMI (= exit's eth0) — NAT worked"
else
    echo "FAIL: target saw $WHOAMI, expected $EXIT_BRIDGE_IP" >&2
    exit 1
fi

echo "=== probe: 256 KB download through NATed path ==="
TMP=$(mktemp)
docker exec bifrost-vpn-client curl --max-time 30 -s -o /tmp/big.bin \
    -w "HTTP %{http_code} bytes=%{size_download} time=%{time_total}s\n" \
    http://target:8080/
docker exec bifrost-vpn-client sha256sum /tmp/big.bin > "$TMP"
LOCAL_DIGEST=$(awk '{print $1}' "$TMP")
REMOTE_DIGEST=$(docker exec bifrost-vpn-client curl --max-time 10 -s http://target:8080/digest)
rm -f "$TMP"

echo "local digest  = $LOCAL_DIGEST"
echo "remote digest = $REMOTE_DIGEST"
if [ "$LOCAL_DIGEST" = "$REMOTE_DIGEST" ]; then
    echo "=== PASS: 256 KB through mesh+NAT, sha256 matches ==="
else
    echo "=== FAIL: digest mismatch ==="
    exit 1
fi

echo "=== exit/client log tails ==="
echo "--- client ---"; docker logs --tail 25 bifrost-vpn-client 2>&1
echo "--- exit ---";   docker logs --tail 25 bifrost-vpn-exit   2>&1
