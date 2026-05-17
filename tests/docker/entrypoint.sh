#!/bin/sh
# bifrost-socks5d entrypoint for the docker testbed.
#
# Reads role + peering info from env vars, generates a fresh config
# (TOML, chmod 600), then execs the daemon. Keys are ephemeral per
# container lifetime — fine for the testbed, never use this pattern
# for a long-lived deployment.
#
# Env vars:
#   BIFROST_ROLE=client|exit           required
#   BIFROST_TCP_PORT=9001              norn listen port
#   BIFROST_SOCKS5_LISTEN=0.0.0.0:1080 SOCKS5 listen (client only)
#   BIFROST_EXIT_PUBKEY=<hex>          exit pub key (client only)
#   BIFROST_EXIT_HOST=exit             exit hostname:port (client only)
#   NETEM_DELAY="20ms 5ms" / NETEM_LOSS=1% — optional WAN simulation
set -eu

ROLE="${BIFROST_ROLE:?BIFROST_ROLE must be set to client or exit}"
TCP_PORT="${BIFROST_TCP_PORT:-9001}"
CONFIG=/etc/bifrost/bifrost.toml
mkdir -p /etc/bifrost
chmod 700 /etc/bifrost

apply_netem() {
    if [ -n "${NETEM_DELAY:-}" ] || [ -n "${NETEM_LOSS:-}" ]; then
        DELAY="${NETEM_DELAY:-0ms}"
        LOSS="${NETEM_LOSS:-0%}"
        echo "[entrypoint] netem: delay=${DELAY} loss=${LOSS}"
        # Best-effort: fails silently in environments without NET_ADMIN.
        tc qdisc add dev eth0 root netem delay ${DELAY} loss ${LOSS} 2>/dev/null || \
            echo "[entrypoint] tc qdisc skip (no NET_ADMIN?)"
    fi
}

if [ "$ROLE" = "exit" ]; then
    bifrost-socks5d genconfig --exit > "$CONFIG"
    # If the client hostname is supplied, list it as a static peer so
    # the exit can dial back in case the crossing-dial tiebreak
    # (norn-rs/transport.rs: larger pub_key defers) silenced the
    # client's outbound attempts.
    PEERS_LINE='peers = []'
    if [ -n "${BIFROST_PEER_HOST:-}" ]; then
        PEERS_LINE="peers = [\"tcp://${BIFROST_PEER_HOST}\"]"
    fi
    sed -i \
        -e "s|tcp://0.0.0.0:9001|tcp://0.0.0.0:${TCP_PORT}|" \
        -e 's|tun_name = "norn0"|tun_name = "bifrost-tun"|' \
        -e 's|multicast_enabled = true|multicast_enabled = false|' \
        -e 's|mdns_enabled = true|mdns_enabled = false|' \
        -e 's|admin_socket = "/var/run/norn.sock"|admin_socket = "/tmp/norn.sock"|' \
        -e 's|peer_cache_path = "/var/lib/norn/peers.json"|peer_cache_path = ""|' \
        -e "s|peers = \\[\\]|${PEERS_LINE}|" \
        "$CONFIG"
elif [ "$ROLE" = "client" ]; then
    EXIT_PUB="${BIFROST_EXIT_PUBKEY:?client mode needs BIFROST_EXIT_PUBKEY}"
    EXIT_HOST="${BIFROST_EXIT_HOST:?client mode needs BIFROST_EXIT_HOST}"
    SOCKS5_LISTEN="${BIFROST_SOCKS5_LISTEN:-0.0.0.0:1080}"
    bifrost-socks5d genconfig > "$CONFIG"
    sed -i \
        -e "s|tcp://0.0.0.0:9001|tcp://0.0.0.0:${TCP_PORT}|" \
        -e 's|tun_name = "norn0"|tun_name = "bifrost-tun"|' \
        -e 's|multicast_enabled = true|multicast_enabled = false|' \
        -e 's|mdns_enabled = true|mdns_enabled = false|' \
        -e 's|admin_socket = "/var/run/norn.sock"|admin_socket = "/tmp/norn.sock"|' \
        -e 's|peer_cache_path = "/var/lib/norn/peers.json"|peer_cache_path = ""|' \
        -e "s|socks5_listen = \"127.0.0.1:1080\"|socks5_listen = \"${SOCKS5_LISTEN}\"|" \
        -e "s|peers = \\[\\]|peers = [\"tcp://${EXIT_HOST}\"]|" \
        "$CONFIG"
    sed -i "s|^exits = \\[$|exits = [\n  { pub_key = \"${EXIT_PUB}\", tag = \"docker\" },|" "$CONFIG"
else
    echo "[entrypoint] unknown role: $ROLE" >&2
    exit 2
fi

chmod 600 "$CONFIG"
apply_netem

echo "[entrypoint] role=$ROLE tcp_port=$TCP_PORT — config:"
sed 's/^/  /' "$CONFIG"
echo "[entrypoint] starting daemon"
exec bifrost-socks5d run -c "$CONFIG"
