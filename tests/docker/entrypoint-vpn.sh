#!/bin/sh
# bifrost-vpnd entrypoint for the VPN testbed.
#
# Same env-driven config-generator pattern as entrypoint.sh, but for
# the VPN daemon. Two roles:
#
#   BIFROST_VPN_ROLE=exit
#     Brings up egress TUN + iptables MASQUERADE. Vars:
#       BIFROST_TCP_PORT      (default 9001)
#       BIFROST_EGRESS_IFACE  (default eth0)
#       BIFROST_POOL_BASE     (default 10.55.0.0)
#       BIFROST_POOL_PREFIX   (default 24)
#       BIFROST_PEER_HOST     optional static peer for crossing-dial
#
#   BIFROST_VPN_ROLE=client
#     Opens an Egress stream to BIFROST_EXIT_PUBKEY via BIFROST_EXIT_HOST,
#     receives an allocated IP, brings up the TUN. Default route is
#     left alone unless BIFROST_INSTALL_DEFAULT_ROUTE=1.
#
# NetEm is applied the same way the SOCKS5 entrypoint does it.
set -eu

ROLE="${BIFROST_VPN_ROLE:?BIFROST_VPN_ROLE must be set to client or exit}"
TCP_PORT="${BIFROST_TCP_PORT:-9001}"
CONFIG=/etc/bifrost/bifrost-vpn.toml
mkdir -p /etc/bifrost
chmod 700 /etc/bifrost

apply_netem() {
    if [ -n "${NETEM_DELAY:-}" ] || [ -n "${NETEM_LOSS:-}" ]; then
        DELAY="${NETEM_DELAY:-0ms}"
        LOSS="${NETEM_LOSS:-0%}"
        echo "[vpn-entrypoint] netem: delay=${DELAY} loss=${LOSS}"
        tc qdisc add dev eth0 root netem delay ${DELAY} loss ${LOSS} 2>/dev/null || \
            echo "[vpn-entrypoint] tc qdisc skip (no NET_ADMIN?)"
    fi
}

base_sed() {
    sed -i \
        -e "s|tcp://0.0.0.0:9001|tcp://0.0.0.0:${TCP_PORT}|" \
        -e 's|tun_name = "norn0"|tun_name = "bifrost-mesh"|' \
        -e 's|multicast_enabled = true|multicast_enabled = false|' \
        -e 's|mdns_enabled = true|mdns_enabled = false|' \
        -e 's|admin_socket = "/var/run/norn.sock"|admin_socket = "/tmp/norn.sock"|' \
        -e 's|peer_cache_path = "/var/lib/norn/peers.json"|peer_cache_path = ""|' \
        "$CONFIG"
}

if [ "$ROLE" = "exit" ]; then
    bifrost-vpnd genconfig --exit > "$CONFIG"
    base_sed
    EGRESS_IFACE="${BIFROST_EGRESS_IFACE:-eth0}"
    POOL_BASE="${BIFROST_POOL_BASE:-10.55.0.0}"
    POOL_PREFIX="${BIFROST_POOL_PREFIX:-24}"
    sed -i \
        -e "s|egress_iface = \"eth0\"|egress_iface = \"${EGRESS_IFACE}\"|" \
        -e "s|pool_base    = \"10.55.0.0\"|pool_base    = \"${POOL_BASE}\"|" \
        -e "s|pool_prefix  = 24|pool_prefix  = ${POOL_PREFIX}|" \
        "$CONFIG"
    if [ -n "${BIFROST_PEER_HOST:-}" ]; then
        sed -i "s|peers = \\[\\]|peers = [\"tcp://${BIFROST_PEER_HOST}\"]|" "$CONFIG"
    fi
elif [ "$ROLE" = "client" ]; then
    EXIT_PUB="${BIFROST_EXIT_PUBKEY:?client mode needs BIFROST_EXIT_PUBKEY}"
    EXIT_HOST="${BIFROST_EXIT_HOST:?client mode needs BIFROST_EXIT_HOST}"
    INSTALL_DEFAULT="${BIFROST_INSTALL_DEFAULT_ROUTE:-false}"
    bifrost-vpnd genconfig --client > "$CONFIG"
    base_sed
    sed -i "s|peers = \\[\\]|peers = [\"tcp://${EXIT_HOST}\"]|" "$CONFIG"
    sed -i "s|^exits = \\[$|exits = [\n  { pub_key = \"${EXIT_PUB}\", tag = \"docker\" },|" "$CONFIG"
    if [ "$INSTALL_DEFAULT" = "1" ] || [ "$INSTALL_DEFAULT" = "true" ]; then
        sed -i 's|install_default_route = false|install_default_route = true|' "$CONFIG"
    fi
else
    echo "[vpn-entrypoint] unknown role: $ROLE" >&2
    exit 2
fi

chmod 600 "$CONFIG"
apply_netem

echo "[vpn-entrypoint] role=$ROLE — config:"
sed 's/^/  /' "$CONFIG"
echo "[vpn-entrypoint] starting daemon"
exec bifrost-vpnd run -c "$CONFIG"
