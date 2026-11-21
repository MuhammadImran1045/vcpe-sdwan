#!/bin/sh
# Create a virtual LAN client: a network namespace whose veth peer is attached
# to the CPE LAN bridge, addressed by the same DHCP server as wired LAN hosts.
#
#   sh netns-client.sh add <bridge> [name]     create client, print its lease
#   sh netns-client.sh del [name]              remove client
#
# Works on Alpine (busybox udhcpc). Run as root on the CPE host.
set -eu

action=${1:?usage: netns-client.sh add <bridge> [name] | del [name]}

case "$action" in
    add)
        bridge=${2:?bridge name required}
        ns=${3:-ci-lan1}
        ;;
    del)
        ns=${2:-ci-lan1}
        ;;
    *)
        echo "unknown action $action" >&2
        exit 2
        ;;
esac

peer="v-$ns"                       # host-side veth, max 15 characters
state="/run/netns-client/$ns"

remove() {
    if [ -f "$state/pid" ]; then
        kill "$(cat "$state/pid")" 2>/dev/null || true
    fi
    ip netns del "$ns" 2>/dev/null || true
    ip link del "$peer" 2>/dev/null || true
    rm -rf "$state"
}

if [ "$action" = del ]; then
    remove
    exit 0
fi

[ -d "/sys/class/net/$bridge/bridge" ] || { echo "$bridge is not a Linux bridge" >&2; exit 1; }

remove
mkdir -p "$state"

ip netns add "$ns"
ip link add "$peer" type veth peer name eth0 netns "$ns"
ip link set "$peer" master "$bridge"
ip link set "$peer" up
ip -n "$ns" link set lo up
ip -n "$ns" link set eth0 up

# DHCP hook: runs inside the namespace, so it only configures the client NIC.
cat > "$state/hook" <<'HOOK'
#!/bin/sh
case "$1" in
    deconfig)
        ip -4 addr flush dev "$interface"
        ip link set dev "$interface" up
        ;;
    bound|renew)
        eval "$(ipcalc -p "$ip" "${subnet:-255.255.255.255}")"
        ip -4 addr flush dev "$interface"
        ip addr add "$ip/$PREFIX" dev "$interface"
        gw=${router%% *}
        if [ -n "$gw" ]; then ip route replace default via "$gw" dev "$interface"; fi
        printf 'IP=%s\nPREFIX=%s\nSERVER=%s\nROUTER=%s\n' "$ip" "$PREFIX" "${serverid:-}" "$gw" > "$NETNS_CLIENT_STATE/lease"
        ;;
esac
exit 0
HOOK
chmod 700 "$state/hook"

# -n: fail instead of retrying forever when no DHCP server answers.
NETNS_CLIENT_STATE="$state" ip netns exec "$ns" \
    udhcpc -i eth0 -n -t 8 -T 2 -p "$state/pid" -s "$state/hook" -x "hostname:$ns" >"$state/udhcpc.log" 2>&1 || {
    cat "$state/udhcpc.log" >&2
    echo "no DHCP lease for $ns on $bridge" >&2
    exit 1
}

cat "$state/lease"
