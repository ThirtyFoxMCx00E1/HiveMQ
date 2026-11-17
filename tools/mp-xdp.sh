#!/usr/bin/env bash
# MP XDP game-port filter (3.37 VPS update) - builds and attaches xdp/mp_xdp.c to the public network card.
#   mp-xdp.sh start | stop | status | allow IP | block IP | unblock IP | build
# Settings in /etc/mp-hivemq/mp.env:
#   XDP=1                 0 = never attach (default 1)
#   XDP_PPS=20000         packets per second per source IP before drops (0 = no limit, only size/type checks)
#   XDP_PORTS="1922 1930 1931 1932"
#   XDP_ALLOW="1.2.3.4 5.6.7.8"   IPs never limited (the other regions' VPSes are added from HOST_*)
#   XDP_IFACE=            empty = the interface of the default route
#   4.13.48 - xdp-filter (xdp-tools) in front of it, both on one card through libxdp's dispatcher:
#   XDP_FILTER=0          1 = also run xdp-filter (policy allow: only the rules below are dropped)
#   XDP_FILTER_SRC="17 19 161 389 520 1900 3702 11211"   UDP source ports dropped (reflection / amplification floods:
#                         QOTD, chargen, SNMP, CLDAP, RIP, SSDP, WS-Discovery, memcached). DNS 53 / NTP 123 stay open.
#   XDP_BLOCK="1.2.3.4"   source IPs dropped completely (mp-xdp.sh block IP / unblock IP)
#   Tested on a veth pair (kernel 6.1, xdp-tools 1.6.2): game + TCP ports pass, the source ports above drop, and
#   a 2000-packet flood at 100/s per IP passed 200 (burst). Never use xdp-filter's deny policy: it drops ARP too.
# Native XDP is used when the NIC driver supports it (virtio_net, ena, mlx5, ixgbe...), else generic XDP.
# If anything fails the server just runs without XDP - it is a fast path, never a requirement.
set -uo pipefail
ENV_FILE=/etc/mp-hivemq/mp.env
# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
BASE=${BASE:-/opt/mp}
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="$SRC/../xdp/mp_xdp.c"; [ -f "$C" ] || C="$BASE/kit/xdp/mp_xdp.c"
OBJ=$BASE/xdp/mp_xdp.o
PIN=/sys/fs/bpf/mp_xdp
IFACE=${XDP_IFACE:-$(ip -o -4 route show to default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')}
PORTS=${XDP_PORTS:-"${SERVER_PORT:-1922} 1930 1931 1932"}
PPS=${XDP_PPS:-20000}
log() { logger -t mp-xdp "$*" 2>/dev/null; echo "[mp-xdp] $*"; }

build() {
    command -v clang >/dev/null && command -v bpftool >/dev/null || {
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y -qq clang llvm libbpf-dev >/dev/null 2>&1
        apt-get install -y -qq bpftool >/dev/null 2>&1 || apt-get install -y -qq "linux-tools-$(uname -r)" linux-tools-common >/dev/null 2>&1
    }
    command -v clang >/dev/null || { log "clang missing - XDP skipped"; return 1; }
    mkdir -p "$(dirname "$OBJ")"
    clang -O2 -g -target bpf -I"/usr/include/$(uname -m)-linux-gnu" -c "$C" -o "$OBJ.new" && mv -f "$OBJ.new" "$OBJ"
}
bt() { bpftool "$@" 2>/dev/null; }
FILTER=${XDP_FILTER:-0}
FSRC=${XDP_FILTER_SRC:-"17 19 161 389 520 1900 3702 11211"}
map() { echo "$PIN/maps/$1"; }
le16() { printf '%02x %02x' $(( $1 & 255 )) $(( $1 >> 8 )); }
le32() { printf '%02x %02x %02x %02x' $(( $1 & 255 )) $(( ($1 >> 8) & 255 )) $(( ($1 >> 16) & 255 )) $(( ($1 >> 24) & 255 )); }
ipkey() { local IFS=.; set -- $1; printf '%02x %02x %02x %02x' "$1" "$2" "$3" "$4"; }   # network order
resolve() { getent ahostsv4 "$1" 2>/dev/null | awk 'NR==1{print $1}'; }

allow() {
    local ip=$1; [[ $ip =~ ^[0-9.]+$ ]] || ip=$(resolve "$1"); [ -n "$ip" ] || return 0
    bt map update pinned "$(map mp_allow)" key hex $(ipkey "$ip") value hex 01 && echo "  allow $ip"
}

# 4.13.48: mp_xdp + xdp-filter on one card (libxdp dispatcher: xdp-filter runs first, then mp_xdp)
cfg_maps() {
    local p; [ "$PPS" = 0 ] && p=4294967295 || p=$PPS
    bt map update pinned "$(map mp_cfg)" key hex 00 00 00 00 value hex $(le32 "$p") $(le32 $(( p == 4294967295 ? 0 : p * 2 )))
    for port in $PORTS; do bt map update pinned "$(map mp_ports)" key hex $(le16 "$port") value hex 01; done
    allow 127.0.0.1
    for h in ${XDP_ALLOW:-} ${HOST_ASIA:-} ${HOST_EUROPE:-} ${HOST_NA:-} ${HOST_OCEANIA:-}; do allow "$h"; done
}

start_multi() {
    command -v xdp-filter >/dev/null && command -v xdp-loader >/dev/null || { export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq xdp-tools >/dev/null 2>&1; }
    command -v xdp-filter >/dev/null || { log "xdp-tools missing - mp_xdp alone"; return 1; }
    local mode=native
    xdp-loader load -m native "$IFACE" "$OBJ" >/dev/null 2>&1 || { mode=skb; xdp-loader load -m skb "$IFACE" "$OBJ" >/dev/null 2>&1; } || { log "xdp-loader failed on $IFACE"; return 1; }
    xdp-filter load -m "$mode" -p allow "$IFACE" >/dev/null 2>&1 || { log "xdp-filter load failed - mp_xdp alone"; }
    for p in $FSRC; do xdp-filter port "$p" -m src -p udp >/dev/null 2>&1; done
    for ip in ${XDP_BLOCK:-}; do xdp-filter ip "$ip" -m src >/dev/null 2>&1; done
    # pin mp_xdp's maps where the rest of this script looks for them
    local id; id=$(bpftool -j prog show 2>/dev/null | python3 -c 'import json,sys
p=[x for x in json.load(sys.stdin) if x.get("name")=="mp_xdp"]; print(p[-1]["id"] if p else "")')
    [ -n "$id" ] || { log "mp_xdp not found after load"; return 1; }
    mkdir -p "$PIN/maps"
    for m in $(bpftool -j prog show id "$id" | python3 -c 'import json,sys; print(" ".join(map(str,json.load(sys.stdin)["map_ids"])))'); do
        n=$(bpftool -j map show id "$m" | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')
        bt map pin id "$m" "$PIN/maps/$n"
    done
    echo "$IFACE $mode multi" > "$BASE/xdp/attached"
    MODE=$mode
}

start() {
    [ "${XDP:-1}" = 1 ] || { log "XDP=0 in mp.env - not attached"; stop >/dev/null; return 0; }
    [ -n "$IFACE" ] || { log "no default route interface"; return 1; }
    [ -f "$OBJ" ] && [ "$OBJ" -nt "$C" ] || build || return 1
    command -v bpftool >/dev/null || { log "bpftool missing - XDP skipped"; return 1; }
    mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
    stop >/dev/null 2>&1
    if [ "$FILTER" = 1 ] && start_multi; then
        cfg_maps
        log "attached to $IFACE ($MODE, with xdp-filter: UDP source ports $FSRC dropped${XDP_BLOCK:+, blocked $XDP_BLOCK}), game ports: $PORTS, limit ${PPS}/s per IP"
        return 0
    fi
    bt prog load "$OBJ" "$PIN/prog" type xdp pinmaps "$PIN/maps" || { mkdir -p "$PIN/maps"; bpftool prog load "$OBJ" "$PIN/prog" type xdp pinmaps "$PIN/maps" || { log "load failed"; return 1; }; }
    local mode=xdpdrv
    ip link set dev "$IFACE" xdpdrv pinned "$PIN/prog" 2>/dev/null || { mode=xdpgeneric; ip link set dev "$IFACE" xdpgeneric pinned "$PIN/prog" || { log "attach failed on $IFACE"; rm -rf "$PIN"; return 1; }; }
    echo "$IFACE $mode" > "$BASE/xdp/attached"
    cfg_maps
    log "attached to $IFACE ($mode), game ports: $PORTS, limit ${PPS}/s per IP (burst x2)"
}

stop() {
    local ifc=$IFACE; [ -f "$BASE/xdp/attached" ] && ifc=$(awk '{print $1}' "$BASE/xdp/attached")
    command -v xdp-loader >/dev/null && [ -n "$ifc" ] && xdp-loader unload "$ifc" --all >/dev/null 2>&1
    [ -n "$ifc" ] && { ip link set dev "$ifc" xdpdrv off 2>/dev/null; ip link set dev "$ifc" xdpgeneric off 2>/dev/null; }
    rm -rf "$PIN" "$BASE/xdp/attached"
    echo "[mp-xdp] detached"
}

status() {
    if [ ! -f "$BASE/xdp/attached" ]; then echo "XDP: off"; return 0; fi
    echo "XDP: on ($(cat "$BASE/xdp/attached")), ports $PORTS, ${PPS}/s per IP"
    local names=(passed dropped_size dropped_type dropped_rate)
    for k in 0 1 2 3; do
        n=$(bpftool -j map lookup pinned "$(map stats)" key hex $(le32 $k) 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin); print(sum(int(v.get("value",0)) if not isinstance(v.get("value"),list) else 0 for v in d.get("formatted",{}).get("values",[])))' 2>/dev/null)
        echo "  ${names[$k]}: ${n:-?}"
    done
    if grep -q multi "$BASE/xdp/attached" 2>/dev/null; then
        echo "xdp-filter (in front):"
        xdp-filter status 2>/dev/null | awk '/XDP_DROP|XDP_PASS/ || (/^ +[0-9]/ && $2 ~ /src|dst/)'
    fi
}

case "${1:-status}" in
    start) start;; stop) stop;; status) status;; build) build && echo "built $OBJ";;
    allow) shift; for a in "$@"; do allow "$a"; done;;
    block) shift; for a in "$@"; do xdp-filter ip "$a" -m src && echo "  block $a"; done;;     # needs XDP_FILTER=1
    unblock) shift; for a in "$@"; do xdp-filter ip "$a" -m src -r && echo "  unblock $a"; done;;
    *) echo "usage: $0 start|stop|status|allow IP|block IP|unblock IP|build"; exit 1;;
esac
