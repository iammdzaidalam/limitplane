#!/usr/bin/env bash
# Local proof of the XDP fast path, in a privileged Docker container (Docker Desktop's Linux VM works).
# Two network namespaces joined by a veth pair: "gw" runs the gateway and limitplane-xdp, "cl" sends from
# several source IPs. Checks: the program's verdicts (BPF test runs), manual bans drop at the NIC while
# other IPs pass, autopilot bans reach the NIC, unbans lift, the pps guard drops a UDP flood, a ban lapses
# in the kernel while the loader is frozen, exempt addresses pass inside a banned range, and SIGTERM
# detaches. The whole suite runs once per XDP mode, each in a fresh container.
#
#   ./xdp/test.sh                 # generic, then native; needs docker, builds on the host with Go
#   ./xdp/test.sh native          # one mode
set -euo pipefail

if [[ "${1:-}" != "--inside" ]]; then
	here=$(cd "$(dirname "$0")" && pwd)
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	arch=$(docker version --format '{{.Server.Arch}}')
	echo "building linux/$arch binaries"
	(cd "$here" && GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -o "$work/" ./cmd/limitplane-xdp ./test/udpflood)
	(cd "$here" && GOOS=linux GOARCH=$arch CGO_ENABLED=0 go test -c -o "$work/fastpath.test" ./fastpath)
	(cd "$here/.." && GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -o "$work/" ./cmd/limitplane)
	cp "$0" "$work/test.sh"
	docker build -q -t limitplane-xdp-test - >/dev/null <<-'EOF'
		FROM ubuntu:24.04
		RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 iputils-ping curl >/dev/null && rm -rf /var/lib/apt/lists/*
	EOF
	modes=("$@")
	((${#modes[@]})) || modes=(generic native)
	rc=0
	for m in "${modes[@]}"; do
		echo
		echo "######## $m mode"
		docker run --rm --privileged -v "$work:/w:ro" limitplane-xdp-test bash /w/test.sh --inside "$m" || rc=1
	done
	exit $rc
fi

# ---- inside the container ----
MODE=$2 KEY=xdp-test-key PPS=1000 BURST=2000
case $MODE in generic) FLAG=xdpgeneric ;; native) FLAG=xdp ;; *) echo "mode $MODE?"; exit 2 ;; esac
GW=http://127.0.0.1:9090
fails=0 passes=0
pass() { echo "PASS  $*"; passes=$((passes + 1)); }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
refute() { local d=$1; shift; if "$@" >/dev/null 2>&1; then fail "$d"; else pass "$d"; fi; }
gw() { ip netns exec gw "$@"; }
cl() { ip netns exec cl "$@"; }
metric() { gw curl -s 127.0.0.1:9102/metrics | awk -v k="$1" '$1 == k { print $2 }'; }
api() { gw curl -s -H "Authorization: Bearer $TOKEN" "$@"; }
ping4() { cl ping -c 2 -i 0.2 -W 1 -I "$1" 10.99.0.1; }
ping6() { cl ping -6 -c 2 -i 0.2 -W 1 -I "$1" fd00:99::1; }
http() { cl curl -s -o /dev/null -w '%{http_code}' --max-time 2 --interface "$1" http://10.99.0.1:9090/v1/ping; }
http200() { [[ "$(http "$1")" == 200 ]]; }
silent() { [[ "$(http "$1")" == 000 ]]; } # no HTTP answer at all: dropped below the gateway
stat() { gw /w/limitplane-xdp stats --iface veth-gw | tr ' ' '\n' | sed -n "s/^$1=//p"; }
stormed() { api "$GW/api/bans" | grep -q "\"client\":\"$1\"[^}]*\"reason\":\"storm\""; }
settle() { sleep 2.5; } # > one sync interval plus a request

ip netns add gw
ip netns add cl
ip link add veth-gw type veth peer name veth-cl
ip link set veth-gw netns gw
ip link set veth-cl netns cl
gw ip addr add 10.99.0.1/24 dev veth-gw
gw ip addr add fd00:99::1/64 dev veth-gw nodad
for i in 2 3 4 5 6; do cl ip addr add "10.99.0.$i/24" dev veth-cl; done
for i in 2 3; do cl ip addr add "fd00:99::$i/64" dev veth-cl nodad; done
gw ip link set lo up; gw ip link set veth-gw up
cl ip link set lo up; cl ip link set veth-cl up

echo "== kernel $(uname -r), $MODE mode"
echo "== program verdicts (BPF_PROG_TEST_RUN)"
check "fastpath package tests against the kernel" /w/fastpath.test -test.run 'Program|Open'

ip netns exec gw /w/limitplane --addr :9090 --admin-key "$KEY" >/tmp/gateway.log 2>&1 &
GW_PID=$!
for _ in $(seq 50); do gw curl -sf "$GW/healthz" >/dev/null && break; sleep 0.1; done
TOKEN=$(gw curl -s -d "{\"key\":\"$KEY\"}" "$GW/api/login" | sed 's/.*"token":"\([^"]*\)".*/\1/')

echo "== baseline, no XDP (also warms ARP/ND caches)"
for s in 10.99.0.2 10.99.0.3 10.99.0.4 10.99.0.5 10.99.0.6; do check "ping from $s" ping4 $s; done
for s in fd00:99::2 fd00:99::3; do check "ping6 from $s" ping6 $s; done
check "http from 10.99.0.2" http200 10.99.0.2

# Not via gw(): a function would background a subshell, and $! must be the loader for the SIGTERM test.
ip netns exec gw /w/limitplane-xdp --iface veth-gw --mode "$MODE" --gateway "$GW" --admin-key "$KEY" \
	--pps $PPS --burst $BURST --exempt 10.99.0.6 --metrics 127.0.0.1:9102 >/tmp/xdp.log 2>&1 &
XDP_PID=$!
for _ in $(seq 50); do gw curl -sf 127.0.0.1:9102/metrics >/dev/null && break; sleep 0.1; done
if ! gw ip link show veth-gw | grep -Eq "mtu [0-9]+ $FLAG "; then
	cat /tmp/xdp.log
	echo "FAIL  limitplane-xdp did not attach in $MODE mode"
	exit 1
fi
pass "attached in $MODE mode: $(gw ip -d link show veth-gw | grep -o 'prog/xdp id [0-9]*' | head -1)"

echo "== manual ban: 10.99.0.2 and fd00:99::2 (5 min), 10.99.0.5 (1 min, for the expiry check)"
api -d '{"client":"10.99.0.2","minutes":5}' "$GW/api/bans"
api -d '{"client":"fd00:99::2","minutes":5}' "$GW/api/bans"
api -d '{"client":"10.99.0.5","minutes":1}' "$GW/api/bans"
SHORT_UNTIL=$(($(date +%s) + 60))
settle
before=$(metric 'limitplane_xdp_packets_total{action="drop_ban"}')
refute "ping from banned 10.99.0.2 dropped" ping4 10.99.0.2
check "http from banned 10.99.0.2 gets no answer" silent 10.99.0.2
refute "ping6 from banned fd00:99::2 dropped" ping6 fd00:99::2
check "ping from 10.99.0.3 passes" ping4 10.99.0.3
check "http from 10.99.0.3 passes" http200 10.99.0.3
check "ping6 from fd00:99::3 passes" ping6 fd00:99::3
after=$(metric 'limitplane_xdp_packets_total{action="drop_ban"}')
check "drop_ban counter rose ($before -> $after)" test "$after" -gt "$before"
check "ban map holds 3 prefixes" test "$(metric limitplane_xdp_bans)" = 3
check "stats subcommand agrees: $(gw /w/limitplane-xdp stats --iface veth-gw)" test "$(stat bans)" = 3

echo "== autopilot: 10.99.0.4 storms the gateway until it is banned"
codes=$(for _ in $(seq 60); do http 10.99.0.4; echo; done | sort | uniq -c | tr -s ' \n' ' ')
echo "      responses: $codes"
check "gateway autopilot banned 10.99.0.4 (storm)" stormed 10.99.0.4
settle
check "http from 10.99.0.4 now gets no answer (dropped at the NIC)" silent 10.99.0.4
refute "ping from 10.99.0.4 dropped" ping4 10.99.0.4

echo "== unban 10.99.0.2"
api -X DELETE "$GW/api/bans/10.99.0.2"
settle
check "ping from 10.99.0.2 passes again" ping4 10.99.0.2
check "ban map holds 3 prefixes (fd00:99::2, 10.99.0.4, 10.99.0.5)" test "$(metric limitplane_xdp_bans)" = 3

echo "== pps guard: UDP flood from 10.99.0.3 (budget ${PPS}pps, burst $BURST)"
dr0=$(metric 'limitplane_xdp_packets_total{action="drop_rate"}')
gw /w/udpflood --listen 10.99.0.1:9999 -d 5s >/tmp/sink.txt &
SINK=$!
sleep 0.3
cl /w/udpflood --to 10.99.0.1:9999 --from 10.99.0.3 -d 3s --workers 2 | tee /tmp/flood.txt | sed 's/^/      flood: /'
wait $SINK
sed 's/^/      sink:  /' /tmp/sink.txt
dr1=$(metric 'limitplane_xdp_packets_total{action="drop_rate"}')
sent=$(sed 's/.*sent=\([0-9]*\).*/\1/' /tmp/flood.txt)
got=$(sed 's/.*received=\([0-9]*\).*/\1/' /tmp/sink.txt)
echo "      drop_rate: $dr0 -> $dr1"
check "flood sent well over budget ($sent > $((PPS * 3 + BURST)))" test "$sent" -gt $((PPS * 3 + BURST))
check "drop_rate rose by $((dr1 - dr0))" test "$dr1" -gt "$dr0"
# 3s at PPS plus one burst, with 10% slack for the 0.3s head start and timer edges.
check "received $got <= budget $(((PPS * 3 + BURST) * 11 / 10))" test "$got" -le $(((PPS * 3 + BURST) * 11 / 10))
check "ping from 10.99.0.3 recovers after the flood" ping4 10.99.0.3

echo "== kernel-side expiry: freeze the loader, let the 1-minute ban on 10.99.0.5 lapse"
left=$((SHORT_UNTIL - $(date +%s)))
check "suite reached the freeze with ${left}s of the ban left" test "$left" -ge 5
kill -STOP $XDP_PID
refute "ping from 10.99.0.5 dropped, loader frozen" ping4 10.99.0.5
sleep $((left > 0 ? left + 1 : 1))
check "ping from 10.99.0.5 passes once the ban lapsed, loader still frozen" ping4 10.99.0.5
check "kernel counts 2 live bans (stats: $(gw /w/limitplane-xdp stats --iface veth-gw))" test "$(stat bans)" = 2
kill -CONT $XDP_PID
settle
check "thawed loader deleted the lapsed entry" test "$(metric limitplane_xdp_bans)" = 2

echo "== CIDR ban: 10.99.0.0/29 covers .2 to .7, except the exempt .6"
api -d '{"client":"10.99.0.0/29","minutes":5}' "$GW/api/bans"
settle
refute "ping from 10.99.0.3 dropped by the /29" ping4 10.99.0.3
check "ping from exempt 10.99.0.6 passes inside the /29" ping4 10.99.0.6
refute "http from exempt 10.99.0.6 reaches the gateway (which enforces the /29 itself)" silent 10.99.0.6
check "http from 10.99.0.4 still dropped by its own ban" silent 10.99.0.4

echo "== SIGTERM detaches"
kill -TERM $XDP_PID
if wait $XDP_PID; then pass "limitplane-xdp exited 0"; else fail "limitplane-xdp exit code $?"; fi
refute "no XDP program left on veth-gw" bash -c "ip netns exec gw ip link show veth-gw | grep -q xdp"
check "banned fd00:99::2 reaches the host again" ping6 fd00:99::2
check "10.99.0.3 (in the banned /29) reaches the host again" ping4 10.99.0.3

echo "== limitplane-xdp log"
sed 's/^/      /' /tmp/xdp.log
kill $GW_PID 2>/dev/null || true
echo
if ((fails)); then echo "$MODE: $fails of $((passes + fails)) checks failed"; exit 1; fi
echo "$MODE: all $passes checks passed"
