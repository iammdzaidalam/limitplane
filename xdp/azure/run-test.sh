#!/usr/bin/env bash
# Floods the target three times and prints one row per phase:
#   no-xdp    the kernel stack takes the whole flood
#   xdp-rate  limitplane-xdp attached, the per-source pps guard drops the excess
#   xdp-ban   the flood source banned through the gateway API, dropped by the LPM trie
# Meanwhile a well-behaved client (the attacker's primary IP) measures gateway latency.
# Results are also written to results/. Rerunnable: it resets the target before and after.
# Remote commands are built locally on purpose; remote-side $ is escaped or single-quoted.
# shellcheck disable=SC2029,SC2016
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=common.sh
source ./common.sh
need_az

DUR=${DUR:-20} # seconds per flood
MODE=${MODE:-native}
IFACE=${IFACE:-eth0}
GUARD_PPS=${GUARD_PPS:-10000}
GUARD_BURST=${GUARD_BURST:-20000}
PROBE_RPS=${PROBE_RPS:-20} # demo-pro-key allows 50/s

pub() { az network public-ip show -g "$RG" -n "$1-pip" --query ipAddress -o tsv; }
target_pub=$(pub "$TARGET")
attacker_pub=$(pub "$ATTACKER")
[[ -n $target_pub && -n $attacker_pub ]] || die "VMs not found in $RG; run ./provision.sh"
ssh_opts=(-i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)
on_target() { ssh "${ssh_opts[@]}" "$ADMIN@$target_pub" "$@"; }
on_attacker() { ssh "${ssh_opts[@]}" "$ADMIN@$attacker_pub" "$@"; }

units="lp-xdp lp-gateway"
reset_target() {
	on_target "sudo systemctl stop $units 2>/dev/null; sudo systemctl reset-failed $units 2>/dev/null; sudo ip link set dev $IFACE xdp off; true"
}

work=$(mktemp -d)
trap 'reset_target || true; rm -rf "$work"' EXIT
mkdir -p results
out="results/run-$(date -u +%Y%m%dT%H%M%SZ).txt"
exec > >(tee "$out") 2>&1

echo "building linux/$ARCH binaries"
(cd .. && GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build -o "$work/" ./cmd/limitplane-xdp ./test/udpflood ./test/probe)
(cd ../.. && GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build -o "$work/" ./cmd/limitplane)
cp remote.sh "$work/"
for h in "$target_pub" "$attacker_pub"; do
	ssh "${ssh_opts[@]}" "$ADMIN@$h" mkdir -p lp
	scp -q "${ssh_opts[@]}" "$work"/* "$ADMIN@$h:lp/"
done

reset_target
on_target "sudo systemd-run -q --unit lp-gateway --uid $ADMIN --setenv LIMITPLANE_ADMIN_KEY=$ADMIN_KEY /home/$ADMIN/lp/limitplane --addr :9090"
on_target 'for _ in $(seq 50); do curl -sf localhost:9090/healthz >/dev/null && exit; sleep 0.2; done; exit 1' || die "gateway did not start"
on_attacker "sudo ip addr replace $FLOOD_IP/24 dev $IFACE"
echo "target $TARGET_SIZE ($(on_target nproc) vCPU, $(on_target uname -r)), attacker $ATTACKER_SIZE, ${DUR}s floods"
echo

cols="%-9s %10s %10s %10s %10s %10s %6s %8s %8s %7s\n"
# shellcheck disable=SC2059
printf "$cols" phase sent_pps nic_rx_pps app_rx_pps ban_drop rate_drop cpu% softirq% p99_ms errors

# measure PHASE: flood for DUR seconds while probing, then print the row.
measure() {
	local a b sink probe
	sleep 2
	on_target "lp/udpflood --listen :9999 -d $((DUR + 4))s" >"$work/sink" &
	sink=$!
	sleep 1
	a=$(on_target "lp/remote.sh snap $IFACE")
	on_attacker "lp/probe --url http://$TARGET_IP:9090/v1/ping --key demo-pro-key --rps $PROBE_RPS -d ${DUR}s" >"$work/probe" &
	probe=$!
	on_attacker "lp/udpflood --to $TARGET_IP:9999 --from $FLOOD_IP --workers \$(nproc) -d ${DUR}s" >"$work/flood"
	b=$(on_target "lp/remote.sh snap $IFACE")
	wait "$probe" "$sink"
	# shellcheck disable=SC2059
	awk -v phase="$1" -v dur="$DUR" -v a="$a" -v b="$b" -v cols="$cols" \
		-v sent="$(sed -n 's/.*pps=\([0-9]*\).*/\1/p' "$work/flood")" \
		-v got="$(sed -n 's/.*received=\([0-9]*\).*/\1/p' "$work/sink")" \
		-v p99="$(sed -n 's/.*p99_ms=\([0-9.]*\).*/\1/p' "$work/probe")" \
		-v errs="$(sed -n 's/.*errors=\([0-9]*\).*/\1/p' "$work/probe")" '
	BEGIN {
		split(a, x, " "); split(b, y, " ")
		tot = y[1] - x[1]
		printf cols, phase, sent, int((y[4] - x[4]) / dur), int(got / dur), int((y[6] - x[6]) / dur), int((y[7] - x[7]) / dur),
			sprintf("%.0f", 100 * (tot - (y[2] - x[2])) / tot), sprintf("%.0f", 100 * (y[3] - x[3]) / tot), p99, errs
	}'
}

measure no-xdp

on_target "sudo systemd-run -q --unit lp-xdp --setenv LIMITPLANE_ADMIN_KEY=$ADMIN_KEY /home/$ADMIN/lp/limitplane-xdp \
	--iface $IFACE --mode $MODE --gateway http://127.0.0.1:9090 --pps $GUARD_PPS --burst $GUARD_BURST --metrics 127.0.0.1:9102"
if ! on_target 'for _ in $(seq 50); do curl -sf localhost:9102/metrics >/dev/null && exit; sleep 0.2; done; exit 1'; then
	on_target "sudo journalctl -u lp-xdp --no-pager | tail -20"
	die "limitplane-xdp did not attach in $MODE mode (try MODE=generic)"
fi
measure xdp-rate

on_target "lp/remote.sh ban $ADMIN_KEY $FLOOD_IP"
sleep 2 # one sync interval
measure xdp-ban

echo
echo "hook: $(on_target "ip -d link show $IFACE" | grep -oE 'xdp(generic|offload|drv)?' | head -1), pps guard $GUARD_PPS/s burst $GUARD_BURST"
on_target "sudo journalctl -u lp-xdp --no-pager -o cat | tail -5"
echo "saved $out"
