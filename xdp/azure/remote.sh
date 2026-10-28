#!/usr/bin/env bash
# Helper that run-test.sh copies to the target and calls over SSH.
#   remote.sh snap IFACE      one line: cpu_total cpu_idle cpu_softirq nic_rx xdp_pass xdp_drop_ban xdp_drop_rate
#   remote.sh ban KEY CLIENT  bans CLIENT for 10 minutes through the gateway admin API
set -euo pipefail
gw=http://127.0.0.1:9090

case $1 in
snap)
	read -r _ user nice system idle iowait irq softirq steal _ </proc/stat
	rx=$(cat "/sys/class/net/$2/statistics/rx_packets")
	metrics=$(curl -s --max-time 1 http://127.0.0.1:9102/metrics || true)
	xdp() { awk -v k="limitplane_xdp_packets_total{action=\"$1\"}" '$1 == k { n = $2 } END { print n + 0 }' <<<"$metrics"; }
	echo "$((user + nice + system + idle + iowait + irq + softirq + steal)) $((idle + iowait)) $softirq $rx $(xdp pass) $(xdp drop_ban) $(xdp drop_rate)"
	;;
ban)
	tok=$(curl -fsS -d "{\"key\":\"$2\"}" "$gw/api/login" | sed 's/.*"token":"\([^"]*\)".*/\1/')
	curl -fsS -H "Authorization: Bearer $tok" -d "{\"client\":\"$3\",\"minutes\":10,\"reason\":\"flood-test\"}" "$gw/api/bans"
	;;
*)
	echo "usage: $0 snap IFACE | ban KEY CLIENT" >&2
	exit 2
	;;
esac
