# XDP fast path

`limitplane-xdp` drops packets from banned clients in the NIC driver, before the kernel allocates
anything for them, and drops per-source packet floods the same way. The gateway still decides who is
banned; the fast path only makes a ban cheap to enforce. It lives in its own Go module (`xdp/`) so the
gateway stays standard-library only.

```
request ──> gateway ──> autopilot: 20 burst blocks in 10s ──> ban (5 min)    POST /api/bans (manual, IP or CIDR)
                                                              │                    │
                                                              └──── GET /api/bans <┘
                                                                        │ every 1s, diff
                                                                limitplane-xdp ──> bans (LPM trie)
                                                                                     │
packet ──> NIC driver ──> XDP fastpath: banned? drop · over pps? drop · else pass ──> kernel stack ──> gateway
```

## The program (`xdp/bpf/fastpath.c`)

1. Parse Ethernet, then up to two VLAN tags (802.1ad outer, 802.1Q inner), then the IPv4 or IPv6
   source address. Anything else (ARP, LLDP) passes.
2. Look the source up in the `bans` trie. An exempt entry passes at once, skipping step 3. A ban whose
   deadline hasn't passed: `XDP_DROP`, count `drop_ban`. A lapsed one counts as a miss.
3. Run one GCRA step for the source in the `rate` map, with the budget from the `config` map.
   Over budget: `XDP_DROP`, count `drop_rate`.
4. Otherwise `XDP_PASS`, count `pass`.

Every pointer is bounds-checked against `data_end` before use, which is what the verifier wants. The
VLAN handling is written out twice instead of looped because bpf2go compiles with `-mcpu=v1`, which has
no bounded loops; that keeps the object loadable on old kernels. No libbpf or kernel headers: the few
structs and helper IDs are declared in the file, so any clang with a BPF target builds it.

| Map | Type | Key → value | Size |
| --- | --- | --- | --- |
| `bans` | LPM trie | prefix length + 16-byte address → deadline (ns, `CLOCK_MONOTONIC`; 0 none, 1 exempt) | 65,536 |
| `rate` | LRU hash | 16-byte source → GCRA arrival time (ns) | 262,144 |
| `config` | array | 0 → pps interval and burst (ns) | 1 |
| `stats` | per-CPU array | pass / drop_ban / drop_rate → packets | 3 |

### Why an LPM trie for bans

- **CIDRs for free.** A ban can be a host, a /24, or an IPv6 /64. A hash map would need one lookup per
  possible prefix length (up to 129); the trie does one longest-prefix lookup.
- **One map for both families.** IPv4 is stored IPv4-mapped (`::ffff:a.b.c.d`, prefix 96+n), so IPv4 and
  IPv6 bans share one trie and one lookup path.
- **Same bans, two layers.** The gateway also enforces CIDRs (one map lookup per prefix length in use),
  so a ban holds whether or not the fast path runs; XDP just stops the packets before the stack sees them.

A trie lookup walks nodes, so it costs more than a hash lookup, but it is still small next to what the
stack spends on a packet that it lets through.

### Bans expire in the kernel

Each ban carries its deadline on the clock `bpf_ktime_get_ns()` reads, so a ban lapses on time even if
the loader hangs, is stopped, or can't reach the gateway. The test freezes the loader with `SIGSTOP` and
watches a 1-minute ban stop dropping when it runs out.

- **Wall clock to monotonic, every sync.** `/api/bans` gives a wall-clock `until`. The loader reads both
  clocks together each sync and writes `now_mono + (until - now_wall)`. If a deadline drifts more than
  100 ms from what is installed it is rewritten, so a wall-clock step (NTP, or a VM resuming: the
  monotonic clock doesn't count suspend) is corrected within one tick. An offset taken once at startup
  would carry every later step into every deadline. The slack absorbs read jitter and the millisecond
  rounding of a Redis-backed gateway's TTLs.
- **No expiry.** Gateway bans always have one (1 minute to 7 days). An `until` too far out for the clock
  to hold is written as 0, which never lapses, rather than overflowing.
- **Lapsed entries are a miss, not deleted by the program.** The verifier accepts `bpf_map_delete_elem`
  on an LPM trie from XDP (checked on 6.12), but the loader stays the only writer: a program delete
  racing a re-ban would erase the new ban while the loader believes it is installed, and the delete
  takes the trie's lock in the packet path. The loader deletes lapsed entries on its next sync.
- **Covering bans.** The trie returns only the longest match, so a lapsed /32 inside a live /24 would
  let the host through. The loader writes each prefix with the latest deadline of any ban covering it.
- **Exempt prefixes** (`--exempt`) are entries with the reserved value 1. Being more specific, they win
  the longest match inside any wider ban, and the program passes them without the pps guard. A ban inside
  an exempt prefix isn't installed. Use it for the management network, monitoring and your own balancer.

### Why a shared LRU hash for the pps guard

- **Shared, not per-CPU.** RSS spreads a flood's packets over every receive queue. Per-CPU buckets would
  give each source `pps × CPUs`. Two CPUs can race on one source's slot; the worst case lets a few extra
  packets through, which is fine for a flood guard.
- **LRU, not plain hash.** A flood from many sources would fill a plain hash map, after which new sources
  could not be tracked. LRU evicts the quietest sources instead.
- **GCRA,** the same algorithm the gateway uses: one u64 per source, no refill timer.
- **IPv6 is limited per /64.** One host usually owns a whole /64 and could rotate addresses inside it.

The guard is off by default (`--pps 0`). It counts every packet from a source, so set it well above what a
legitimate client sends: a single fast TCP upload can be tens of thousands of packets per second.

## How bans reach the NIC

1. Autopilot bans a client after repeated burst blocks, or an admin posts `/api/bans`. The gateway rejects
   that client's requests immediately.
2. `limitplane-xdp` logs in once (`POST /api/login`; the token lasts 12h and is renewed on a 401) and
   polls `GET /api/bans` every second.
3. It diffs the list against what it installed: new bans are added, lifted or expired ones deleted,
   changed deadlines rewritten. A steady state makes no syscalls. Writes that fail are retried next tick.
4. From then on the client's packets die in the driver: no skb, no TCP handshake, no Go goroutine.

So the gateway enforces a ban at once and the NIC enforces it within about a second. Failure modes:

- **Gateway unreachable:** keep enforcing the bans already installed until their own expiry, so a gateway
  restart doesn't open the gates. `limitplane_xdp_sync_errors_total` counts failures.
- **Loader hung or stopped:** bans still lapse on time in the kernel; unbans wait until it runs again.
- **Loader exits or crashes:** the program is attached through a BPF link owned by the process, so the
  kernel detaches it when the process dies. The fast path fails open; the gateway still enforces bans.
  Pinning the link would keep the program after the loader is gone, but nothing could then lift a ban:
  an admin's unban, or a false-positive autopilot ban on a customer, would hold at the NIC for up to
  7 days after the gateway let them back. Failing open loses the cheap drop and the pps guard, not the
  ban. Run the loader under a supervisor (`Restart=always`); it re-attaches and resyncs in its first
  tick. The map isn't pinned either, so if the gateway is down at that moment the NIC has no bans until
  it answers.
- **Ban client that isn't an IP or CIDR, or is exempt:** skipped and counted in `limitplane_xdp_bans_skipped`.

## Limits

- **IPv4 options and IPv6 extension headers** don't matter: only the source address is read, and it sits
  at a fixed offset. Fragments all carry the source address, so they are dropped too.
- **VLAN:** up to two tags. Deeper stacks and tunnels (VXLAN, GRE, IP-in-IP) are matched on the outer
  source, which is usually not the client.
- **Proxies:** XDP sees the packet's source. If the gateway runs behind a proxy or L7 load balancer
  (`--trust-proxy`), bans name the `X-Forwarded-For` client, but the gateway host only sees the proxy.
  Run the fast path where client IPs arrive: the edge host, or behind an L4 balancer that preserves them.
- **Spoofed floods:** a per-source guard can't stop a flood that randomises its source; that needs
  upstream scrubbing or SYN cookies. The LRU keeps the map from filling.
- **Generic vs native:** `--mode native` runs in the driver before any skb exists and needs driver support
  (mlx5, ice, i40e, ixgbe, ena, hv_netvsc, mana, virtio_net and others). `--mode generic` runs after the
  skb is built, on any interface; it still skips the rest of the stack, the socket and the gateway, but
  saves less. Many drivers refuse native XDP above a ~3.5 KB MTU, so jumbo frames may need generic mode.
- **Bans cover everything** from that source, including SSH. The admin API on loopback never crosses the
  NIC, so the loader can't lock itself out; `--exempt` keeps a ban on a wide range off your own hosts.
- **Clocks:** deadlines assume the loader and the gateway agree on wall time (same host, or NTP).
- Needs Linux 5.9+ (BPF links for XDP) and root or `CAP_BPF` + `CAP_NET_ADMIN`.

## Running it

```bash
cd xdp && go build ./cmd/limitplane-xdp
sudo ./limitplane-xdp --iface eth0 --gateway http://127.0.0.1:8080 --pps 20000 --burst 40000
#   --admin-key or LIMITPLANE_ADMIN_KEY; --mode generic; --metrics :9102; --exempt 10.0.0.0/8,192.0.2.7;
#   in proxy mode use --gateway http://127.0.0.1:8080/_limitplane
sudo ./limitplane-xdp stats --iface eth0
# pass=11 drop_ban=9 drop_rate=0 bans=3
```

`stats` reads the kernel maps of the program a running loader attached to that interface (found through
its BPF link), so it works with `--metrics` off and while the loader is frozen. `bans` counts entries the
program would drop on now, not lapsed or exempt ones.

`--metrics` serves Prometheus text: `limitplane_xdp_packets_total{action="pass|drop_ban|drop_rate"}`,
`limitplane_xdp_bans`, `limitplane_xdp_bans_skipped`, `limitplane_xdp_sync_errors_total`,
`limitplane_xdp_last_sync_timestamp_seconds`.

The compiled object and Go bindings are committed (`xdp/fastpath/fastpath_bpfel.{o,go}`), so building
needs no clang. After editing the C:

```bash
cd xdp && BPF2GO_CC=/opt/homebrew/opt/llvm/bin/clang BPF2GO_STRIP=/opt/homebrew/opt/llvm/bin/llvm-strip go generate ./fastpath
```

## Local test (Docker)

```bash
./xdp/test.sh            # generic, then native
./xdp/test.sh native     # one mode
```

Runs the whole suite once per XDP mode, each in a fresh privileged container (Docker Desktop's Linux VM
works). It first runs the `fastpath` package's kernel tests: real program verdicts through
`BPF_PROG_TEST_RUN` (bans with and without deadlines, lapsed, exempt, VLAN-tagged, IPv6 /64, the pps
guard) and that `stats` finds a running program. Then two network namespaces joined by a veth pair: `gw`
runs the gateway and `limitplane-xdp`, `cl` sends from several source IPs. It checks that a manual ban
(IPv4 and IPv6) drops ping and HTTP while other sources pass, that an autopilot ban triggered by
hammering the gateway reaches the NIC, that unban lifts it, that a UDP flood is cut to the pps budget,
that a 1-minute ban lapses in the kernel while the loader is `SIGSTOP`ped (and the thawed loader then
deletes it), that a CIDR ban covers its range except an exempt address, that `stats` agrees with
`/metrics`, and that SIGTERM detaches the program. Native XDP on veth needs nothing on the peer for
`XDP_DROP` and `XDP_PASS` (an XDP program or GRO on the peer only matters for `XDP_REDIRECT` into it).
From two runs on an M-series Mac (kernel 6.12):

```
generic: all 41 checks passed
      flood: sent=7089408 failed=0 seconds=3.00 pps=2363038
      sink:  received=5036 seconds=5.00 pps=1007
      drop_rate: 0 -> 7084372
native: all 41 checks passed
      flood: sent=2137600 failed=0 seconds=3.00 pps=712381
      sink:  received=5000 seconds=5.01 pps=999
      drop_rate: 0 -> 2129400
```

Over several runs the flood reached 2.1 to 2.4M pps in generic mode and 0.6 to 1.9M in native, all of
it dropped but the 1,000 pps budget plus one burst. Native is slower here, not faster: veth hands the
program an skb the sender already built, through a ring drained by NAPI on another CPU, instead of
inline in the sender. The run proves the native path works; what it saves needs a real NIC.

## Azure test (optional, not run)

The numbers above come from the Docker test. For native mode on real NICs, `xdp/azure/` provisions two VMs with accelerated networking, floods the target with and without the
native-mode fast path, and reports pps sent, received and dropped, CPU, softirq and gateway p99. Steps
and cost (about $0.31/hour) are in [xdp/azure/README.md](../xdp/azure/README.md).
