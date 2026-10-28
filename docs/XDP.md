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
2. Look the source up in the `bans` trie. Hit: `XDP_DROP`, count `drop_ban`.
3. Run one GCRA step for the source in the `rate` map, with the budget from the `config` map.
   Over budget: `XDP_DROP`, count `drop_rate`.
4. Otherwise `XDP_PASS`, count `pass`.

Every pointer is bounds-checked against `data_end` before use, which is what the verifier wants. The
VLAN handling is written out twice instead of looped because bpf2go compiles with `-mcpu=v1`, which has
no bounded loops; that keeps the object loadable on old kernels. No libbpf or kernel headers: the few
structs and helper IDs are declared in the file, so any clang with a BPF target builds it.

| Map | Type | Key → value | Size |
| --- | --- | --- | --- |
| `bans` | LPM trie | prefix length + 16-byte address → 1 | 65,536 |
| `rate` | LRU hash | 16-byte source → GCRA arrival time (ns) | 262,144 |
| `config` | array | 0 → pps interval and burst (ns) | 1 |
| `stats` | per-CPU array | pass / drop_ban / drop_rate → packets | 3 |

### Why an LPM trie for bans

- **CIDRs for free.** A ban can be a host, a /24, or an IPv6 /64. A hash map would need one lookup per
  possible prefix length (up to 129); the trie does one longest-prefix lookup.
- **One map for both families.** IPv4 is stored IPv4-mapped (`::ffff:a.b.c.d`, prefix 96+n), so IPv4 and
  IPv6 bans share one trie and one lookup path.
- **The gateway can't do this.** Its ban check is an exact string match on the client IP. A CIDR posted to
  `/api/bans` does nothing in the gateway but is enforced in the trie; `xdp/test.sh` proves it.

A trie lookup walks nodes, so it costs more than a hash lookup, but it is still small next to what the
stack spends on a packet that it lets through.

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
3. It diffs the list against what it installed: new bans are added, lifted or expired ones deleted. A
   steady state makes no syscalls. Writes that fail are retried on the next tick.
4. From then on the client's packets die in the driver: no skb, no TCP handshake, no Go goroutine.

So the gateway enforces a ban at once and the NIC enforces it within about a second. Failure modes:

- **Gateway unreachable:** keep enforcing the bans already installed until their own expiry, so a gateway
  restart doesn't open the gates. `limitplane_xdp_sync_errors_total` counts failures.
- **Loader exits or crashes:** the program is attached through a BPF link owned by the process, so the
  kernel detaches it when the process dies. The fast path fails open; the gateway still enforces bans.
- **Ban client that isn't an IP or CIDR:** skipped and counted in `limitplane_xdp_bans_skipped`.

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
  NIC, so the loader can't lock itself out.
- Needs Linux 5.9+ (BPF links for XDP) and root or `CAP_BPF` + `CAP_NET_ADMIN`.

## Running it

```bash
cd xdp && go build ./cmd/limitplane-xdp
sudo ./limitplane-xdp --iface eth0 --gateway http://127.0.0.1:8080 --pps 20000 --burst 40000
#   --admin-key or LIMITPLANE_ADMIN_KEY; --mode generic; --metrics :9102; in proxy mode use
#   --gateway http://127.0.0.1:8080/_limitplane
```

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
./xdp/test.sh
```

Runs in a privileged container (Docker Desktop's Linux VM works). Two network namespaces joined by a veth
pair: `gw` runs the gateway and `limitplane-xdp --mode generic`, `cl` sends from several source IPs. It
checks that a manual ban (IPv4 and IPv6) drops ping and HTTP while other sources pass, that an autopilot
ban triggered by hammering the gateway reaches the NIC, that unban lifts it, that a CIDR ban covers its
range, that a UDP flood is cut to the pps budget, and that SIGTERM detaches the program. From one run
on an M-series Mac (kernel 6.12, generic mode on veth):

```
== pps guard: UDP flood from 10.99.0.3 (budget 1000pps, burst 2000)
      flood: sent=10217216 failed=0 seconds=3.00 pps=3405617
      sink:  received=5037 seconds=5.00 pps=1007
      drop_rate: 0 -> 10212179
```

3.4M packets per second dropped on one veth with generic XDP; the socket saw the 1,000 pps budget plus
one burst.

## Azure test

`xdp/azure/` provisions two VMs with accelerated networking, floods the target with and without the
native-mode fast path, and reports pps sent, received and dropped, CPU, softirq and gateway p99. Steps
and cost (about $0.31/hour) are in [xdp/azure/README.md](../xdp/azure/README.md).
