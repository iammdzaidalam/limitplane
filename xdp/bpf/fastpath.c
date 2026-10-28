// SPDX-License-Identifier: (MIT OR GPL-2.0)
// fastpath drops banned and flooding sources at the NIC, before the kernel stack.
// Self-contained (no libbpf or kernel headers) so it builds with any clang that has a bpf target.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __always_inline inline __attribute__((always_inline))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) __builtin_bswap16(x)
#define htonl(x) __builtin_bswap32(x)
#else
#define htons(x) (x)
#define htonl(x) (x)
#endif

// Helper IDs from include/uapi/linux/bpf.h.
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;

enum { XDP_DROP = 1, XDP_PASS = 2 };
enum { BPF_ANY = 0, BPF_F_NO_PREALLOC = 1 };
enum { BPF_MAP_TYPE_ARRAY = 2, BPF_MAP_TYPE_PERCPU_ARRAY = 6, BPF_MAP_TYPE_LRU_HASH = 9, BPF_MAP_TYPE_LPM_TRIE = 11 };
enum { ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD, ETH_P_8021Q = 0x8100, ETH_P_8021AD = 0x88A8 };
enum { STAT_PASS, STAT_DROP_BAN, STAT_DROP_RATE, STAT_MAX };

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

struct ethhdr {
	__u8 dst[6];
	__u8 src[6];
	__u16 proto;
};

struct vlanhdr {
	__u16 tci;
	__u16 proto;
};

// Only the source address is read, so IPv4 options and IPv6 extension headers never matter.
struct iphdr {
	__u8 ihl_ver, tos;
	__u16 len, id, frag;
	__u8 ttl, proto;
	__u16 csum;
	__u32 saddr, daddr;
};

struct ipv6hdr {
	__u32 ver_tc_flow;
	__u16 len;
	__u8 next, hop;
	__u32 saddr[4], daddr[4];
};

// IPv4 is stored as IPv4-mapped IPv6 (::ffff:a.b.c.d, prefix 96+n), so one trie holds both families.
struct ban_key {
	__u32 prefixlen; // host order, as the LPM trie requires
	__u32 addr[4];   // network order
};

// Rate-limit source: the IPv4 address (mapped, as above) or the IPv6 /64.
struct src_key {
	__u32 addr[4];
};

struct rate_cfg {
	__u64 interval_ns; // 1e9/pps; 0 disables the guard
	__u64 burst_ns;    // burst * interval_ns
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC); // required for LPM tries
	__uint(max_entries, 65536);
	__type(key, struct ban_key);
	__type(value, __u8);
} bans SEC(".maps");

// One theoretical arrival time (GCRA, the same algorithm as the gateway) per source.
// Shared LRU rather than per-CPU: RSS spreads a flood over CPUs, so a per-CPU bucket would multiply the budget.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 262144);
	__type(key, struct src_key);
	__type(value, __u64);
} rate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rate_cfg);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline int count(__u32 stat, int action) {
	__u64 *n = bpf_map_lookup_elem(&stats, &stat);
	if (n) // the verifier rejects a dereference without this check, even for an array
		*n += 1;
	return action;
}

// over_budget runs one GCRA step: admit if the new arrival time stays within burst of now.
// Two CPUs can race on one source's slot; the worst case admits a few extra packets.
static __always_inline int over_budget(struct src_key *src) {
	__u32 zero = 0;
	struct rate_cfg *cfg = bpf_map_lookup_elem(&config, &zero);
	if (!cfg || !cfg->interval_ns)
		return 0;
	__u64 now = bpf_ktime_get_ns();
	__u64 *tat = bpf_map_lookup_elem(&rate, src);
	if (!tat) {
		__u64 next = now + cfg->interval_ns;
		bpf_map_update_elem(&rate, src, &next, BPF_ANY);
		return 0;
	}
	__u64 next = (*tat > now ? *tat : now) + cfg->interval_ns;
	if (next - now > cfg->burst_ns)
		return 1;
	*tat = next;
	return 0;
}

SEC("xdp")
int fastpath(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return XDP_PASS;
	__u16 proto = eth->proto;
	void *l3 = eth + 1;

	// Up to two VLAN tags (802.1ad outer, 802.1Q inner). Written out because -mcpu=v1 has no loops.
	if (proto == htons(ETH_P_8021Q) || proto == htons(ETH_P_8021AD)) {
		struct vlanhdr *v = l3;
		if ((void *)(v + 1) > end)
			return XDP_PASS;
		proto = v->proto;
		l3 = v + 1;
	}
	if (proto == htons(ETH_P_8021Q)) {
		struct vlanhdr *v = l3;
		if ((void *)(v + 1) > end)
			return XDP_PASS;
		proto = v->proto;
		l3 = v + 1;
	}

	struct ban_key key = {};
	struct src_key src = {};
	if (proto == htons(ETH_P_IP)) {
		struct iphdr *ip = l3;
		if ((void *)(ip + 1) > end)
			return XDP_PASS;
		key.prefixlen = 128;
		key.addr[2] = htonl(0xffff);
		key.addr[3] = ip->saddr;
		src.addr[2] = key.addr[2];
		src.addr[3] = ip->saddr;
	} else if (proto == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = l3;
		if ((void *)(ip6 + 1) > end)
			return XDP_PASS;
		key.prefixlen = 128;
		key.addr[0] = ip6->saddr[0];
		key.addr[1] = ip6->saddr[1];
		key.addr[2] = ip6->saddr[2];
		key.addr[3] = ip6->saddr[3];
		// Rate by /64: one IPv6 host usually owns a whole /64 and could rotate through it.
		src.addr[0] = ip6->saddr[0];
		src.addr[1] = ip6->saddr[1];
	} else {
		return count(STAT_PASS, XDP_PASS); // ARP, LLDP and friends
	}

	if (bpf_map_lookup_elem(&bans, &key))
		return count(STAT_DROP_BAN, XDP_DROP);
	if (over_budget(&src))
		return count(STAT_DROP_RATE, XDP_DROP);
	return count(STAT_PASS, XDP_PASS);
}

char __license[] SEC("license") = "Dual MIT/GPL";
