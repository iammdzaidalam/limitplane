package redisx

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	numSlots     = 16384
	maxRedirects = 3
	// a failed node is skipped this long, so a dead master costs one timeout a second, not one per request
	nodeCooldown = time.Second
	// MOVED and node failures refresh the slot map in the background at most this often
	refreshGap = time.Second
)

// ErrNodeDown means one Cluster node (or one slot range) failed while the rest may be fine:
// the node is unreachable, its slots are moving (TRYAGAIN), or redirects didn't settle.
// Callers can fail over for this request without writing off the whole Cluster.
var ErrNodeDown = errors.New("redisx: cluster node unavailable")

type cluster struct {
	c     *Client
	slots [numSlots]atomic.Pointer[node] // nil: unknown, ask any node and follow MOVED

	mu    sync.Mutex
	nodes map[string]*node // every node seen, seeds included

	refreshMu sync.Mutex
	loaded    atomic.Bool  // the slot map has been read at least once
	busy      atomic.Bool  // a background refresh is running
	tried     atomic.Int64 // last background refresh (unix nanos)
}

func newCluster(c *Client, seeds []string) *cluster {
	cl := &cluster{c: c, nodes: map[string]*node{}}
	for _, s := range seeds {
		cl.node(s)
	}
	return cl
}

// node returns the pool for addr, creating it on first sight.
func (cl *cluster) node(addr string) *node {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	n := cl.nodes[addr]
	if n == nil {
		n = cl.c.newNode(addr)
		cl.nodes[addr] = n
	}
	return n
}

func (cl *cluster) all() []*node {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	out := make([]*node, 0, len(cl.nodes))
	for _, n := range cl.nodes {
		out = append(out, n)
	}
	return out
}

// do routes args by its first key, following at most maxRedirects MOVED/ASK replies.
func (cl *cluster) do(ctx context.Context, args []any) (any, error) {
	if !cl.loaded.Load() {
		if err := cl.load(ctx); err != nil {
			return nil, err
		}
	}
	slot := -1
	var n *node
	if k, ok := firstKey(args); ok {
		slot = Slot(k)
		n = cl.slots[slot].Load()
	}
	if n == nil {
		n = cl.any()
	}
	asking := false
	for i := 0; ; i++ {
		v, err := n.call(ctx, args, asking)
		e, ok := err.(Error)
		if !ok {
			return v, err
		}
		kind, rest, _ := strings.Cut(string(e), " ")
		switch kind {
		case "MOVED", "ASK":
		case "TRYAGAIN", "CLUSTERDOWN":
			return nil, fmt.Errorf("%w: %s: %w", ErrNodeDown, n.addr, e)
		default:
			return v, err
		}
		if i == maxRedirects {
			return nil, fmt.Errorf("%w: too many redirects: %w", ErrNodeDown, e)
		}
		s, addr, _ := strings.Cut(rest, " ")
		if strings.HasPrefix(addr, ":") { // no host: same as the node that answered
			h, _, _ := net.SplitHostPort(n.addr)
			addr = net.JoinHostPort(h, addr[1:])
		}
		next := cl.node(addr)
		asking = kind == "ASK" // one-shot: the slot is mid-migration, the map stays
		if !asking {
			if s, err := strconv.Atoi(s); err == nil && s >= 0 && s < numSlots {
				cl.slots[s].Store(next)
			}
			cl.refreshSoon()
		}
		n = next
	}
}

// any is a random known master, or a seed before the map is loaded. For keyless commands.
func (cl *cluster) any() *node {
	if n := cl.slots[rand.IntN(numSlots)].Load(); n != nil {
		return n
	}
	ns := cl.all()
	return ns[rand.IntN(len(ns))]
}

// call is node.do plus the node's breaker. Connection failures come back wrapped in ErrNodeDown.
func (n *node) call(ctx context.Context, args []any, asking bool) (any, error) {
	if time.Now().UnixNano() < n.downUntil.Load() {
		return nil, fmt.Errorf("%w: %s", ErrNodeDown, n.addr)
	}
	v, err := n.do(ctx, args, asking)
	var rerr Error
	if err != nil && !errors.As(err, &rerr) && ctx.Err() == nil {
		n.downUntil.Store(time.Now().Add(nodeCooldown).UnixNano())
		n.c.cluster.refreshSoon() // it may have failed over to a replica
		return nil, fmt.Errorf("%w: %s: %w", ErrNodeDown, n.addr, err)
	}
	return v, err
}

func (n *node) isDown(now int64) bool { return now < n.downUntil.Load() }

var slotsCmd = []any{"CLUSTER", "SLOTS"}

// load reads the slot map unless a concurrent caller already has.
func (cl *cluster) load(ctx context.Context) error {
	cl.refreshMu.Lock()
	defer cl.refreshMu.Unlock()
	if cl.loaded.Load() {
		return nil
	}
	return cl.read(ctx)
}

func (cl *cluster) refresh(ctx context.Context) error {
	cl.refreshMu.Lock()
	defer cl.refreshMu.Unlock()
	return cl.read(ctx)
}

// read loads CLUSTER SLOTS from the first node that answers, healthy nodes first. Holds refreshMu.
func (cl *cluster) read(ctx context.Context) error {
	ns := cl.all()
	now := time.Now().UnixNano()
	ordered := make([]*node, 0, len(ns))
	for _, down := range []bool{false, true} {
		for _, n := range ns {
			if n.isDown(now) == down {
				ordered = append(ordered, n)
			}
		}
	}
	var err error
	for _, n := range ordered {
		var v any
		if v, err = n.do(ctx, slotsCmd, false); err != nil {
			continue
		}
		h, _, _ := net.SplitHostPort(n.addr)
		var rs []slotRange
		if rs, err = parseSlots(v, h); err != nil {
			continue
		}
		owner := make([]*node, numSlots)
		for _, r := range rs {
			m := cl.node(r.addr)
			for s := r.start; s <= r.end; s++ {
				owner[s] = m
			}
		}
		for s, m := range owner {
			cl.slots[s].Store(m)
		}
		cl.loaded.Store(true)
		return nil
	}
	return fmt.Errorf("redisx: cluster slots: %w", err)
}

// refreshSoon reloads the slot map in the background, at most once per refreshGap.
func (cl *cluster) refreshSoon() {
	now := time.Now().UnixNano()
	if now-cl.tried.Load() < int64(refreshGap) || !cl.busy.CompareAndSwap(false, true) {
		return
	}
	cl.tried.Store(now)
	go func() {
		defer cl.busy.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cl.refresh(ctx)
	}()
}

type slotRange struct {
	start, end int
	addr       string
}

// parseSlots reads a CLUSTER SLOTS reply: [[start, end, [host, port, id...], replicas...]...].
// An empty host means "the node you asked" (self), "?" an unknown endpoint (skipped).
func parseSlots(v any, self string) ([]slotRange, error) {
	rows, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("redisx: bad CLUSTER SLOTS reply %v", v)
	}
	out := make([]slotRange, 0, len(rows))
	for _, row := range rows {
		f, ok := row.([]any)
		if !ok || len(f) < 3 {
			return nil, fmt.Errorf("redisx: bad CLUSTER SLOTS row %v", row)
		}
		start, ok1 := f[0].(int64)
		end, ok2 := f[1].(int64)
		m, ok3 := f[2].([]any)
		if !ok1 || !ok2 || !ok3 || len(m) < 2 || start < 0 || start > end || end >= numSlots {
			return nil, fmt.Errorf("redisx: bad CLUSTER SLOTS row %v", row)
		}
		host, _ := m[0].(string)
		port, ok := m[1].(int64)
		if !ok {
			return nil, fmt.Errorf("redisx: bad CLUSTER SLOTS row %v", row)
		}
		if host == "?" {
			continue
		}
		if host == "" {
			host = self
		}
		out = append(out, slotRange{int(start), int(end), net.JoinHostPort(host, strconv.FormatInt(port, 10))})
	}
	if len(out) == 0 {
		return nil, errors.New("redisx: no slots assigned (cluster not created yet?)")
	}
	return out, nil
}

// Slot is a key's Cluster hash slot: CRC16 of the key mod 16384, or of the part between the first
// "{" and the next "}" when that is non-empty, so lp:{acme}:r and lp:{acme}:q:2026-10 share a slot.
func Slot(key string) int {
	if i := strings.IndexByte(key, '{'); i >= 0 {
		if j := strings.IndexByte(key[i+1:], '}'); j > 0 {
			key = key[i+1 : i+1+j]
		}
	}
	return int(crc16(key) & (numSlots - 1))
}

// crc16 is CRC-16/XMODEM (poly 0x1021, init 0), the one Redis Cluster uses.
func crc16(s string) uint16 {
	var c uint16
	for i := 0; i < len(s); i++ {
		c = c<<8 ^ crcTable[byte(c>>8)^s[i]]
	}
	return c
}

var crcTable = func() (t [256]uint16) {
	for i := range t {
		c := uint16(i) << 8
		for range 8 {
			if c&0x8000 != 0 {
				c = c<<1 ^ 0x1021
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return t
}()

// firstKey is the key a command routes by. Scripts route by their first key; keyless
// commands (and scripts with no keys) go to any node.
func firstKey(args []any) (string, bool) {
	if len(args) < 2 {
		return "", false
	}
	name, _ := args[0].(string)
	switch strings.ToUpper(name) {
	case "EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO", "FCALL", "FCALL_RO":
		if len(args) < 4 {
			return "", false
		}
		switch n := args[2].(type) {
		case int:
			if n < 1 {
				return "", false
			}
		case int64:
			if n < 1 {
				return "", false
			}
		default:
			return "", false
		}
		return argString(args[3]), true
	case "PING", "ECHO", "PUBLISH", "SCAN", "TIME", "INFO", "CLUSTER", "SCRIPT", "DBSIZE",
		"KEYS", "CONFIG", "COMMAND", "CLIENT", "PUBSUB", "FLUSHALL", "FLUSHDB", "WAIT":
		return "", false
	}
	return argString(args[1]), true
}

func argString(a any) string {
	if s, ok := a.(string); ok {
		return s
	}
	return string(appendArg(nil, a))
}
