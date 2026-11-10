// Package redisx is a minimal RESP2 Redis client with connection pools, for one server or a Cluster.
package redisx

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Error is an error reply from the server; the connection is still usable.
type Error string

func (e Error) Error() string { return string(e) }

const (
	poolSize = 16
	// used when the caller's ctx has no deadline, so a blackholed Redis can't hang a request
	defaultTimeout = 2 * time.Second
	// pooled conns idle longer are closed, not reused: servers and load balancers drop idle conns
	maxIdle = 30 * time.Second
)

var errClosed = errors.New("redisx: client closed")

// errDead is a conn that failed before any reply byte, other than by timing out: it was already
// closed under us, so the command never ran and can be resent on a new conn.
var errDead = errors.New("redisx: connection closed")

// Client talks to one Redis, or to a Cluster when the URL scheme is redis+cluster.
type Client struct {
	user, pass string
	db         int
	tls        *tls.Config
	node       *node    // one server
	cluster    *cluster // or a Cluster (node is nil)
	closed     atomic.Bool
}

// node is one server and its idle connections.
type node struct {
	c         *Client
	addr      string
	idle      chan *conn
	downUntil atomic.Int64 // Cluster only: unix nanos until which the node is skipped
}

type conn struct {
	nc   net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	idle time.Time // when it was pooled
}

// Dial is New plus a check that the server (or one Cluster node) is there.
func Dial(addr string) (*Client, error) {
	c, err := New(addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c.cluster != nil {
		err = c.cluster.refresh(ctx)
	} else {
		var cn *conn
		if cn, err = c.node.dial(ctx); err == nil {
			c.node.put(cn)
		}
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// New parses addr without connecting: connections are made on demand, so a Redis that isn't up
// yet is retried by later commands. addr is "host:port", "redis[s]://[user]:pass@host:port/db",
// or "redis[s]+cluster://[user]:pass@host1:port,host2:port" for a Cluster (seeds; db must be 0).
func New(addr string) (*Client, error) {
	c := &Client{}
	hosts := []string{addr}
	if strings.Contains(addr, "://") {
		u, hs, err := parseURL(addr)
		if err != nil {
			return nil, err
		}
		hosts = hs
		if u.User != nil {
			c.user = u.User.Username()
			c.pass, _ = u.User.Password()
		}
		if db := strings.TrimPrefix(u.Path, "/"); db != "" {
			if c.db, err = strconv.Atoi(db); err != nil {
				return nil, fmt.Errorf("redisx: bad db %q", db)
			}
		}
		if strings.HasPrefix(u.Scheme, "rediss") {
			c.tls = &tls.Config{}
		}
		if strings.HasSuffix(u.Scheme, "+cluster") {
			if c.db != 0 {
				return nil, errors.New("redisx: Cluster has only db 0")
			}
			c.cluster = newCluster(c, hosts)
			return c, nil
		}
	}
	c.node = c.newNode(hosts[0])
	return c, nil
}

// parseURL splits off the host list by hand: url.Parse rejects "h1:7001,h2".
func parseURL(addr string) (*url.URL, []string, error) {
	scheme, rest, _ := strings.Cut(addr, "://")
	switch scheme {
	case "redis", "rediss", "redis+cluster", "rediss+cluster":
	default:
		return nil, nil, fmt.Errorf("redisx: unsupported scheme %q", scheme)
	}
	auth, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		auth, path = rest[:i], rest[i:]
	}
	user, hostList := "", auth
	if i := strings.LastIndexByte(auth, '@'); i >= 0 {
		user, hostList = auth[:i+1], auth[i+1:]
	}
	var hosts []string
	for _, h := range strings.Split(hostList, ",") {
		if h == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(h); err != nil {
			h = net.JoinHostPort(strings.Trim(h, "[]"), "6379")
		}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 || len(hosts) > 1 && !strings.HasSuffix(scheme, "+cluster") {
		return nil, nil, fmt.Errorf("redisx: bad host list %q", hostList)
	}
	u, err := url.Parse(scheme + "://" + user + hosts[0] + path)
	return u, hosts, err
}

func (c *Client) newNode(addr string) *node {
	return &node{c: c, addr: addr, idle: make(chan *conn, poolSize)}
}

func (n *node) dial(ctx context.Context) (*conn, error) {
	if _, ok := ctx.Deadline(); !ok { // a blackholed host would otherwise hang until the OS gives up
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	c := n.c
	var nc net.Conn
	var err error
	if c.tls != nil {
		cfg := c.tls.Clone()
		cfg.ServerName, _, _ = net.SplitHostPort(n.addr)
		nc, err = (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", n.addr)
	} else {
		nc, err = (&net.Dialer{}).DialContext(ctx, "tcp", n.addr)
	}
	if err != nil {
		return nil, err
	}
	cn := &conn{nc: nc, r: bufio.NewReader(nc), w: bufio.NewWriter(nc)}
	var setup [][]any
	if c.pass != "" {
		if c.user != "" {
			setup = append(setup, []any{"AUTH", c.user, c.pass})
		} else {
			setup = append(setup, []any{"AUTH", c.pass})
		}
	}
	if c.db != 0 {
		setup = append(setup, []any{"SELECT", c.db})
	}
	for _, args := range setup {
		if _, err := cn.do(ctx, args); err != nil {
			nc.Close()
			return nil, fmt.Errorf("redisx: %s: %w", args[0], err)
		}
	}
	return cn, nil
}

func (n *node) put(cn *conn) {
	if n.c.closed.Load() {
		cn.nc.Close()
		return
	}
	cn.idle = time.Now()
	select {
	case n.idle <- cn:
	default:
		cn.nc.Close()
	}
}

var askingCmd = []any{"ASKING"}

// get takes a pooled conn (pooled = true) or dials one.
func (n *node) get(ctx context.Context) (cn *conn, pooled bool, err error) {
	for {
		select {
		case cn = <-n.idle:
			if time.Since(cn.idle) < maxIdle {
				return cn, true, nil
			}
			cn.nc.Close()
		default:
			cn, err = n.dial(ctx)
			return cn, false, err
		}
	}
}

// do runs one command on a pooled conn; asking sends ASKING first (a Cluster ASK redirect).
// A pooled conn found dead is replaced once: only the first command sent on it can have hit that.
func (n *node) do(ctx context.Context, args []any, asking bool) (any, error) {
	cn, pooled, err := n.get(ctx)
	if err != nil {
		return nil, err
	}
	first := args
	if asking {
		first = askingCmd
	}
	v, err := cn.do(ctx, first)
	if pooled && errors.Is(err, errDead) {
		cn.nc.Close()
		if cn, err = n.dial(ctx); err != nil {
			return nil, err
		}
		v, err = cn.do(ctx, first)
	}
	if asking && err == nil {
		v, err = cn.do(ctx, args)
	}
	var rerr Error
	if err != nil && !errors.As(err, &rerr) {
		cn.nc.Close()
		return nil, err
	}
	n.put(cn)
	return v, err
}

func (n *node) drain() {
	for {
		select {
		case cn := <-n.idle:
			cn.nc.Close()
		default:
			return
		}
	}
}

// Do sends one command. Replies map to string, int64, []any, nil, or an Error.
// On a Cluster it goes to the node owning the first key's slot (see firstKey).
func (c *Client) Do(ctx context.Context, args ...any) (any, error) {
	if c.closed.Load() {
		return nil, errClosed
	}
	if c.cluster != nil {
		return c.cluster.do(ctx, args)
	}
	return c.node.do(ctx, args, false)
}

func (c *Client) Close() error {
	c.closed.Store(true)
	if c.cluster != nil {
		for _, n := range c.cluster.all() {
			n.drain()
		}
		return nil
	}
	c.node.drain()
	return nil
}

func (cn *conn) do(ctx context.Context, args []any) (any, error) {
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(defaultTimeout)
	}
	cn.nc.SetDeadline(dl)
	stop := context.AfterFunc(ctx, func() { cn.nc.SetDeadline(time.Unix(1, 0)) })
	v, err := cn.roundTrip(args)
	if !stop() {
		// cancel fired: the deadline is poisoned, make the caller drop this conn
		return nil, ctx.Err()
	}
	if err != nil && ctx.Err() != nil {
		var rerr Error
		if !errors.As(err, &rerr) {
			return nil, ctx.Err()
		}
	}
	// the socket deadline can beat the ctx timer by a hair; report it as the ctx deadline
	if ok && errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, context.DeadlineExceeded
	}
	return v, err
}

func (cn *conn) roundTrip(args []any) (any, error) {
	if err := cn.write(args); err != nil {
		return nil, dead(err)
	}
	if _, err := cn.r.Peek(1); err != nil {
		return nil, dead(err)
	}
	return readReply(cn.r)
}

// dead marks err as errDead unless it is a timeout (a slow server, or the caller giving up).
func dead(err error) error {
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return err
	}
	return fmt.Errorf("%w: %w", errDead, err)
}

// CallerGaveUp reports whether err is ctx's doing: it was cancelled, or a timeout hit at its
// deadline. The socket deadline can fire a hair before ctx.Err() is set, so this goes by err too.
// Such a failure says nothing about the server.
func CallerGaveUp(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return true
	}
	_, ok := ctx.Deadline() // without one, any timeout is our own default
	return ok && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded))
}

func (cn *conn) write(args []any) error {
	var scratch, num [64]byte
	w := cn.w
	w.WriteByte('*')
	w.Write(strconv.AppendInt(scratch[:0], int64(len(args)), 10))
	w.WriteString("\r\n")
	for _, a := range args {
		b := appendArg(scratch[:0], a)
		w.WriteByte('$')
		w.Write(strconv.AppendInt(num[:0], int64(len(b)), 10))
		w.WriteString("\r\n")
		w.Write(b)
		w.WriteString("\r\n")
	}
	return w.Flush()
}

func appendArg(b []byte, a any) []byte {
	switch v := a.(type) {
	case string:
		return append(b, v...)
	case []byte:
		return append(b, v...)
	case int:
		return strconv.AppendInt(b, int64(v), 10)
	case int64:
		return strconv.AppendInt(b, v, 10)
	case float64:
		return strconv.AppendFloat(b, v, 'f', -1, 64)
	default:
		return fmt.Append(b, v)
	}
}

func readReply(r *bufio.Reader) (any, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return nil, fmt.Errorf("redisx: bad line %q", line)
	}
	kind, body := line[0], string(line[1:len(line)-2])
	switch kind {
	case '+':
		return body, nil
	case '-':
		return nil, Error(body)
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$', '*':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, fmt.Errorf("redisx: bad length %q", body)
		}
		if n < 0 {
			return nil, nil
		}
		if kind == '$' {
			buf := make([]byte, n+2)
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, err
			}
			return string(buf[:n]), nil
		}
		arr := make([]any, n)
		for i := range arr {
			v, err := readReply(r)
			var rerr Error
			if errors.As(err, &rerr) {
				arr[i] = rerr // keep reading so the stream stays in sync
				continue
			}
			if err != nil {
				return nil, err
			}
			arr[i] = v
		}
		return arr, nil
	}
	return nil, fmt.Errorf("redisx: unknown reply type %q", kind)
}

// Script is a Lua script run with EVALSHA, falling back to EVAL once on NOSCRIPT. On a Cluster
// each node loads it the first time a key routes there.
type Script struct{ src, sha string }

func NewScript(src string) *Script {
	h := sha1.Sum([]byte(src))
	return &Script{src: src, sha: hex.EncodeToString(h[:])}
}

func (c *Client) Eval(ctx context.Context, s *Script, keys []string, args ...any) (any, error) {
	a := make([]any, 0, 3+len(keys)+len(args))
	a = append(a, "EVALSHA", s.sha, len(keys))
	for _, k := range keys {
		a = append(a, k)
	}
	a = append(a, args...)
	v, err := c.Do(ctx, a...)
	if e, ok := err.(Error); ok && strings.HasPrefix(string(e), "NOSCRIPT") {
		a[0], a[1] = "EVAL", s.src
		return c.Do(ctx, a...)
	}
	return v, err
}
