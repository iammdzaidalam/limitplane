// Package redisx is a minimal RESP2 Redis client with a connection pool.
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
)

type Client struct {
	addr, user, pass string
	db               int
	tls              *tls.Config
	idle             chan *conn
	closed           atomic.Bool
}

type conn struct {
	nc net.Conn
	r  *bufio.Reader
	w  *bufio.Writer
}

// Dial is New plus one connection to check the server is there.
func Dial(addr string) (*Client, error) {
	c, err := New(addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	c.put(cn)
	return c, nil
}

// New parses addr ("host:port" or "redis[s]://[user]:pass@host:port/db") without connecting:
// connections are made on demand, so a Redis that isn't up yet is retried by later commands.
func New(addr string) (*Client, error) {
	c := &Client{addr: addr, idle: make(chan *conn, poolSize)}
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil {
			return nil, err
		}
		if u.Scheme != "redis" && u.Scheme != "rediss" {
			return nil, fmt.Errorf("redisx: unsupported scheme %q", u.Scheme)
		}
		c.addr = u.Host
		if u.Port() == "" {
			c.addr = net.JoinHostPort(u.Hostname(), "6379")
		}
		if u.User != nil {
			c.user = u.User.Username()
			c.pass, _ = u.User.Password()
		}
		if db := strings.TrimPrefix(u.Path, "/"); db != "" {
			if c.db, err = strconv.Atoi(db); err != nil {
				return nil, fmt.Errorf("redisx: bad db %q", db)
			}
		}
		if u.Scheme == "rediss" {
			c.tls = &tls.Config{ServerName: u.Hostname()}
		}
	}
	return c, nil
}

func (c *Client) dial(ctx context.Context) (*conn, error) {
	if _, ok := ctx.Deadline(); !ok { // a blackholed host would otherwise hang until the OS gives up
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	var nc net.Conn
	var err error
	if c.tls != nil {
		nc, err = (&tls.Dialer{Config: c.tls}).DialContext(ctx, "tcp", c.addr)
	} else {
		nc, err = (&net.Dialer{}).DialContext(ctx, "tcp", c.addr)
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

func (c *Client) put(cn *conn) {
	if c.closed.Load() {
		cn.nc.Close()
		return
	}
	select {
	case c.idle <- cn:
	default:
		cn.nc.Close()
	}
}

// Do sends one command. Replies map to string, int64, []any, nil, or an Error.
func (c *Client) Do(ctx context.Context, args ...any) (any, error) {
	if c.closed.Load() {
		return nil, errors.New("redisx: client closed")
	}
	var cn *conn
	select {
	case cn = <-c.idle:
	default:
		var err error
		if cn, err = c.dial(ctx); err != nil {
			return nil, err
		}
	}
	v, err := cn.do(ctx, args)
	var rerr Error
	if err != nil && !errors.As(err, &rerr) {
		// shortcut: no retry on a stale pooled conn; fine while Redis has no idle timeout.
		cn.nc.Close()
		return nil, err
	}
	c.put(cn)
	return v, err
}

func (c *Client) Close() error {
	c.closed.Store(true)
	for {
		select {
		case cn := <-c.idle:
			cn.nc.Close()
		default:
			return nil
		}
	}
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
	if err := w.Flush(); err != nil {
		return nil, err
	}
	return readReply(cn.r)
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

// Script is a Lua script run with EVALSHA, falling back to EVAL once on NOSCRIPT.
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
