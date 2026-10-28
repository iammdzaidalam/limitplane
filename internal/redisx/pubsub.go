package redisx

import (
	"context"
	"fmt"
	"time"
)

// Sub is a dedicated connection in subscribe mode. Receive and Ping must be called from one
// goroutine; Close may be called from any.
type Sub struct{ cn *conn }

// Message is one push: Kind is "message", "subscribe" or "pong".
type Message struct{ Kind, Channel, Data string }

// Subscribe opens a connection subscribed to channel. On a Cluster any node will do: PUBLISH
// reaches every node, so healthy nodes are tried first.
func (c *Client) Subscribe(ctx context.Context, channel string) (*Sub, error) {
	if c.closed.Load() {
		return nil, errClosed
	}
	ns := []*node{c.node}
	if c.cluster != nil {
		ns = c.cluster.all()
		now := time.Now().UnixNano()
		for i, n := range ns { // move one healthy node to the front
			if !n.isDown(now) {
				ns[0], ns[i] = ns[i], ns[0]
				break
			}
		}
	}
	var err error
	for _, n := range ns {
		var cn *conn
		if cn, err = n.dial(ctx); err != nil {
			continue
		}
		var v any
		if v, err = cn.do(ctx, []any{"SUBSCRIBE", channel}); err == nil {
			if m, ok := message(v); ok && m.Kind == "subscribe" {
				cn.nc.SetDeadline(time.Time{})
				return &Sub{cn}, nil
			}
			err = fmt.Errorf("redisx: unexpected SUBSCRIBE reply %v", v)
		}
		cn.nc.Close()
	}
	return nil, err
}

// Receive waits up to timeout for the next push. A timeout returns os.ErrDeadlineExceeded; the
// stream is still in sync unless a push was cut in half, which the next Receive reports as an error.
func (s *Sub) Receive(timeout time.Duration) (Message, error) {
	s.cn.nc.SetReadDeadline(time.Now().Add(timeout))
	v, err := readReply(s.cn.r)
	if err != nil {
		return Message{}, err
	}
	m, ok := message(v)
	if !ok {
		return Message{}, fmt.Errorf("redisx: unexpected push %v", v)
	}
	return m, nil
}

// Ping asks for a "pong" push, to tell an idle subscription from a dead one.
func (s *Sub) Ping() error {
	s.cn.nc.SetWriteDeadline(time.Now().Add(defaultTimeout))
	return s.cn.write([]any{"PING"})
}

func (s *Sub) Close() error { return s.cn.nc.Close() }

func message(v any) (Message, bool) {
	a, ok := v.([]any)
	if !ok || len(a) < 2 {
		return Message{}, false
	}
	var m Message
	m.Kind, ok = a[0].(string)
	m.Channel, _ = a[1].(string)
	if len(a) > 2 {
		m.Data, _ = a[2].(string)
	}
	return m, ok
}
