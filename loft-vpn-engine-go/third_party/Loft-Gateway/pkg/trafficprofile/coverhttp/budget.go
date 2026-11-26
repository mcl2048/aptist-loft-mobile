package coverhttp

import (
	"context"
	"net"
	"sync"
)

// MaxRejections is a per-physical-connection budget, not a source-IP ban. This
// avoids an unbounded address table and avoids punishing other clients behind NAT.
const MaxRejections = 8

type budgetKey struct{}
type budget struct {
	mu                    sync.Mutex
	count                 int
	authenticated, closed bool
	conn                  net.Conn
}

// ConnContext is used only on dedicated QUBF listeners.
func ConnContext(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, budgetKey{}, &budget{conn: conn})
}

// Authenticate protects an HTTP/2 connection once a request proves possession
// of valid protocol credentials. Rejected sibling streams must not kill it.
func Authenticate(ctx context.Context) bool {
	b, _ := ctx.Value(budgetKey{}).(*budget)
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.authenticated = true
	return true
}

// Reject runs after the bounded cover write. Only the winning close owner acts
// outside the lock; authentication cannot revive an exhausted connection.
func Reject(ctx context.Context) {
	b, _ := ctx.Value(budgetKey{}).(*budget)
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.authenticated || b.closed {
		b.mu.Unlock()
		return
	}
	b.count++
	closeNow := b.count >= MaxRejections
	if closeNow {
		b.closed = true
	}
	b.mu.Unlock()
	if closeNow {
		_ = b.conn.Close()
	}
}
