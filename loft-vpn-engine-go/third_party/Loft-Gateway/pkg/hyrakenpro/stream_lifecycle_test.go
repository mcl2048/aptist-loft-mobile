package hyrakenpro

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestProZeroDeadlineWaitUsesSessionOwner(t *testing.T) {
	ctx, closeSession := context.WithCancel(context.Background())
	defer closeSession()
	stream := &Stream{session: &session{ctx: ctx}}
	_ = ctx.Done()
	for _, write := range []bool{false, true} {
		allocations := testing.AllocsPerRun(100, func() {
			wait, release, _ := stream.deadlineContext(write)
			_ = wait.Done()
			release()
		})
		if allocations != 0 {
			t.Errorf("write=%v zero-deadline wait allocated %g times", write, allocations)
		}
		wait, release, _ := stream.deadlineContext(write)
		release()
		if wait.Err() != nil {
			t.Errorf("write=%v releasing a wait canceled the session-owned context: %v", write, wait.Err())
		}
	}
}

func TestProHTTP2WriteBudget(t *testing.T) {
	if got := HTTP2Settings().WriteByteTimeout; got != 45*time.Second {
		t.Fatalf("HTTP/2 write timeout = %s, want %s", got, 45*time.Second)
	}
}

func TestProClosedPooledSessionIsReplacedWithinOriginalDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := NewClient(ctx, ClientConfig{
		URL: "https://relay.example.test/tunnel", Seed: "synthetic-node-seed-32-bytes-long",
		Transport: TransportTCP, Connections: 1,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errReplacementDialObserved{}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	physical, peer := net.Pipe()
	defer peer.Close()
	var stale *session
	stale, err = newSession(client.ctx, closeOnFirstWrite{Conn: physical, cancel: func() { stale.cancel() }},
		recordKeys{suite: 2}, true, "", nil, nil, nil, TransportTCP, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stale.Close()
	client.pool = append(client.pool, stale)
	connection, err := client.DialContext(ctx, "tcp", "destination.example.test:443")
	if connection != nil {
		connection.Close()
		t.Fatal("replacement fixture cannot establish a socket")
	}
	if !errors.Is(err, errReplacementDialObserved{}) {
		t.Fatalf("wanted replacement dial, received %v", err)
	}
}

type errReplacementDialObserved struct{}

func (errReplacementDialObserved) Error() string { return "synthetic replacement dial observed" }

type closeOnFirstWrite struct {
	net.Conn
	cancel func()
}

func (c closeOnFirstWrite) Write([]byte) (int, error) {
	c.cancel()
	return 0, net.ErrClosed
}
