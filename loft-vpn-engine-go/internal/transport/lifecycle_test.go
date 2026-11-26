package transport

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	socks "github.com/sagernet/sing/protocol/socks"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
)

// Android's bounded resolver callback can remain inside platform code until
// its own deadline. Close must cancel it and join, rather than clear credentials
// and return a released receipt while startup still owns the configuration.
type heldResolver struct {
	observedPolicy
	entered chan struct{}
	release chan struct{}
}

type heldProtector struct {
	observedPolicy
	hold    atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (p *heldProtector) Protect(fd int) error {
	if p.hold.Load() {
		close(p.entered)
		<-p.release
	}
	return p.observedPolicy.Protect(fd)
}

// A socket inside the platform's before-connect callback is still an admitted
// business owner. Closing the client must cancel and join it before returning.
func TestCloseJoinsPendingSOCKSBusinessOpen(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer testsupport.Close(t, conn)
				_ = socks.HandleConnectionEx(ctx, conn, bufio.NewReader(conn), nil, socksEcho{}, nil, 2*time.Second, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
			}()
		}
	}()
	policy := &heldProtector{entered: make(chan struct{}), release: make(chan struct{})}
	client, err := NewClient(ctx, &nodeconfig.Config{Protocol: "socks5", Address: listener.Addr().String()}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	policy.hold.Store(true)
	openDone := make(chan error, 1)
	go func() {
		conn, err := client.DialTCP(ctx, "echo.test:7")
		if conn != nil {
			_ = conn.Close()
		}
		openDone <- err
	}()
	select {
	case <-policy.entered:
	case <-time.After(time.Second):
		t.Fatal("business open did not enter the platform callback")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	returnedEarly := false
	select {
	case err := <-closeDone:
		if err != nil {
			t.Errorf("unexpected early close failure: %v", err)
		}
		returnedEarly = true
	case <-time.After(30 * time.Millisecond):
	}
	close(policy.release)
	select {
	case err := <-openDone:
		if err == nil {
			t.Fatal("closed business open returned a live association")
		}
	case <-time.After(time.Second):
		t.Fatal("closing owner did not cancel/join the business open")
	}
	if !returnedEarly {
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("close did not finish after its business owner joined")
		}
	}
	if returnedEarly {
		t.Fatal("close returned with an admitted business open still pending")
	}
	if client.Stats().PhysicalOpen != 0 {
		t.Fatal("close retained a pending physical admission")
	}
}

func (p *heldResolver) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	close(p.entered)
	<-p.release
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ctx.Err()
}

func TestCloseJoinsPendingReadyBeforeClearingCredentials(t *testing.T) {
	cfg := fixtureNode(t, "hyraken-pro", "tcp", false)
	_, port, _ := net.SplitHostPort(cfg.Address)
	cfg.Address = net.JoinHostPort("node.invalid", port)
	policy := &heldResolver{entered: make(chan struct{}), release: make(chan struct{})}
	client, err := NewClient(context.Background(), cfg, policy)
	if err != nil {
		t.Fatal(err)
	}
	readyDone := make(chan error, 1)
	go func() { readyDone <- client.Ready(context.Background()) }()
	select {
	case <-policy.entered:
	case <-time.After(time.Second):
		t.Fatal("startup did not enter the resolver boundary")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	returnedEarly := false
	select {
	case err := <-closeDone:
		if err != nil {
			t.Errorf("unexpected early close failure: %v", err)
		}
		returnedEarly = true
	case <-time.After(30 * time.Millisecond):
	}
	close(policy.release)
	select {
	case err := <-readyDone:
		if err == nil {
			t.Fatal("closed startup reported authentication success")
		}
	case <-time.After(time.Second):
		t.Fatal("closing owner did not join startup")
	}
	if !returnedEarly {
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("close remained blocked after startup joined")
		}
	}
	if returnedEarly {
		t.Fatal("close returned before the blocked resolver/startup joined")
	}
	if client.Stats().PhysicalOpen != 0 || policy.count.Load() != 0 {
		t.Fatal("canceled startup reopened a physical socket")
	}
	if err := client.Ready(context.Background()); err == nil {
		t.Fatal("closed client reopened startup")
	}
}

// Real peer shutdown must revoke the authenticated receipt; a Pro pool must
// not silently redial and an X peer must not retain cached successful Ready.
func TestUnexpectedPeerLossRevokesReadinessAndStopsNewBusinessOpens(t *testing.T) {
	for _, test := range []struct{ name, kind, carrier string }{{"X", "hyrakenx", ""}, {"ProTCP", "hyraken-pro", "tcp"}, {"ProGRPC", "hyraken-pro", "grpc"}} {
		t.Run(test.name, func(t *testing.T) {
			cfg, shutdown := fixtureNodeWithShutdown(t, test.kind, test.carrier, false)
			client, err := NewClient(context.Background(), cfg, &observedPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			defer testsupport.Close(t, client)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := client.Ready(ctx); err != nil {
				t.Fatal(err)
			}
			conn, err := client.DialTCP(ctx, "echo.test:7")
			if err != nil {
				t.Fatal(err)
			}
			defer testsupport.Close(t, conn)
			shutdown()
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			_, readErr := conn.Read(make([]byte, 1))
			if readErr == nil {
				t.Fatal("remote peer shutdown did not end the real stream")
			}
			var timeout net.Error
			if errors.As(readErr, &timeout) && timeout.Timeout() {
				t.Fatalf("remote peer shutdown produced only a read deadline: %T", readErr)
			}
			if test.kind == "hyrakenx" {
				requireXRemotePeerClose(t, ctx, client)
			}
			deadline := time.Now().Add(300 * time.Millisecond)
			for client.Ready(ctx) == nil {
				if time.Now().After(deadline) {
					t.Fatal("dead authenticated peer retained a successful Ready receipt")
				}
				time.Sleep(time.Millisecond)
			}
			if conn, err := client.DialTCP(ctx, "echo.test:7"); err == nil {
				_ = conn.Close()
				t.Fatal("lost generation silently reopened a business stream")
			}
			if err := client.Close(); err != nil || client.Stats().PhysicalOpen != 0 {
				t.Fatal("lost generation did not release its physical owners")
			}
		})
	}
}
