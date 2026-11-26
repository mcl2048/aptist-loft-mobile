package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
	x "loft.local/hyrakenx"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
)

func requireXRemotePeerClose(t *testing.T, ctx context.Context, client *Client) {
	t.Helper()
	// Read the connection's terminal receipt independently of a business stream,
	// which the loss owner may already have canceled during cleanup.
	_, err := client.peer.Receive(ctx)
	var closed *quic.ApplicationError
	if !errors.As(err, &closed) || !closed.Remote {
		t.Fatalf("X shutdown did not deliver a remote authenticated CLOSE: %T", err)
	}
}

// Destroying the local UDP transport and sending an authenticated peer CLOSE
// are different events. A stream deadline cannot turn the former into the latter.
func TestXShutdownModeDistinguishesPeerCloseFromSocketDisappearance(t *testing.T) {
	for _, sendClose := range []bool{false, true} {
		name := "socket_disappearance"
		if sendClose {
			name = "peer_close"
		}
		t.Run(name, func(t *testing.T) {
			id := testsupport.Certificates(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			seed := []byte("0123456789abcdef0123456789abcdef")
			listener, err := x.Listen("127.0.0.1:0", id.ServerTLS, seed)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			type acceptResult struct {
				peer *x.Peer
				err  error
			}
			accepted := make(chan acceptResult, 1)
			acceptDone := make(chan struct{})
			go func() {
				defer close(acceptDone)
				peer, err := listener.Accept(ctx)
				accepted <- acceptResult{peer, err}
			}()
			defer func() { cancel(); _ = listener.Close(); <-acceptDone }()
			cfg := &nodeconfig.Config{Protocol: "hyrakenx", Address: listener.Addr().String(), TLS: id.ClientTLS, Seed: seed}
			client, err := NewClient(context.Background(), cfg, &observedPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			defer testsupport.Close(t, client)
			if err := client.Ready(ctx); err != nil {
				t.Fatal(err)
			}
			result := <-accepted
			if result.err != nil {
				t.Fatal(result.err)
			}
			defer testsupport.Close(t, result.peer)
			conn, err := client.DialTCP(ctx, "echo.test:7")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }() // Abort can return a stream cancel-close error; physical release is checked below.
			serverConn, _, _, err := result.peer.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = serverConn.Close() }()
			if sendClose {
				if err := result.peer.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-result.peer.Done():
			case <-ctx.Done():
				t.Fatal("server transport teardown did not complete")
			}
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			_, readErr := conn.Read(make([]byte, 1))
			var timeout net.Error
			isTimeout := errors.As(readErr, &timeout) && timeout.Timeout()
			if sendClose {
				if readErr == nil || isTimeout {
					t.Fatalf("explicit peer CLOSE produced no transport closure: %T", readErr)
				}
				requireXRemotePeerClose(t, ctx, client)
				select {
				case <-client.Lost():
				case <-time.After(300 * time.Millisecond):
					t.Fatal("authenticated peer CLOSE did not revoke readiness")
				}
				if err := client.Ready(ctx); err == nil {
					t.Fatal("closed authenticated peer retained Ready")
				}
			} else {
				if !isTimeout {
					t.Fatalf("silent socket disappearance did not produce the expected read deadline: %T", readErr)
				}
				select {
				case <-client.peer.Done():
					t.Fatal("silent socket disappearance fabricated a remote peer closure")
				default:
				}
				select {
				case <-client.Lost():
					t.Fatal("ordinary stream deadline fabricated an authenticated loss receipt")
				default:
				}
				if err := client.Ready(ctx); err != nil {
					t.Fatal("stream deadline revoked a still-live local peer")
				}
			}
			if err := client.Close(); err != nil || client.Stats().PhysicalOpen != 0 {
				t.Fatal("shutdown control did not release its physical owner")
			}
		})
	}
}

func TestXReadDeadlinePreservesAuthenticatedPeerAndUsableStream(t *testing.T) {
	cfg := fixtureNode(t, "hyrakenx", "", false)
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
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, readErr := conn.Read(make([]byte, 1))
	var timeout net.Error
	if !errors.As(readErr, &timeout) || !timeout.Timeout() {
		t.Fatalf("idle stream did not reach an ordinary read deadline: %T", readErr)
	}
	select {
	case <-client.Lost():
		t.Fatal("ordinary read deadline revoked authenticated readiness")
	default:
	}
	if err := client.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("usable after read deadline")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("ordinary deadline made the authenticated stream unusable")
	}
	if err := client.Close(); err != nil || client.Stats().PhysicalOpen != 0 {
		t.Fatal("deadline control did not release its physical owner")
	}
}
