package transport

import (
	"context"
	"io"
	"testing"
	"time"

	x "loft.local/hyrakenx"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
)

// The actual X consumer must preserve reliable FIN and late reverse bytes;
// adapter ForceClose is reserved for final ownership cleanup after the reply.
func TestActualXHalfClosePreservesLateReverseBytesAndRemoteEOF(t *testing.T) {
	identity := testsupport.Certificates(t)
	seed := []byte("0123456789abcdef0123456789abcdef")
	listener, err := x.Listen("127.0.0.1:0", identity.ServerTLS.Clone(), seed)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() {
		peer, err := listener.Accept(ctx)
		if err != nil {
			served <- err
			return
		}
		defer testsupport.Close(t, peer)
		stream, network, target, err := peer.AcceptStream(ctx)
		if err != nil || network != "tcp" || target != "reverse.test:7" {
			served <- io.ErrUnexpectedEOF
			return
		}
		defer func() { _ = stream.Close() }() // Protocol cancellation may report a cancel-close error; final runtime release is asserted.
		payload, err := io.ReadAll(stream)
		if err != nil || string(payload) != "request before FIN" {
			served <- io.ErrUnexpectedEOF
			return
		}
		if _, err := stream.Write([]byte("late X reverse bytes")); err != nil {
			served <- err
			return
		}
		if err := stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			served <- err
			return
		}
		// Keep the owning QUIC session alive until the client has consumed its
		// reliable tail; a peer abort is distinct from successful stream FIN.
		<-ctx.Done()
		served <- nil
	}()
	client, err := NewClient(ctx, &nodeconfig.Config{Protocol: "hyrakenx", Address: listener.Addr().String(), Seed: seed, TLS: identity.ClientTLS.Clone(), Pin: identity.Pin, Mode: "flash", Scenario: "bulk"}, &observedPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, client)
	if err := client.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialTCP(ctx, "reverse.test:7")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, conn)
	if _, err := conn.Write([]byte("request before FIN")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	response, err := io.ReadAll(conn)
	if err != nil || string(response) != "late X reverse bytes" {
		t.Fatal("actual X consumer lost FIN, late reverse bytes, or remote EOF")
	}
	cancel()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil || client.Stats().PhysicalOpen != 0 {
		t.Fatal("X half-close retained its physical owner")
	}
}
