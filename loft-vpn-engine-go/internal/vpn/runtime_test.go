package vpn

import (
	"context"
	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

type inertPolicy struct{ calls atomic.Int32 }

func (p *inertPolicy) Protect(fd int) error { p.calls.Add(1); return nil }
func (p *inertPolicy) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	p.calls.Add(1)
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ctx.Err()
}

// Removing the Android listener must not leave a lifetime worker after terminal
// Close. An in-flight callback remains an owner until it returns, so completion
// cannot report all resources released merely by clearing the function pointer.
func TestCloseJoinsListenerAndKeepsReleaseUnconfirmedWhileCallbackRuns(t *testing.T) {
	before := runtime.NumGoroutine()
	r := NewRuntime(&inertPolicy{})
	entered := make(chan struct{})
	release := make(chan struct{})
	r.SetListener(func(string) { close(entered); <-release })
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("registered listener did not receive its actual snapshot")
	}
	r.SetListener(nil)
	closeDone := make(chan error, 1)
	go func() { closeDone <- r.Close() }()
	returnedEarly := false
	select {
	case err := <-closeDone:
		if err != nil {
			t.Errorf("unexpected early close failure: %v", err)
		}
		returnedEarly = true
	case <-time.After(30 * time.Millisecond):
	}
	owned := !r.Snapshot().ResourcesReleased
	close(release)
	if !returnedEarly {
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("terminal close did not join its returned listener")
		}
	}
	if returnedEarly || !owned {
		t.Fatal("close confirmed release while its listener callback was still owned")
	}
	if snapshot := r.Snapshot(); snapshot.State != "closed" || !snapshot.ResourcesReleased {
		t.Fatal("joined terminal close did not publish released state")
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatal("terminal close retained its idle listener worker")
		}
		time.Sleep(time.Millisecond)
	}
}

// A pipe or arbitrary fd cannot become a VPN permission/TUN receipt. Reject it
// before resolving a node, opening a socket or reporting connected.
func TestStartRejectsNonTUNDescriptorBeforeAnyNetworkWork(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, read)
	defer testsupport.Close(t, write)
	policy := &inertPolicy{}
	runtime := configuredTestRuntime(t, policy, "1.1.1.1:53")
	defer testsupport.Close(t, runtime)
	if err := runtime.Start(int(read.Fd()), "socks5://127.0.0.1:1080", "198.18.0.1/30", 1280); err == nil {
		t.Fatal("ordinary file descriptor fabricated a TUN receipt")
	}
	if policy.calls.Load() != 0 {
		t.Fatal("invalid TUN initialized node networking")
	}
	snapshot := runtime.Snapshot()
	if snapshot.TransportReady || snapshot.TunOwned || !snapshot.ForwardingDisabled {
		t.Fatal("failed start fabricated forwarding readiness")
	}
}

// A malformed upstream cannot change a running/public profile or create a
// hidden direct DNS fallback; initial settings only accept literal IP endpoints.
func TestDNSSettingsValidateAtomicallyWithoutNetwork(t *testing.T) {
	policy := &inertPolicy{}
	runtime := NewRuntime(policy)
	defer testsupport.Close(t, runtime)
	for _, address := range []string{"https://example.com/dns-query", "example.com:53", "1.1.1.1:0", "127.0.0.1:65536", ""} {
		if err := runtime.SetDNSUpstream(address); err == nil {
			t.Fatal("invalid literal DNS upstream accepted")
		}
	}
	if err := runtime.SetDNSUpstream("1.1.1.1:53"); err != nil {
		t.Fatal(err)
	}
	if policy.calls.Load() != 0 {
		t.Fatal("settings change made a network request")
	}
}
