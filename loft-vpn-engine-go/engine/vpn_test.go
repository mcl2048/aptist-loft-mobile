package engine

import (
	"testing"
)

// Android protection is mandatory: no default-true platform adapter can create
// a VPN runtime that later sends an unprotected physical socket.
func TestVPNRuntimeRequiresExplicitPlatformOwner(t *testing.T) {
	runtime, err := NewVPNRuntime(nil)
	if err == nil || runtime != nil {
		t.Fatal("VPN runtime accepted missing Android platform ownership")
	}
}

// Generated Java can create a zero struct; it must remain unavailable and
// reject Start without a platform rather than fabricate an active VPN.
func TestZeroVPNRuntimeCannotStartAndClosesIdempotently(t *testing.T) {
	var runtime VPNRuntime
	if err := runtime.Start(-1, "socks5://127.0.0.1:1080", "198.18.0.1/30", 1280); err == nil {
		t.Fatal("unowned generated wrapper started a VPN")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}
