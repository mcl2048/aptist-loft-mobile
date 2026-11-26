//go:build !linux

package hyrakenpro

import (
	"errors"
	"net"
	"syscall"
)

// TCPControl preserves the host sender where Linux Brutal is unavailable.
func TCPControl(_ string, _ string, _ syscall.RawConn) error { return nil }

// ApplyTCP keeps ordinary TCP latency bounded without Linux-only options.
func ApplyTCP(conn net.Conn) error {
	if conn == nil {
		return errors.New("Hyraken Pro: missing TCP connection")
	}
	if c, ok := conn.(*net.TCPConn); ok {
		return c.SetNoDelay(true)
	}
	return nil
}

// TCPControlFor rejects unavailable explicit congestion choices.
func TCPControlFor(mode string) func(string, string, syscall.RawConn) error {
	return func(n, a string, r syscall.RawConn) error {
		if mode == "bbr" {
			return errors.New("hyrakenpro: BBR is unavailable on this platform")
		}
		return TCPControl(n, a, r)
	}
}
func ApplyTCPWithCongestion(c net.Conn, mode string) error {
	if mode == "bbr" {
		return errors.New("hyrakenpro: BBR is unavailable on this platform")
	}
	return ApplyTCP(c)
}
