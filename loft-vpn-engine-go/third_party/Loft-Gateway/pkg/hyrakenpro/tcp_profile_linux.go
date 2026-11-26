//go:build linux

package hyrakenpro

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var proBeastFallbackOnce sync.Once

// TCPControl installs the dedicated Pro policy before connect. It is also
// suitable for ListenConfig.Control; accepted sockets are checked by ApplyTCP.
func TCPControl(network, address string, raw syscall.RawConn) error {
	return TCPControlFor("beast")(network, address, raw)
}

// TCPControlFor selects a dedicated Beast policy or strict BBR.
func TCPControlFor(congestion string) func(string, string, syscall.RawConn) error {
	return func(network, _ string, raw syscall.RawConn) error {
		if !strings.HasPrefix(network, "tcp") {
			return nil
		}
		if raw == nil {
			return errors.New("Hyraken Pro: missing TCP descriptor")
		}
		var optionErr error
		if err := raw.Control(func(fd uintptr) { optionErr = applyProTCP(int(fd), congestion) }); err != nil {
			return err
		}
		return optionErr
	}
}

// ApplyTCP runs on the raw accepted socket, before TLS or HTTP wrappers hide it.
// Logical net.Pipe and stream connections intentionally have no socket policy.
func ApplyTCP(conn net.Conn) error { return ApplyTCPWithCongestion(conn, "beast") }

// ApplyTCPWithCongestion observes BBR installation and fails if unavailable.
func ApplyTCPWithCongestion(conn net.Conn, congestion string) error {
	if conn == nil {
		return errors.New("Hyraken Pro: missing TCP connection")
	}
	c, ok := conn.(syscall.Conn)
	if !ok {
		if congestion == "bbr" {
			return errors.New("hyrakenpro: cannot verify requested BBR on wrapped socket")
		}
		return nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	return TCPControlFor(congestion)("tcp", conn.RemoteAddr().String(), raw)
}

func applyProTCP(fd int, congestion string) error {
	p := DefaultTCPProfile()
	current, err := unix.GetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	if err != nil {
		return fmt.Errorf("Hyraken Pro TCP sender: %w", err)
	}
	if congestion == "bbr" {
		if current != "bbr" {
			if err := unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr"); err != nil {
				return fmt.Errorf("hyrakenpro: requested BBR unavailable: %w", err)
			}
		}
		actual, err := unix.GetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION)
		if err != nil || actual != "bbr" {
			return fmt.Errorf("hyrakenpro: BBR verification failed (%s): %v", actual, err)
		}
	}
	_, peerErr := unix.Getpeername(fd)
	// A connected route-managed Brutal socket already owns a shared quota.
	selected := current == "brutal" && peerErr == nil
	if !selected && congestion != "bbr" {
		switchErr := error(nil)
		if current != "brutal" {
			switchErr = unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal")
		}
		if switchErr == nil {
			var params [20]byte
			binary.LittleEndian.PutUint64(params[:8], p.BrutalRate)
			binary.LittleEndian.PutUint32(params[8:12], 18) // gain 1.8, independent group 0
			switchErr = unix.SetsockoptString(fd, unix.IPPROTO_TCP, 23301, string(params[:]))
			selected = switchErr == nil
		}
		if !selected {
			// Never leave Brutal's unconfigured default rate installed.
			// Prefer the host's actual BBR implementation; its name does not
			// establish BBRv3. Recovery and pacing remain owned by that kernel.
			bbrErr := selectProTCPSender(fd, "bbr")
			if bbrErr != nil {
				if err := selectProTCPSender(fd, "cubic"); err != nil {
					return fmt.Errorf("hyrakenpro: adaptive fallback: BBR unavailable (%v); CUBIC unavailable: %w", bbrErr, err)
				}
			}
			proBeastFallbackOnce.Do(func() {
				if bbrErr == nil {
					log.Printf("[Hyraken Pro] TCP Brutal unavailable; verified kernel BBR fallback: %v", switchErr)
				} else {
					log.Printf("[Hyraken Pro] TCP Brutal unavailable; verified CUBIC fallback (BBR unavailable: %v): %v", bbrErr, switchErr)
				}
			})
		}
	}
	// TCP_USER_TIMEOUT bounds an unacknowledged outage, not application idle.
	// SO_*BUF/MSS/TFO/linear RTO are deliberately left to the kernel policy.
	for _, option := range []struct{ level, name, value int }{
		{unix.IPPROTO_TCP, unix.TCP_NODELAY, 1},
		{unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, p.UserTimeoutMS},
		{unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, p.NotsentLowat},
		{unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1},

		{unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, p.KeepIdleSeconds},
		{unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, p.KeepIntervalSec},
		{unix.IPPROTO_TCP, unix.TCP_KEEPCNT, p.KeepCount},
	} {
		if err := unix.SetsockoptInt(fd, option.level, option.name, option.value); err != nil {
			return fmt.Errorf("Hyraken Pro TCP option %d: %w", option.name, err)
		}
	}
	return nil
}

// selectProTCPSender verifies local selection, including an already active mode.
// Avoid resetting a live sender or rejecting a locked-but-correct socket merely
// to set the same name again. No global algorithm, qdisc or rate is changed.
func selectProTCPSender(fd int, name string) error {
	current, err := unix.GetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	if err != nil {
		return fmt.Errorf("read current sender: %w", err)
	}
	if current != name {
		if err := unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, name); err != nil {
			return fmt.Errorf("select %s: %w", name, err)
		}
	}
	actual, err := unix.GetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	if err != nil {
		return fmt.Errorf("verify %s: %w", name, err)
	}
	if actual != name {
		return fmt.Errorf("verify %s: actual sender %q", name, actual)
	}
	return nil
}
