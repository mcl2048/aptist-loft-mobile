//go:build linux

package hyrakenx

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Linux doubles SO_*BUF requests for kernel bookkeeping: each owned socket
// requests at most 1 MiB per direction (2 MiB effective), subject to host caps.
// These kernel queue limits are separate from QUIC credit and process RSS.
const ownedUDPSocketBuffer = 1 << 20

var socketBufferWarning [2]sync.Once

// GateConn deliberately hides syscall.Conn: QUIC descriptor I/O would bypass
// its authentication. Tune only sockets created by Listen and Dial, before
// wrapping them; caller-owned PacketConns retain their owner's policy.
func configureOwnedUDPSocket(socket net.PacketConn) {
	udp, ok := socket.(*net.UDPConn)
	if !ok {
		return
	}
	raw, rawErr := udp.SyscallConn()
	for i, direction := range []struct {
		name   string
		option int
		limit  string
	}{{"receive", unix.SO_RCVBUF, "rmem_max"}, {"send", unix.SO_SNDBUF, "wmem_max"}} {
		err := rawErr
		var effective int
		if err == nil {
			var data []byte
			data, err = os.ReadFile("/proc/sys/net/core/" + direction.limit)
			if err == nil {
				var maximum int
				maximum, err = strconv.Atoi(strings.TrimSpace(string(data)))
				if err == nil {
					effective, err = growOwnedUDPBuffer(raw, direction.option, maximum)
				}
			}
		}
		if err != nil {
			// At most one diagnostic per direction for the process. Report only
			// local option state, never socket addresses or deployment secrets.
			socketBufferWarning[i].Do(func() {
				log.Printf("hyrakenx: UDP %s buffer best effort: requested=%d effective=%d: %v", direction.name, ownedUDPSocketBuffer, effective, err)
			})
		}
	}
	if rawErr == nil {
		// Optional metadata only on constructor-owned UDP sockets. Failure is
		// intentionally nonfatal: NewGateConn independently reads back capability
		// and leaves QUIC on its original basicConn when the options are absent.
		_ = raw.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)
		})
	}
}

func growOwnedUDPBuffer(raw syscall.RawConn, option, maximum int) (int, error) {
	var effective int
	var optionErr error
	err := raw.Control(func(fd uintptr) {
		effective, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, option)
		if optionErr != nil || effective >= 2*ownedUDPSocketBuffer {
			return
		}
		// Read the host cap before writing: when a host's default exceeds a
		// subsequently lowered cap, even a larger request can shrink a queue.
		request := min(ownedUDPSocketBuffer, maximum)
		if request <= 0 || request <= effective/2 {
			optionErr = errors.New("host cap prevents buffer growth")
			return
		}
		if optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option, request); optionErr != nil {
			return
		}
		effective, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, option)
		if optionErr == nil && effective < 2*ownedUDPSocketBuffer {
			optionErr = fmt.Errorf("host capped effective buffer below %d", 2*ownedUDPSocketBuffer)
		}
	})
	// net's RawConn.Control wraps failures in OpError with the local address.
	// Keep the underlying cause for the bounded diagnostic, without the peer
	// or listener endpoint even if setup races with socket closure.
	var networkError *net.OpError
	if errors.As(err, &networkError) {
		err = networkError.Err
	}
	return effective, errors.Join(err, optionErr)
}
