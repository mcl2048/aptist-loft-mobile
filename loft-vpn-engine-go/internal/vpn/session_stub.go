//go:build !with_gvisor

package vpn

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/transport"
	"net/netip"
	"time"
)

const GVisorBuilt = false

type session struct{}

func startSession(ctx context.Context, fd int, name string, address netip.Prefix, mtu int, cfg *nodeconfig.Config, policy transport.SocketPolicy, networkPolicy networkprivacy.Policy, lost func(string)) (*session, error) {
	_ = unix.Close(fd)
	return nil, errors.New("loft.vpn.gvisor_not_built")
}
func (s *session) facts(snapshot *Snapshot)          {}
func (s *session) stop() error                       { return nil }
func (s *session) abort()                            {}
func (s *session) signalCancellation()               {}
func (s *session) waitForwarding()                   {}
func (s *session) drain(timeout time.Duration) error { return errors.New("loft.vpn.gvisor_not_built") }
