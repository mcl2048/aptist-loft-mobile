//go:build linux || android

package vpn

import (
	"errors"
	"golang.org/x/sys/unix"
)

func duplicateTUN(fd int) (int, string, error) {
	if fd < 0 {
		return -1, "", errors.New("loft.vpn.invalid_tun_fd")
	}
	request, err := unix.NewIfreq("")
	if err != nil {
		return -1, "", errors.New("loft.vpn.invalid_tun_fd")
	}
	if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, request); err != nil || request.Uint16()&unix.IFF_TUN == 0 || request.Uint16()&unix.IFF_NO_PI == 0 {
		return -1, "", errors.New("loft.vpn.invalid_tun_fd")
	}
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return -1, "", errors.New("loft.vpn.tun_dup_failed")
	}
	if err := unix.SetNonblock(dup, true); err != nil {
		_ = unix.Close(dup)
		return -1, "", errors.New("loft.vpn.tun_configuration_failed")
	}
	return dup, request.Name(), nil
}
