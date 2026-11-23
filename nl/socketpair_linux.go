package nl

import (
	"os"

	"golang.org/x/sys/unix"
)

// NewNetlinkSocketPairForTest creates two connected netlink sockets of the
// given protocol that deliver messages to each other instead of to the kernel.
// It exists for tests that need a deterministic peer to answer, reorder, or
// delay ACKs; production code must keep using GetNetlinkSocketAt or Subscribe.
//
// Connecting two userspace netlink ports requires CAP_NET_ADMIN, like the rest
// of the netlink test suite. The returned sockets are non-blocking and the
// caller owns both: closing one does not close the other.
func NewNetlinkSocketPairForTest(protocol int) (*NetlinkSocket, *NetlinkSocket, error) {
	fd0, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return nil, nil, err
	}
	fd1, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		unix.Close(fd0)
		return nil, nil, err
	}

	fail := func() (*NetlinkSocket, *NetlinkSocket, error) {
		unix.Close(fd0)
		unix.Close(fd1)
		return nil, nil, err
	}

	if err := unix.Bind(fd0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fail()
	}
	if err := unix.Bind(fd1, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fail()
	}

	sa0, err := unix.Getsockname(fd0)
	if err != nil {
		return fail()
	}
	sa1, err := unix.Getsockname(fd1)
	if err != nil {
		return fail()
	}
	pid0 := sa0.(*unix.SockaddrNetlink).Pid
	pid1 := sa1.(*unix.SockaddrNetlink).Pid

	if err := unix.Connect(fd0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: pid1}); err != nil {
		return fail()
	}
	if err := unix.Connect(fd1, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: pid0}); err != nil {
		return fail()
	}

	if err := unix.SetNonblock(fd0, true); err != nil {
		return fail()
	}
	if err := unix.SetNonblock(fd1, true); err != nil {
		return fail()
	}

	s0 := &NetlinkSocket{
		fd:   int32(fd0),
		file: os.NewFile(uintptr(fd0), "netlink-test"),
		lsa:  unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: pid1},
	}
	s1 := &NetlinkSocket{
		fd:   int32(fd1),
		file: os.NewFile(uintptr(fd1), "netlink-test"),
		lsa:  unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: pid0},
	}
	return s0, s1, nil
}
