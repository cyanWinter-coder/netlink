//go:build !linux
// +build !linux

package netlink

import (
	"context"
)

// LinkXdpReplaceOptions is the non-Linux stub of the Linux type.
type LinkXdpReplaceOptions struct {
	Fd         int
	Flags      uint32
	ExpectedFd int
}

// LinkReplaceXdpFd is not implemented on non-Linux platforms.
func LinkReplaceXdpFd(_ context.Context, _ Link, _ LinkXdpReplaceOptions) error {
	return ErrNotImplemented
}

// LinkReplaceXdpFd is not implemented on non-Linux platforms.
func (h *Handle) LinkReplaceXdpFd(_ context.Context, _ Link, _ LinkXdpReplaceOptions) error {
	return ErrNotImplemented
}
