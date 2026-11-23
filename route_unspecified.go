//go:build !linux
// +build !linux

package netlink

import (
	"context"
	"errors"
	"strconv"
)

func (r *Route) ListFlags() []string {
	return []string{}
}

func (n *NexthopInfo) ListFlags() []string {
	return []string{}
}

func (s Scope) String() string {
	return "unknown"
}

func (p RouteProtocol) String() string {
	return strconv.Itoa(int(p))
}

// RouteReplaceBatch is only supported on Linux.
func RouteReplaceBatch(_ context.Context, _ []*Route) error {
	return errors.New("route batch operations are not supported on this platform")
}

// RouteReplaceBatch is only supported on Linux.
func (h *Handle) RouteReplaceBatch(_ context.Context, _ []*Route) error {
	return errors.New("route batch operations are not supported on this platform")
}

// RouteBatch is only supported on Linux.
func RouteBatch(_ context.Context, _ []RouteBatchItem) error {
	return errors.New("route batch operations are not supported on this platform")
}

// RouteBatch is only supported on Linux.
func (h *Handle) RouteBatch(_ context.Context, _ []RouteBatchItem) error {
	return errors.New("route batch operations are not supported on this platform")
}
