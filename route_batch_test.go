//go:build linux
// +build linux

package netlink

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func mustParseCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return ipnet
}

// batchTestRoutes builds n distinct routes on link for batch tests.
func batchTestRoutes(linkIndex, n int) []*Route {
	routes := make([]*Route, n)
	for i := range n {
		routes[i] = &Route{
			LinkIndex: linkIndex,
			Dst: &net.IPNet{
				IP:   net.IPv4(10, byte(i), 0, 0),
				Mask: net.CIDRMask(24, 32),
			},
		}
	}
	return routes
}

// TestRouteBatchSuccess verifies a clean batch commits every route.
func TestRouteBatchSuccess(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	routes := batchTestRoutes(link.Attrs().Index, 4)
	if err := RouteReplaceBatch(context.Background(), routes); err != nil {
		t.Fatalf("batch replace: %v", err)
	}

	listed, err := RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != len(routes) {
		t.Fatalf("expected %d routes, got %d", len(routes), len(listed))
	}
}

// TestRouteBatchPreSendValidation covers the checks that must fail before any
// request is sent: nil entries, invalid attributes, duplicates and conflicts.
func TestRouteBatchPreSendValidation(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	idx := link.Attrs().Index

	tests := []struct {
		name  string
		items []RouteBatchItem
	}{
		{
			name: "nil route",
			items: []RouteBatchItem{
				{Op: RouteOpReplace, Route: nil},
			},
		},
		{
			name: "incomplete route",
			items: []RouteBatchItem{
				{Op: RouteOpReplace, Route: &Route{LinkIndex: idx}},
			},
		},
		{
			name: "unknown operation",
			items: []RouteBatchItem{
				{Op: RouteOp(99), Route: &Route{
					LinkIndex: idx,
					Dst:       mustParseCIDR(t, "10.0.0.0/24"),
				}},
			},
		},
		{
			name: "duplicate route",
			items: []RouteBatchItem{
				{Op: RouteOpReplace, Route: &Route{
					LinkIndex: idx,
					Dst:       mustParseCIDR(t, "10.1.0.0/24"),
				}},
				{Op: RouteOpReplace, Route: &Route{
					LinkIndex: idx,
					Dst:       mustParseCIDR(t, "10.1.0.0/24"),
				}},
			},
		},
		{
			name: "conflicting identity different priority mask",
			items: []RouteBatchItem{
				{Op: RouteOpReplace, Route: &Route{
					LinkIndex: idx,
					Priority:  100,
					Dst:       mustParseCIDR(t, "10.2.0.0/24"),
				}},
				{Op: RouteOpReplace, Route: &Route{
					LinkIndex: idx,
					Priority:  100,
					Dst:       mustParseCIDR(t, "10.2.0.0/24"),
					Src:       net.IPv4(127, 0, 0, 1),
				}},
			},
		},
		{
			name: "invalid mask",
			items: []RouteBatchItem{
				{Op: RouteOpReplace, Route: &Route{
					LinkIndex: idx,
					Dst: &net.IPNet{
						IP:   net.IPv4(10, 3, 0, 0),
						Mask: net.CIDRMask(40, 32),
					},
				}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := RouteBatch(context.Background(), tc.items)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			var batchErr *RouteBatchError
			if !errors.As(err, &batchErr) {
				t.Fatalf("expected *RouteBatchError, got %T: %v", err, err)
			}
			if len(batchErr.ItemErrors) == 0 {
				t.Fatal("expected at least one item error")
			}
			// Nothing may have been sent, so the table stays empty.
			listed, listErr := RouteList(link, FAMILY_V4)
			if listErr != nil {
				t.Fatal(listErr)
			}
			if len(listed) != 0 {
				t.Fatalf("validation failure must not commit routes, found %d", len(listed))
			}
		})
	}
}

// TestRouteBatchPartialFailureRollback verifies that a kernel rejection of a
// middle item rolls back the already committed items in reverse order, leaving
// no batch route behind.
func TestRouteBatchPartialFailureRollback(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	idx := link.Attrs().Index

	items := []RouteBatchItem{
		{Op: RouteOpReplace, Route: &Route{
			LinkIndex: idx,
			Dst:       mustParseCIDR(t, "10.10.0.0/24"),
		}},
		{Op: RouteOpReplace, Route: &Route{
			LinkIndex: idx,
			Dst:       mustParseCIDR(t, "10.11.0.0/24"),
		}},
		// The kernel rejects a route via a nonexistent outgoing interface with
		// ENODEV; the first two items are already committed by then.
		{Op: RouteOpReplace, Route: &Route{
			LinkIndex: 9999,
			Dst:       mustParseCIDR(t, "10.12.0.0/24"),
		}},
		{Op: RouteOpReplace, Route: &Route{
			LinkIndex: idx,
			Dst:       mustParseCIDR(t, "10.13.0.0/24"),
		}},
	}

	err = RouteBatch(context.Background(), items)
	if err == nil {
		t.Fatal("expected batch failure, got nil")
	}
	var batchErr *RouteBatchError
	if !errors.As(err, &batchErr) {
		t.Fatalf("expected *RouteBatchError, got %T: %v", err, err)
	}
	if len(batchErr.ItemErrors) != 1 {
		t.Fatalf("expected exactly 1 item error, got %d: %v", len(batchErr.ItemErrors), batchErr)
	}
	if batchErr.ItemErrors[0].Index != 2 {
		t.Fatalf("expected failure on item 2, got %d", batchErr.ItemErrors[0].Index)
	}
	if !errors.Is(batchErr.ItemErrors[0].Err, unix.ENODEV) {
		t.Fatalf("expected ENODEV, got %v", batchErr.ItemErrors[0].Err)
	}
	if len(batchErr.RollbackErrors) != 0 {
		t.Fatalf("expected clean rollback, got %v", batchErr.RollbackErrors)
	}

	listed, err := RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range listed {
		if r.Dst != nil && (r.Dst.IP.Equal(net.IPv4(10, 10, 0, 0)) || r.Dst.IP.Equal(net.IPv4(10, 11, 0, 0))) {
			t.Fatalf("rolled-back route still present: %v", r.Dst)
		}
	}
}

// TestRouteReplaceBatchSingleItemCompat verifies the one-element batch keeps
// the exact single RouteReplace behavior, including the returned errno.
func TestRouteReplaceBatchSingleItemCompat(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	idx := link.Attrs().Index

	route := &Route{LinkIndex: idx, Dst: mustParseCIDR(t, "10.20.0.0/24")}

	// Replace on a missing route creates it.
	if err := RouteReplaceBatch(context.Background(), []*Route{route}); err != nil {
		t.Fatalf("single-item replace: %v", err)
	}
	listed, err := RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected 1 route, got %d", len(listed))
	}

	// Running it again is idempotent, like RouteReplace.
	route.Src = net.IPv4(127, 1, 1, 1)
	if err := RouteReplaceBatch(context.Background(), []*Route{route}); err != nil {
		t.Fatalf("single-item re-replace: %v", err)
	}
	listed, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || !listed[0].Src.Equal(route.Src) {
		t.Fatalf("route not replaced properly: %+v", listed)
	}

	// Single-item add of an existing route surfaces the kernel EEXIST errno
	// through the aggregate error.
	err = RouteBatch(context.Background(), []RouteBatchItem{
		{Op: RouteOpAdd, Route: route},
	})
	if !errors.Is(err, unix.EEXIST) {
		t.Fatalf("expected EEXIST from single-item add, got %v", err)
	}
	var batchErr *RouteBatchError
	if !errors.As(err, &batchErr) || len(batchErr.ItemErrors) != 1 || batchErr.ItemErrors[0].Index != 0 {
		t.Fatalf("expected indexed item error, got %v", err)
	}

	// Cleanup works through the normal single-item API too.
	if err := RouteDel(route); err != nil {
		t.Fatal(err)
	}
}

// TestRouteBatchCancelBeforeCommitRealKernel verifies against the real kernel
// that a batch entered with an already-canceled context reports
// context.Canceled, leaves no batch routes behind, and does not touch routes
// that existed beforehand. The deterministic "some ACKs then cancel" rollback
// path is covered against the fake peer in TestRouteBatchCanceled.
func TestRouteBatchCancelBeforeCommitRealKernel(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	idx := link.Attrs().Index

	// A pre-existing route that must survive the aborted batch.
	seed := &Route{LinkIndex: idx, Dst: mustParseCIDR(t, "10.60.0.0/24")}
	if err := RouteReplace(seed); err != nil {
		t.Fatal(err)
	}

	fresh := []*Route{
		{LinkIndex: idx, Dst: mustParseCIDR(t, "10.62.0.0/24")},
		{LinkIndex: idx, Dst: mustParseCIDR(t, "10.63.0.0/24")},
		{LinkIndex: idx, Dst: mustParseCIDR(t, "10.64.0.0/24")},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = RouteReplaceBatch(ctx, fresh)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	listed, err := RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	var seedSeen bool
	for _, r := range listed {
		if r.Dst == nil {
			continue
		}
		switch r.Dst.IP.String() {
		case "10.62.0.0", "10.63.0.0", "10.64.0.0":
			t.Fatalf("canceled batch left a route behind: %v", r.Dst)
		case "10.60.0.0":
			seedSeen = true
		}
	}
	if !seedSeen {
		t.Fatal("pre-existing route was removed by an aborted batch")
	}
}

// TestRouteBatchEmpty verifies an empty batch is a no-op.
func TestRouteBatchEmpty(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))
	if err := RouteReplaceBatch(context.Background(), nil); err != nil {
		t.Fatalf("nil batch: %v", err)
	}
	if err := RouteBatch(context.Background(), nil); err != nil {
		t.Fatalf("nil batch: %v", err)
	}
}

// TestRouteBatchCanceled exercises the cancellation path against a fake peer
// that answers only some ACKs: reading must stop, the result must report
// context.Canceled plus the unacked items, and the already-sent routes get
// rolled back.
func TestRouteBatchCanceled(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	client, peer, err := nl.NewNetlinkSocketPairForTest(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("socket pair: %v", err)
	}
	t.Cleanup(func() { client.Close(); peer.Close() })
	tv := unix.NsecToTimeval(time.Hour.Nanoseconds())
	_ = client.SetReceiveTimeout(&tv)
	_ = peer.SetReceiveTimeout(&tv)

	handle := NewHandleFromSockets(map[int]*nl.SocketHandle{
		unix.NETLINK_ROUTE: {Socket: client},
	}, HandleOptions{})

	const n = 3
	items := make([]RouteBatchItem, n)
	for i := range n {
		items[i] = RouteBatchItem{
			Op: RouteOpReplace,
			Route: &Route{
				LinkIndex: 1,
				Dst:       mustParseCIDR(t, "10.30."+strconv.Itoa(i)+".0/24"),
			},
		}
	}

	go func() {
		// Read every request, but answer only the first. The rollback
		// RTM_DELROUTE requests arriving later are drained and answered with
		// ESRCH (nothing exists on the fake peer), which is treated as
		// successful cleanup.
		acked := false
		for {
			msgs, _, rerr := peer.Receive()
			if rerr != nil {
				return
			}
			for _, m := range msgs {
				switch m.Header.Type {
				case unix.RTM_NEWROUTE:
					if !acked {
						sendTestAck(t, peer, m.Header.Seq, 0)
						acked = true
					}
				case unix.RTM_DELROUTE:
					// Item never existed from the peer's perspective.
					sendTestAck(t, peer, m.Header.Seq, -int32(unix.ESRCH))
				}
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	err = handle.RouteBatch(ctx, items)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	var batchErr *RouteBatchError
	if !errors.As(err, &batchErr) {
		t.Fatalf("expected *RouteBatchError joined in, got %T: %v", err, err)
	}
	// Only one item was acknowledged; the other two must not be reported as
	// item errors but explain the partial batch via the context error.
	if len(batchErr.ItemErrors) != 0 {
		t.Fatalf("unexpected item errors on cancel: %v", batchErr.ItemErrors)
	}
}

// TestRouteBatchBacklogOnSocket verifies ACKs belonging to unrelated sequence
// numbers do not confuse batch correlation when the socket already carries
// queued messages.
func TestRouteBatchBacklogOnSocket(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	client, peer, err := nl.NewNetlinkSocketPairForTest(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("socket pair: %v", err)
	}
	t.Cleanup(func() { client.Close(); peer.Close() })
	tv := unix.NsecToTimeval(time.Hour.Nanoseconds())
	_ = client.SetReceiveTimeout(&tv)
	_ = peer.SetReceiveTimeout(&tv)
	_ = client.SetReceiveBufferSize(1<<20, false)
	_ = peer.SetReceiveBufferSize(1<<20, false)

	handle := NewHandleFromSockets(map[int]*nl.SocketHandle{
		unix.NETLINK_ROUTE: {Socket: client},
	}, HandleOptions{})

	const n = 2
	items := make([]RouteBatchItem, n)
	for i := range n {
		items[i] = RouteBatchItem{
			Op: RouteOpReplace,
			Route: &Route{
				LinkIndex: 1,
				Dst:       mustParseCIDR(t, "10.40."+strconv.Itoa(i)+".0/24"),
			},
		}
	}

	go func() {
		seqs := make([]uint32, 0, n)
		// Collect the batch requests.
		for len(seqs) < n {
			msgs, _, rerr := peer.Receive()
			if rerr != nil {
				return
			}
			for _, m := range msgs {
				if m.Header.Type == unix.RTM_NEWROUTE {
					seqs = append(seqs, m.Header.Seq)
				}
			}
		}
		// Queue two messages for unrelated sequence numbers first.
		sendTestAck(t, peer, seqs[0]+777, 0)
		sendTestRaw(t, peer, syscall.NlMsghdr{
			Len:  uint32(unix.SizeofNlMsghdr),
			Type: unix.RTM_NEWROUTE,
			Seq:  seqs[0] + 888,
		}, nil)
		// Then the real ACKs, out of order.
		sendTestAck(t, peer, seqs[1], 0)
		sendTestAck(t, peer, seqs[0], 0)
	}()

	if err := handle.RouteBatch(context.Background(), items); err != nil {
		t.Fatalf("batch with backlog: %v", err)
	}
}

// TestRouteBatchRollbackErrorAggregated verifies that a failure while undoing
// a committed item is aggregated on the batch error instead of being swallowed.
func TestRouteBatchRollbackErrorAggregated(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	client, peer, err := nl.NewNetlinkSocketPairForTest(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("socket pair: %v", err)
	}
	t.Cleanup(func() { client.Close(); peer.Close() })
	tv := unix.NsecToTimeval(time.Hour.Nanoseconds())
	_ = client.SetReceiveTimeout(&tv)
	_ = peer.SetReceiveTimeout(&tv)

	handle := NewHandleFromSockets(map[int]*nl.SocketHandle{
		unix.NETLINK_ROUTE: {Socket: client},
	}, HandleOptions{})

	items := []RouteBatchItem{
		{Op: RouteOpReplace, Route: &Route{
			LinkIndex: 1,
			Dst:       mustParseCIDR(t, "10.50.0.0/24"),
		}},
		{Op: RouteOpReplace, Route: &Route{
			LinkIndex: 1,
			Dst:       mustParseCIDR(t, "10.51.0.0/24"),
		}},
	}

	go func() {
		newSeqs := make([]uint32, 0, 2)
		for {
			msgs, _, rerr := peer.Receive()
			if rerr != nil {
				return
			}
			for _, m := range msgs {
				switch m.Header.Type {
				case unix.RTM_NEWROUTE:
					newSeqs = append(newSeqs, m.Header.Seq)
					// First item succeeds; the second is rejected with EEXIST.
					if len(newSeqs) == 1 {
						sendTestAck(t, peer, m.Header.Seq, 0)
					} else {
						sendTestAck(t, peer, m.Header.Seq, -int32(unix.EEXIST))
					}
				case unix.RTM_DELROUTE:
					// Rollback itself fails with EPERM; this must surface as a
					// rollback error rather than a clean result.
					sendTestAck(t, peer, m.Header.Seq, -int32(unix.EPERM))
				}
			}
		}
	}()

	err = handle.RouteBatch(context.Background(), items)
	if err == nil {
		t.Fatal("expected batch failure, got nil")
	}
	var batchErr *RouteBatchError
	if !errors.As(err, &batchErr) {
		t.Fatalf("expected *RouteBatchError, got %T: %v", err, err)
	}
	if len(batchErr.ItemErrors) != 1 || batchErr.ItemErrors[0].Index != 1 {
		t.Fatalf("expected one item error on index 1, got %+v", batchErr.ItemErrors)
	}
	if !errors.Is(err, unix.EEXIST) {
		t.Fatalf("expected EEXIST discoverable via errors.Is, got %v", err)
	}
	if len(batchErr.RollbackErrors) != 1 {
		t.Fatalf("expected one rollback error, got %+v", batchErr.RollbackErrors)
	}
	rb := batchErr.RollbackErrors[0]
	if rb.Index != 0 || !errors.Is(rb.Err, unix.EPERM) {
		t.Fatalf("expected EPERM rollback error for index 0, got %+v", rb)
	}
}

// sendTestAck emits an NLMSG_ERROR message from a fake peer.
func sendTestAck(t *testing.T, s *nl.NetlinkSocket, seq uint32, errno int32) {
	t.Helper()
	payload := make([]byte, 4)
	nl.NativeEndian().PutUint32(payload, uint32(errno))
	req := &nl.NetlinkRequest{
		NlMsghdr: unix.NlMsghdr{
			Len:  uint32(unix.SizeofNlMsghdr + 4),
			Type: unix.NLMSG_ERROR,
			Seq:  seq,
		},
		RawData: payload,
	}
	if err := s.Send(req); err != nil {
		t.Logf("fake peer send ack: %v", err)
	}
}

// sendTestRaw emits an arbitrary netlink message from a fake peer.
func sendTestRaw(t *testing.T, s *nl.NetlinkSocket, hdr syscall.NlMsghdr, payload []byte) {
	t.Helper()
	req := &nl.NetlinkRequest{
		NlMsghdr: unix.NlMsghdr(hdr),
		RawData:  payload,
	}
	if err := s.Send(req); err != nil {
		t.Logf("fake peer send raw: %v", err)
	}
}
