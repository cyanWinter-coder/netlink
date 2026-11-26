package netlink

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func testRoute(dst string, table int) Route {
	_, ipNet, err := net.ParseCIDR(dst)
	if err != nil {
		panic(err)
	}
	return Route{
		LinkIndex: 1,
		Dst:       ipNet,
		Table:     table,
		Family:    unix.AF_INET,
		Scope:     unix.RT_SCOPE_UNIVERSE,
		Type:      unix.RTN_UNICAST,
	}
}

// TestReconcileSnapshotFinalVersion proves requirement 3: when the same
// object appears in the dump and in a stashed incremental event, only its
// final consistent version is published, never both.
func TestReconcileSnapshotFinalVersion(t *testing.T) {
	r1 := testRoute("10.0.0.0/24", unix.RT_TABLE_MAIN)
	r2 := testRoute("10.0.1.0/24", unix.RT_TABLE_MAIN)
	r1Updated := r1
	r1Updated.Priority = 500

	snapshot := map[string]Route{
		routeKey(r1): r1,
		routeKey(r2): r2,
	}
	// r1 changed while the dump was in flight; r3 was added; r2 was deleted.
	r3 := testRoute("10.0.2.0/24", unix.RT_TABLE_MAIN)
	stashed := []RouteUpdate{
		{Type: unix.RTM_NEWROUTE, Route: r1Updated},
		{Type: unix.RTM_NEWROUTE, Route: r3},
		{Type: unix.RTM_DELROUTE, Route: r2},
	}

	upserts, deletes := reconcileSnapshot(snapshot, stashed)

	upsertByDst := make(map[string]Route, len(upserts))
	for _, r := range upserts {
		upsertByDst[r.Dst.String()] = r
	}
	if len(upserts) != 2 {
		t.Fatalf("expected 2 upserts (r1 final + r3), got %d: %+v", len(upserts), upserts)
	}
	if got := upsertByDst["10.0.0.0/24"]; got.Priority != 500 {
		t.Fatalf("r1 must carry the stashed final version, got priority %d", got.Priority)
	}
	if _, ok := upsertByDst["10.0.1.0/24"]; ok {
		t.Fatal("r2 was deleted during the dump and must not be upserted")
	}
	if len(deletes) != 1 || deletes[0].Dst.String() != "10.0.1.0/24" {
		t.Fatalf("expected one delete for r2, got %+v", deletes)
	}
}

// TestReconcileSnapshotDeleteThenReadd covers the flip-flop case: a delete
// followed by a re-add while the dump runs must end in an upsert, and an
// add followed by a delete must end in a tombstone.
func TestReconcileSnapshotDeleteThenReadd(t *testing.T) {
	r1 := testRoute("10.1.0.0/24", unix.RT_TABLE_MAIN)
	r2 := testRoute("10.1.1.0/24", unix.RT_TABLE_MAIN)

	snapshot := map[string]Route{
		routeKey(r1): r1,
		routeKey(r2): r2,
	}
	stashed := []RouteUpdate{
		{Type: unix.RTM_DELROUTE, Route: r1},
		{Type: unix.RTM_NEWROUTE, Route: r1}, // re-added: final state exists
		{Type: unix.RTM_NEWROUTE, Route: r2}, // no-op add
		{Type: unix.RTM_DELROUTE, Route: r2}, // then deleted: final state gone
	}

	upserts, deletes := reconcileSnapshot(snapshot, stashed)
	if len(upserts) != 1 || upserts[0].Dst.String() != "10.1.0.0/24" {
		t.Fatalf("r1 should be re-added, got upserts %+v", upserts)
	}
	if len(deletes) != 1 || deletes[0].Dst.String() != "10.1.1.0/24" {
		t.Fatalf("r2 should be tombstoned, got deletes %+v", deletes)
	}
}

// TestReconcileSnapshotStableOrder ensures replay emission is deterministic
// regardless of Go map iteration order.
func TestReconcileSnapshotStableOrder(t *testing.T) {
	snapshot := make(map[string]Route)
	const n = 25
	for i := 0; i < n; i++ {
		r := testRoute("10.2."+strconv.Itoa(i)+".0/24", unix.RT_TABLE_MAIN)
		snapshot[routeKey(r)] = r
	}
	upserts, _ := reconcileSnapshot(snapshot, nil)
	if len(upserts) != n {
		t.Fatalf("expected %d upserts, got %d", n, len(upserts))
	}
	for i := 1; i < len(upserts); i++ {
		if routeKey(upserts[i-1]) >= routeKey(upserts[i]) {
			t.Fatalf("upserts not sorted by key at index %d", i)
		}
	}
}

// TestRouteKeyIdentity verifies the reconciliation key distinguishes routes
// that differ only in kernel-identity fields, and is stable across equal
// routes with independently parsed prefixes.
func TestRouteKeyIdentity(t *testing.T) {
	base := testRoute("10.3.0.0/24", unix.RT_TABLE_MAIN)
	same := testRoute("10.3.0.0/24", unix.RT_TABLE_MAIN)
	if routeKey(base) != routeKey(same) {
		t.Fatal("equal routes must produce equal keys")
	}
	otherTable := base
	otherTable.Table = unix.RT_TABLE_LOCAL
	if routeKey(base) == routeKey(otherTable) {
		t.Fatal("different tables must produce different keys")
	}
	otherDst := testRoute("10.3.1.0/24", unix.RT_TABLE_MAIN)
	if routeKey(base) == routeKey(otherDst) {
		t.Fatal("different destinations must produce different keys")
	}
}

// TestEmitAssignsMonotonicSeq checks requirement 1 at the unit level: every
// emitted event gets a strictly increasing sequence and the LastSeq accessor
// tracks it.
func TestEmitAssignsMonotonicSeq(t *testing.T) {
	sub := newTestSubscription(t, 4)
	defer sub.Close()

	for i := 1; i <= 3; i++ {
		ok := sub.emit(RouteEvent{Kind: RouteEventChange, Generation: 1,
			Update: RouteUpdate{Type: unix.RTM_NEWROUTE}})
		if !ok {
			t.Fatalf("emit %d failed", i)
		}
		if got := sub.LastSeq(); got != uint64(i) {
			t.Fatalf("LastSeq = %d, want %d", got, i)
		}
	}
	received := drainEvents(sub.Events(), 3, time.Second)
	for i, ev := range received {
		if ev.Seq != uint64(i+1) {
			t.Fatalf("event %d Seq = %d, want %d", i, ev.Seq, i+1)
		}
	}
}

// drainOne reads a single event, failing the test on timeout.
func drainOne(t *testing.T, ch <-chan RouteEvent) RouteEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
		return RouteEvent{}
	}
}

// TestEmitOverflowEvictsAndMarks covers the primary backpressure path
// (requirement 4): once the bounded queue fills, the next emit fails without
// blocking, evicts the oldest unconsumed event, and guarantees a sequenced
// Truncated marker carrying the current generation.
func TestEmitOverflowEvictsAndMarks(t *testing.T) {
	const queueLen = 2
	sub := newTestSubscription(t, queueLen)
	defer sub.Close()

	for i := 0; i < queueLen; i++ {
		if !sub.emit(RouteEvent{Kind: RouteEventChange, Generation: 7}) {
			t.Fatalf("emit %d should fit the queue", i)
		}
	}
	// Overflow must return false immediately, never block.
	done := make(chan bool, 1)
	go func() { done <- sub.emit(RouteEvent{Kind: RouteEventChange, Generation: 7}) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("emit on a full queue must return false")
		}
	case <-time.After(time.Second):
		t.Fatal("emit blocked on a full queue; backpressure is not bounded")
	}

	// The oldest change was evicted; one surviving change then the marker.
	first := drainOne(t, sub.Events())
	if first.Kind != RouteEventChange || first.Seq == 0 {
		t.Fatalf("expected a sequenced surviving change, got %+v", first)
	}
	marker := drainOne(t, sub.Events())
	if marker.Kind != RouteEventTruncated || marker.Generation != 7 || marker.Seq == 0 {
		t.Fatalf("expected a sequenced gen-7 Truncated marker, got %+v", marker)
	}
	if marker.Seq <= first.Seq {
		t.Fatal("Truncated marker must advance the sequence")
	}
}

// TestEmitOverflowNeverBlocks hammers emit from multiple goroutines while
// nobody drains, proving the monitor can never stall on a slow consumer.
func TestEmitOverflowNeverBlocks(t *testing.T) {
	sub := newTestSubscription(t, 1)
	defer sub.Close()

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				sub.emit(RouteEvent{Kind: RouteEventChange, Generation: 1})
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("emit blocked under concurrent overflow")
	}
}

// TestEmitOverflowMarkerAlwaysDelivered fills the queue and overflows
// repeatedly without draining; every overflow must still leave a Truncated
// marker behind, so a stalled consumer is signaled deterministically.
func TestEmitOverflowMarkerAlwaysDelivered(t *testing.T) {
	const queueLen = 2
	sub := newTestSubscription(t, queueLen)
	defer sub.Close()

	for i := 0; i < queueLen; i++ {
		sub.emit(RouteEvent{Kind: RouteEventChange, Generation: 7})
	}
	for i := 0; i < 5; i++ {
		if sub.emit(RouteEvent{Kind: RouteEventChange, Generation: 7}) {
			t.Fatal("overflow emit must fail")
		}
	}
	// Drain everything; at least one marker must be present.
	sawMarker := false
	for {
		select {
		case ev := <-sub.Events():
			if ev.Kind == RouteEventTruncated {
				sawMarker = true
			}
			if ev.Seq == 0 {
				t.Fatal("every event must carry a sequence")
			}
		case <-time.After(100 * time.Millisecond):
			if !sawMarker {
				t.Fatal("no Truncated marker delivered despite repeated overflow")
			}
			return
		}
	}
}

// TestCloseWakesWaiters covers requirement 5 at the primitive level:
// Close unblocks a backoff sleep immediately rather than waiting out its
// full duration. Full channel-close semantics are covered by
// TestSubscriptionCloseUnblocksReceive in the fake-socket test file.
func TestCloseWakesWaiters(t *testing.T) {
	sub := newTestSubscription(t, DefaultQueueLength)

	sleepReturned := make(chan bool, 1)
	go func() {
		sleepReturned <- sub.sleep(time.Minute)
	}()

	if err := sub.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case ok := <-sleepReturned:
		if ok {
			t.Fatal("sleep should return false when woken by Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake the backoff waiter")
	}
	// Close is idempotent.
	if err := sub.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestEmitAfterCloseFails ensures no event can be published once shutdown
// has started, so waiters never receive half-written state.
func TestEmitAfterCloseFails(t *testing.T) {
	sub := newTestSubscription(t, 4)
	if err := sub.Close(); err != nil {
		t.Fatal(err)
	}
	if sub.emit(RouteEvent{Kind: RouteEventChange}) {
		t.Fatal("emit after Close must fail")
	}
	if err := sub.emitOrErr(RouteEvent{Kind: RouteEventChange}); !errors.Is(err, ErrSubscriptionClosed) {
		t.Fatalf("emitOrErr after Close = %v, want ErrSubscriptionClosed", err)
	}
}

// newTestSubscription builds a subscription without starting its run loop
// (the loop needs a real socket); unit tests drive emit/sleep directly.
func newTestSubscription(t *testing.T, queueLen int) *ResumableRouteSubscription {
	t.Helper()
	none := netns.None()
	sub := &ResumableRouteSubscription{
		opts:   ResumableRouteOptions{Namespace: &none, QueueLength: queueLen},
		events: make(chan RouteEvent, queueLen),
		errs:   make(chan error, 1),
		done:   make(chan struct{}),
		wake:   make(chan struct{}),
	}
	return sub
}

func drainEvents(ch <-chan RouteEvent, want int, timeout time.Duration) []RouteEvent {
	out := make([]RouteEvent, 0, want)
	deadline := time.After(timeout)
	for len(out) < want {
		select {
		case ev := <-ch:
			out = append(out, ev)
		case <-deadline:
			return out
		}
	}
	return out
}
