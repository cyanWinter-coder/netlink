package netlink

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// fakeConn is a scripted routeConn. Each Receive call returns the next
// queued batch; when the script is exhausted it blocks on a condvar until
// Close (waking with an error) or more batches are enqueued.
type fakeBatch struct {
	msgs   []syscall.NetlinkMessage
	portid uint32 // 0 means the kernel
}

type fakeConn struct {
	mu      sync.Mutex
	cond    *sync.Cond
	batches []fakeBatch
	closed  bool
	sendCnt int
}

func newFakeConn() *fakeConn {
	c := &fakeConn{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *fakeConn) enqueue(batch ...syscall.NetlinkMessage) {
	c.mu.Lock()
	c.batches = append(c.batches, fakeBatch{msgs: batch})
	c.cond.Broadcast()
	c.mu.Unlock()
}

// enqueueFrom schedules a batch whose Receive reports the given sender
// portid instead of the kernel, to exercise the sender check.
func (c *fakeConn) enqueueFrom(portid uint32, batch ...syscall.NetlinkMessage) {
	c.mu.Lock()
	c.batches = append(c.batches, fakeBatch{msgs: batch, portid: portid})
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *fakeConn) Receive() ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error) {
	c.mu.Lock()
	for len(c.batches) == 0 && !c.closed {
		c.cond.Wait()
	}
	if c.closed {
		c.mu.Unlock()
		return nil, nil, errors.New("fake conn closed")
	}
	batch := c.batches[0]
	c.batches = c.batches[1:]
	portid := batch.portid
	if portid == 0 {
		portid = nl.PidKernel
	}
	c.mu.Unlock()
	return batch.msgs, &unix.SockaddrNetlink{Pid: portid}, nil
}

func (c *fakeConn) Send(*nl.NetlinkRequest) error {
	c.mu.Lock()
	c.sendCnt++
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) SetReceiveTimeout(*unix.Timeval) error { return nil }
func (c *fakeConn) SetReceiveBufferSize(int, bool) error  { return nil }
func (c *fakeConn) sends() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendCnt
}

// fakeRouter dials successive fake connections, letting a test script a
// disconnect followed by a reconnect with its own snapshot.
type fakeRouter struct {
	mu        sync.Mutex
	conns     []*fakeConn
	failCalls map[int]bool // 0-based dial calls that must fail
	calls     int
}

func (r *fakeRouter) dial() (routeConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	call := r.calls
	r.calls++
	if r.failCalls[call] {
		return nil, errors.New("scripted dial failure")
	}
	// Failures do not consume a scripted connection: index conns by the
	// number of successful dials.
	success := call
	for i := 0; i < call; i++ {
		if r.failCalls[i] {
			success--
		}
	}
	if success >= len(r.conns) {
		return nil, fmt.Errorf("fakeRouter: no more scripted connections (call %d)", call)
	}
	return r.conns[success], nil
}

// newInjectedSubscription builds a subscription driven by scripted fake
// connections instead of kernel sockets, with a short reconnect backoff.
func newInjectedSubscription(t *testing.T, router *fakeRouter, queueLen int) *ResumableRouteSubscription {
	t.Helper()
	none := netns.None()
	sub := &ResumableRouteSubscription{
		opts:   ResumableRouteOptions{Namespace: &none, QueueLength: queueLen},
		events: make(chan RouteEvent, queueLen),
		errs:   make(chan error, 1),
		done:   make(chan struct{}),
		wake:   make(chan struct{}),
	}
	sub.dial = router.dial
	sub.wg.Add(1)
	go sub.run()
	return sub
}

func dumpDoneMsg() syscall.NetlinkMessage {
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}}
}

// serializeRouteForTest renders r through the same attribute pipeline the
// library uses for RTM_NEWROUTE, so deserializeRoute inside the monitor
// parses exactly what the kernel would send. It deliberately stops short of
// routeHandle's socket Execute so the test needs no privileges.
func serializeRouteForTest(t *testing.T, r Route, typ uint16, flags uint16) syscall.NetlinkMessage {
	t.Helper()
	req := pkgHandle().newNetlinkRequest(int(typ), int(flags|unix.NLM_F_REQUEST))
	// prepareRouteReq registers the RtMsg header and all RTA attributes on
	// the request itself; it must not be added a second time.
	if err := pkgHandle().prepareRouteReq(&r, req, nl.NewRtMsg()); err != nil {
		t.Fatalf("prepareRouteReq: %v", err)
	}
	raw := req.Serialize()
	msgs, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		t.Fatalf("ParseNetlinkMessage: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected one netlink message, got %d", len(msgs))
	}
	return msgs[0]
}

func dumpRouteMsg(t *testing.T, r Route) syscall.NetlinkMessage {
	t.Helper()
	return serializeRouteForTest(t, r, unix.RTM_NEWROUTE, unix.NLM_F_DUMP)
}

func eventRouteMsg(t *testing.T, typ uint16, r Route) syscall.NetlinkMessage {
	t.Helper()
	return serializeRouteForTest(t, r, typ, 0)
}

// waitForEvent returns the next event matching one of the given kinds,
// failing the test on timeout.
func waitForEvent(t *testing.T, ch <-chan RouteEvent, timeout time.Duration, kinds ...int) RouteEvent {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-ch:
			for _, k := range kinds {
				if ev.Kind == k {
					return ev
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for event kinds %v", kinds)
		}
	}
}

// collectSync reads events up to and including the next SyncEnd and returns
// all change events seen between the markers.
func collectSync(t *testing.T, ch <-chan RouteEvent) []RouteEvent {
	t.Helper()
	start := waitForEvent(t, ch, 2*time.Second, RouteEventSyncStart)
	if start.Seq == 0 {
		t.Fatal("SyncStart must carry a sequence number")
	}
	var changes []RouteEvent
	for {
		ev := waitForEvent(t, ch, 2*time.Second,
			RouteEventChange, RouteEventSyncEnd, RouteEventTruncated)
		if ev.Kind == RouteEventSyncEnd {
			return changes
		}
		if ev.Kind == RouteEventTruncated {
			t.Fatal("unexpected truncation during snapshot replay")
		}
		changes = append(changes, ev)
	}
}

// TestSubscriptionInitialReplay drives one connection through its initial
// dump and checks the snapshot is framed by SyncStart/SyncEnd with
// generation and sequence metadata on every event.
func TestSubscriptionInitialReplay(t *testing.T) {
	conn := newFakeConn()
	router := &fakeRouter{conns: []*fakeConn{conn}}
	sub := newInjectedSubscription(t, router, 16)
	defer sub.Close()

	r1 := testRoute("10.0.0.0/24", unix.RT_TABLE_MAIN)
	r2 := testRoute("10.0.1.0/24", unix.RT_TABLE_MAIN)
	// Dump batch, then leave the connection idle in incremental mode.
	conn.enqueue(dumpRouteMsg(t, r1), dumpRouteMsg(t, r2), dumpDoneMsg())

	changes := collectSync(t, sub.Events())
	if len(changes) != 2 {
		t.Fatalf("expected 2 snapshot routes, got %d", len(changes))
	}
	prevSeq := uint64(0)
	for _, ev := range changes {
		if ev.Generation != 1 {
			t.Fatalf("snapshot generation = %d, want 1", ev.Generation)
		}
		if ev.Seq <= prevSeq || ev.Update.Type != unix.RTM_NEWROUTE {
			t.Fatalf("bad snapshot event %+v", ev)
		}
		prevSeq = ev.Seq
	}
	if got := sub.Generation(); got != 1 {
		t.Fatalf("Generation accessor = %d, want 1", got)
	}
	if conn.sends() != 1 {
		t.Fatalf("expected exactly one RTM_GETROUTE dump, got %d", conn.sends())
	}
}

// TestSubscriptionReconnectResync scripts a connection death followed by a
// fresh connection: the monitor must bump the generation, re-dump, and
// reconcile an event racing the second dump without duplicating the object.
func TestSubscriptionReconnectResync(t *testing.T) {
	first := newFakeConn()
	second := newFakeConn()
	router := &fakeRouter{conns: []*fakeConn{first, second}}
	sub := newInjectedSubscription(t, router, 32)
	defer sub.Close()

	r1 := testRoute("10.1.0.0/24", unix.RT_TABLE_MAIN)
	r2 := testRoute("10.1.1.0/24", unix.RT_TABLE_MAIN)
	first.enqueue(dumpRouteMsg(t, r1), dumpDoneMsg())
	if changes := collectSync(t, sub.Events()); len(changes) != 1 {
		t.Fatalf("first snapshot should contain r1 only, got %d", len(changes))
	}

	// r1 changes on the live stream, then the socket breaks.
	r1Changed := r1
	r1Changed.Priority = 999
	first.enqueue(eventRouteMsg(t, unix.RTM_NEWROUTE, r1Changed))
	ev := waitForEvent(t, sub.Events(), time.Second, RouteEventChange)
	if ev.Generation != 1 || ev.Update.Route.Priority != 999 {
		t.Fatalf("incremental event mismatch: %+v", ev)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// Reconnect: the second dump races an update to r1 (final version wins,
	// published once) and a delete of r2 that the snapshot never knew.
	r1Final := r1
	r1Final.Priority = 2000
	r2Final := r2
	second.enqueue(
		dumpRouteMsg(t, r1),
		eventRouteMsg(t, unix.RTM_NEWROUTE, r1Final),
		eventRouteMsg(t, unix.RTM_DELROUTE, r2Final),
		dumpDoneMsg(),
	)

	changes := collectSync(t, sub.Events())
	if got := sub.Generation(); got != 2 {
		t.Fatalf("after reconnect generation = %d, want 2", got)
	}
	byDst := map[string]RouteEvent{}
	for _, c := range changes {
		byDst[c.Update.Route.Dst.String()] = c
	}
	r1Event, ok := byDst["10.1.0.0/24"]
	if !ok || r1Event.Update.Route.Priority != 2000 {
		t.Fatalf("r1 must appear once with final priority, got %+v", byDst)
	}
	if r1Event.Generation != 2 {
		t.Fatalf("replayed event generation = %d, want 2", r1Event.Generation)
	}
	del, ok := byDst["10.1.1.0/24"]
	if !ok || del.Update.Type != unix.RTM_DELROUTE {
		t.Fatalf("r2 delete must be replayed, got %+v", byDst)
	}

	// After SyncEnd the second generation relays pure incremental events.
	r3 := testRoute("10.1.2.0/24", unix.RT_TABLE_MAIN)
	second.enqueue(eventRouteMsg(t, unix.RTM_NEWROUTE, r3))
	live := waitForEvent(t, sub.Events(), time.Second, RouteEventChange)
	if live.Generation != 2 || live.Update.Route.Dst.String() != "10.1.2.0/24" {
		t.Fatalf("post-sync incremental event mismatch: %+v", live)
	}
}

// TestSubscriptionBackpressureTruncatesAndResyncs fills the consumer queue:
// overflow must surface a Truncated marker and automatically start a new
// generation whose snapshot re-converges the state.
func TestSubscriptionBackpressureTruncatesAndResyncs(t *testing.T) {
	first := newFakeConn()
	second := newFakeConn()
	router := &fakeRouter{conns: []*fakeConn{first, second}}
	const queueLen = 2
	sub := newInjectedSubscription(t, router, queueLen)
	defer sub.Close()

	keep := testRoute("10.2.0.0/24", unix.RT_TABLE_MAIN)
	first.enqueue(dumpRouteMsg(t, keep), dumpDoneMsg())
	collectSync(t, sub.Events())

	// Flood more events than the queue holds. The monitor must reject rather
	// than block, emit Truncated, and reconnect.
	for i := 0; i < queueLen+3; i++ {
		r := testRoute("10.2."+strconv.Itoa(10+i)+".0/24", unix.RT_TABLE_MAIN)
		first.enqueue(eventRouteMsg(t, unix.RTM_NEWROUTE, r))
	}
	// The reconnecting generation dumps the surviving state.
	second.enqueue(dumpRouteMsg(t, keep), dumpDoneMsg())

	// A dedicated drainer keeps the queue from staying saturated, which would
	// otherwise make the resync itself hit backpressure and cascade. The
	// test inspects the recorded stream once the post-truncation snapshot
	// completes.
	records := make(chan RouteEvent, 64)
	go func() {
		for ev := range sub.Events() {
			records <- ev
		}
		close(records)
	}()

	deadline := time.After(5 * time.Second)
	var (
		sawTruncated bool
		sawResync    bool
		resyncGen    uint64
		changes      []RouteEvent
	)
	for {
		select {
		case ev := <-records:
			switch ev.Kind {
			case RouteEventTruncated:
				sawTruncated = true
			case RouteEventSyncStart:
				if ev.Generation >= 2 {
					sawResync = true
					resyncGen = ev.Generation
				}
			case RouteEventChange:
				if sawResync && ev.Generation == resyncGen {
					changes = append(changes, ev)
				}
			case RouteEventSyncEnd:
				if sawResync && ev.Generation == resyncGen {
					goto resyncDone
				}
			}
		case <-deadline:
			t.Fatal("timed out waiting for post-truncation resync")
		}
	}
resyncDone:
	if !sawTruncated {
		t.Fatal("overflow did not surface a Truncated marker")
	}
	if sub.Generation() < 2 {
		t.Fatalf("expected resync generation >= 2, got %d", sub.Generation())
	}
	if len(changes) != 1 || changes[0].Update.Route.Dst.String() != "10.2.0.0/24" {
		t.Fatalf("resync snapshot must converge back to keep, got %+v", changes)
	}
}

// TestSubscriptionDialFailureRetries verifies the monitor keeps reconnecting
// through transient dial errors instead of terminating.
func TestSubscriptionDialFailureRetries(t *testing.T) {
	conn := newFakeConn()
	router := &fakeRouter{conns: []*fakeConn{conn}, failCalls: map[int]bool{0: true}}
	sub := newInjectedSubscription(t, router, 8)
	defer sub.Close()

	r := testRoute("10.3.0.0/24", unix.RT_TABLE_MAIN)
	conn.enqueue(dumpRouteMsg(t, r), dumpDoneMsg())

	changes := collectSync(t, sub.Events())
	if len(changes) != 1 || changes[0].Update.Route.Dst.String() != "10.3.0.0/24" {
		t.Fatalf("snapshot after dial retry mismatch: %+v", changes)
	}
	if router.calls < 2 {
		t.Fatalf("expected a failed then successful dial, calls=%d", router.calls)
	}
}

// TestSubscriptionCloseUnblocksReceive closes an idle subscription and
// asserts the run loop exits, both output channels close and no goroutine
// stays blocked on the fake connection.
func TestSubscriptionCloseUnblocksReceive(t *testing.T) {
	conn := newFakeConn()
	router := &fakeRouter{conns: []*fakeConn{conn}}
	sub := newInjectedSubscription(t, router, 8)

	conn.enqueue(dumpDoneMsg()) // empty initial snapshot
	waitForEvent(t, sub.Events(), time.Second, RouteEventSyncStart)
	waitForEvent(t, sub.Events(), time.Second, RouteEventSyncEnd)

	if err := sub.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := <-sub.Events(); ok {
		t.Fatal("Events must be closed after Close")
	}
	select {
	case err := <-sub.Errors():
		if !errors.Is(err, ErrSubscriptionClosed) {
			t.Fatalf("Errors = %v, want ErrSubscriptionClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal error not delivered")
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if !conn.closed {
		t.Fatal("underlying connection was not closed on shutdown")
	}
}

// TestSubscriptionImmediateClose races Close against the very first dial and
// snapshot. It must never panic on a double socket Close and must release
// every goroutine.
func TestSubscriptionImmediateClose(t *testing.T) {
	for i := 0; i < 25; i++ {
		conn := newFakeConn()
		router := &fakeRouter{conns: []*fakeConn{conn}}
		sub := newInjectedSubscription(t, router, 8)
		// Close without scripting any snapshot; the run loop may be dialing,
		// dumping or already idle in relay.
		if err := sub.Close(); err != nil {
			t.Fatalf("iteration %d Close: %v", i, err)
		}
		select {
		case <-sub.Done():
		case <-time.After(time.Second):
			t.Fatalf("iteration %d: Done not closed after Close", i)
		}
	}
}

// TestSubscriptionDumpInterruptedRetries scripts a first dump carrying
// NLM_F_DUMP_INTR (table mutated mid-snapshot) followed by a clean retry, and
// asserts only the consistent second snapshot is published.
func TestSubscriptionDumpInterruptedRetries(t *testing.T) {
	conn := newFakeConn()
	router := &fakeRouter{conns: []*fakeConn{conn}}
	sub := newInjectedSubscription(t, router, 16)
	defer sub.Close()

	bad := testRoute("10.4.0.0/24", unix.RT_TABLE_MAIN)
	good := testRoute("10.4.1.0/24", unix.RT_TABLE_MAIN)

	intrMsg := dumpDoneMsg()
	intrMsg.Header.Flags = unix.NLM_F_DUMP_INTR

	// First dump attempt is interrupted and must be discarded.
	conn.enqueue(dumpRouteMsg(t, bad), intrMsg)
	// Second attempt completes consistently.
	conn.enqueue(dumpRouteMsg(t, good), dumpDoneMsg())

	waitForEvent(t, sub.Events(), 2*time.Second, RouteEventSyncStart)
	var dsts []string
	for {
		ev := waitForEvent(t, sub.Events(), 2*time.Second,
			RouteEventChange, RouteEventSyncEnd)
		if ev.Kind == RouteEventSyncEnd {
			break
		}
		dsts = append(dsts, ev.Update.Route.Dst.String())
	}
	if len(dsts) != 1 || dsts[0] != "10.4.1.0/24" {
		t.Fatalf("interrupted dump must be discarded, got %v", dsts)
	}
	// Two dump requests prove the monitor retried rather than publishing
	// inconsistent state.
	if got := conn.sends(); got != 2 {
		t.Fatalf("expected 2 RTM_GETROUTE dumps after interruption, got %d", got)
	}
}

// TestSubscriptionNonKernelSenderIgnored ensures messages from a sender other
// than the kernel are dropped without poisoning the snapshot.
func TestSubscriptionNonKernelSenderIgnored(t *testing.T) {
	conn := newFakeConn()
	router := &fakeRouter{conns: []*fakeConn{conn}}
	sub := newInjectedSubscription(t, router, 16)
	defer sub.Close()

	r := testRoute("10.5.0.0/24", unix.RT_TABLE_MAIN)
	conn.enqueue(dumpRouteMsg(t, r), dumpDoneMsg())
	// Inject a foreign-sender batch while in incremental relay mode.
	conn.enqueueFrom(4242, eventRouteMsg(t, unix.RTM_NEWROUTE,
		testRoute("10.5.9.0/24", unix.RT_TABLE_MAIN)))
	// A legitimate event must still flow after the foreign one.
	conn.enqueue(eventRouteMsg(t, unix.RTM_NEWROUTE,
		testRoute("10.5.1.0/24", unix.RT_TABLE_MAIN)))

	collectSync(t, sub.Events())
	ev := waitForEvent(t, sub.Events(), time.Second, RouteEventChange)
	if ev.Update.Route.Dst.String() != "10.5.1.0/24" {
		t.Fatalf("foreign sender event leaked, got %s", ev.Update.Route.Dst)
	}
}
