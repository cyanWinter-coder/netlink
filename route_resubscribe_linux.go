package netlink

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Event kinds delivered by [ResumableRouteSubscription].
const (
	// RouteEventChange carries an RTM_NEWROUTE or RTM_DELROUTE notification.
	RouteEventChange = iota
	// RouteEventSyncStart marks the beginning of a resync: either the initial
	// snapshot or the replay following a reconnect. Events delivered between
	// SyncStart and [RouteEventSyncEnd] converge the consumer's view onto the
	// kernel's current state.
	RouteEventSyncStart
	// RouteEventSyncEnd marks the end of a consistent snapshot.
	RouteEventSyncEnd
	// RouteEventTruncated signals that the subscription's internal queue
	// overflowed because the consumer was too slow. The subscription has
	// automatically started a full resync; events that were still queued for
	// the affected connection generation must be considered lost.
	RouteEventTruncated
)

// ErrSubscriptionClosed is returned by [ResumableRouteSubscription.Close]
// helpers and delivered through the error channel after the subscription has
// been shut down deliberately.
var ErrSubscriptionClosed = errors.New("route subscription closed")

// DefaultQueueLength is the default per-subscription event queue capacity.
const DefaultQueueLength = 128

// resubscribeBackoff is the delay between reconnect attempts while the
// kernel keeps refusing a new socket.
const resubscribeBackoff = 100 * time.Millisecond

// RouteEvent is a single notification emitted by a
// [ResumableRouteSubscription].
type RouteEvent struct {
	// Kind is one of the RouteEvent* constants.
	Kind int
	// Generation is the connection generation the event belongs to. It is
	// incremented every time the monitor reconnects to the kernel. Sync
	// markers always use the generation whose snapshot they describe.
	Generation uint64
	// Seq is the per-subscription monotonically increasing event sequence
	// number. The consumer can persist LastSeq together with its applied
	// state to prove exactly-once application across its own restarts.
	Seq uint64
	// Update is populated for Kind == RouteEventChange.
	Update RouteUpdate
}

// ResumableRouteOptions configures [NewResumableRouteSubscription].
type ResumableRouteOptions struct {
	// Namespace selects the network namespace to monitor. A nil value or an
	// unset NsHandle monitors the namespace the goroutine runs in.
	Namespace *netns.NsHandle
	// QueueLength is the maximum number of events buffered for the consumer.
	// When the queue is full, a [RouteEventTruncated] event is emitted and a
	// full resync is triggered. Zero selects [DefaultQueueLength].
	QueueLength int
	// ErrorCallback, when non-nil, receives non-fatal errors such as a
	// reconnect failure that will be retried, or an [ErrDumpInterrupted]
	// snapshot which is retried automatically.
	ErrorCallback func(error)
	// ReceiveBufferSize / ReceiveBufferForceSize / ReceiveTimeout are passed
	// through to each underlying netlink socket, mirroring
	// [RouteSubscribeOptions].
	ReceiveBufferSize      int
	ReceiveBufferForceSize bool
	ReceiveTimeout         *unix.Timeval
}

// ResumableRouteSubscription is a reconnecting route monitor.
//
// It guarantees:
//
//   - Every emitted event carries a connection Generation and a monotonic
//     per-subscription Seq ([ResumableRouteSubscription.LastSeq]).
//   - After a socket loss it reconnects, performs a consistent RTM_GETROUTE
//     dump while stashing live events, reconciles both sources, and only
//     then switches back to the pure incremental stream.
//   - An object touched by both the snapshot and the incremental stream is
//     published exactly once, in its final consistent version.
//   - A slow consumer never blocks the kernel socket: on queue overflow it
//     receives [RouteEventTruncated] followed by a fresh snapshot resync.
//   - Close unblocks every waiter and releases every underlying socket.
type ResumableRouteSubscription struct {
	opts ResumableRouteOptions

	events chan RouteEvent
	errs   chan error

	generation atomic.Uint64
	lastSeq    atomic.Uint64

	closeOnce sync.Once
	done      chan struct{}

	// wake is closed by Close so a reconnect backoff can return early.
	wakeMu sync.Mutex
	wake   chan struct{}

	wg sync.WaitGroup

	// dial opens one monitor connection. It is a field so tests can inject
	// fake connections; production code dials a real netlink socket.
	dial func() (routeConn, error)
}

// routeConn is the subset of [nl.NetlinkSocket] used by the monitor.
type routeConn interface {
	Receive() ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error)
	Send(*nl.NetlinkRequest) error
	Close() error
	SetReceiveTimeout(*unix.Timeval) error
	SetReceiveBufferSize(int, bool) error
}

// dialNetlink opens a multicast netlink socket in the configured namespace.
func (s *ResumableRouteSubscription) dialNetlink() (routeConn, error) {
	return nl.SubscribeAt(*s.opts.Namespace, netns.None(),
		unix.NETLINK_ROUTE, unix.RTNLGRP_IPV4_ROUTE, unix.RTNLGRP_IPV6_ROUTE)
}

// NewResumableRouteSubscription starts a resumable route monitor. The
// returned subscription owns its goroutines and sockets; callers must invoke
// [ResumableRouteSubscription.Close] to release them.
func NewResumableRouteSubscription(opts ResumableRouteOptions) (*ResumableRouteSubscription, error) {
	queueLen := opts.QueueLength
	if queueLen <= 0 {
		queueLen = DefaultQueueLength
	}
	if opts.Namespace == nil {
		none := netns.None()
		opts.Namespace = &none
	}
	sub := &ResumableRouteSubscription{
		opts:   opts,
		events: make(chan RouteEvent, queueLen),
		errs:   make(chan error, 1),
		done:   make(chan struct{}),
		wake:   make(chan struct{}),
	}
	sub.dial = sub.dialNetlink
	sub.wg.Add(1)
	go sub.run()
	return sub, nil
}

// Events returns the channel carrying route events and resync markers.
// The channel is closed when the subscription shuts down.
func (s *ResumableRouteSubscription) Events() <-chan RouteEvent { return s.events }

// Errors returns a channel that yields at most one terminal error. A clean
// [ResumableRouteSubscription.Close] yields [ErrSubscriptionClosed].
func (s *ResumableRouteSubscription) Errors() <-chan error { return s.errs }

// Generation returns the current connection generation. It starts at one and
// is incremented on every reconnect.
func (s *ResumableRouteSubscription) Generation() uint64 { return s.generation.Load() }

// LastSeq returns the sequence number of the most recently emitted event.
// Zero means no event has been emitted yet.
func (s *ResumableRouteSubscription) LastSeq() uint64 { return s.lastSeq.Load() }

// Close stops the monitor, closes all sockets and unblocks the monitor
// goroutine. It is safe to call multiple times and from any goroutine.
func (s *ResumableRouteSubscription) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.wakeMu.Lock()
		close(s.wake)
		s.wakeMu.Unlock()
	})
	s.wg.Wait()
	return nil
}

// Done returns a channel closed when the monitor has fully stopped.
func (s *ResumableRouteSubscription) Done() <-chan struct{} { return s.done }

// run owns the reconnect/resync state machine.
func (s *ResumableRouteSubscription) run() {
	defer s.wg.Done()
	defer close(s.events)
	defer close(s.errs)

	var terminal error
	for {
		if s.isDone() {
			terminal = ErrSubscriptionClosed
			break
		}
		gen := s.generation.Add(1)
		err := s.serveGeneration(gen)
		if s.isDone() {
			terminal = ErrSubscriptionClosed
			break
		}
		if err != nil {
			s.reportError(fmt.Errorf("route monitor generation %d failed: %w", gen, err))
		}
		if !s.sleep(resubscribeBackoff) {
			terminal = ErrSubscriptionClosed
			break
		}
	}
	// errs has room for exactly this terminal send; use a non-blocking send
	// defensively so the run goroutine can never get stuck here and deadlock
	// a waiting Close.
	select {
	case s.errs <- terminal:
	default:
	}
}

// serveGeneration opens one socket, performs the snapshot reconcile and then
// relays the incremental stream until the socket dies or the queue
// overflows.
func (s *ResumableRouteSubscription) serveGeneration(gen uint64) error {
	sock, err := s.dial()
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	defer sock.Close()

	if s.opts.ReceiveTimeout != nil {
		if err := sock.SetReceiveTimeout(s.opts.ReceiveTimeout); err != nil {
			return fmt.Errorf("set receive timeout: %w", err)
		}
	}
	if s.opts.ReceiveBufferSize != 0 {
		if err := sock.SetReceiveBufferSize(s.opts.ReceiveBufferSize, s.opts.ReceiveBufferForceSize); err != nil {
			return fmt.Errorf("set receive buffer: %w", err)
		}
	}

	// Closing the socket from the done watcher makes a blocked Receive fail
	// immediately, so Close never waits on kernel traffic. The watcher and
	// the deferred Close both call Close, so guard it with once: the concrete
	// netlink socket and the test fakes alike tolerate a single Close.
	var sockOnce sync.Once
	closeSock := func() { sockOnce.Do(func() { _ = sock.Close() }) }
	stopWatcher := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-s.done:
			closeSock()
		case <-stopWatcher:
		}
		close(watchDone)
	}()
	defer func() {
		close(stopWatcher)
		<-watchDone
		closeSock()
	}()

	if err := s.resync(gen, sock); err != nil {
		return err
	}
	return s.relayIncremental(gen, sock)
}

// resync drives the dump-then-reconcile protocol:
//
//  1. multicast events arriving while the dump is in flight are stashed;
//  2. the dump produces a keyed snapshot;
//  3. stashed events are folded into the snapshot so each object keeps its
//     final version;
//  4. the reconciled view is published between SyncStart/SyncEnd markers.
func (s *ResumableRouteSubscription) resync(gen uint64, sock routeConn) error {
	var (
		snapshot        map[string]Route
		stashed         []RouteUpdate
		dumpInterrupted bool
	)

	// Retry the whole dump when the kernel flags NLM_F_DUMP_INTR: the table
	// mutated mid-snapshot, so the collected view may miss or duplicate
	// objects. Each attempt starts from empty state.
	for {
		if err := s.sendRouteDump(sock); err != nil {
			return fmt.Errorf("send dump: %w", err)
		}

		snapshot = make(map[string]Route)
		stashed = nil
		dumpInterrupted = false
		dumpDone := false

		for !dumpDone {
			msgs, from, err := sock.Receive()
			if err != nil {
				return fmt.Errorf("receive during dump: %w", err)
			}
			if from.Pid != nl.PidKernel {
				s.reportError(fmt.Errorf("ignore message from non-kernel sender portid %d", from.Pid))
				continue
			}
			for _, m := range msgs {
				if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
					dumpInterrupted = true
				}
				switch m.Header.Type {
				case unix.NLMSG_DONE:
					dumpDone = true
				case unix.NLMSG_ERROR:
					if code := nlInt32(m.Data); code != 0 {
						return fmt.Errorf("dump error: %v", unix.Errno(-code))
					}
				case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
					route, err := deserializeRoute(m.Data)
					if err != nil {
						s.reportError(fmt.Errorf("deserialize route during dump: %w", err))
						continue
					}
					update := RouteUpdate{
						Type:    m.Header.Type,
						NlFlags: m.Header.Flags & routeNlFlagMask,
						Route:   route,
					}
					// Dump entries (NLM_F_DUMP set) populate the snapshot;
					// multicast notifications racing the dump are stashed.
					if m.Header.Flags&unix.NLM_F_DUMP != 0 {
						snapshot[routeKey(route)] = route
					} else {
						stashed = append(stashed, update)
					}
				}
			}
		}

		if !dumpInterrupted {
			break
		}
		s.reportError(ErrDumpInterrupted)
	}

	// Fold every event observed during the dump into the snapshot. Later
	// stashed events win, so an object touched by both sources is published
	// once, in its final consistent version.
	upserts, deletes := reconcileSnapshot(snapshot, stashed)

	if err := s.emitOrErr(RouteEvent{Kind: RouteEventSyncStart, Generation: gen}); err != nil {
		return err
	}
	for _, route := range upserts {
		if err := s.emitOrErr(RouteEvent{
			Kind:       RouteEventChange,
			Generation: gen,
			Update: RouteUpdate{
				Type:  unix.RTM_NEWROUTE,
				Route: route,
			},
		}); err != nil {
			return err
		}
	}
	// Objects that existed before the generation but were deleted while the
	// dump ran must be replayed as deletes; the snapshot alone cannot
	// express them.
	for _, route := range deletes {
		if err := s.emitOrErr(RouteEvent{
			Kind:       RouteEventChange,
			Generation: gen,
			Update: RouteUpdate{
				Type:  unix.RTM_DELROUTE,
				Route: route,
			},
		}); err != nil {
			return err
		}
	}
	return s.emitOrErr(RouteEvent{Kind: RouteEventSyncEnd, Generation: gen})
}

// reconcileSnapshot merges a keyed dump snapshot with the multicast events
// stashed while the dump was in flight.
//
// Later stashed events win: an object present in both is returned exactly
// once in upserts with its post-dump version; a stashed delete removes it
// from upserts and produces a delete carrying the last known identifying
// fields. The returned slices are sorted by route key for deterministic
// emission.
func reconcileSnapshot(snapshot map[string]Route, stashed []RouteUpdate) (upserts, deletes []Route) {
	tombstoned := make(map[string]struct{})
	for _, update := range stashed {
		key := routeKey(update.Route)
		switch update.Type {
		case unix.RTM_DELROUTE:
			delete(snapshot, key)
			tombstoned[key] = struct{}{}
		case unix.RTM_NEWROUTE:
			delete(tombstoned, key)
			snapshot[key] = update.Route
		}
	}

	upserts = make([]Route, 0, len(snapshot))
	for _, key := range sortedRouteKeys(snapshot) {
		upserts = append(upserts, snapshot[key])
	}
	deletes = make([]Route, 0, len(tombstoned))
	for _, key := range sortedTombstones(tombstoned) {
		deletes = append(deletes, stashedRouteFor(stashed, key))
	}
	return upserts, deletes
}

// relayIncremental forwards multicast events after the snapshot has been
// reconciled. A queue overflow raises Truncated and forces a new generation.
func (s *ResumableRouteSubscription) relayIncremental(gen uint64, sock routeConn) error {
	for {
		msgs, from, err := sock.Receive()
		if err != nil {
			if s.isDone() {
				return ErrSubscriptionClosed
			}
			return fmt.Errorf("receive: %w", err)
		}
		if from.Pid != nl.PidKernel {
			s.reportError(fmt.Errorf("ignore message from non-kernel sender portid %d", from.Pid))
			continue
		}
		for _, m := range msgs {
			if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				s.reportError(ErrDumpInterrupted)
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE, unix.NLMSG_ERROR:
				// ACKs and stray dump terminators are not route events.
				if m.Header.Type == unix.NLMSG_ERROR && nlInt32(m.Data) != 0 {
					s.reportError(fmt.Errorf("netlink error: %v", unix.Errno(-nlInt32(m.Data))))
				}
				continue
			case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
			default:
				continue
			}
			route, err := deserializeRoute(m.Data)
			if err != nil {
				s.reportError(fmt.Errorf("deserialize route: %w", err))
				continue
			}
			event := RouteEvent{
				Kind:       RouteEventChange,
				Generation: gen,
				Update: RouteUpdate{
					Type:    m.Header.Type,
					NlFlags: m.Header.Flags & routeNlFlagMask,
					Route:   route,
				},
			}
			if err := s.emitOrErr(event); err != nil {
				return err
			}
		}
	}
}

// emit enqueues an event, assigning the next sequence number. When the
// bounded queue is full the consumer is too slow: the oldest unconsumed
// event is dropped to make room for a guaranteed Truncated marker, and emit
// returns false so the caller tears the generation down and resyncs. The
// marker is therefore always delivered, and the dropped event's sequence
// gap lets the consumer prove the truncation independently.
func (s *ResumableRouteSubscription) emit(event RouteEvent) bool {
	if s.isDone() {
		return false
	}
	event.Seq = s.lastSeq.Add(1)
	select {
	case s.events <- event:
		return true
	default:
	}

	// Queue saturated: evict the head (oldest unconsumed event) so the
	// Truncated marker always has a slot.
	select {
	case <-s.events:
	default:
	}
	select {
	case s.events <- RouteEvent{
		Kind:       RouteEventTruncated,
		Generation: event.Generation,
		Seq:        s.lastSeq.Add(1),
	}:
	default:
	}
	return false
}

// errQueueOverflow is internal: a failed emit outside shutdown means backpressure.
var errQueueOverflow = errors.New("route event queue overflow")

// emitOrErr wraps emit, translating a failed enqueue into the correct
// terminal error: [ErrSubscriptionClosed] during shutdown,
// [errQueueOverflow] otherwise (the Truncated marker was already queued).
func (s *ResumableRouteSubscription) emitOrErr(event RouteEvent) error {
	if s.emit(event) {
		return nil
	}
	if s.isDone() {
		return ErrSubscriptionClosed
	}
	return errQueueOverflow
}

func (s *ResumableRouteSubscription) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// sleep waits for the reconnect backoff or an immediate Close wakeup.
// It returns false when the subscription is shutting down.
func (s *ResumableRouteSubscription) sleep(d time.Duration) bool {
	s.wakeMu.Lock()
	wake := s.wake
	s.wakeMu.Unlock()
	select {
	case <-s.done:
		return false
	case <-wake:
		return false
	case <-time.After(d):
		return true
	}
}

func (s *ResumableRouteSubscription) reportError(err error) {
	if s.opts.ErrorCallback != nil && err != nil {
		s.opts.ErrorCallback(err)
	}
}

func (s *ResumableRouteSubscription) sendRouteDump(sock routeConn) error {
	req := pkgHandle().newNetlinkRequest(unix.RTM_GETROUTE, unix.NLM_F_DUMP)
	req.AddData(nl.NewIfInfomsg(unix.AF_UNSPEC))
	return sock.Send(req)
}

// routeNlFlagMask mirrors the flags forwarded by the plain RouteSubscribe.
var routeNlFlagMask = uint16(unix.NLM_F_REPLACE | unix.NLM_F_EXCL | unix.NLM_F_CREATE | unix.NLM_F_APPEND)

// routeKey identifies a route object for dump/incremental reconciliation.
// It mirrors the kernel route identity carried in RtMsg and the key
// attributes: table, type, scope, tos, destination (including MPLS),
// iif/oif and multipath topology. Mutable attributes such as RTA_PRIORITY,
// gateway or metrics are deliberately excluded — an update to them must
// collapse onto the same object rather than look like a new one.
func routeKey(r Route) string {
	dst := ""
	if r.Dst != nil {
		dst = r.Dst.String()
	}
	mpls := ""
	if r.MPLSDst != nil {
		mpls = fmt.Sprintf("%d", *r.MPLSDst)
	}
	return fmt.Sprintf("%d|%d|%d|%d|%s|%s|%d|%d|%d",
		r.Table, r.Type, r.Scope, r.Tos, dst, mpls,
		r.LinkIndex, r.ILinkIndex, len(r.MultiPath))
}

func sortedRouteKeys(m map[string]Route) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedTombstones(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// stashedRouteFor recovers the last stashed update carrying key, so a
// replayed delete still contains the identifying fields of the object.
func stashedRouteFor(stashed []RouteUpdate, key string) Route {
	for i := len(stashed) - 1; i >= 0; i-- {
		if routeKey(stashed[i].Route) == key {
			return stashed[i].Route
		}
	}
	return Route{}
}

func nlInt32(b []byte) int32 {
	if len(b) < 4 {
		return 0
	}
	return int32(native.Uint32(b[:4]))
}
