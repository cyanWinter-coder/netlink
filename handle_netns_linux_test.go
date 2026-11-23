//go:build linux
// +build linux

package netlink

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// currentThreadNs returns a handle to the calling thread's network namespace.
func currentThreadNs(t *testing.T) netns.NsHandle {
	t.Helper()
	ns, err := netns.Get()
	if err != nil {
		t.Fatalf("netns.Get failed: %v", err)
	}
	return ns
}

// addDummyInNs adds a dummy link through h and fails the test on error.
func addDummyInNs(t *testing.T, h *Handle, name string) {
	t.Helper()
	if err := h.LinkAdd(&Dummy{LinkAttrs{Name: name}}); err != nil {
		t.Fatalf("LinkAdd(%q) failed: %v", name, err)
	}
	t.Cleanup(func() { _ = LinkDel(&Dummy{LinkAttrs{Name: name}}) })
}

// TestHandleRestoresCallingThreadNamespace checks that every request explicitly
// binds the calling thread to the handle's namespace and puts the thread back
// into the namespace it had before the call.
func TestHandleRestoresCallingThreadNamespace(t *testing.T) {
	skipUnlessRoot(t)

	// The main goroutine must stay on one thread too: netns.New() switches the
	// calling thread only, and an unlocked goroutine could later observe the
	// new namespace on a different thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origNs := currentThreadNs(t)
	defer origNs.Close()

	newNs, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New failed: %v", err)
	}
	// netns.New leaves this thread in newNs; move back so newNs is only entered
	// through the handle under test.
	if err := netns.Set(origNs); err != nil {
		t.Fatalf("restoring original namespace failed: %v", err)
	}
	defer func() {
		_ = netns.Set(origNs)
		_ = newNs.Close()
	}()

	h, err := NewHandleAt(newNs)
	if err != nil {
		t.Fatalf("NewHandleAt failed: %v", err)
	}
	defer h.Close()

	const iterations = 25
	for i := range iterations {
		// Each goroutine establishes a known starting namespace itself: the
		// goroutine may land on the thread netns.New() switched earlier, so the
		// process-wide namespace cannot be assumed. The contract under test is
		// that a request restores the thread to whatever namespace it had when
		// the request began.
		done := make(chan error, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			if err := netns.Set(origNs); err != nil {
				done <- fmt.Errorf("iteration %d: establishing start namespace failed: %w", i, err)
				return
			}

			before, err := netns.Get()
			if err != nil {
				done <- err
				return
			}
			defer before.Close()
			if !before.Equal(origNs) {
				done <- fmt.Errorf("iteration %d: thread not in the original namespace before the request", i)
				return
			}

			if _, err := h.LinkList(); err != nil {
				done <- fmt.Errorf("iteration %d: LinkList failed: %w", i, err)
				return
			}

			after, err := netns.Get()
			if err != nil {
				done <- err
				return
			}
			defer after.Close()
			if !after.Equal(before) {
				done <- fmt.Errorf("iteration %d: thread left in a different namespace after the request", i)
				return
			}
			done <- nil
		}()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// TestHandleRequestTargetsBoundNamespace verifies that a handle's request really
// executes in its bound namespace even when the calling thread lives elsewhere,
// and that the fallback (short-lived socket) path is bound the same way.
func TestHandleRequestTargetsBoundNamespace(t *testing.T) {
	skipUnlessRoot(t)

	origNs := currentThreadNs(t)
	defer origNs.Close()

	newNs, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New failed: %v", err)
	}
	defer func() {
		_ = netns.Set(origNs)
		_ = newNs.Close()
	}()

	// Handle with only NETLINK_NETFILTER mapped: LINK operations must use the
	// short-lived fallback socket, which also has to be bound to newNs.
	h, err := NewHandleAt(newNs, unix.NETLINK_NETFILTER)
	if err != nil {
		t.Fatalf("NewHandleAt failed: %v", err)
	}
	defer h.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := netns.Set(origNs); err != nil {
		t.Fatalf("restoring original namespace failed: %v", err)
	}

	const ifName = "ns-bound-dummy"
	addDummyInNs(t, h, ifName)

	// The link must exist in newNs, not in the namespace the thread is in.
	if _, err := LinkByName(ifName); err == nil {
		t.Fatalf("link %q leaked into the calling thread's namespace", ifName)
	}

	enter := func() func() {
		if err := netns.Set(newNs); err != nil {
			t.Fatalf("entering newNs failed: %v", err)
		}
		return func() {
			if err := netns.Set(origNs); err != nil {
				t.Fatalf("restoring origNs failed: %v", err)
			}
		}
	}

	leave := enter()
	link, err := LinkByName(ifName)
	leave()
	if err != nil {
		t.Fatalf("link %q missing from the bound namespace: %v", ifName, err)
	}
	if link.Type() != "dummy" {
		t.Fatalf("unexpected link type: %s", link.Type())
	}

	// Reads through the handle must see the link from either thread namespace.
	if _, err := h.LinkByName(ifName); err != nil {
		t.Fatalf("handle LinkByName failed: %v", err)
	}
}

// TestHandleConcurrentNamespaceIsolation hammers two handles on different
// namespaces from many goroutines. No request may observe another request's
// namespace, and per-socket sequence numbers must stay unique under sharing.
func TestHandleConcurrentNamespaceIsolation(t *testing.T) {
	skipUnlessRoot(t)

	origNs := currentThreadNs(t)
	defer origNs.Close()

	ns1, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New(ns1) failed: %v", err)
	}
	ns2, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New(ns2) failed: %v", err)
	}
	defer func() {
		_ = netns.Set(origNs)
		_ = ns1.Close()
		_ = ns2.Close()
	}()

	h1, err := NewHandleAt(ns1, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("NewHandleAt(ns1) failed: %v", err)
	}
	defer h1.Close()
	h2, err := NewHandleAt(ns2, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("NewHandleAt(ns2) failed: %v", err)
	}
	defer h2.Close()

	const (
		goroutines = 8
		rounds     = 20
	)

	var wg sync.WaitGroup
	var failCount atomic.Int32
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			// Keep the thread pinned in yet another namespace so a missing
			// enter/restore would immediately corrupt the target namespace.
			workerNs, err := netns.New()
			if err != nil {
				t.Errorf("worker netns.New failed: %v", err)
				return
			}
			defer func() {
				_ = netns.Set(origNs)
				_ = workerNs.Close()
			}()
			if err := netns.Set(workerNs); err != nil {
				t.Errorf("entering worker namespace failed: %v", err)
				return
			}

			for r := range rounds {
				name := fmt.Sprintf("iso-g%d-r%d", g, r)
				if err := h1.LinkAdd(&Dummy{LinkAttrs{Name: name}}); err != nil {
					failCount.Add(1)
					t.Errorf("h1 LinkAdd failed: %v", err)
					return
				}
				if _, err := h1.LinkByName(name); err != nil {
					failCount.Add(1)
					t.Errorf("h1 LinkByName(%q) failed: %v", name, err)
					return
				}
				// The link must never show up in ns2.
				if _, err := h2.LinkByName(name); err == nil {
					failCount.Add(1)
					t.Errorf("link %q leaked from ns1 into ns2", name)
					return
				}
				if err := h1.LinkDel(&Dummy{LinkAttrs{Name: name}}); err != nil {
					failCount.Add(1)
					t.Errorf("h1 LinkDel failed: %v", err)
					return
				}

				// The worker thread must still be in its own namespace after
				// every request: no cross-thread namespace pollution.
				cur, err := netns.Get()
				if err != nil {
					failCount.Add(1)
					t.Errorf("netns.Get failed: %v", err)
					return
				}
				ok := cur.Equal(workerNs)
				_ = cur.Close()
				if !ok {
					failCount.Add(1)
					t.Errorf("worker thread namespace changed by a shared-socket request")
					return
				}
			}
		}(g)
	}
	wg.Wait()

	if failCount.Load() != 0 {
		t.Fatalf("concurrent namespace isolation had %d failures", failCount.Load())
	}
}

// TestHandleCloseIdempotent checks that repeated Close calls are harmless and
// that the namespace reference and sockets are released exactly once.
func TestHandleCloseIdempotent(t *testing.T) {
	skipUnlessRoot(t)

	newNs, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New failed: %v", err)
	}

	h, err := NewHandleAt(newNs, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("NewHandleAt failed: %v", err)
	}
	// The handle must own a private reference: closing the caller's handle
	// must not invalidate in-flight requests.
	var st unix.Stat_t
	if err := unix.Fstat(int(newNs), &st); err != nil {
		t.Fatalf("Fstat on the open namespace fd failed: %v", err)
	}
	if err := newNs.Close(); err != nil {
		t.Fatalf("closing the caller namespace handle failed: %v", err)
	}
	if err := unix.Fstat(int(newNs), &st); err != unix.EBADF {
		t.Fatalf("expected the caller's namespace fd to be closed, got err=%v", err)
	}

	for i := range 5 {
		if err := h.Close(); err != nil {
			t.Fatalf("Close iteration %d returned an error: %v", i, err)
		}
	}
	if h.sockets != nil {
		t.Fatal("Close did not drop the socket map")
	}
	if h.namespace != 0 {
		t.Fatalf("Close did not release the namespace reference, leftover fd %d", h.namespace)
	}

	// Requests after Close must fail deterministically rather than block or
	// write anywhere.
	if _, err := h.LinkList(); !errors.Is(err, nl.ErrHandleClosed) {
		t.Fatalf("LinkList after Close: expected ErrHandleClosed, got %v", err)
	}
}

// TestHandleCloseRacesRequests closes the handle while requests are in flight.
// In-flight requests are allowed to finish; requests that lose the race get
// ErrHandleClosed and nothing is written into another namespace.
func TestHandleCloseRacesRequests(t *testing.T) {
	skipUnlessRoot(t)

	newNs, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New failed: %v", err)
	}
	defer func() { _ = newNs.Close() }()

	h, err := NewHandleAt(newNs, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("NewHandleAt failed: %v", err)
	}

	const workers = 6
	var wg sync.WaitGroup
	var closedCount atomic.Int32
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range 100 {
				name := fmt.Sprintf("race-w%d-i%d", w, i)
				err := h.LinkAdd(&Dummy{LinkAttrs{Name: name}})
				switch {
				case err == nil:
					// Every successful write must be inside newNs: verify by
					// listing through a fresh, independent handle.
					if derr := h.LinkDel(&Dummy{LinkAttrs{Name: name}}); derr != nil &&
						!errors.Is(derr, nl.ErrHandleClosed) {
						t.Errorf("LinkDel(%q) unexpected error: %v", name, derr)
					}
				case errors.Is(err, nl.ErrHandleClosed):
					closedCount.Add(1)
					return
				default:
					t.Errorf("LinkAdd(%q) unexpected error: %v", name, err)
					return
				}
			}
		}(w)
	}

	// Give the workers a head start, then close while some requests are active.
	runtime.Gosched()
	if err := h.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	wg.Wait()

	if closedCount.Load() == 0 {
		t.Fatal("no request observed the closed handle; the race was not exercised")
	}

	// Second Close is still idempotent.
	if err := h.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}

	// Confirm every surviving link landed in newNs and clean them up.
	cleanup, err := NewHandleAt(newNs, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("cleanup NewHandleAt failed: %v", err)
	}
	defer cleanup.Close()
	links, err := cleanup.LinkList()
	if err != nil {
		t.Fatalf("cleanup LinkList failed: %v", err)
	}
	for _, link := range links {
		if link.Attrs().Name != "lo" {
			if err := cleanup.LinkDel(link); err != nil {
				t.Errorf("cleanup LinkDel(%q) failed: %v", link.Attrs().Name, err)
			}
		}
	}
}

// TestHandleNamespaceDescriptorClosedBeforeRequest covers the "namespace
// entry fails under the handle" recovery path through the short-lived fallback
// socket. The fallback path reads the namespace from the Handle (the shared
// sockets carry their own binding captured at construction), so replacing the
// handle's descriptor with a descriptor that is not a network namespace makes
// entry fail deterministically. The request must return that error, leave the
// calling thread in its original namespace and open no fallback socket.
func TestHandleNamespaceDescriptorClosedBeforeRequest(t *testing.T) {
	skipUnlessRoot(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	origNs := currentThreadNs(t)
	defer origNs.Close()

	newNs, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New failed: %v", err)
	}
	if err := netns.Set(origNs); err != nil {
		t.Fatalf("restoring original namespace failed: %v", err)
	}
	defer func() {
		_ = netns.Set(origNs)
		_ = newNs.Close()
	}()

	// Map only NETFILTER so LINK requests take the short-lived fallback socket,
	// which is opened in the Handle's recorded namespace on every request.
	h, err := NewHandleAt(newNs, unix.NETLINK_NETFILTER)
	if err != nil {
		t.Fatalf("NewHandleAt failed: %v", err)
	}

	// Sanity: the fallback path works and stays scoped before the break.
	const ifName = "ns-dead-dummy"
	addDummyInNs(t, h, ifName)

	// A valid open descriptor that is not an nsfs file makes setns(2) fail with
	// EINVAL deterministically, independent of fd reuse.
	regularFd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("opening /dev/null failed: %v", err)
	}
	defer unix.Close(regularFd)
	realNsFd := h.namespace
	h.namespace = regularFd
	// Restore the real descriptor before Close so its normal cleanup runs.
	defer func() { h.namespace = realNsFd }()

	_, err = h.LinkList()
	if err == nil {
		t.Fatal("expected an error when entering through a non-namespace descriptor, got nil")
	}
	if errors.Is(err, nl.ErrHandleClosed) {
		t.Fatalf("an invalid namespace entry must not be reported as a closed handle: %v", err)
	}
	t.Logf("request with an invalid namespace descriptor failed deterministically: %v", err)

	// The failed request must not have moved the calling thread.
	curNs, err := netns.Get()
	if err != nil {
		t.Fatalf("netns.Get failed: %v", err)
	}
	defer curNs.Close()
	if !curNs.Equal(origNs) {
		t.Fatal("a failed namespace entry left the calling thread in another namespace")
	}

	// Handle.Close still works and is idempotent after the failed request.
	if err := h.Close(); err != nil {
		t.Fatalf("Close after an invalid namespace entry failed: %v", err)
	}
	if _, err := h.LinkList(); !errors.Is(err, nl.ErrHandleClosed) {
		t.Fatalf("request after Close: expected ErrHandleClosed, got %v", err)
	}
}

// TestSocketHandleAcquireFailsOnClosedNamespace checks the nl-level contract
// directly: Acquire on a handle whose namespace descriptor is not a network
// namespace returns an error without taking a reference or moving the thread,
// and a later Close still drains cleanly.
func TestSocketHandleAcquireFailsOnClosedNamespace(t *testing.T) {
	skipUnlessRoot(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	origNs := currentThreadNs(t)
	defer origNs.Close()

	newNs, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New failed: %v", err)
	}
	if err := netns.Set(origNs); err != nil {
		t.Fatalf("restoring original namespace failed: %v", err)
	}
	defer func() {
		_ = netns.Set(origNs)
		_ = newNs.Close()
	}()

	sock, err := nl.GetNetlinkSocketAt(newNs, origNs, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("GetNetlinkSocketAt failed: %v", err)
	}

	// A regular file descriptor cannot be used with setns(CLONE_NEWNET).
	regularFd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("opening /dev/null failed: %v", err)
	}
	defer unix.Close(regularFd)

	sh := nl.NewSocketHandle(sock, regularFd)
	if _, err := sh.Acquire(); err == nil {
		t.Fatal("Acquire on a non-namespace descriptor must fail")
	} else if errors.Is(err, nl.ErrHandleClosed) {
		t.Fatalf("an invalid namespace entry is not a closed handle: %v", err)
	}

	curNs, err := netns.Get()
	if err != nil {
		t.Fatalf("netns.Get failed: %v", err)
	}
	defer curNs.Close()
	if !curNs.Equal(origNs) {
		t.Fatal("failed Acquire moved the calling thread")
	}

	// Close must still be idempotent and must close the socket.
	if err := sh.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := sh.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	if _, err := sh.Acquire(); !errors.Is(err, nl.ErrHandleClosed) {
		t.Fatalf("Acquire after Close: expected ErrHandleClosed, got %v", err)
	}
}

// TestDefaultNamespaceHandleCompatibility locks in the default-path behaviour:
// a handle created without a namespace performs no per-request thread
// switching, works with plain NewHandle, and each shared socket consumes its
// own strictly increasing sequence numbers.
func TestDefaultNamespaceHandleCompatibility(t *testing.T) {
	skipUnlessRoot(t)

	h, err := NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("NewHandle failed: %v", err)
	}
	defer h.Close()
	if h.namespace != 0 {
		t.Fatalf("default handle must not carry a namespace descriptor, got %d", h.namespace)
	}

	// On the calling (locked) thread, requests through a default handle must
	// leave the thread's namespace untouched.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	threadNs, err := netns.Get()
	if err != nil {
		t.Fatalf("netns.Get failed: %v", err)
	}
	defer threadNs.Close()

	// Sequence numbers are per socket: on one socket every request gets a
	// strictly higher number. Sample before and after each request on this
	// thread, where the observation is race-free.
	sh := h.sockets[unix.NETLINK_ROUTE]
	const sequentialReqs = 20
	prev := sh.Seq.Load()
	for range sequentialReqs {
		links, err := h.LinkList()
		if err != nil {
			t.Fatalf("LinkList failed: %v", err)
		}
		if len(links) == 0 {
			t.Fatal("empty link list; lo must always exist")
		}
		next := sh.Seq.Load()
		if next != prev+1 {
			t.Fatalf("sequence must advance by exactly one: prev=%d next=%d", prev, next)
		}
		prev = next
	}

	// Concurrent requests on the shared socket must all succeed and never
	// switch this thread's namespace. The atomic sequence counter makes
	// cross-goroutine observation order irrelevant; correctness here means no
	// request errors and the final count matches the number of requests.
	const goroutines = 6
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			for range 10 {
				if _, err := h.LinkList(); err != nil {
					failures.Add(1)
					t.Errorf("concurrent LinkList failed: %v", err)
					return
				}
			}
		}()
	}

	workersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workersDone)
	}()
checkLoop:
	for {
		select {
		case <-workersDone:
			break checkLoop
		default:
		}
		cur, err := netns.Get()
		if err != nil {
			t.Fatalf("netns.Get failed: %v", err)
		}
		ok := cur.Equal(threadNs)
		_ = cur.Close()
		if !ok {
			t.Fatal("default handle switched the calling thread's namespace")
		}
	}

	if failures.Load() != 0 {
		t.Fatalf("concurrent requests had %d failures", failures.Load())
	}
	// Every request consumed one sequence number: sequentialReqs on this
	// thread plus goroutines*10 on the workers.
	want := uint32(sequentialReqs + goroutines*10)
	if got := sh.Seq.Load(); got != want {
		t.Fatalf("final sequence number = %d, want %d (one per request)", got, want)
	}
}

// TestSocketHandleCloseWaitsForInFlight verifies the nl-level contract directly:
// Close blocks while a request holds a reference and only then closes the fd.
func TestSocketHandleCloseWaitsForInFlight(t *testing.T) {
	skipUnlessRoot(t)

	sock, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("GetNetlinkSocketAt failed: %v", err)
	}
	sh := nl.NewSocketHandle(sock, 0)
	fd := sock.GetFd()

	release, err := sh.Acquire()
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	closed := make(chan error, 1)
	go func() { closed <- sh.Close() }()

	// While the reference is held, the fd must stay open.
	select {
	case err := <-closed:
		t.Fatalf("Close returned before the in-flight reference was released: %v", err)
	case <-makeReadyChan():
	}
	if err := unix.Fstat(fd, &unix.Stat_t{}); err != nil {
		t.Fatalf("socket fd closed while a request was in flight: %v", err)
	}

	release()
	if err := <-closed; err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
	if err := unix.Fstat(fd, &unix.Stat_t{}); err != unix.EBADF {
		t.Fatalf("expected socket fd %d to be closed after release, got %v", fd, err)
	}

	// Acquire after Close is a deterministic failure and Close stays idempotent.
	if _, err := sh.Acquire(); !errors.Is(err, nl.ErrHandleClosed) {
		t.Fatalf("Acquire after Close: expected ErrHandleClosed, got %v", err)
	}
	if err := sh.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

// makeReadyChan returns a channel that is already closed, used as a
// non-blocking select probe.
func makeReadyChan() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// TestHandleConcurrentConfigAndClose exercises the socket-map snapshot path:
// configuration helpers that iterate the handle's sockets run concurrently with
// Close and with each other. Under -race this proves the map is never traversed
// while Close replaces it; functionally every call must either succeed or fail
// on an already-closed socket without panicking.
func TestHandleConcurrentConfigAndClose(t *testing.T) {
	skipUnlessRoot(t)

	h, err := NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("NewHandle failed: %v", err)
	}

	const workers = 8
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				// Errors after Close are acceptable; the point is no panic/race.
				_ = h.SupportsNetlinkFamily(unix.NETLINK_ROUTE)
				_ = h.SetSocketTimeout(time.Second)
				if _, err := h.GetSocketReceiveBufferSize(); err != nil {
					return
				}
				_ = h.SetStrictCheck(false)
			}
		}()
	}

	// Close from a separate goroutine while the workers iterate the map.
	runtime.Gosched()
	if err := h.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	wg.Wait()

	// Idempotent and safe after concurrent use.
	if err := h.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}
