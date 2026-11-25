package netlink

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// fakeXdpOps is an in-memory xdpOps for testing the replacement state
// machine without a kernel. "Open" fds are positive integers allocated from
// a counter; closeFd marks them closed so tests can assert fd lifetimes.
type fakeXdpOps struct {
	state          xdpState
	atomicSupport  bool
	applyErr       error
	stateErr       error
	fdForIDErr     error
	progIDForFdErr error
	closeErr       error
	// applyFunc, when set, fully owns the post-SETLINK state transition;
	// the fake does not update f.state itself. Tests model "ACK returned but
	// the program did not attach" by simply leaving f.state untouched.
	applyFunc    func(call fakeApplyCall) error
	nextFd       int
	closedFds    map[int]bool
	applyCalls   []fakeApplyCall
	stateCalls   int
	fdForIDCalls []uint32
}

type fakeApplyCall struct {
	fd         int
	expectedFd int
	flags      uint32
}

func newFakeXdpOps() *fakeXdpOps {
	return &fakeXdpOps{
		nextFd:    100,
		closedFds: map[int]bool{},
	}
}

func (f *fakeXdpOps) currentState(_ Link) (xdpState, error) {
	f.stateCalls++
	if f.stateErr != nil {
		return xdpState{}, f.stateErr
	}
	return f.state, nil
}

func (f *fakeXdpOps) apply(_ Link, fd, expectedFd int, flags uint32) error {
	call := fakeApplyCall{fd: fd, expectedFd: expectedFd, flags: flags}
	f.applyCalls = append(f.applyCalls, call)
	if f.applyFunc != nil {
		// The hook owns both the error decision and any state transition.
		return f.applyFunc(call)
	}
	if f.applyErr != nil {
		// A failed SETLINK does not change attachment state; tests that
		// need partial-failure semantics use applyFunc.
		return f.applyErr
	}
	// Model the kernel: a successful SETLINK changes the attachment state.
	if fd < 0 {
		f.state = xdpState{}
	} else {
		f.state = xdpState{progID: uint32(fd), flags: flags}
	}
	return nil
}

func (f *fakeXdpOps) bpfFdForID(id uint32) (int, error) {
	f.fdForIDCalls = append(f.fdForIDCalls, id)
	if f.fdForIDErr != nil {
		return 0, f.fdForIDErr
	}
	f.nextFd++
	return f.nextFd, nil
}

// progIDForFdErr makes bpfProgIDForFd fail; tests use it to exercise the
// fallback that only checks whether anything is attached.
func (f *fakeXdpOps) bpfProgIDForFd(fd int) (uint32, error) {
	if f.progIDForFdErr != nil {
		return 0, f.progIDForFdErr
	}
	// The fake models an attached program's id as its SETLINK fd.
	return uint32(fd), nil
}

func (f *fakeXdpOps) closeFd(fd int) error {
	f.closedFds[fd] = true
	return f.closeErr
}

func (f *fakeXdpOps) atomicReplaceSupported() bool {
	return f.atomicSupport
}

func (f *fakeXdpOps) isClosed(fd int) bool {
	return f.closedFds[fd]
}

func fakeLink() Link {
	return &Device{LinkAttrs: LinkAttrs{Index: 7, Name: "fake0"}}
}

// TestXdpReplaceRejectsInvalidInputs covers the pre-mutation validation in
// requirement 1: validateXdpReplace must reject bad inputs before any kernel
// interaction. The fd-closing contract is asserted by the lifecycle tests.
func TestXdpReplaceRejectsInvalidInputs(t *testing.T) {
	link := fakeLink()
	const newFd = 42

	cases := []struct {
		name string
		ctx  context.Context
		link Link
		opts LinkXdpReplaceOptions
		want string
	}{
		{
			name: "already canceled context",
			ctx:  canceledContext(),
			link: link,
			opts: LinkXdpReplaceOptions{Fd: newFd},
			want: context.Canceled.Error(),
		},
		{
			name: "nil link",
			ctx:  context.Background(),
			link: nil,
			opts: LinkXdpReplaceOptions{Fd: newFd},
			want: "nil link",
		},
		{
			name: "negative fd",
			ctx:  context.Background(),
			link: link,
			opts: LinkXdpReplaceOptions{Fd: -1},
			want: "invalid new XDP program fd",
		},
		{
			name: "unknown flags",
			ctx:  context.Background(),
			link: link,
			opts: LinkXdpReplaceOptions{Fd: newFd, Flags: 0x80000000},
			want: "unknown XDP flags",
		},
		{
			name: "noexist flag rejected",
			ctx:  context.Background(),
			link: link,
			opts: LinkXdpReplaceOptions{Fd: newFd, Flags: nl.XDP_FLAGS_UPDATE_IF_NOEXIST},
			want: "UPDATE_IF_NOEXIST",
		},
		{
			name: "skb and drv mode together rejected",
			ctx:  context.Background(),
			link: link,
			opts: LinkXdpReplaceOptions{Fd: newFd, Flags: nl.XDP_FLAGS_SKB_MODE | nl.XDP_FLAGS_DRV_MODE},
			want: "mutually exclusive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateXdpReplace(tc.ctx, tc.link, tc.opts)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}

	// The Handle entry point rejects a nil context and still closes the fd
	// supplied with the rejected request.
	fakeFd := 43
	err := pkgHandle().LinkReplaceXdpFd(nil, link, LinkXdpReplaceOptions{Fd: fakeFd})
	if err == nil || !strings.Contains(err.Error(), "nil context") {
		t.Fatalf("want nil-context error, got %v", err)
	}
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("closing the placeholder fd must surface EBADF in the joined error, got %v", err)
	}
}

// TestXdpReplaceAtomicCAS verifies the supported path: one SETLINK carrying
// both the new fd and IFLA_XDP_EXPECTED_FD, with no detach in between.
func TestXdpReplaceAtomicCAS(t *testing.T) {
	ops := newFakeXdpOps()
	ops.atomicSupport = true
	ops.state = xdpState{progID: 11, flags: nl.XDP_FLAGS_SKB_MODE}

	const newFd = 50
	const callerExpectedFd = 60
	err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{
		Fd:         newFd,
		Flags:      nl.XDP_FLAGS_DRV_MODE,
		ExpectedFd: callerExpectedFd,
	})
	if err != nil {
		t.Fatalf("replacement failed: %v", err)
	}
	if len(ops.applyCalls) != 1 {
		t.Fatalf("want exactly one atomic SETLINK, got %d: %+v", len(ops.applyCalls), ops.applyCalls)
	}
	call := ops.applyCalls[0]
	if call.fd != newFd || call.expectedFd != callerExpectedFd || call.flags != nl.XDP_FLAGS_DRV_MODE {
		t.Fatalf("unexpected SETLINK attrs: %+v", call)
	}
	// Success leaves the new fd with the caller and the caller's expected fd
	// untouched.
	if ops.isClosed(newFd) {
		t.Fatalf("new fd must remain open on success")
	}
	if ops.isClosed(callerExpectedFd) {
		t.Fatalf("caller-owned expected fd must never be closed")
	}
	if len(ops.fdForIDCalls) != 0 {
		t.Fatalf("caller-provided expected fd must suppress bpfFdForID, got %v", ops.fdForIDCalls)
	}
	if ops.state.progID != uint32(newFd) || ops.state.flags != nl.XDP_FLAGS_DRV_MODE {
		t.Fatalf("final state not updated: %+v", ops.state)
	}
}

// TestXdpReplaceFallbackPlainSetlink verifies that kernels without
// EXPECTED_FD get a single in-place SETLINK and never a detach-first dance.
// Without a caller-provided ExpectedFd the library opens a temporary fd for
// the running program and releases it once the replacement completes.
func TestXdpReplaceFallbackPlainSetlink(t *testing.T) {
	ops := newFakeXdpOps()
	ops.atomicSupport = false
	ops.state = xdpState{progID: 11, flags: nl.XDP_FLAGS_SKB_MODE}

	const newFd = 51
	err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{
		Fd:    newFd,
		Flags: nl.XDP_FLAGS_SKB_MODE,
	})
	if err != nil {
		t.Fatalf("replacement failed: %v", err)
	}
	if len(ops.applyCalls) != 1 {
		t.Fatalf("want one plain SETLINK, got %+v", ops.applyCalls)
	}
	call := ops.applyCalls[0]
	if call.fd != newFd || call.expectedFd != -1 {
		t.Fatalf("plain replacement must not carry EXPECTED_FD: %+v", call)
	}
	// The library opened its own fd for the old program (for rollback) and
	// closed it again after the successful replacement.
	if len(ops.fdForIDCalls) != 1 || ops.fdForIDCalls[0] != 11 {
		t.Fatalf("expected one bpfFdForID(11), got %v", ops.fdForIDCalls)
	}
	if !ops.isClosed(101) {
		t.Fatalf("library-opened old fd 101 must be closed after success")
	}
	if ops.isClosed(newFd) {
		t.Fatalf("new fd must remain open on success")
	}
}

// TestXdpReplaceAttachWithoutOldProgram covers the no-prior-attachment case:
// a plain attach with no EXPECTED_FD and no bpfFdForID lookup.
func TestXdpReplaceAttachWithoutOldProgram(t *testing.T) {
	ops := newFakeXdpOps()
	ops.atomicSupport = true

	const newFd = 52
	err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{Fd: newFd})
	if err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	if len(ops.applyCalls) != 1 {
		t.Fatalf("want one SETLINK, got %+v", ops.applyCalls)
	}
	if call := ops.applyCalls[0]; call.expectedFd != -1 || call.fd != newFd {
		t.Fatalf("unexpected attach attrs: %+v", call)
	}
	if len(ops.fdForIDCalls) != 0 {
		t.Fatalf("nothing attached: bpfFdForID must not run, got %v", ops.fdForIDCalls)
	}
}

// TestXdpReplaceRollbackAfterApplyError verifies requirement 3: when the
// replacement request fails and the old program is gone, the original
// program and flags are restored and the errors are aggregated.
func TestXdpReplaceRollbackAfterApplyError(t *testing.T) {
	ops := newFakeXdpOps()
	ops.atomicSupport = true
	ops.state = xdpState{progID: 11, flags: nl.XDP_FLAGS_SKB_MODE}
	applyErr := errors.New("kernel says no")
	applyCount := 0
	// Simulate the failed SETLINK having detached the old program anyway;
	// the rollback SETLINK then re-attaches it through the normal path.
	ops.applyFunc = func(call fakeApplyCall) error {
		applyCount++
		if applyCount == 1 {
			ops.state = xdpState{}
			return applyErr
		}
		ops.state = xdpState{progID: uint32(call.fd), flags: call.flags}
		return nil
	}

	const newFd = 53
	const callerExpectedFd = 61
	err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{
		Fd:         newFd,
		Flags:      nl.XDP_FLAGS_DRV_MODE,
		ExpectedFd: callerExpectedFd,
	})
	if err == nil {
		t.Fatalf("expected aggregated error")
	}
	if !errors.Is(err, applyErr) {
		t.Fatalf("aggregated error must wrap the SETLINK error, got %v", err)
	}
	if len(ops.applyCalls) != 2 {
		t.Fatalf("want failed replace plus rollback SETLINK, got %+v", ops.applyCalls)
	}
	rollback := ops.applyCalls[1]
	if rollback.fd != callerExpectedFd || rollback.flags != nl.XDP_FLAGS_SKB_MODE || rollback.expectedFd != -1 {
		t.Fatalf("rollback must restore old fd and flags: %+v", rollback)
	}
	// The fake models progID as the SETLINK's fd, so the restored state
	// records callerExpectedFd; the important assertions are the rollback
	// call attrs above and the original flags coming back.
	if ops.state.progID != uint32(callerExpectedFd) || ops.state.flags != nl.XDP_FLAGS_SKB_MODE {
		t.Fatalf("original state not restored: %+v", ops.state)
	}
	if !ops.isClosed(newFd) {
		t.Fatalf("failed replacement must close the new fd")
	}
	if ops.isClosed(callerExpectedFd) {
		t.Fatalf("caller-owned old fd must not be closed")
	}
}

// TestXdpReplaceRollbackDetachWhenNothingWasAttached verifies that rolling
// back over a link that had no program means detaching, not re-attaching.
func TestXdpReplaceRollbackDetachWhenNothingWasAttached(t *testing.T) {
	ops := newFakeXdpOps()
	applyErr := errors.New("boom")
	ops.applyFunc = func(call fakeApplyCall) error {
		if call.fd >= 0 {
			// The failed attach nevertheless left a program behind.
			ops.state = xdpState{progID: 99, flags: 0}
			return applyErr
		}
		// Rollback detach: the kernel clears the attachment.
		ops.state = xdpState{}
		return nil
	}

	const newFd = 54
	err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{Fd: newFd})
	if err == nil || !errors.Is(err, applyErr) {
		t.Fatalf("want wrapped apply error, got %v", err)
	}
	if len(ops.applyCalls) != 2 {
		t.Fatalf("want failed attach plus rollback detach, got %+v", ops.applyCalls)
	}
	if rollback := ops.applyCalls[1]; rollback.fd != -1 {
		t.Fatalf("rollback over empty snapshot must detach (fd=-1), got %+v", rollback)
	}
	if ops.state.attached() {
		t.Fatalf("rollback did not detach stray program: %+v", ops.state)
	}
	if !ops.isClosed(newFd) {
		t.Fatalf("new fd must be closed on failure")
	}
}

// TestXdpReplaceRollbackFailureAggregates verifies that a failed restore
// surfaces both the original cause and the rollback error.
func TestXdpReplaceRollbackFailureAggregates(t *testing.T) {
	ops := newFakeXdpOps()
	ops.atomicSupport = true
	ops.state = xdpState{progID: 11, flags: nl.XDP_FLAGS_SKB_MODE}
	replaceErr := errors.New("replace failed")
	rollbackErr := errors.New("rollback failed")
	callCount := 0
	ops.applyFunc = func(call fakeApplyCall) error {
		callCount++
		if callCount == 1 {
			ops.state = xdpState{}
			return replaceErr
		}
		return rollbackErr
	}

	err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{Fd: 55, ExpectedFd: 62})
	if !errors.Is(err, replaceErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("aggregated error must contain both causes, got %v", err)
	}
}

// TestXdpReplaceCancellationSkipsRollback verifies requirement 4: after
// cancellation the new fd is closed, no rollback SETLINK is attempted, and
// caller-owned old fds stay open.
func TestXdpReplaceCancellationSkipsRollback(t *testing.T) {
	ops := newFakeXdpOps()
	ops.atomicSupport = true
	ops.state = xdpState{progID: 11, flags: nl.XDP_FLAGS_SKB_MODE}
	// The SETLINK blocks until the context is canceled, then returns.
	ctx, cancel := context.WithCancel(context.Background())
	ops.applyFunc = func(call fakeApplyCall) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}

	const newFd = 56
	const callerExpectedFd = 63
	err := replaceXdp(ctx, ops, fakeLink(), LinkXdpReplaceOptions{
		Fd:         newFd,
		ExpectedFd: callerExpectedFd,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if len(ops.applyCalls) != 1 {
		t.Fatalf("cancellation must not trigger rollback SETLINKs, got %+v", ops.applyCalls)
	}
	if !ops.isClosed(newFd) {
		t.Fatalf("canceled replacement must close the new fd")
	}
	if ops.isClosed(callerExpectedFd) {
		t.Fatalf("referenced old fd must remain open after cancellation")
	}
}

// TestXdpReplaceTimeoutSkipsRollback verifies requirement 4 for the timeout
// flavor of cancellation: the deadline error is returned, the new fd is
// closed and no rollback SETLINK is issued.
func TestXdpReplaceTimeoutSkipsRollback(t *testing.T) {
	ops := newFakeXdpOps()
	ops.atomicSupport = true
	ops.state = xdpState{progID: 11, flags: nl.XDP_FLAGS_SKB_MODE}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	ops.applyFunc = func(call fakeApplyCall) error {
		<-ctx.Done()
		return ctx.Err()
	}

	const newFd = 64
	err := replaceXdp(ctx, ops, fakeLink(), LinkXdpReplaceOptions{Fd: newFd, ExpectedFd: 65})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context.DeadlineExceeded, got %v", err)
	}
	if len(ops.applyCalls) != 1 {
		t.Fatalf("timeout must not trigger rollback SETLINKs, got %+v", ops.applyCalls)
	}
	if !ops.isClosed(newFd) {
		t.Fatalf("timed-out replacement must close the new fd")
	}
	if ops.isClosed(65) {
		t.Fatalf("referenced old fd must remain open after timeout")
	}
}

// TestXdpReplaceCancellationBeforeApply verifies that canceling between the
// snapshot and the SETLINK aborts without touching the kernel.
func TestXdpReplaceCancellationBeforeApply(t *testing.T) {
	ops := newFakeXdpOps()
	ops.state = xdpState{progID: 11}
	ctx, cancel := context.WithCancel(context.Background())
	applyCount := 0
	ops.applyFunc = func(call fakeApplyCall) error {
		applyCount++
		return nil
	}
	cancel()

	err := replaceXdp(ctx, ops, fakeLink(), LinkXdpReplaceOptions{Fd: 57})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if applyCount != 0 {
		t.Fatalf("no SETLINK expected after pre-apply cancellation")
	}
	if !ops.isClosed(57) {
		t.Fatalf("new fd must be closed on cancellation")
	}
}

// TestXdpReplaceVerifyFailureRollsBack verifies the post-attach confirmation:
// if the new program never shows up as attached, the old program is restored.
func TestXdpReplaceVerifyFailureRollsBack(t *testing.T) {
	ops := newFakeXdpOps()
	ops.atomicSupport = false
	ops.state = xdpState{progID: 11, flags: nl.XDP_FLAGS_SKB_MODE}
	// The replacement SETLINK returns ACK but neither the new program
	// attaches nor the old one survives, so the confirmation snapshot finds
	// an unprotected link and rollback must re-attach the old program.
	ops.applyFunc = func(call fakeApplyCall) error {
		if len(ops.applyCalls) == 1 {
			ops.state = xdpState{}
			return nil
		}
		// Rollback SETLINK: model the kernel re-attaching the old program.
		ops.state = xdpState{progID: uint32(call.fd), flags: call.flags}
		return nil
	}

	const newFd = 58
	err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{Fd: newFd})
	if err == nil {
		t.Fatalf("expected verification failure")
	}
	if !strings.Contains(err.Error(), "not attached after replacement") {
		t.Fatalf("want verification error, got %v", err)
	}
	if len(ops.applyCalls) != 2 {
		t.Fatalf("want replace plus rollback, got %+v", ops.applyCalls)
	}
	// The rollback's SETLINK must restore the old program and flags. The
	// fake allocates fd 101 for the old program (id 11); the fake models
	// progID as the SETLINK fd.
	rollback := ops.applyCalls[1]
	if rollback.fd != 101 || rollback.flags != nl.XDP_FLAGS_SKB_MODE {
		t.Fatalf("rollback must re-attach the old program: %+v", rollback)
	}
	if ops.state.progID != 101 {
		t.Fatalf("old program not restored: %+v", ops.state)
	}
	if !ops.isClosed(newFd) {
		t.Fatalf("new fd must be closed after failed verification")
	}
}

// TestXdpReplaceWrongProgramTriggersRollback verifies the strong
// post-attach confirmation: if the link ends up carrying a different program
// than the one requested, the original program is restored.
func TestXdpReplaceWrongProgramTriggersRollback(t *testing.T) {
	ops := newFakeXdpOps()
	ops.atomicSupport = false
	ops.state = xdpState{progID: 11, flags: nl.XDP_FLAGS_SKB_MODE}
	ops.applyFunc = func(call fakeApplyCall) error {
		if len(ops.applyCalls) == 1 {
			// The SETLINK succeeded but left a foreign program (id 999)
			// attached instead of the requested newFd.
			ops.state = xdpState{progID: 999, flags: call.flags}
			return nil
		}
		ops.state = xdpState{progID: uint32(call.fd), flags: call.flags}
		return nil
	}

	const newFd = 80
	err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{Fd: newFd})
	if err == nil {
		t.Fatalf("expected wrong-program confirmation failure")
	}
	if !strings.Contains(err.Error(), "want") {
		t.Fatalf("want program-mismatch error, got %v", err)
	}
	if len(ops.applyCalls) != 2 {
		t.Fatalf("want replace plus rollback, got %+v", ops.applyCalls)
	}
	// Rollback re-attaches the old program through its freshly opened fd 101.
	if rollback := ops.applyCalls[1]; rollback.fd != 101 {
		t.Fatalf("rollback must re-attach old program, got %+v", rollback)
	}
	if ops.state.progID != 101 {
		t.Fatalf("old program not restored: %+v", ops.state)
	}
	if !ops.isClosed(newFd) {
		t.Fatalf("new fd must be closed after failed confirmation")
	}
}

// TestXdpReplaceProgInfoUnavailableFallback verifies that when the new
// program's id cannot be resolved, the confirmation falls back to the
// attached-only check instead of failing a healthy replacement.
func TestXdpReplaceProgInfoUnavailableFallback(t *testing.T) {
	ops := newFakeXdpOps()
	ops.atomicSupport = true
	ops.state = xdpState{progID: 11, flags: nl.XDP_FLAGS_SKB_MODE}
	ops.progIDForFdErr = errors.New("bpf info unavailable")

	const newFd = 81
	err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{Fd: newFd})
	if err != nil {
		t.Fatalf("replacement must fall back to attached-only check, got %v", err)
	}
	if len(ops.applyCalls) != 1 {
		t.Fatalf("want one SETLINK, got %+v", ops.applyCalls)
	}
	if ops.isClosed(newFd) {
		t.Fatalf("new fd must remain open on success")
	}
}

// TestXdpReplaceClosesLibraryOpenedOldFd verifies that an old fd the library
// itself opened from the program id is released on every path, while a
// caller-provided fd is never closed.
func TestXdpReplaceClosesLibraryOpenedOldFd(t *testing.T) {
	ops := newFakeXdpOps()
	ops.atomicSupport = true
	ops.state = xdpState{progID: 11, flags: nl.XDP_FLAGS_SKB_MODE}
	if err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{Fd: 70}); err != nil {
		t.Fatalf("replacement failed: %v", err)
	}
	if len(ops.fdForIDCalls) != 1 {
		t.Fatalf("expected library to open old-program fd, got %v", ops.fdForIDCalls)
	}
	// The opened fd (nextFd started at 100, first allocation is 101) must
	// have been closed.
	if !ops.isClosed(101) {
		t.Fatalf("library-opened old fd 101 must be closed after success")
	}
	if ops.isClosed(70) {
		t.Fatalf("new fd stays open on success")
	}
}

// TestXdpReplaceSnapshotError verifies that a GETLINK failure before the
// mutation still closes the new fd and returns the cause.
func TestXdpReplaceSnapshotError(t *testing.T) {
	ops := newFakeXdpOps()
	snapErr := errors.New("getlink failed")
	ops.stateErr = snapErr
	err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{Fd: 71})
	if !errors.Is(err, snapErr) {
		t.Fatalf("want snapshot error wrapped, got %v", err)
	}
	if len(ops.applyCalls) != 0 {
		t.Fatalf("snapshot failure must not reach SETLINK")
	}
	if !ops.isClosed(71) {
		t.Fatalf("new fd must be closed after snapshot failure")
	}
}

// TestXdpReplaceFdCloseErrorAggregated verifies that an error while closing
// the new fd is joined with the primary failure rather than swallowed.
func TestXdpReplaceFdCloseErrorAggregated(t *testing.T) {
	ops := newFakeXdpOps()
	applyErr := errors.New("setlink failed")
	ops.applyErr = applyErr
	closeErr := errors.New("close failed")
	ops.closeErr = closeErr
	err := replaceXdp(context.Background(), ops, fakeLink(), LinkXdpReplaceOptions{Fd: 72})
	if !errors.Is(err, applyErr) || !errors.Is(err, closeErr) {
		t.Fatalf("want both apply and close errors aggregated, got %v", err)
	}
}

// TestValidateXdpReplaceHappyPath exercises validation with well-formed
// options without entering the state machine.
func TestValidateXdpReplaceHappyPath(t *testing.T) {
	if err := validateXdpReplace(context.Background(), fakeLink(), LinkXdpReplaceOptions{Fd: 1}); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
