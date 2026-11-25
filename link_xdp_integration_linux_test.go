package netlink

import (
	"context"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// These tests drive the real RTM_SETLINK/RTM_GETLINK and bpf syscall paths.
// They require root (or CAP_BPF/CAP_NET_ADMIN) and skip otherwise, matching
// the rest of the netlink integration suite.

// setupXdpTestLink creates a fresh netns and a dummy link to attach XDP
// programs to. Generic (skb) XDP works on dummy links.
func setupXdpTestLink(t *testing.T) Link {
	t.Helper()
	t.Cleanup(setUpNetlinkTest(t))

	link := &Dummy{LinkAttrs: LinkAttrs{Name: "xdptest"}}
	if err := LinkAdd(link); err != nil {
		t.Skipf("dummy link unavailable, skipping XDP integration test: %v", err)
	}
	t.Cleanup(func() { _ = LinkDel(link) })
	return link
}

func loadXdpProgOrSkip(t *testing.T, ret uint32) int {
	t.Helper()
	fd, err := loadSimpleBpf(BPF_PROG_TYPE_XDP, ret)
	if err != nil {
		t.Skipf("loading bpf XDP program failed, skipping: %v", err)
	}
	return fd
}

func xdpAttached(t *testing.T, link Link) *LinkXdp {
	t.Helper()
	current, err := LinkByIndex(link.Attrs().Index)
	if err != nil {
		t.Fatalf("get link: %v", err)
	}
	xdp := current.Attrs().Xdp
	if xdp == nil {
		t.Fatalf("link reports no XDP block at all")
	}
	return xdp
}

// TestLinkReplaceXdpIntegration verifies the full replacement flow against a
// real kernel, including the legacy attach/detach API compatibility.
func TestLinkReplaceXdpIntegration(t *testing.T) {
	link := setupXdpTestLink(t)

	oldFd := loadXdpProgOrSkip(t, 2 /*XDP_PASS*/)
	t.Cleanup(func() { _ = unix.Close(oldFd) })
	newFd := loadXdpProgOrSkip(t, 2)
	t.Cleanup(func() { _ = unix.Close(newFd) })

	// Legacy attach API still works and is the baseline for replacement.
	if err := LinkSetXdpFdWithFlags(link, oldFd, nl.XDP_FLAGS_SKB_MODE); err != nil {
		t.Skipf("generic XDP attach unsupported on this link/kernel: %v", err)
	}
	t.Cleanup(func() { _ = LinkSetXdpFd(link, -1) })

	before := xdpAttached(t, link)
	if !before.Attached || before.ProgId == 0 {
		t.Fatalf("baseline program not attached: %+v", before)
	}

	// Rollback-safe replacement with a fresh program id.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := LinkReplaceXdpFd(ctx, link, LinkXdpReplaceOptions{
		Fd:    newFd,
		Flags: nl.XDP_FLAGS_SKB_MODE,
	}); err != nil {
		t.Fatalf("replacement failed: %v", err)
	}

	after := xdpAttached(t, link)
	if !after.Attached {
		t.Fatalf("no program attached after replacement")
	}
	if after.ProgId == before.ProgId {
		t.Fatalf("program id unchanged after replacement: %d", after.ProgId)
	}
	if after.Flags&nl.XDP_FLAGS_SKB_MODE == 0 {
		t.Fatalf("skb mode flag lost after replacement: %+v", after)
	}

	// Legacy detach API still works and leaves the link unprotected.
	if err := LinkSetXdpFd(link, -1); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if gone := xdpAttached(t, link); gone.Attached {
		t.Fatalf("program still attached after detach: %+v", gone)
	}
}

// TestLinkReplaceXdpRejectsBadFlags verifies validation happens before any
// kernel state change and the rejected new fd is closed by the library.
func TestLinkReplaceXdpRejectsBadFlags(t *testing.T) {
	link := setupXdpTestLink(t)
	oldFd := loadXdpProgOrSkip(t, 2)
	t.Cleanup(func() { _ = unix.Close(oldFd) })
	newFd := loadXdpProgOrSkip(t, 2)

	if err := LinkSetXdpFdWithFlags(link, oldFd, nl.XDP_FLAGS_SKB_MODE); err != nil {
		t.Skipf("generic XDP attach unsupported: %v", err)
	}
	t.Cleanup(func() { _ = LinkSetXdpFd(link, -1) })
	before := xdpAttached(t, link)

	err := LinkReplaceXdpFd(context.Background(), link, LinkXdpReplaceOptions{
		Fd:    newFd,
		Flags: nl.XDP_FLAGS_UPDATE_IF_NOEXIST,
	})
	if err == nil {
		t.Fatalf("expected UPDATE_IF_NOEXIST to be rejected")
	}

	// The new fd must have been closed by the failed replacement.
	if _, statErr := unix.FcntlInt(uintptr(newFd), unix.F_GETFD, 0); statErr == nil {
		t.Fatalf("rejected new fd was not closed")
	}
	// The old program must be untouched.
	after := xdpAttached(t, link)
	if !after.Attached || after.ProgId != before.ProgId {
		t.Fatalf("old attachment changed after rejected replacement: before=%+v after=%+v", before, after)
	}
}

// TestLinkReplaceXdpRollbackOnBadFd verifies that a replacement whose new fd
// is invalid never leaves the link unprotected: the original program stays
// attached and the error is returned.
func TestLinkReplaceXdpRollbackOnBadFd(t *testing.T) {
	link := setupXdpTestLink(t)
	oldFd := loadXdpProgOrSkip(t, 2)
	t.Cleanup(func() { _ = unix.Close(oldFd) })

	if err := LinkSetXdpFdWithFlags(link, oldFd, nl.XDP_FLAGS_SKB_MODE); err != nil {
		t.Skipf("generic XDP attach unsupported: %v", err)
	}
	t.Cleanup(func() { _ = LinkSetXdpFd(link, -1) })
	before := xdpAttached(t, link)

	// /dev/null is a valid open fd but not a bpf program; the SETLINK must
	// reject it without touching the running attachment.
	badFd, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	replaceErr := LinkReplaceXdpFd(context.Background(), link, LinkXdpReplaceOptions{
		Fd:    badFd,
		Flags: nl.XDP_FLAGS_SKB_MODE,
	})
	if replaceErr == nil {
		t.Fatalf("expected replacement with non-bpf fd to fail")
	}

	after := xdpAttached(t, link)
	if !after.Attached {
		t.Fatalf("link left unprotected after failed replacement")
	}
	if after.ProgId != before.ProgId {
		t.Fatalf("program changed despite failed replacement: before=%d after=%d", before.ProgId, after.ProgId)
	}
	if after.Flags != before.Flags {
		t.Fatalf("flags changed despite failed replacement: before=%d after=%d", before.Flags, after.Flags)
	}
}

// TestLinkReplaceXdpCanceledContext verifies that a context already
// canceled before the call aborts without a SETLINK and closes the new fd.
func TestLinkReplaceXdpCanceledContext(t *testing.T) {
	link := setupXdpTestLink(t)
	oldFd := loadXdpProgOrSkip(t, 2)
	t.Cleanup(func() { _ = unix.Close(oldFd) })
	newFd := loadXdpProgOrSkip(t, 2)

	if err := LinkSetXdpFdWithFlags(link, oldFd, nl.XDP_FLAGS_SKB_MODE); err != nil {
		t.Skipf("generic XDP attach unsupported: %v", err)
	}
	t.Cleanup(func() { _ = LinkSetXdpFd(link, -1) })
	before := xdpAttached(t, link)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := LinkReplaceXdpFd(ctx, link, LinkXdpReplaceOptions{Fd: newFd, Flags: nl.XDP_FLAGS_SKB_MODE})
	if err == nil {
		t.Fatalf("expected context.Canceled")
	}

	if _, statErr := unix.FcntlInt(uintptr(newFd), unix.F_GETFD, 0); statErr == nil {
		t.Fatalf("new fd was not closed after canceled replacement")
	}
	after := xdpAttached(t, link)
	if !after.Attached || after.ProgId != before.ProgId {
		t.Fatalf("old attachment changed after canceled replacement: before=%+v after=%+v", before, after)
	}
}
