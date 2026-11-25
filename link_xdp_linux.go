package netlink

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// xdpExpectedFdMinKernel is the first kernel that supports
// IFLA_XDP_EXPECTED_FD, which lets the kernel replace an XDP program
// atomically (commit 87b4c6182ab1, "xdp: xdp_channel ops ... expected_fd").
const xdpExpectedFdMinKernel = 5

// xdpExpectedFdMinMajor is the major kernel version (5.9) carrying
// IFLA_XDP_EXPECTED_FD.
const xdpExpectedFdMinMajor = 9

// LinkXdpReplaceOptions controls a rollback-safe XDP program replacement
// carried out by [LinkReplaceXdpFd].
//
// XDP programs have no priority attribute; the attachment state that is
// preserved (and restored on rollback) is the program itself plus its
// attachment flags.
type LinkXdpReplaceOptions struct {
	// Fd is the BPF_PROG_TYPE_XDP program to attach. It must be a valid,
	// open bpf program fd. On an unsuccessful replacement (error,
	// cancellation, timeout) the library closes the fd; on success the fd
	// stays open and the caller remains responsible for it.
	Fd int

	// Flags are the XDP attachment flags, e.g. nl.XDP_FLAGS_SKB_MODE.
	// nl.XDP_FLAGS_UPDATE_IF_NOEXIST is rejected: it forbids replacing an
	// existing attachment, which contradicts a replacement request.
	Flags uint32

	// ExpectedFd optionally names the fd of the program currently expected
	// on the link, enabling the kernel's atomic compare-and-replace
	// (IFLA_XDP_EXPECTED_FD). The zero value (or any negative value) means
	// "not provided": when an older program is attached, the library then
	// obtains a temporary fd for the running program from its id instead.
	//
	// A caller-owned fd passed here is never closed by the library and stays
	// usable for the caller's own rollback handling.
	ExpectedFd int
}

// expectedFdUnset reports whether the caller declined to name the currently
// attached program's fd. Since the zero value is the natural "not provided"
// value of an int field, zero and negative values both mean "unset".
func expectedFdUnset(fd int) bool {
	return fd <= 0
}

// xdpState is the attachment snapshot used to roll a replacement back.
type xdpState struct {
	// progID is the id of the attached program, or 0 when none was attached.
	progID uint32
	// flags are the attachment flags in effect before the replacement.
	flags uint32
}

// xdpOps abstracts the kernel interactions the replacement state machine
// needs. The production implementation drives RTM_SETLINK/RTM_GETLINK over
// the Handle; tests substitute a fake.
type xdpOps interface {
	// currentState snapshots the program id and flags attached to the link.
	currentState(link Link) (xdpState, error)
	// apply sends one RTM_SETLINK. fd == -1 detaches; expectedFd >= 0 adds
	// IFLA_XDP_EXPECTED_FD for an atomic compare-and-replace.
	apply(link Link, fd, expectedFd int, flags uint32) error
	// bpfFdForID opens a new bpf program fd for the program with the given
	// id. The caller owns the returned fd.
	bpfFdForID(id uint32) (int, error)
	// bpfProgIDForFd returns the kernel id of the program behind a bpf fd,
	// used to confirm that the attached program is the requested one.
	bpfProgIDForFd(fd int) (uint32, error)
	// closeFd closes a fd the library itself acquired. It is never called
	// with a caller-owned fd.
	closeFd(fd int) error
	// atomicReplaceSupported reports whether the kernel understands
	// IFLA_XDP_EXPECTED_FD.
	atomicReplaceSupported() bool
}

// LinkReplaceXdpFd atomically, where supported, replaces the XDP program on
// link with the program given in opts.Fd.
//
// The old program is never detached before the new one is confirmed
// attached. On kernels supporting IFLA_XDP_EXPECTED_FD (5.9+) the kernel
// performs the replacement in one compare-and-swap operation; otherwise a
// single RTM_SETLINK carrying the new fd is issued, which the kernel applies
// by replacing the running program in place. If that request nevertheless
// leaves the link without the old program, the original program and flags
// are restored and the resulting errors are joined into the returned error.
//
// On cancellation, timeout or failure the replacement closes opts.Fd itself,
// since the program never became the link's active attachment. On success
// the fd is left open, as with LinkSetXdpFdWithFlags: the kernel holds its
// own reference and closing the fd does not detach the program. A
// caller-owned opts.ExpectedFd is never closed.
func LinkReplaceXdpFd(ctx context.Context, link Link, opts LinkXdpReplaceOptions) error {
	return pkgHandle().LinkReplaceXdpFd(ctx, link, opts)
}

// LinkReplaceXdpFd is the Handle variant of [LinkReplaceXdpFd].
func (h *Handle) LinkReplaceXdpFd(ctx context.Context, link Link, opts LinkXdpReplaceOptions) error {
	if err := validateXdpReplace(ctx, link, opts); err != nil {
		// Validation happens before any kernel state change. The new
		// program never made it onto the link, so close the fd to keep the
		// no-leak contract; only a non-negative fd was a real open fd.
		if opts.Fd >= 0 {
			return errors.Join(err, unix.Close(opts.Fd))
		}
		return err
	}
	return replaceXdp(ctx, handleXdpOps{h: h}, link, opts)
}

// validateXdpReplace checks every input before the kernel state is touched.
func validateXdpReplace(ctx context.Context, link Link, opts LinkXdpReplaceOptions) error {
	if ctx == nil {
		return errors.New("netlink: nil context for XDP replacement")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if link == nil {
		return errors.New("netlink: nil link for XDP replacement")
	}
	base := link.Attrs()
	if base == nil {
		return errors.New("netlink: link without attributes for XDP replacement")
	}
	if opts.Fd < 0 {
		return fmt.Errorf("netlink: invalid new XDP program fd %d", opts.Fd)
	}
	if opts.Flags&^nl.XDP_FLAGS_MASK != 0 {
		return fmt.Errorf("netlink: unknown XDP flags 0x%x", opts.Flags)
	}
	if opts.Flags&nl.XDP_FLAGS_UPDATE_IF_NOEXIST != 0 {
		return errors.New("netlink: XDP_FLAGS_UPDATE_IF_NOEXIST cannot replace an attached XDP program")
	}
	if opts.Flags&(nl.XDP_FLAGS_SKB_MODE|nl.XDP_FLAGS_DRV_MODE) == (nl.XDP_FLAGS_SKB_MODE | nl.XDP_FLAGS_DRV_MODE) {
		return errors.New("netlink: XDP_FLAGS_SKB_MODE and XDP_FLAGS_DRV_MODE are mutually exclusive")
	}
	// Whether a program is actually attached (and thus an ExpectedFd is
	// usable) is established from a fresh GETLINK snapshot in replaceXdp;
	// the link object's cached Xdp block may be stale.
	return nil
}

// replaceXdp is the rollback state machine. It is split off from the Handle
// method so tests can inject a fake xdpOps.
func replaceXdp(ctx context.Context, ops xdpOps, link Link, opts LinkXdpReplaceOptions) (retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// The new fd is closed on every unsuccessful path. On success the
	// kernel keeps its own reference and the fd remains owned by the caller,
	// mirroring LinkSetXdpFdWithFlags.
	replaceSucceeded := false
	defer func() {
		if !replaceSucceeded {
			if err := ops.closeFd(opts.Fd); err != nil && retErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close new XDP fd: %w", err))
			} else if err != nil && retErr == nil {
				retErr = fmt.Errorf("close new XDP fd: %w", err)
			}
		}
	}()

	// Snapshot the running program and flags before changing anything.
	snap, err := ops.currentState(link)
	if err != nil {
		return fmt.Errorf("read current XDP state: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Resolve the fd used for the atomic guard and for rollback. A
	// caller-owned fd is borrowed and never closed; an fd we open ourselves
	// is ours to close once the old program is no longer needed. The fd is
	// resolved whenever an old program is attached, even on kernels without
	// EXPECTED_FD: a partially-failed SETLINK can leave the link bare, in
	// which case rollback needs the fd to re-attach.
	oldFd := opts.ExpectedFd
	oldFdOwned := false
	if snap.progID != 0 && expectedFdUnset(oldFd) {
		oldFd, err = ops.bpfFdForID(snap.progID)
		if err != nil {
			return fmt.Errorf("open fd for attached XDP program %d: %w", snap.progID, err)
		}
		oldFdOwned = true
	}
	defer func() {
		// A fd the library itself acquired is released as soon as the old
		// program is no longer referenced by this replacement. A
		// caller-owned fd (opts.ExpectedFd) is never touched.
		if oldFdOwned {
			_ = ops.closeFd(oldFd)
		}
	}()

	// Prefer the kernel's atomic compare-and-replace when it is available
	// and an old program is attached. With no program attached there is
	// nothing to guard against and a plain attach is atomic already.
	expectedFd := -1
	if snap.progID != 0 && !expectedFdUnset(oldFd) && ops.atomicReplaceSupported() {
		expectedFd = oldFd
	}

	applyErr := ops.apply(link, opts.Fd, expectedFd, opts.Flags)
	if applyErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// Cancellation/timeout: do not trust the kernel state and do
			// not issue further requests. The new fd is closed by the
			// deferred cleanup; caller-owned old fds are left open.
			return ctxErr
		}
		return rollbackXdpReplace(ctx, ops, link, snap, oldFd, applyErr)
	}

	// Confirm the new attachment before declaring success. The link must
	// carry a program, and - when the new program's id can be resolved from
	// its fd - it must be that exact program rather than some other program
	// left behind by a partially-applied request.
	current, err := ops.currentState(link)
	if err != nil {
		return rollbackXdpReplace(ctx, ops, link, snap, oldFd,
			fmt.Errorf("verify XDP replacement: %w", err))
	}
	if !current.attached() {
		return rollbackXdpReplace(ctx, ops, link, snap, oldFd,
			errors.New("XDP program is not attached after replacement"))
	}
	if wantID, idErr := ops.bpfProgIDForFd(opts.Fd); idErr == nil && current.progID != wantID {
		return rollbackXdpReplace(ctx, ops, link, snap, oldFd,
			fmt.Errorf("XDP replacement attached program %d, want %d", current.progID, wantID))
	}

	// Success: the kernel holds its own reference to the new program. Keep
	// the caller's fd open and leave the old program's state to the deferred
	// owned-fd cleanup.
	replaceSucceeded = true
	return nil
}

// rollbackXdpReplace restores the snapshot after a failed replacement and
// joins every error encountered along the way.
func rollbackXdpReplace(ctx context.Context, ops xdpOps, link Link, snap xdpState, oldFd int, cause error) error {
	var errs []error
	if cause != nil {
		errs = append(errs, cause)
	}

	// Nothing was attached before, so restoring means detaching whatever the
	// failed request left behind.
	if snap.progID == 0 {
		if err := ops.apply(link, -1, -1, 0); err != nil {
			errs = append(errs, fmt.Errorf("rollback XDP detach: %w", err))
		}
		return errors.Join(errs...)
	}

	// Re-attach the original program with its original flags. Normally
	// oldFd was resolved before the SETLINK, but re-open it defensively if
	// it is not at hand (e.g. a future caller path that skipped resolution).
	// The program stays referenced by this fd, so the re-attach works even
	// if the failed request detached it.
	if expectedFdUnset(oldFd) {
		opened, err := ops.bpfFdForID(snap.progID)
		if err != nil {
			errs = append(errs, fmt.Errorf("reopen fd for XDP program %d during rollback: %w", snap.progID, err))
			return errors.Join(errs...)
		}
		oldFd = opened
		defer func() { _ = ops.closeFd(opened) }()
	}
	if err := ops.apply(link, oldFd, -1, snap.flags); err != nil {
		errs = append(errs, fmt.Errorf("rollback XDP attach: %w", err))
		return errors.Join(errs...)
	}

	// Verify the restore actually took.
	current, err := ops.currentState(link)
	if err != nil {
		errs = append(errs, fmt.Errorf("verify XDP rollback: %w", err))
		return errors.Join(errs...)
	}
	if current.progID != snap.progID {
		errs = append(errs, fmt.Errorf("XDP rollback restored program %d, want %d", current.progID, snap.progID))
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		errs = append(errs, ctxErr)
	}
	return errors.Join(errs...)
}

func (s xdpState) attached() bool {
	return s.progID != 0
}

// --- production xdpOps backed by a Handle ---

type handleXdpOps struct {
	h *Handle
}

func (ops handleXdpOps) currentState(link Link) (xdpState, error) {
	base := link.Attrs()
	ops.h.ensureIndex(base)
	current, err := ops.h.LinkByIndex(base.Index)
	if err != nil {
		return xdpState{}, err
	}
	state := xdpState{}
	if xdp := current.Attrs().Xdp; xdp != nil {
		state.flags = xdp.Flags
		if xdp.Attached && xdp.ProgId != 0 {
			state.progID = xdp.ProgId
		}
	}
	return state, nil
}

func (ops handleXdpOps) apply(link Link, fd, expectedFd int, flags uint32) error {
	base := link.Attrs()
	ops.h.ensureIndex(base)
	req := ops.h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)
	addXdpReplaceAttrs(req, fd, expectedFd, flags)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func (ops handleXdpOps) closeFd(fd int) error {
	return unix.Close(fd)
}

func (ops handleXdpOps) atomicReplaceSupported() bool {
	kernel, major, err := linuxKernelVersion()
	if err != nil {
		return false
	}
	return kernel > xdpExpectedFdMinKernel ||
		(kernel == xdpExpectedFdMinKernel && major >= xdpExpectedFdMinMajor)
}

// linuxKernelVersion returns the major and minor numbers from the running
// kernel release, e.g. (5, 9) for "5.9.0-...".
func linuxKernelVersion() (int, int, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return 0, 0, err
	}
	release := make([]byte, 0, len(uts.Release))
	for _, b := range uts.Release {
		if b == 0 {
			break
		}
		release = append(release, byte(b))
	}
	var major, minor int
	if _, err := fmt.Sscanf(string(release), "%d.%d", &major, &minor); err != nil {
		return 0, 0, fmt.Errorf("parse kernel release %q: %w", string(release), err)
	}
	return major, minor, nil
}

// bpfAttrProgGetFdByID mirrors the first words of the kernel bpf_attr union
// used by BPF_PROG_GET_FD_BY_ID: bpf_attr.prog_id occupies the first u32.
type bpfAttrProgGetFdByID struct {
	ProgID uint32
	_      uint32
	_      [120]byte
}

func (ops handleXdpOps) bpfFdForID(id uint32) (int, error) {
	attr := bpfAttrProgGetFdByID{ProgID: id}
	fd, _, errno := unix.Syscall(unix.SYS_BPF,
		uintptr(unix.BPF_PROG_GET_FD_BY_ID),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

// bpfAttrGetInfo mirrors the bpf_attr fields used by
// BPF_OBJ_GET_INFO_BY_FD: bpf_fd (u32), info_len (u32) and the info pointer
// (u64), all at the start of the bpf_attr union.
type bpfAttrGetInfo struct {
	Fd      uint32
	InfoLen uint32
	InfoPtr uintptr
	_       [112]byte
}

// bpfProgInfo mirrors the leading fields of struct bpf_prog_info; the
// program id is the second u32, right after the type.
type bpfProgInfo struct {
	Type uint32
	ID   uint32
	_    [116]byte
}

func (ops handleXdpOps) bpfProgIDForFd(fd int) (uint32, error) {
	var info bpfProgInfo
	attr := bpfAttrGetInfo{
		Fd:      uint32(fd),
		InfoLen: uint32(unsafe.Sizeof(info)),
		InfoPtr: uintptr(unsafe.Pointer(&info)),
	}
	if _, _, errno := unix.Syscall(unix.SYS_BPF,
		uintptr(unix.BPF_OBJ_GET_INFO_BY_FD),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr)); errno != 0 {
		return 0, errno
	}
	return info.ID, nil
}

// addXdpReplaceAttrs serializes the IFLA_XDP nest for a replacement request.
// fd == -1 encodes a detach; expectedFd >= 0 adds IFLA_XDP_EXPECTED_FD so
// the kernel only swaps the program if the expected one is still attached.
func addXdpReplaceAttrs(req *nl.NetlinkRequest, fd, expectedFd int, flags uint32) {
	attrs := nl.NewRtAttr(unix.IFLA_XDP|unix.NLA_F_NESTED, nil)

	b := make([]byte, 4)
	native.PutUint32(b, uint32(fd))
	attrs.AddRtAttr(nl.IFLA_XDP_FD, b)

	if flags != 0 {
		b := make([]byte, 4)
		native.PutUint32(b, flags)
		attrs.AddRtAttr(nl.IFLA_XDP_FLAGS, b)
	}

	if expectedFd >= 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(expectedFd))
		attrs.AddRtAttr(nl.IFLA_XDP_EXPECTED_FD, b)
	}

	req.AddData(attrs)
}
