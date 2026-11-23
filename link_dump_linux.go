//go:build linux
// +build linux

package netlink

import (
	"errors"
	"fmt"
	"sort"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// LinkRecordError describes a single link record that could not be decoded
// while listing links. Index is the interface index the record belongs to;
// it is 0 when the record was too truncated to even carry an index.
//
// LinkList and LinkListWithContext keep decoding the remaining records when
// they hit a bad one and report every failure as a joined error of
// *LinkRecordError values, so one corrupted record no longer hides the rest
// of the dump.
type LinkRecordError struct {
	Index int
	Err   error
}

func (e *LinkRecordError) Error() string {
	return fmt.Sprintf("netlink: link record for ifindex %d: %v", e.Index, e.Err)
}

func (e *LinkRecordError) Unwrap() error { return e.Err }

// linkDumpKey identifies the stream of generations a single interface
// produces inside one dump: records are grouped by the sequence number of
// the request they answered and by interface index.
type linkDumpKey struct {
	seq   uint32
	index int32
}

// linkDumpAggregator folds the records of one link dump into a single
// consistent view. Nothing is published while the dump is still streaming;
// the caller gets one complete, deduplicated image per interface at the end.
type linkDumpAggregator struct {
	links map[linkDumpKey]Link
	errs  []error
}

func newLinkDumpAggregator() *linkDumpAggregator {
	return &linkDumpAggregator{links: make(map[linkDumpKey]Link)}
}

// add decodes one raw dump record and folds it into the view. Records that
// cannot be decoded are remembered as *LinkRecordError and do not disturb
// the records around them. Later records for the same key replace earlier
// ones, so the newest complete image of an interface wins; a broken record
// never replaces a complete one.
func (a *linkDumpAggregator) add(hdr *unix.NlMsghdr, data []byte) {
	index, err := peekLinkRecordIndex(data)
	if err != nil {
		a.errs = append(a.errs, &LinkRecordError{Err: err})
		return
	}
	if family := data[0]; family != unix.AF_UNSPEC && family != unix.AF_BRIDGE {
		a.errs = append(a.errs, &LinkRecordError{
			Index: int(index),
			Err:   fmt.Errorf("unknown address family %d", family),
		})
		return
	}
	link, err := LinkDeserialize(hdr, data)
	if err != nil {
		a.errs = append(a.errs, &LinkRecordError{Index: int(index), Err: err})
		return
	}
	var seq uint32
	if hdr != nil {
		seq = hdr.Seq
	}
	a.links[linkDumpKey{seq: seq, index: index}] = link
}

// addMessage adapts add to the nl.ExecuteIterFullContext callback shape.
func (a *linkDumpAggregator) addMessage(msg syscall.NetlinkMessage) bool {
	hdr := unix.NlMsghdr(msg.Header)
	a.add(&hdr, msg.Data)
	return true
}

// result returns the aggregated links ordered by interface index, plus a
// joined error holding one *LinkRecordError per record that failed to
// decode (nil when every record decoded).
func (a *linkDumpAggregator) result() ([]Link, error) {
	keys := make([]linkDumpKey, 0, len(a.links))
	for k := range a.links {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].index != keys[j].index {
			return keys[i].index < keys[j].index
		}
		return keys[i].seq < keys[j].seq
	})
	links := make([]Link, 0, len(keys))
	for _, k := range keys {
		links = append(links, a.links[k])
	}
	return links, errors.Join(a.errs...)
}

// peekLinkRecordIndex extracts the interface index from a raw ifinfomsg
// record. It tolerates records truncated right after the index field so
// that the error reported for them can still carry the index.
func peekLinkRecordIndex(data []byte) (int32, error) {
	const indexOff = 4 // family(1) + pad(1) + type(2)
	if len(data) < indexOff+4 {
		return 0, fmt.Errorf("got short ifinfomsg from netlink: %d bytes", len(data))
	}
	return int32(nl.NativeEndian().Uint32(data[indexOff:])), nil
}
