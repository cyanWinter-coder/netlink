//go:build linux
// +build linux

package netlink

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// buildLinkRecord serializes a minimal RTM_NEWLINK record for ifindex index.
func buildLinkRecord(index int32, name string, mtu uint32) []byte {
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = index
	msg.Type = unix.ARPHRD_ETHER
	data := msg.Serialize()
	data = append(data, nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(name)).Serialize()...)
	data = append(data, nl.NewRtAttr(unix.IFLA_MTU, nl.Uint32Attr(mtu)).Serialize()...)
	return data
}

func dumpMessage(seq uint32, data []byte) syscall.NetlinkMessage {
	return syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  unix.RTM_NEWLINK,
			Flags: unix.NLM_F_MULTI,
			Seq:   seq,
		},
		Data: data,
	}
}

func linkByIndexFromList(t *testing.T, links []Link, index int) Link {
	t.Helper()
	for _, l := range links {
		if l.Attrs().Index == index {
			return l
		}
	}
	t.Fatalf("link with ifindex %d not found in %v", index, links)
	return nil
}

func TestLinkDumpAggregatorOutOfOrderGenerations(t *testing.T) {
	agg := newLinkDumpAggregator()

	// First pass over the table.
	agg.addMessage(dumpMessage(7, buildLinkRecord(1, "eth0", 1500)))
	agg.addMessage(dumpMessage(7, buildLinkRecord(2, "eth1", 1500)))
	// The interface changed mid-dump and the kernel re-reported it,
	// interleaved with records for other interfaces.
	agg.addMessage(dumpMessage(7, buildLinkRecord(3, "eth2", 1500)))
	agg.addMessage(dumpMessage(7, buildLinkRecord(1, "eth0", 9000)))

	links, err := agg.result()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(links) != 3 {
		t.Fatalf("expected 3 deduplicated links, got %d: %v", len(links), links)
	}
	// Deterministic output: sorted by ifindex, no intermediate generations.
	for i := 1; i < len(links); i++ {
		if links[i-1].Attrs().Index >= links[i].Attrs().Index {
			t.Fatalf("links not sorted by ifindex: %v", links)
		}
	}
	if got := linkByIndexFromList(t, links, 1).Attrs().MTU; got != 9000 {
		t.Fatalf("expected newest generation of ifindex 1 (mtu 9000), got mtu %d", got)
	}
}

func TestLinkDumpAggregatorGenerationsAcrossSeqs(t *testing.T) {
	agg := newLinkDumpAggregator()

	// A retried dump answers with a fresh sequence number; records from the
	// two attempts must not be merged into one half-old half-new image.
	agg.addMessage(dumpMessage(7, buildLinkRecord(1, "eth0", 1500)))
	agg.addMessage(dumpMessage(8, buildLinkRecord(1, "eth0", 9000)))

	links, err := agg.result()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("expected one image per sequence number, got %d", len(links))
	}
}

func TestLinkDumpAggregatorTruncatedRecord(t *testing.T) {
	agg := newLinkDumpAggregator()

	agg.addMessage(dumpMessage(7, buildLinkRecord(1, "eth0", 1500)))

	// A record whose last attribute is cut short must not abort the dump.
	broken := buildLinkRecord(2, "eth1", 1500)
	broken = broken[:len(broken)-2]
	agg.addMessage(dumpMessage(7, broken))

	// A truncated newer generation must not replace a complete older one.
	agg.addMessage(dumpMessage(7, buildLinkRecord(3, "eth2", 1500)))
	brokenNewer := buildLinkRecord(3, "eth2", 9000)
	brokenNewer = brokenNewer[:len(brokenNewer)-2]
	agg.addMessage(dumpMessage(7, brokenNewer))

	links, err := agg.result()
	if err == nil {
		t.Fatal("expected an indexed error for the truncated records")
	}
	var recErr *LinkRecordError
	if !errors.As(err, &recErr) {
		t.Fatalf("expected a *LinkRecordError, got %T: %v", err, err)
	}
	if recErr.Index != 2 {
		t.Fatalf("expected error for ifindex 2, got %d", recErr.Index)
	}
	if len(links) != 2 {
		t.Fatalf("expected 2 links despite the broken records, got %d: %v", len(links), links)
	}
	if got := linkByIndexFromList(t, links, 3).Attrs().MTU; got != 1500 {
		t.Fatalf("broken newer generation replaced the complete image; mtu = %d", got)
	}
}

func TestLinkDumpAggregatorUnknownFamily(t *testing.T) {
	agg := newLinkDumpAggregator()

	agg.addMessage(dumpMessage(7, buildLinkRecord(1, "eth0", 1500)))

	unknown := buildLinkRecord(2, "eth1", 1500)
	unknown[0] = 0x7f // not AF_UNSPEC / AF_BRIDGE
	agg.addMessage(dumpMessage(7, unknown))

	links, err := agg.result()
	if err == nil {
		t.Fatal("expected an indexed error for the unknown family")
	}
	var recErr *LinkRecordError
	if !errors.As(err, &recErr) {
		t.Fatalf("expected a *LinkRecordError, got %T: %v", err, err)
	}
	if recErr.Index != 2 {
		t.Fatalf("expected error for ifindex 2, got %d", recErr.Index)
	}
	if len(links) != 1 || links[0].Attrs().Index != 1 {
		t.Fatalf("expected only ifindex 1 to survive, got %v", links)
	}
}

func TestLinkDumpAggregatorShortRecord(t *testing.T) {
	agg := newLinkDumpAggregator()

	// Too short to even carry an ifindex: reported without one, and the
	// records around it are still processed independently.
	agg.addMessage(dumpMessage(7, []byte{unix.AF_UNSPEC, 0, 1}))
	agg.addMessage(dumpMessage(7, buildLinkRecord(1, "eth0", 1500)))

	links, err := agg.result()
	if err == nil {
		t.Fatal("expected an error for the short record")
	}
	var recErr *LinkRecordError
	if !errors.As(err, &recErr) {
		t.Fatalf("expected a *LinkRecordError, got %T: %v", err, err)
	}
	if recErr.Index != 0 {
		t.Fatalf("expected index 0 for an unidentifiable record, got %d", recErr.Index)
	}
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
}

func TestLinkListWithContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	links, err := LinkListWithContext(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if links != nil {
		t.Fatalf("expected no links on cancellation, got %v", links)
	}
}

func TestLinkListWithContextConsistentView(t *testing.T) {
	links, err := LinkListWithContext(context.Background())
	if err != nil {
		t.Fatalf("LinkListWithContext failed: %v", err)
	}
	if len(links) == 0 {
		t.Fatal("expected at least one link")
	}
	seen := make(map[int]bool, len(links))
	for i, l := range links {
		idx := l.Attrs().Index
		if seen[idx] {
			t.Fatalf("duplicate ifindex %d in LinkList result", idx)
		}
		seen[idx] = true
		if i > 0 && links[i-1].Attrs().Index >= idx {
			t.Fatalf("links not sorted by ifindex: %v", links)
		}
	}
}

func TestLinkListConcurrentChurn(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	const linkCount = 1000
	links := make([]Link, 0, linkCount)
	for i := range linkCount {
		link := &Dummy{LinkAttrs{Name: fmt.Sprintf("churn%04d", i)}}
		if err := LinkAdd(link); err != nil {
			t.Fatalf("failed to add link %d: %v", i, err)
		}
		links = append(links, link)
	}
	t.Cleanup(func() {
		for _, link := range links {
			_ = LinkDel(link)
		}
	})

	dumpHandle, err := NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dumpHandle.Close() })

	churnHandle, err := NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { churnHandle.Close() })

	churn := churnLink(churnHandle)
	defer func() {
		if err := churn.stopAndWait(); err != nil {
			t.Error(err)
		}
	}()

	// Make sure the churn actually interrupts dumps in this environment,
	// otherwise the consistency checks below would not exercise anything.
	if err := waitForExecuteIterDumpInterrupted(dumpHandle, churn); err != nil {
		t.Fatal(err)
	}

	sawInterrupted := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		list, err := dumpHandle.LinkList()
		switch {
		case err == nil:
			// stable dump
		case errors.Is(err, ErrDumpInterrupted):
			sawInterrupted = true
		default:
			t.Fatalf("unexpected LinkList error: %v", err)
		}

		seen := make(map[int]bool, len(list))
		for i, l := range list {
			idx := l.Attrs().Index
			if seen[idx] {
				t.Fatalf("duplicate ifindex %d in LinkList result during churn", idx)
			}
			seen[idx] = true
			if i > 0 && list[i-1].Attrs().Index >= idx {
				t.Fatalf("LinkList result not sorted by ifindex during churn")
			}
		}
		if err := churn.errValue(); err != nil {
			t.Fatal(err)
		}
	}
	if !sawInterrupted {
		t.Fatal("churn did not interrupt any dump; consistency checks were not exercised")
	}
}

func TestLinkListWithContextCancelDuringDump(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	const linkCount = 1000
	links := make([]Link, 0, linkCount)
	for i := range linkCount {
		link := &Dummy{LinkAttrs{Name: fmt.Sprintf("cancel%04d", i)}}
		if err := LinkAdd(link); err != nil {
			t.Fatalf("failed to add link %d: %v", i, err)
		}
		links = append(links, link)
	}
	t.Cleanup(func() {
		for _, link := range links {
			_ = LinkDel(link)
		}
	})

	// Cancel the context while the dump is streaming. The dump must stop
	// reading kernel messages and report the cancellation; a dump that
	// finished before the cancellation is fine too.
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(time.Millisecond, cancel)
	list, err := LinkListWithContext(ctx)
	if err == nil {
		if len(list) == 0 {
			t.Fatal("expected links from a completed dump")
		}
		return
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if list != nil {
		t.Fatalf("expected buffered messages to be released on cancel, got %d links", len(list))
	}
}
