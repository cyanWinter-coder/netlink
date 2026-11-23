package nl

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// skipUnlessCapNetAdmin skips tests that need to connect two userspace
// netlink ports, an operation gated by CAP_NET_ADMIN.
func skipUnlessCapNetAdmin(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("test requires CAP_NET_ADMIN (root)")
	}
}

// newTestBatchSocket wires one end of a connected netlink socket pair into a
// SocketHandle and returns the peer end used to answer requests.
func newTestBatchSocket(t *testing.T, protocol int) (*SocketHandle, *NetlinkSocket) {
	t.Helper()
	skipUnlessCapNetAdmin(t)

	client, peer, err := NewNetlinkSocketPairForTest(protocol)
	if err != nil {
		t.Fatalf("create socket pair: %v", err)
	}
	t.Cleanup(func() {
		client.Close()
		peer.Close()
	})
	tv := unix.NsecToTimeval(time.Hour.Nanoseconds())
	if err := client.SetReceiveTimeout(&tv); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReceiveTimeout(&tv); err != nil {
		t.Fatal(err)
	}
	// Backlogged tests queue several ACKs before the client reads; the default
	// buffer can drop them, so request a large one and don't fail if the cap
	// enforced by rmem_max is smaller.
	_ = client.SetReceiveBufferSize(1<<20, false)
	_ = peer.SetReceiveBufferSize(1<<20, false)
	return &SocketHandle{Socket: client}, peer
}

func newBatchRequest(handle *SocketHandle, protocol int) *NetlinkRequest {
	req := NewNetlinkRequest(unix.RTM_NEWROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	req.Sockets = map[int]*SocketHandle{protocol: handle}
	return req
}

// readRequest receives one message on the peer and returns its header.
func readRequest(t *testing.T, peer *NetlinkSocket) syscall.NlMsghdr {
	t.Helper()
	msgs, _, err := peer.Receive()
	if err != nil {
		t.Fatalf("peer receive: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	return msgs[0].Header
}

// writeAck sends an NLMSG_ERROR answer for seq. errno 0 is a plain ACK, any
// other errno is reported as that error.
func writeAck(t *testing.T, peer *NetlinkSocket, seq uint32, errno int32) {
	t.Helper()
	payload := make([]byte, 4)
	NativeEndian().PutUint32(payload, uint32(errno))
	msg := syscallNetlinkError(seq, payload)
	if err := peer.Send(msg); err != nil {
		t.Fatalf("peer send ack: %v", err)
	}
}

// writeRaw sends a prebuilt netlink message from the peer.
func writeRaw(t *testing.T, peer *NetlinkSocket, hdr syscall.NlMsghdr, payload []byte) {
	t.Helper()
	msg := &NetlinkRequest{NlMsghdr: unix.NlMsghdr(hdr), RawData: payload}
	if err := peer.Send(msg); err != nil {
		t.Fatalf("peer send: %v", err)
	}
}

func syscallNetlinkError(seq uint32, payload []byte) *NetlinkRequest {
	return &NetlinkRequest{
		NlMsghdr: unix.NlMsghdr{
			Len:   uint32(unix.SizeofNlMsghdr + len(payload)),
			Type:  unix.NLMSG_ERROR,
			Flags: 0,
			Seq:   seq,
			Pid:   0,
		},
		RawData: payload,
	}
}

// TestBatchExecuteAckCorrelation verifies ACKs are matched by sequence number
// in stable index order, including when they arrive out of order.
func TestBatchExecuteAckCorrelation(t *testing.T) {
	handle, peer := newTestBatchSocket(t, unix.NETLINK_ROUTE)

	const n = 4
	batch := NewNetlinkRequestBatch(n)
	for range n {
		batch.Add(newBatchRequest(handle, unix.NETLINK_ROUTE))
	}

	go func() {
		seqs := make([]uint32, 0, n)
		for len(seqs) < n {
			msgs, _, rerr := peer.Receive()
			if rerr != nil {
				return
			}
			for _, m := range msgs {
				seqs = append(seqs, m.Header.Seq)
			}
		}
		// Reply in reverse order, with item 2 carrying EEXIST.
		for i := n - 1; i >= 0; i-- {
			errno := int32(0)
			if i == 2 {
				errno = -int32(unix.EEXIST)
			}
			writeAck(t, peer, seqs[i], errno)
		}
	}()

	results, err := batch.Execute(context.Background(), unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(results) != n {
		t.Fatalf("expected %d results, got %d", n, len(results))
	}
	for i, r := range results {
		if !r.Acked {
			t.Errorf("result %d not acked", i)
		}
	}
	if !errors.Is(results[2].Err, unix.EEXIST) {
		t.Errorf("result 2: expected EEXIST, got %v", results[2].Err)
	}
	for i := range n {
		if i == 2 {
			continue
		}
		if results[i].Err != nil {
			t.Errorf("result %d: expected success, got %v", i, results[i].Err)
		}
	}
}

// TestBatchExecuteIgnoresBackloggedMessages verifies messages queued on the
// socket for other sequence numbers do not get attributed to the batch.
func TestBatchExecuteIgnoresBackloggedMessages(t *testing.T) {
	handle, peer := newTestBatchSocket(t, unix.NETLINK_ROUTE)

	batch := NewNetlinkRequestBatch(2)
	batch.Add(newBatchRequest(handle, unix.NETLINK_ROUTE))
	batch.Add(newBatchRequest(handle, unix.NETLINK_ROUTE))

	go func() {
		seqs := make([]uint32, 0, 2)
		for len(seqs) < 2 {
			msgs, _, rerr := peer.Receive()
			if rerr != nil {
				return
			}
			for _, m := range msgs {
				seqs = append(seqs, m.Header.Seq)
			}
		}
		// A backlogged ACK for a sequence number nobody is waiting on, plus a
		// stray data message, must be ignored.
		writeAck(t, peer, seqs[0]+1000, 0)
		writeRaw(t, peer, syscall.NlMsghdr{
			Len:  uint32(unix.SizeofNlMsghdr),
			Type: unix.RTM_NEWROUTE,
			Seq:  seqs[0] + 2000,
		}, nil)
		writeAck(t, peer, seqs[1], 0)
		writeAck(t, peer, seqs[0], 0)
	}()

	results, err := batch.Execute(context.Background(), unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if !r.Acked || r.Err != nil {
			t.Errorf("result %d: expected clean ack, got acked=%v err=%v", i, r.Acked, r.Err)
		}
	}

	// The backlogged messages stay on the socket: a subsequent batch reuses
	// the sequence counter and still only counts its own ACKs.
	second := NewNetlinkRequestBatch(1)
	second.Add(newBatchRequest(handle, unix.NETLINK_ROUTE))
	go func() {
		hdr := readRequest(t, peer)
		writeAck(t, peer, hdr.Seq, 0)
	}()
	results, err = second.Execute(context.Background(), unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("second execute: %v", err)
	}
	if len(results) != 1 || !results[0].Acked || results[0].Err != nil {
		t.Fatalf("unexpected second batch result: %+v", results)
	}
}

// TestBatchExecuteCanceled verifies that canceling the context stops reading,
// marks unacknowledged requests as such, and leaves the socket usable for the
// ACKs that were already in flight.
func TestBatchExecuteCanceled(t *testing.T) {
	handle, peer := newTestBatchSocket(t, unix.NETLINK_ROUTE)

	const n = 3
	batch := NewNetlinkRequestBatch(n)
	for range n {
		batch.Add(newBatchRequest(handle, unix.NETLINK_ROUTE))
	}

	// seqCh hands the observed sequence numbers from the single peer goroutine
	// to the test goroutine, so no slice is touched concurrently.
	seqCh := make(chan uint32, n)
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		seen := 0
		answered := false
		for seen < n {
			msgs, _, rerr := peer.Receive()
			if rerr != nil {
				return
			}
			for _, m := range msgs {
				seqCh <- m.Header.Seq
				seen++
				// Only the first request is answered; the rest stay silent
				// until the batch gives up.
				if !answered {
					writeAck(t, peer, m.Header.Seq, 0)
					answered = true
				}
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	results, err := batch.Execute(ctx, unix.NETLINK_ROUTE)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if len(results) != n {
		t.Fatalf("expected %d results, got %d", n, len(results))
	}
	if !results[0].Acked || results[0].Err != nil {
		t.Errorf("result 0: expected clean ack, got %+v", results[0])
	}
	for i := 1; i < n; i++ {
		if results[i].Acked {
			t.Errorf("result %d should not be acked after cancellation", i)
		}
	}

	// Drain the sequence numbers observed by the peer and answer the pending
	// requests from the same goroutine context, then confirm a new batch on the
	// same handle completes.
	seqs := make([]uint32, 0, n)
	for i := 0; i < n; i++ {
		seqs = append(seqs, <-seqCh)
	}
	<-peerDone
	for _, seq := range seqs[1:] {
		writeAck(t, peer, seq, 0)
	}

	next := NewNetlinkRequestBatch(1)
	next.Add(newBatchRequest(handle, unix.NETLINK_ROUTE))
	go func() {
		msgs, _, rerr := peer.Receive()
		if rerr != nil {
			return
		}
		for _, m := range msgs {
			writeAck(t, peer, m.Header.Seq, 0)
		}
	}()
	results, err = next.Execute(context.Background(), unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("execute after cancel: %v", err)
	}
	if !results[0].Acked || results[0].Err != nil {
		t.Fatalf("unexpected result after cancel: %+v", results)
	}
}

// TestBatchExecuteSendError verifies a send failure returns partial results
// with the unsent requests unacked.
func TestBatchExecuteSendError(t *testing.T) {
	skipUnlessCapNetAdmin(t)

	client, peer, err := NewNetlinkSocketPairForTest(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("create socket pair: %v", err)
	}
	peer.Close() // closing the peer makes later sends fail with EPIPE/ECONNRESET
	t.Cleanup(func() { client.Close() })

	handle := &SocketHandle{Socket: client}
	const n = 8
	batch := NewNetlinkRequestBatch(n)
	for range n {
		batch.Add(newBatchRequest(handle, unix.NETLINK_ROUTE))
	}

	results, err := batch.Execute(context.Background(), unix.NETLINK_ROUTE)
	if err == nil {
		t.Fatal("expected a send error, got nil")
	}
	if len(results) != n {
		t.Fatalf("expected %d result slots, got %d", n, len(results))
	}
	acked := 0
	for _, r := range results {
		if r.Acked {
			acked++
		}
	}
	if acked != 0 {
		t.Fatalf("no ACK expected when the peer is gone, got %d acked", acked)
	}
}

// TestBatchExecuteEmpty verifies an empty batch is a no-op.
func TestBatchExecuteEmpty(t *testing.T) {
	batch := NewNetlinkRequestBatch(0)
	results, err := batch.Execute(context.Background(), unix.NETLINK_ROUTE)
	if err != nil || results != nil {
		t.Fatalf("expected nil, nil, got %v, %v", results, err)
	}
}
