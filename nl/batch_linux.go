package nl

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BatchResult is the outcome of a single request of a [NetlinkRequestBatch].
//
// Acked reports whether an ACK (an NLMSG_ERROR message carrying errno 0, or an
// NLMSG_DONE without an error payload) was received for the request. It is
// false for every request that had not been acknowledged when the batch stopped
// reading, including requests whose ACK was still in flight when the context
// was canceled.
type BatchResult struct {
	Seq   uint32
	Err   error
	Acked bool
}

// NetlinkRequestBatch is an ordered set of netlink requests that are sent over
// one socket and whose replies are correlated by sequence number rather than by
// receive order. This allows a caller to submit several changes at once and
// learn exactly which requests the kernel accepted, even when some requests
// fail, when ACKs arrive out of order, or when messages unrelated to the batch
// are queued on a shared socket.
//
// All requests must target the same socket type (e.g. unix.NETLINK_ROUTE).
// Every request is expected to carry NLM_F_ACK so that the kernel answers it
// with an NLMSG_ERROR message.
type NetlinkRequestBatch struct {
	Requests []*NetlinkRequest
}

// NewNetlinkRequestBatch allocates a batch with the given capacity.
func NewNetlinkRequestBatch(capacity int) *NetlinkRequestBatch {
	return &NetlinkRequestBatch{Requests: make([]*NetlinkRequest, 0, capacity)}
}

// Add appends a request to the batch.
func (b *NetlinkRequestBatch) Add(req *NetlinkRequest) {
	b.Requests = append(b.Requests, req)
}

// Execute sends every request in stable order and waits for their ACKs.
//
// The returned results are indexed by request index, so result[i] always
// corresponds to batch.Requests[i] regardless of the order in which the kernel
// replies. Requests are sent until the first send error; the results for
// requests that never left this process have Acked == false and a nil Err, and
// the send error is returned together with the partial results.
//
// Receive stops as soon as every sent request has been acknowledged or ctx is
// canceled. On cancellation the remaining results keep Acked == false and the
// context error is joined into the returned error; messages already queued on
// the socket for another sequence number are left untouched, so a later
// request on the same socket can still consume them.
func (b *NetlinkRequestBatch) Execute(ctx context.Context, sockType int) ([]BatchResult, error) {
	if len(b.Requests) == 0 {
		return nil, nil
	}

	results := make([]BatchResult, len(b.Requests))
	seqToIndex := make(map[uint32]int, len(b.Requests))

	var (
		s            *NetlinkSocket
		sharedSocket bool
	)
	if sh, ok := b.Requests[0].Sockets[sockType]; ok && sh != nil {
		s = sh.Socket
		sharedSocket = true
	}
	if s == nil {
		var err error
		s, err = getNetlinkSocket(sockType)
		if err != nil {
			return results, err
		}
		if err := s.SetSendTimeout(&SocketTimeoutTv); err != nil {
			_ = s.Close()
			return results, err
		}
		if err := s.SetReceiveTimeout(&SocketTimeoutTv); err != nil {
			_ = s.Close()
			return results, err
		}
		if EnableErrorMessageReporting {
			// ignore error, it's non-critical
			_ = s.SetExtAck(true)
		}
		defer s.Close()
	} else {
		s.Lock()
		defer s.Unlock()
	}

	// Stable sequence numbers, one per request, make ACK correlation independent
	// of reply ordering and of messages backlogged on the socket. A handle-owned
	// socket sequences requests from its SocketHandle counter; a short-lived
	// socket uses the package-wide counter, as NewNetlinkRequest would.
	var sh *SocketHandle
	if handles := b.Requests[0].Sockets; handles != nil {
		sh = handles[sockType]
	}
	sent := 0
	for i, req := range b.Requests {
		var seq uint32
		if sh != nil {
			seq = atomic.AddUint32(&sh.Seq, 1)
		} else {
			seq = atomic.AddUint32(&nextSeqNr, 1)
		}
		req.Seq = seq
		results[i].Seq = seq
		seqToIndex[seq] = i

		if err := s.Send(req); err != nil {
			return results, fmt.Errorf("send batch request %d (seq %d): %w", i, seq, err)
		}
		sent++
	}

	acked := 0
	var recvErr error
	for acked < sent {
		if err := ctx.Err(); err != nil {
			recvErr = errors.Join(recvErr, err)
			break
		}

		msgs, _, err := b.receive(ctx, s)
		if err != nil {
			// A timeout while the context is still active means some ACKs will
			// never arrive; report it like any other transport failure so the
			// caller can roll the acknowledged requests back.
			recvErr = errors.Join(recvErr, err)
			break
		}

		for _, m := range msgs {
			index, ok := seqToIndex[m.Header.Seq]
			if !ok {
				// Backlogged message for another request on the shared socket:
				// leave it for the owner of that sequence number.
				if sharedSocket {
					continue
				}
				recvErr = errors.Join(recvErr, fmt.Errorf("unexpected seq nr %d", m.Header.Seq))
				continue
			}
			if results[index].Acked {
				continue
			}

			switch m.Header.Type {
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					recvErr = errors.Join(recvErr, fmt.Errorf("short NLMSG_ERROR for seq %d", m.Header.Seq))
					continue
				}
				errno := int32(NativeEndian().Uint32(m.Data[0:4]))
				if errno == 0 {
					results[index].Acked = true
					acked++
					continue
				}
				results[index].Acked = true
				results[index].Err = annotateNetlinkError(syscall.Errno(-errno), m)
				acked++
			case unix.NLMSG_DONE:
				// NLMSG_DONE might carry an nlmsgerr payload (errno first);
				// without one it is a plain end marker and counts as an ACK.
				if len(m.Data) >= 4 {
					if errno := int32(NativeEndian().Uint32(m.Data[0:4])); errno != 0 {
						results[index].Acked = true
						results[index].Err = annotateNetlinkError(syscall.Errno(-errno), m)
						acked++
						continue
					}
				}
				results[index].Acked = true
				acked++
			}
		}
	}

	return results, recvErr
}

// ExecuteOne sends a single request and waits for its sequence-number
// correlated ACK. It is the single-message form of [NetlinkRequestBatch.Execute]:
// it shares the same correlation and backlog handling and does not require the
// reply to come from pid 0, which makes it usable over connected userspace
// sockets (tests) as well as kernel sockets.
func (req *NetlinkRequest) ExecuteOne(ctx context.Context, sockType int) error {
	batch := &NetlinkRequestBatch{Requests: []*NetlinkRequest{req}}
	results, err := batch.Execute(ctx, sockType)
	if len(results) == 1 && results[0].Err != nil {
		return errors.Join(results[0].Err, err)
	}
	return err
}

// receive waits for one netlink message batch, honoring ctx cancellation
// without changing the socket's configured timeouts.
func (b *NetlinkRequestBatch) receive(ctx context.Context, s *NetlinkSocket) ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error) {
	for {
		// Poll with a short, finite timeout so cancellation is picked up
		// promptly while an idle socket simply loops back into the wait.
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(s.GetFd()), Events: unix.POLLIN}}, 100)
		if err != nil {
			if err == unix.EINTR {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, nil, ctxErr
				}
				continue
			}
			return nil, nil, err
		}
		if n == 0 {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			continue
		}
		return s.Receive()
	}
}

// annotateNetlinkError decodes the extended ACK attributes (NLMSGERR_ATTR_*)
// following an NLMSG_ERROR payload, mirroring the annotation done by
// [NetlinkRequest.executeIter].
func annotateNetlinkError(err error, m syscall.NetlinkMessage) error {
	if m.Header.Flags&unix.NLM_F_ACK_TLVS == 0 || len(m.Data) <= 4 {
		return err
	}

	unreadData := m.Data[4:]
	if m.Header.Flags&unix.NLM_F_CAPPED != 0 {
		// The request payload is capped, just skip the nlmsghdr.
		if len(unreadData) < syscall.SizeofNlMsghdr {
			return err
		}
		unreadData = unreadData[syscall.SizeofNlMsghdr:]
	} else {
		// Skip the entire echoed request message.
		if len(unreadData) < syscall.SizeofNlMsghdr {
			return err
		}
		echoReqH := (*syscall.NlMsghdr)(unsafe.Pointer(&unreadData[0]))
		unreadData = unreadData[nlmAlignOf(int(echoReqH.Len)):]
	}

	for len(unreadData) >= syscall.SizeofRtAttr {
		attr := (*syscall.RtAttr)(unsafe.Pointer(&unreadData[0]))
		if int(attr.Len) < syscall.SizeofRtAttr || int(attr.Len) > len(unreadData) {
			break
		}
		attrData := unreadData[syscall.SizeofRtAttr:attr.Len]
		if attr.Type == NLMSGERR_ATTR_MSG {
			err = fmt.Errorf("%w: %s", err, unix.ByteSliceToString(attrData))
		}
		unreadData = unreadData[rtaAlignOf(int(attr.Len)):]
	}
	return err
}
