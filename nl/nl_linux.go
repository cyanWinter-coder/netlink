// Package nl has low level primitives for making Netlink calls.
package nl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/cpu"
	"golang.org/x/sys/unix"
)

const (
	// Family type definitions
	FAMILY_ALL  = unix.AF_UNSPEC
	FAMILY_V4   = unix.AF_INET
	FAMILY_V6   = unix.AF_INET6
	FAMILY_MPLS = unix.AF_MPLS
	// Arbitrary set value (greater than default 4k) to allow receiving
	// from kernel more verbose messages e.g. for statistics,
	// tc rules or filters, or other more memory requiring data.
	RECEIVE_BUFFER_SIZE = 65536
	// Kernel netlink pid
	PidKernel     uint32 = 0
	SizeofCnMsgOp        = 0x18
)

const (
	NHA_RES_GROUP  = 12 // Nest containing attributes specific to resilient groups
	NHA_RES_BUCKET = 13 // Nest containing attributes specific to buckets
)

const (
	NHA_RES_GROUP_UNSPEC           = iota
	NHA_RES_GROUP_BUCKETS          // u16: Number of buckets in the hash table
	NHA_RES_GROUP_IDLE_TIMER       // u32: Idle timer in units of clock_t
	NHA_RES_GROUP_UNBALANCED_TIMER // u32: Unbalanced timer in units of clock_t
	NHA_RES_GROUP_UNBALANCED_TIME  // u64: Time out of balance (read-only for dumps)
)

// NHA_RES_GROUP_PAD is padding attribute
const NHA_RES_GROUP_PAD = NHA_RES_GROUP_UNSPEC

// SupportedNlFamilies contains the list of netlink families this netlink package supports
var SupportedNlFamilies = []int{unix.NETLINK_ROUTE, unix.NETLINK_XFRM, unix.NETLINK_NETFILTER}

var nextSeqNr uint32

// Default netlink socket timeout, 60s
var SocketTimeoutTv = unix.Timeval{Sec: 60, Usec: 0}

// ErrorMessageReporting is the default error message reporting configuration for the new netlink sockets
var EnableErrorMessageReporting bool = false

// ErrDumpInterrupted is an instance of errDumpInterrupted, used to report that
// a netlink function has set the NLM_F_DUMP_INTR flag in a response message,
// indicating that the results may be incomplete or inconsistent.
var ErrDumpInterrupted = errDumpInterrupted{}

// ErrHandleClosed is returned when a request is submitted to a socket handle
// that has already been closed, or when Close races with a request in flight.
// It is a deterministic failure: no message is sent on the socket and nothing
// is written into another network namespace.
var ErrHandleClosed = errors.New("netlink socket handle is closed")

// errDumpInterrupted is an error type, used to report that NLM_F_DUMP_INTR was
// set in a netlink response.
type errDumpInterrupted struct{}

func (errDumpInterrupted) Error() string {
	return "results may be incomplete or inconsistent"
}

func (errDumpInterrupted) Temporary() bool { return true }

// Before errDumpInterrupted was introduced, EINTR was returned when a netlink
// response had NLM_F_DUMP_INTR. Retain backward compatibility with code that
// may be checking for EINTR using Is.
func (e errDumpInterrupted) Is(target error) bool {
	return target == unix.EINTR
}

// GetIPFamily returns the family type of a net.IP.
func GetIPFamily(ip net.IP) int {
	if len(ip) <= net.IPv4len {
		return FAMILY_V4
	}
	if ip.To4() != nil {
		return FAMILY_V4
	}
	return FAMILY_V6
}

// NativeEndian gets native endianness for the system
func NativeEndian() binary.ByteOrder {
	return binary.NativeEndian
}

// Byte swap a 16 bit value if we aren't big endian
func Swap16(i uint16) uint16 {
	if cpu.IsBigEndian {
		return i
	}
	return (i&0xff00)>>8 | (i&0xff)<<8
}

// Byte swap a 32 bit value if aren't big endian
func Swap32(i uint32) uint32 {
	if cpu.IsBigEndian {
		return i
	}
	return (i&0xff000000)>>24 | (i&0xff0000)>>8 | (i&0xff00)<<8 | (i&0xff)<<24
}

const (
	NLMSGERR_ATTR_UNUSED = 0
	NLMSGERR_ATTR_MSG    = 1
	NLMSGERR_ATTR_OFFS   = 2
	NLMSGERR_ATTR_COOKIE = 3
	NLMSGERR_ATTR_POLICY = 4
)

type NetlinkRequestData interface {
	Len() int
	Serialize() []byte
}

const (
	PROC_CN_MCAST_LISTEN = 1
	PROC_CN_MCAST_IGNORE
)

type CbID struct {
	Idx uint32
	Val uint32
}

type CnMsg struct {
	ID     CbID
	Seq    uint32
	Ack    uint32
	Length uint16
	Flags  uint16
}

type CnMsgOp struct {
	CnMsg
	// here we differ from the C header
	Op uint32
}

func NewCnMsg(idx, val, op uint32) *CnMsgOp {
	var cm CnMsgOp

	cm.ID.Idx = idx
	cm.ID.Val = val

	cm.Ack = 0
	cm.Seq = 1
	cm.Length = uint16(binary.Size(op))
	cm.Op = op

	return &cm
}

func (msg *CnMsgOp) Serialize() []byte {
	return (*(*[SizeofCnMsgOp]byte)(unsafe.Pointer(msg)))[:]
}

func DeserializeCnMsgOp(b []byte) *CnMsgOp {
	return (*CnMsgOp)(unsafe.Pointer(&b[0:SizeofCnMsgOp][0]))
}

func (msg *CnMsgOp) Len() int {
	return SizeofCnMsgOp
}

// IfInfomsg is related to links, but it is used for list requests as well
type IfInfomsg struct {
	unix.IfInfomsg
}

// Create an IfInfomsg with family specified
func NewIfInfomsg(family int) *IfInfomsg {
	return &IfInfomsg{
		IfInfomsg: unix.IfInfomsg{
			Family: uint8(family),
		},
	}
}

func DeserializeIfInfomsg(b []byte) *IfInfomsg {
	if len(b) < unix.SizeofIfInfomsg {
		return nil
	}
	return (*IfInfomsg)(unsafe.Pointer(&b[0:unix.SizeofIfInfomsg][0]))
}

func (msg *IfInfomsg) Serialize() []byte {
	return (*(*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(msg)))[:]
}

func (msg *IfInfomsg) Len() int {
	return unix.SizeofIfInfomsg
}

func (msg *IfInfomsg) EncapType() string {
	switch msg.Type {
	case 0:
		return "generic"
	case unix.ARPHRD_ETHER:
		return "ether"
	case unix.ARPHRD_EETHER:
		return "eether"
	case unix.ARPHRD_AX25:
		return "ax25"
	case unix.ARPHRD_PRONET:
		return "pronet"
	case unix.ARPHRD_CHAOS:
		return "chaos"
	case unix.ARPHRD_IEEE802:
		return "ieee802"
	case unix.ARPHRD_ARCNET:
		return "arcnet"
	case unix.ARPHRD_APPLETLK:
		return "atalk"
	case unix.ARPHRD_DLCI:
		return "dlci"
	case unix.ARPHRD_ATM:
		return "atm"
	case unix.ARPHRD_METRICOM:
		return "metricom"
	case unix.ARPHRD_IEEE1394:
		return "ieee1394"
	case unix.ARPHRD_INFINIBAND:
		return "infiniband"
	case unix.ARPHRD_SLIP:
		return "slip"
	case unix.ARPHRD_CSLIP:
		return "cslip"
	case unix.ARPHRD_SLIP6:
		return "slip6"
	case unix.ARPHRD_CSLIP6:
		return "cslip6"
	case unix.ARPHRD_RSRVD:
		return "rsrvd"
	case unix.ARPHRD_ADAPT:
		return "adapt"
	case unix.ARPHRD_ROSE:
		return "rose"
	case unix.ARPHRD_X25:
		return "x25"
	case unix.ARPHRD_HWX25:
		return "hwx25"
	case unix.ARPHRD_PPP:
		return "ppp"
	case unix.ARPHRD_HDLC:
		return "hdlc"
	case unix.ARPHRD_LAPB:
		return "lapb"
	case unix.ARPHRD_DDCMP:
		return "ddcmp"
	case unix.ARPHRD_RAWHDLC:
		return "rawhdlc"
	case unix.ARPHRD_TUNNEL:
		return "ipip"
	case unix.ARPHRD_TUNNEL6:
		return "tunnel6"
	case unix.ARPHRD_FRAD:
		return "frad"
	case unix.ARPHRD_SKIP:
		return "skip"
	case unix.ARPHRD_LOOPBACK:
		return "loopback"
	case unix.ARPHRD_LOCALTLK:
		return "ltalk"
	case unix.ARPHRD_FDDI:
		return "fddi"
	case unix.ARPHRD_BIF:
		return "bif"
	case unix.ARPHRD_SIT:
		return "sit"
	case unix.ARPHRD_IPDDP:
		return "ip/ddp"
	case unix.ARPHRD_IPGRE:
		return "gre"
	case unix.ARPHRD_PIMREG:
		return "pimreg"
	case unix.ARPHRD_HIPPI:
		return "hippi"
	case unix.ARPHRD_ASH:
		return "ash"
	case unix.ARPHRD_ECONET:
		return "econet"
	case unix.ARPHRD_IRDA:
		return "irda"
	case unix.ARPHRD_FCPP:
		return "fcpp"
	case unix.ARPHRD_FCAL:
		return "fcal"
	case unix.ARPHRD_FCPL:
		return "fcpl"
	case unix.ARPHRD_FCFABRIC:
		return "fcfb0"
	case unix.ARPHRD_FCFABRIC + 1:
		return "fcfb1"
	case unix.ARPHRD_FCFABRIC + 2:
		return "fcfb2"
	case unix.ARPHRD_FCFABRIC + 3:
		return "fcfb3"
	case unix.ARPHRD_FCFABRIC + 4:
		return "fcfb4"
	case unix.ARPHRD_FCFABRIC + 5:
		return "fcfb5"
	case unix.ARPHRD_FCFABRIC + 6:
		return "fcfb6"
	case unix.ARPHRD_FCFABRIC + 7:
		return "fcfb7"
	case unix.ARPHRD_FCFABRIC + 8:
		return "fcfb8"
	case unix.ARPHRD_FCFABRIC + 9:
		return "fcfb9"
	case unix.ARPHRD_FCFABRIC + 10:
		return "fcfb10"
	case unix.ARPHRD_FCFABRIC + 11:
		return "fcfb11"
	case unix.ARPHRD_FCFABRIC + 12:
		return "fcfb12"
	case unix.ARPHRD_IEEE802_TR:
		return "tr"
	case unix.ARPHRD_IEEE80211:
		return "ieee802.11"
	case unix.ARPHRD_IEEE80211_PRISM:
		return "ieee802.11/prism"
	case unix.ARPHRD_IEEE80211_RADIOTAP:
		return "ieee802.11/radiotap"
	case unix.ARPHRD_IEEE802154:
		return "ieee802.15.4"

	case 65534:
		return "none"
	case 65535:
		return "void"
	}
	return fmt.Sprintf("unknown%d", msg.Type)
}

// Round the length of a netlink message up to align it properly.
// Taken from syscall/netlink_linux.go by The Go Authors under BSD-style license.
func nlmAlignOf(msglen int) int {
	return (msglen + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1)
}

func rtaAlignOf(attrlen int) int {
	return (attrlen + unix.RTA_ALIGNTO - 1) & ^(unix.RTA_ALIGNTO - 1)
}

func NewIfInfomsgChild(parent *RtAttr, family int) *IfInfomsg {
	msg := NewIfInfomsg(family)
	parent.children = append(parent.children, msg)
	return msg
}

type Uint32Bitfield struct {
	Value    uint32
	Selector uint32
}

func (a *Uint32Bitfield) Serialize() []byte {
	return (*(*[SizeofUint32Bitfield]byte)(unsafe.Pointer(a)))[:]
}

func DeserializeUint32Bitfield(data []byte) *Uint32Bitfield {
	return (*Uint32Bitfield)(unsafe.Pointer(&data[0:SizeofUint32Bitfield][0]))
}

type Uint32Attribute struct {
	Type  uint16
	Value uint32
}

func (a *Uint32Attribute) Serialize() []byte {
	native := NativeEndian()
	buf := make([]byte, rtaAlignOf(8))
	native.PutUint16(buf[0:2], 8)
	native.PutUint16(buf[2:4], a.Type)

	if a.Type&NLA_F_NET_BYTEORDER != 0 {
		binary.BigEndian.PutUint32(buf[4:], a.Value)
	} else {
		native.PutUint32(buf[4:], a.Value)
	}
	return buf
}

func (a *Uint32Attribute) Len() int {
	return 8
}

// Extend RtAttr to handle data and children
type RtAttr struct {
	unix.RtAttr
	Data     []byte
	children []NetlinkRequestData
}

// Create a new Extended RtAttr object
func NewRtAttr(attrType int, data []byte) *RtAttr {
	return &RtAttr{
		RtAttr: unix.RtAttr{
			Type: uint16(attrType),
		},
		children: []NetlinkRequestData{},
		Data:     data,
	}
}

// NewRtAttrChild adds an RtAttr as a child to the parent and returns the new attribute
//
// Deprecated: Use AddRtAttr() on the parent object
func NewRtAttrChild(parent *RtAttr, attrType int, data []byte) *RtAttr {
	return parent.AddRtAttr(attrType, data)
}

// AddRtAttr adds an RtAttr as a child and returns the new attribute
func (a *RtAttr) AddRtAttr(attrType int, data []byte) *RtAttr {
	attr := NewRtAttr(attrType, data)
	a.children = append(a.children, attr)
	return attr
}

// AddChild adds an existing NetlinkRequestData as a child.
func (a *RtAttr) AddChild(attr NetlinkRequestData) {
	a.children = append(a.children, attr)
}

func (a *RtAttr) Len() int {
	if len(a.children) == 0 {
		return (unix.SizeofRtAttr + len(a.Data))
	}

	l := 0
	for _, child := range a.children {
		l += rtaAlignOf(child.Len())
	}
	l += unix.SizeofRtAttr
	return rtaAlignOf(l + len(a.Data))
}

// Serialize the RtAttr into a byte array
// This can't just unsafe.cast because it must iterate through children.
func (a *RtAttr) Serialize() []byte {
	native := NativeEndian()

	length := a.Len()
	buf := make([]byte, rtaAlignOf(length))

	next := 4
	if a.Data != nil {
		copy(buf[next:], a.Data)
		next += rtaAlignOf(len(a.Data))
	}
	if len(a.children) > 0 {
		for _, child := range a.children {
			childBuf := child.Serialize()
			copy(buf[next:], childBuf)
			next += rtaAlignOf(len(childBuf))
		}
	}

	if l := uint16(length); l != 0 {
		native.PutUint16(buf[0:2], l)
	}
	native.PutUint16(buf[2:4], a.Type)
	return buf
}

type NetlinkRequest struct {
	unix.NlMsghdr
	Data    []NetlinkRequestData
	RawData []byte
	Sockets map[int]*SocketHandle

	RetryInterrupted bool

	// namespace is the network namespace a short-lived fallback socket must be
	// opened in. It is ignored when the request runs on a shared socket from
	// Sockets, which carries its own namespace. A non-positive value means the
	// caller's current namespace.
	namespace int
	// closed, when non-nil, is consulted before opening a fallback socket. If it
	// reports the owning handle as closed the request fails with ErrHandleClosed
	// instead of opening a socket.
	closed func() bool
}

// WithNamespace records the network namespace (an open nsfs file descriptor, or
// a non-positive value for the caller's current namespace) that short-lived
// fallback sockets for this request must be opened in, together with a callback
// that reports whether the owning handle has been closed.
func (req *NetlinkRequest) WithNamespace(ns int, closed func() bool) *NetlinkRequest {
	req.namespace = ns
	req.closed = closed
	return req
}

// Serialize the Netlink Request into a byte array
func (req *NetlinkRequest) Serialize() []byte {
	length := unix.SizeofNlMsghdr
	dataBytes := make([][]byte, len(req.Data))
	for i, data := range req.Data {
		dataBytes[i] = data.Serialize()
		length = length + len(dataBytes[i])
	}
	length += len(req.RawData)

	req.Len = uint32(length)
	b := make([]byte, length)
	hdr := (*(*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(req)))[:]
	next := unix.SizeofNlMsghdr
	copy(b[0:next], hdr)
	for _, data := range dataBytes {
		for _, dataByte := range data {
			b[next] = dataByte
			next = next + 1
		}
	}
	// Add the raw data if any
	if len(req.RawData) > 0 {
		copy(b[next:length], req.RawData)
	}
	return b
}

func (req *NetlinkRequest) AddData(data NetlinkRequestData) {
	req.Data = append(req.Data, data)
}

// AddRawData adds raw bytes to the end of the NetlinkRequest object during serialization
func (req *NetlinkRequest) AddRawData(data []byte) {
	req.RawData = append(req.RawData, data...)
}

// Execute the request against the given sockType.
// Returns a list of netlink messages in serialized format, optionally filtered
// by resType.
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
func (req *NetlinkRequest) Execute(sockType int, resType uint16) ([][]byte, error) {
	attempts := 1
	if req.RetryInterrupted {
		// Only retry if the Request is configured to do so for backwards compat.
		attempts = 10
	}

	var lastRes [][]byte
	for range attempts {
		var res [][]byte
		err := req.executeIter(sockType, resType, func(msg []byte) bool {
			res = append(res, msg)
			return true
		})
		if err == nil {
			return res, nil
		}
		lastRes = res

		if !errors.Is(err, ErrDumpInterrupted) {
			// Do not wrap the error from ExecuteIter. It gets type-asserted and
			// replaced with sentinels in some callers, and wrapping breaks that.
			return nil, err
		}
	}

	return lastRes, fmt.Errorf("execute netlink request after %d attempts: %w", attempts, ErrDumpInterrupted)
}

// ExecuteIter executes the request against the given sockType.
// Calls the provided callback func once for each netlink message.
// If the callback returns false, it is not called again, but
// the remaining messages are consumed/discarded.
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
//
// Thread safety: ExecuteIter holds a lock on the socket until it finishes
// iteration, so the callback must not call back into the netlink API. When
// RetryInterrupted is enabled, messages are buffered until a complete dump is
// received and then passed to the callback after the socket lock is released.
func (req *NetlinkRequest) ExecuteIter(sockType int, resType uint16, f func(msg []byte) bool) error {
	if !req.RetryInterrupted {
		return req.executeIter(sockType, resType, f)
	}

	msgs, err := req.Execute(sockType, resType)
	for _, msg := range msgs {
		if cont := f(msg); !cont {
			break
		}
	}
	return err
}

func (req *NetlinkRequest) executeIter(sockType int, resType uint16, f func(msg []byte) bool) error {
	var (
		s   *NetlinkSocket
		err error
	)

	// release scopes everything that must be undone before returning: the
	// namespace entered for this request and any reference taken on a shared
	// socket. It is a no-op until one of those has been acquired.
	release := func() {}
	defer func() { release() }()

	var sh *SocketHandle
	if req.Sockets != nil {
		if h, ok := req.Sockets[sockType]; ok {
			sh = h
		}
	}
	sharedSocket := sh != nil

	if sh == nil {
		// Short-lived fallback socket. Open it inside the request namespace so
		// the caller thread's current namespace can never leak into the socket.
		if req.closed != nil && req.closed() {
			return ErrHandleClosed
		}
		var leave func()
		leave, err = enterNetns(req.namespace)
		if err != nil {
			return err
		}
		release = leave

		s, err = getNetlinkSocket(sockType)
		if err != nil {
			return err
		}

		if err := s.SetSendTimeout(&SocketTimeoutTv); err != nil {
			return err
		}
		if err := s.SetReceiveTimeout(&SocketTimeoutTv); err != nil {
			return err
		}
		if EnableErrorMessageReporting {
			// ignore error, it's non-critical
			_ = s.SetExtAck(true)
		}

		defer s.Close()
	} else {
		// Pin the socket and, if it has a namespace, pin the calling OS thread
		// and move it into that namespace for the whole request. Every
		// concurrent request takes its own thread, so they never switch the
		// namespace under each other.
		var leave func()
		leave, err = sh.Acquire()
		if err != nil {
			return err
		}
		release = leave
		s = sh.Socket
		req.Seq = sh.nextSeq()
	}

	if err := s.Send(req); err != nil {
		return err
	}

	pid, err := s.GetPid()
	if err != nil {
		return err
	}

	dumpIntr := false

done:
	for {
		msgs, from, err := s.Receive()
		if err != nil {
			return err
		}
		if from.Pid != PidKernel {
			return fmt.Errorf("Wrong sender portid %d, expected %d", from.Pid, PidKernel)
		}
		for _, m := range msgs {
			if m.Header.Seq != req.Seq {
				if sharedSocket {
					continue
				}
				return fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, req.Seq)
			}
			if m.Header.Pid != pid {
				continue
			}

			if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				dumpIntr = true
			}

			if m.Header.Type == unix.NLMSG_DONE || m.Header.Type == unix.NLMSG_ERROR {
				// NLMSG_DONE might have no payload, if so assume no error.
				if m.Header.Type == unix.NLMSG_DONE && len(m.Data) == 0 {
					break done
				}

				native := NativeEndian()
				errno := int32(native.Uint32(m.Data[0:4]))
				if errno == 0 {
					break done
				}
				var err error
				err = syscall.Errno(-errno)

				unreadData := m.Data[4:]

				if m.Header.Type == unix.NLMSG_ERROR {
					if m.Header.Flags&unix.NLM_F_CAPPED != 0 {
						// The request payload is capped, just skip the nlmsghdr
						unreadData = unreadData[syscall.SizeofNlMsghdr:]
					} else {
						// Skip the entire request message
						echoReqH := (*syscall.NlMsghdr)(unsafe.Pointer(&unreadData[0]))
						unreadData = unreadData[nlmAlignOf(int(echoReqH.Len)):]
					}
				}

				if m.Header.Flags&unix.NLM_F_ACK_TLVS != 0 && len(unreadData) > syscall.SizeofNlMsghdr {
					// Annotate `err` using nlmsgerr attributes.
					for len(unreadData) >= syscall.SizeofRtAttr {
						attr := (*syscall.RtAttr)(unsafe.Pointer(&unreadData[0]))
						attrData := unreadData[syscall.SizeofRtAttr:attr.Len]

						switch attr.Type {
						case NLMSGERR_ATTR_MSG:
							err = fmt.Errorf("%w: %s", err, unix.ByteSliceToString(attrData))
						default:
							// TODO: handle other NLMSGERR_ATTR types
						}

						unreadData = unreadData[rtaAlignOf(int(attr.Len)):]
					}
				}

				return err
			}
			if resType != 0 && m.Header.Type != resType {
				continue
			}
			if cont := f(m.Data); !cont {
				// Drain the rest of the messages from the kernel but don't
				// pass them to the iterator func.
				f = dummyMsgIterFunc
			}
			if m.Header.Flags&unix.NLM_F_MULTI == 0 {
				break done
			}
		}
	}
	if dumpIntr {
		return ErrDumpInterrupted
	}
	return nil
}

func dummyMsgIterFunc(msg []byte) bool {
	return true
}

// Create a new netlink request from proto and flags
// Note the Len value will be inaccurate once data is added until
// the message is serialized
func NewNetlinkRequest(proto, flags int) *NetlinkRequest {
	return &NetlinkRequest{
		NlMsghdr: unix.NlMsghdr{
			Len:   uint32(unix.SizeofNlMsghdr),
			Type:  uint16(proto),
			Flags: unix.NLM_F_REQUEST | uint16(flags),
			Seq:   atomic.AddUint32(&nextSeqNr, 1),
		},
	}
}

type NetlinkSocket struct {
	fd             int32
	file           *os.File
	lsa            unix.SockaddrNetlink
	sendTimeout    int64 // Access using atomic.Load/StoreInt64
	receiveTimeout int64 // Access using atomic.Load/StoreInt64
	sync.Mutex
}

// getNetlinkSocket opens a new non-blocking netlink socket for protocol, binds it and enables
// extended ACK reporting when EnableErrorMessageReporting is set.
func getNetlinkSocket(protocol int) (*NetlinkSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return nil, err
	}
	err = unix.SetNonblock(fd, true)
	if err != nil {
		return nil, err
	}
	s := &NetlinkSocket{
		fd:   int32(fd),
		file: os.NewFile(uintptr(fd), "netlink"),
	}
	s.lsa.Family = unix.AF_NETLINK
	if err := unix.Bind(fd, &s.lsa); err != nil {
		unix.Close(fd)
		return nil, err
	}

	if EnableErrorMessageReporting {
		// ignore error, it's non-critical
		_ = s.SetExtAck(true)
	}

	return s, nil
}

// NewNetlinkSocketFromFd wraps an already open netlink socket.
// Unlike the other constructors it never calls bind().
// This allows netlink to be used where binding is not permitted (notably, Android).
// On success the socket takes ownership of fd and switches it to non-blocking mode.
// On error fd is left untouched and still belongs to the caller.
func NewNetlinkSocketFromFd(fd int) (*NetlinkSocket, error) {
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return nil, err
	}
	if domain != unix.AF_NETLINK {
		return nil, fmt.Errorf("fd %d is not a netlink socket", fd)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	s := &NetlinkSocket{
		fd:   int32(fd),
		file: os.NewFile(uintptr(fd), "netlink"),
	}
	s.lsa.Family = unix.AF_NETLINK

	if EnableErrorMessageReporting {
		// ignore error, it's non-critical
		_ = s.SetExtAck(true)
	}

	return s, nil
}

// GetNetlinkSocketAt opens a netlink socket in the network namespace newNs
// and positions the thread back into the network namespace specified by curNs,
// when done. If curNs is close, the function derives the current namespace and
// moves back into it when done. If newNs is close, the socket will be opened
// in the current network namespace.
func GetNetlinkSocketAt(newNs, curNs netns.NsHandle, protocol int) (*NetlinkSocket, error) {
	restore, err := enterNetnsFrom(newNs, curNs)
	if err != nil {
		return nil, err
	}
	defer restore()
	return getNetlinkSocket(protocol)
}

// enterNetns works like enterNetnsFrom but always restores the thread to the
// namespace it had at the time of the call. The ns argument is an open nsfs
// file descriptor; a non-positive value leaves the thread in its current
// namespace and returns a no-op restore function.
func enterNetns(ns int) (func(), error) {
	if ns <= 0 {
		return func() {}, nil
	}
	return enterNetnsFrom(netns.NsHandle(ns), netns.None())
}

// enterNetnsFrom pins the calling goroutine to its OS thread and moves that
// thread into newNs. The returned function moves the thread back to curNs (or
// to the namespace captured at entry when curNs is closed), releases the
// thread and closes every namespace descriptor this call acquired. It must
// always be invoked, also on the caller's error paths. When newNs is closed
// nothing is switched and the returned function is a no-op.
//
// Pinning the thread matters: setns(2) changes the namespace of one thread,
// not of the goroutine, so every request takes its own enter/restore pair and
// concurrent requests never observe each other's namespace.
func enterNetnsFrom(newNs, curNs netns.NsHandle) (func(), error) {
	if !newNs.IsOpen() {
		return func() {}, nil
	}

	runtime.LockOSThread()

	var (
		savedNs   netns.NsHandle = netns.None()
		ownsSaved bool
	)
	if !curNs.IsOpen() {
		got, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			return nil, fmt.Errorf("could not get current namespace while entering netlink namespace: %v", err)
		}
		savedNs = got
		ownsSaved = true
	} else {
		savedNs = curNs
	}

	if err := netns.Set(newNs); err != nil {
		if ownsSaved {
			_ = savedNs.Close()
		}
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("failed to set into network namespace %d while entering netlink namespace: %v", newNs, err)
	}

	restored := false
	return func() {
		if restored {
			return
		}
		restored = true
		// Restore first, then drop the saved descriptor, then release the
		// thread, so the thread never leaves this function still in newNs.
		if err := netns.Set(savedNs); err != nil {
			// A thread that cannot return to its original namespace must not
			// be reused by another goroutine; keep it pinned.
			return
		}
		if ownsSaved {
			_ = savedNs.Close()
		}
		runtime.UnlockOSThread()
	}, nil
}

// Create a netlink socket with a given protocol (e.g. NETLINK_ROUTE)
// and subscribe it to multicast groups passed in variable argument list.
// Returns the netlink socket on which Receive() method can be called
// to retrieve the messages from the kernel.
func Subscribe(protocol int, groups ...uint) (*NetlinkSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return nil, err
	}
	err = unix.SetNonblock(fd, true)
	if err != nil {
		return nil, err
	}
	s := &NetlinkSocket{
		fd:   int32(fd),
		file: os.NewFile(uintptr(fd), "netlink"),
	}
	s.lsa.Family = unix.AF_NETLINK

	for _, g := range groups {
		s.lsa.Groups |= (1 << (g - 1))
	}

	if err := unix.Bind(fd, &s.lsa); err != nil {
		unix.Close(fd)
		return nil, err
	}

	return s, nil
}

// SubscribeAt works like Subscribe plus let's the caller choose the network
// namespace in which the socket would be opened (newNs). Then control goes back
// to curNs if open, otherwise to the netns at the time this function was called.
func SubscribeAt(newNs, curNs netns.NsHandle, protocol int, groups ...uint) (*NetlinkSocket, error) {
	restore, err := enterNetnsFrom(newNs, curNs)
	if err != nil {
		return nil, err
	}
	defer restore()
	return Subscribe(protocol, groups...)
}

func (s *NetlinkSocket) Close() error {
	return s.file.Close()
}

func (s *NetlinkSocket) GetFd() int {
	return int(s.fd)
}

func (s *NetlinkSocket) GetTimeouts() (send, receive time.Duration) {
	return time.Duration(atomic.LoadInt64(&s.sendTimeout)),
		time.Duration(atomic.LoadInt64(&s.receiveTimeout))
}

func (s *NetlinkSocket) Send(request *NetlinkRequest) error {
	rawConn, err := s.file.SyscallConn()
	if err != nil {
		return err
	}
	var (
		deadline time.Time
		innerErr error
	)
	sendTimeout := atomic.LoadInt64(&s.sendTimeout)
	if sendTimeout != 0 {
		deadline = time.Now().Add(time.Duration(sendTimeout))
	}
	if err := s.file.SetWriteDeadline(deadline); err != nil {
		return err
	}
	serializedReq := request.Serialize()
	err = rawConn.Write(func(fd uintptr) (done bool) {
		innerErr = unix.Sendto(int(s.fd), serializedReq, 0, &s.lsa)
		return innerErr != unix.EWOULDBLOCK
	})
	if innerErr != nil {
		return innerErr
	}
	if err != nil {
		// The timeout was previously implemented using SO_SNDTIMEO on a blocking
		// socket. So, continue to return EAGAIN when the timeout is reached.
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return unix.EAGAIN
		}
		return err
	}
	return nil
}

func (s *NetlinkSocket) Receive() ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error) {
	rawConn, err := s.file.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var (
		deadline time.Time
		fromAddr *unix.SockaddrNetlink
		rb       [RECEIVE_BUFFER_SIZE]byte
		nr       int
		from     unix.Sockaddr
		innerErr error
	)
	receiveTimeout := atomic.LoadInt64(&s.receiveTimeout)
	if receiveTimeout != 0 {
		deadline = time.Now().Add(time.Duration(receiveTimeout))
	}
	if err := s.file.SetReadDeadline(deadline); err != nil {
		return nil, nil, err
	}
	err = rawConn.Read(func(fd uintptr) (done bool) {
		nr, from, innerErr = unix.Recvfrom(int(fd), rb[:], 0)
		return innerErr != unix.EWOULDBLOCK
	})
	if innerErr != nil {
		return nil, nil, innerErr
	}
	if err != nil {
		// The timeout was previously implemented using SO_RCVTIMEO on a blocking
		// socket. So, continue to return EAGAIN when the timeout is reached.
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, nil, unix.EAGAIN
		}
		return nil, nil, err
	}
	fromAddr, ok := from.(*unix.SockaddrNetlink)
	if !ok {
		return nil, nil, fmt.Errorf("Error converting to netlink sockaddr")
	}
	if nr < unix.NLMSG_HDRLEN {
		return nil, nil, fmt.Errorf("Got short response from netlink")
	}
	msgLen := nlmAlignOf(nr)
	rb2 := make([]byte, msgLen)
	copy(rb2, rb[:msgLen])
	nl, err := syscall.ParseNetlinkMessage(rb2)
	if err != nil {
		return nil, nil, err
	}
	return nl, fromAddr, nil
}

// SetSendTimeout allows to set a send timeout on the socket
func (s *NetlinkSocket) SetSendTimeout(timeout *unix.Timeval) error {
	atomic.StoreInt64(&s.sendTimeout, timeout.Nano())
	return nil
}

// SetReceiveTimeout allows to set a receive timeout on the socket
func (s *NetlinkSocket) SetReceiveTimeout(timeout *unix.Timeval) error {
	atomic.StoreInt64(&s.receiveTimeout, timeout.Nano())
	return nil
}

// SetReceiveBufferSize allows to set a receive buffer size on the socket
func (s *NetlinkSocket) SetReceiveBufferSize(size int, force bool) error {
	opt := unix.SO_RCVBUF
	if force {
		opt = unix.SO_RCVBUFFORCE
	}
	return unix.SetsockoptInt(int(s.fd), unix.SOL_SOCKET, opt, size)
}

// SetExtAck requests error messages to be reported on the socket
func (s *NetlinkSocket) SetExtAck(enable bool) error {
	var enableN int
	if enable {
		enableN = 1
	}

	return unix.SetsockoptInt(int(s.fd), unix.SOL_NETLINK, unix.NETLINK_EXT_ACK, enableN)
}

func (s *NetlinkSocket) GetPid() (uint32, error) {
	lsa, err := unix.Getsockname(int(s.fd))
	if err != nil {
		return 0, err
	}
	switch v := lsa.(type) {
	case *unix.SockaddrNetlink:
		return v.Pid, nil
	}
	return 0, fmt.Errorf("Wrong socket type")
}

func ZeroTerminated(s string) []byte {
	bytes := make([]byte, len(s)+1)
	for i := 0; i < len(s); i++ {
		bytes[i] = s[i]
	}
	bytes[len(s)] = 0
	return bytes
}

func NonZeroTerminated(s string) []byte {
	bytes := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		bytes[i] = s[i]
	}
	return bytes
}

func BytesToString(b []byte) string {
	n := bytes.Index(b, []byte{0})
	return string(b[:n])
}

func Uint8Attr(v uint8) []byte {
	return []byte{byte(v)}
}

func Uint16Attr(v uint16) []byte {
	native := NativeEndian()
	bytes := make([]byte, 2)
	native.PutUint16(bytes, v)
	return bytes
}

func BEUint16Attr(v uint16) []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, v)
	return bytes
}

func Uint32Attr(v uint32) []byte {
	native := NativeEndian()
	bytes := make([]byte, 4)
	native.PutUint32(bytes, v)
	return bytes
}

func BEUint32Attr(v uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, v)
	return bytes
}

func Uint64Attr(v uint64) []byte {
	native := NativeEndian()
	bytes := make([]byte, 8)
	native.PutUint64(bytes, v)
	return bytes
}

func BEUint64Attr(v uint64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, v)
	return bytes
}

func ParseRouteAttr(b []byte) ([]syscall.NetlinkRouteAttr, error) {
	var attrs []syscall.NetlinkRouteAttr
	for len(b) >= unix.SizeofRtAttr {
		a, vbuf, alen, err := netlinkRouteAttrAndValue(b)
		if err != nil {
			return nil, err
		}
		ra := syscall.NetlinkRouteAttr{Attr: syscall.RtAttr(*a), Value: vbuf[:int(a.Len)-unix.SizeofRtAttr]}
		attrs = append(attrs, ra)
		b = b[alen:]
	}
	return attrs, nil
}

// ParseRouteAttrAsMap parses provided buffer that contains raw RtAttrs and returns a map of parsed
// atttributes indexed by attribute type or error if occured.
func ParseRouteAttrAsMap(b []byte) (map[uint16]syscall.NetlinkRouteAttr, error) {
	attrMap := make(map[uint16]syscall.NetlinkRouteAttr)

	attrs, err := ParseRouteAttr(b)
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		attrMap[attr.Attr.Type] = attr
	}
	return attrMap, nil
}

func netlinkRouteAttrAndValue(b []byte) (*unix.RtAttr, []byte, int, error) {
	a := (*unix.RtAttr)(unsafe.Pointer(&b[0]))
	if int(a.Len) < unix.SizeofRtAttr || int(a.Len) > len(b) {
		return nil, nil, 0, unix.EINVAL
	}
	return a, b[unix.SizeofRtAttr:], rtaAlignOf(int(a.Len)), nil
}

// SocketHandle contains the netlink socket and the associated
// sequence counter for a specific netlink family.
//
// A SocketHandle may additionally carry the network namespace the socket lives
// in. When it does, every acquire pins the calling goroutine to its OS thread
// and moves that thread into the namespace for the duration of the request, so
// requests sharing the socket never switch the namespace under each other.
//
// Close is idempotent and blocks until every request that acquired the handle
// has released it; the underlying socket file is only closed once the reference
// count is back to zero. Requests arriving after Close fail with
// ErrHandleClosed and never send on the socket.
type SocketHandle struct {
	Seq atomic.Uint32

	Socket *NetlinkSocket

	// namespace is the nsfs descriptor the calling thread is moved into while
	// a request is in flight. The zero value (and any negative value) means
	// "no namespace switching": sockets opened in the caller's current
	// namespace and externally supplied (e.g. Android, never bound) sockets
	// keep this value. A positive value is an open nsfs file descriptor.
	namespace int

	// inFlight counts requests currently holding a reference.
	inFlight sync.WaitGroup
	// closeMu makes the closed transition and the reference acquisition atomic.
	closeMu   sync.RWMutex
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

// NewSocketHandle wraps an existing socket and records the network namespace
// (an open nsfs file descriptor, or a non-positive value for no namespace
// switching) its requests must run in. The handle does not take ownership of
// ns; the caller keeps the right to close it once every handle using it is
// closed.
func NewSocketHandle(socket *NetlinkSocket, ns int) *SocketHandle {
	return &SocketHandle{Socket: socket, namespace: ns}
}

// nextSeq returns the next per-socket sequence number. It is only valid while
// the caller holds a reference obtained via Acquire.
func (sh *SocketHandle) nextSeq() uint32 {
	return sh.Seq.Add(1)
}

// Acquire takes a reference on the handle and, when the handle carries a
// namespace, pins the calling thread into it. The returned function releases
// the reference and restores the thread. If the handle is closed (or closes
// before the reference is taken) Acquire returns ErrHandleClosed and sends
// nothing on the socket.
func (sh *SocketHandle) Acquire() (func(), error) {
	sh.closeMu.RLock()
	if sh.closed {
		sh.closeMu.RUnlock()
		return nil, ErrHandleClosed
	}
	if sh.Socket == nil {
		sh.closeMu.RUnlock()
		return nil, ErrHandleClosed
	}
	sh.inFlight.Add(1)
	sh.closeMu.RUnlock()

	releaseNS := func() {}
	if sh.namespace > 0 {
		restore, err := enterNetns(sh.namespace)
		if err != nil {
			sh.inFlight.Done()
			return nil, err
		}
		releaseNS = restore
	}

	sh.Socket.Lock()
	return func() {
		sh.Socket.Unlock()
		releaseNS()
		sh.inFlight.Done()
	}, nil
}

// Close marks the handle closed, waits for every request in flight to finish,
// and then closes the underlying socket. It is safe to call concurrently with
// request execution and may be called any number of times; only the first call
// can return a non-nil error. A nil Socket is closed without error.
func (sh *SocketHandle) Close() error {
	sh.closeOnce.Do(func() {
		sh.closeMu.Lock()
		sh.closed = true
		sh.closeMu.Unlock()

		// Wait with no lock held: in-flight requests hold their reference and
		// must be able to finish and release it without taking closeMu.
		sh.inFlight.Wait()

		if sh.Socket != nil {
			sh.closeErr = sh.Socket.Close()
		}
	})
	return sh.closeErr
}
