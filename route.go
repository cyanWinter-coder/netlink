package netlink

import (
	"fmt"
	"net"
	"strings"
)

// Scope is an enum representing a route scope.
type Scope uint8

type NextHopFlag int

const (
	RT_FILTER_PROTOCOL uint64 = 1 << (1 + iota)
	RT_FILTER_SCOPE
	RT_FILTER_TYPE
	RT_FILTER_TOS
	RT_FILTER_IIF
	RT_FILTER_OIF
	RT_FILTER_DST
	RT_FILTER_SRC
	RT_FILTER_GW
	RT_FILTER_TABLE
	RT_FILTER_HOPLIMIT
	RT_FILTER_PRIORITY
	RT_FILTER_MARK
	RT_FILTER_MASK
	RT_FILTER_REALM
)

type Destination interface {
	Family() int
	Decode([]byte) error
	Encode() ([]byte, error)
	String() string
	Equal(Destination) bool
}

type Encap interface {
	Type() int
	Decode([]byte) error
	Encode() ([]byte, error)
	String() string
	Equal(Encap) bool
}

type RouteCacheInfo struct {
	Users   uint32
	Age     uint32
	Expires int32
	Error   uint32
	Used    uint32
	Id      uint32
	Ts      uint32
	Tsage   uint32
}

// Protocol describe what was the originator of the route
type RouteProtocol int

// Route represents a netlink route.
type Route struct {
	LinkIndex        int
	ILinkIndex       int
	Scope            Scope
	Dst              *net.IPNet
	Src              net.IP
	Gw               net.IP
	MultiPath        []*NexthopInfo
	Protocol         RouteProtocol
	Priority         int
	Family           int
	Table            int
	Type             int
	Tos              int
	Flags            int
	MPLSDst          *int
	NewDst           Destination
	Encap            Encap
	Via              Destination
	Realm            int
	MTU              int
	MTULock          bool
	Window           int
	Rtt              int
	RttVar           int
	Ssthresh         int
	Cwnd             int
	AdvMSS           int
	Reordering       int
	Hoplimit         int
	InitCwnd         int
	Features         int
	RtoMin           int
	RtoMinLock       bool
	InitRwnd         int
	QuickACK         int
	Congctl          string
	FastOpenNoCookie int
	Expires          int
	CacheInfo        *RouteCacheInfo
	NHID             uint32
}

func (r Route) String() string {
	elems := []string{}
	if len(r.MultiPath) == 0 {
		elems = append(elems, fmt.Sprintf("Ifindex: %d", r.LinkIndex))
	}
	if r.MPLSDst != nil {
		elems = append(elems, fmt.Sprintf("Dst: %d", r.MPLSDst))
	} else {
		elems = append(elems, fmt.Sprintf("Dst: %s", r.Dst))
	}
	if r.NewDst != nil {
		elems = append(elems, fmt.Sprintf("NewDst: %s", r.NewDst))
	}
	if r.Encap != nil {
		elems = append(elems, fmt.Sprintf("Encap: %s", r.Encap))
	}
	if r.Via != nil {
		elems = append(elems, fmt.Sprintf("Via: %s", r.Via))
	}
	elems = append(elems, fmt.Sprintf("Src: %s", r.Src))
	if len(r.MultiPath) > 0 {
		elems = append(elems, fmt.Sprintf("Gw: %s", r.MultiPath))
	} else {
		elems = append(elems, fmt.Sprintf("Gw: %s", r.Gw))
	}
	elems = append(elems, fmt.Sprintf("Flags: %s", r.ListFlags()))
	elems = append(elems, fmt.Sprintf("Table: %d", r.Table))
	elems = append(elems, fmt.Sprintf("Realm: %d", r.Realm))
	if r.Expires != 0 {
		elems = append(elems, fmt.Sprintf("Expires: %dsec", r.Expires))
	}
	if r.NHID != 0 {
		elems = append(elems, fmt.Sprintf("NHID: %d", r.NHID))
	}
	return fmt.Sprintf("{%s}", strings.Join(elems, " "))
}

func (r Route) Equal(x Route) bool {
	return r.LinkIndex == x.LinkIndex &&
		r.ILinkIndex == x.ILinkIndex &&
		r.Scope == x.Scope &&
		ipNetEqual(r.Dst, x.Dst) &&
		r.Src.Equal(x.Src) &&
		r.Gw.Equal(x.Gw) &&
		nexthopInfoSlice(r.MultiPath).Equal(x.MultiPath) &&
		r.Protocol == x.Protocol &&
		r.Priority == x.Priority &&
		r.Realm == x.Realm &&
		r.Table == x.Table &&
		r.Type == x.Type &&
		r.Tos == x.Tos &&
		r.Hoplimit == x.Hoplimit &&
		r.Flags == x.Flags &&
		(r.MPLSDst == x.MPLSDst || (r.MPLSDst != nil && x.MPLSDst != nil && *r.MPLSDst == *x.MPLSDst)) &&
		(r.NewDst == x.NewDst || (r.NewDst != nil && r.NewDst.Equal(x.NewDst))) &&
		(r.Via == x.Via || (r.Via != nil && r.Via.Equal(x.Via))) &&
		(r.Encap == x.Encap || (r.Encap != nil && r.Encap.Equal(x.Encap))) &&
		(r.NHID == x.NHID)
}

func (r *Route) SetFlag(flag NextHopFlag) {
	r.Flags |= int(flag)
}

func (r *Route) ClearFlag(flag NextHopFlag) {
	r.Flags &^= int(flag)
}

type flagString struct {
	f NextHopFlag
	s string
}

// RouteOp selects the netlink operation applied to a Route inside a batch.
type RouteOp int

const (
	// RouteOpAdd creates a route, failing if a matching one already exists.
	// Equivalent to `ip route add`.
	RouteOpAdd RouteOp = iota
	// RouteOpReplace creates or replaces a route.
	// Equivalent to `ip route replace`.
	RouteOpReplace
	// RouteOpChange replaces an existing route, failing if none matches.
	// Equivalent to `ip route change`.
	RouteOpChange
	// RouteOpDelete deletes a matching route.
	// Equivalent to `ip route del`.
	RouteOpDelete
)

// RouteBatchItem is one element of a route batch: the operation to apply and
// the route to apply it to.
type RouteBatchItem struct {
	Op    RouteOp
	Route *Route
}

// RouteBatchItemError reports the failure of a single batch item, identified by
// its stable index in the input slice.
type RouteBatchItemError struct {
	Index int
	Op    RouteOp
	Err   error
}

func (e *RouteBatchItemError) Error() string {
	return fmt.Sprintf("route batch item %d (%s): %v", e.Index, e.Op, e.Err)
}

func (e *RouteBatchItemError) Unwrap() error { return e.Err }

// RouteRollbackError reports that undoing an already applied batch item
// failed. Index identifies the original item; the rollback walks committed
// items in reverse order.
type RouteRollbackError struct {
	Index int
	Op    RouteOp
	Err   error
}

func (e *RouteRollbackError) Error() string {
	return fmt.Sprintf("route batch rollback of item %d (%s): %v", e.Index, e.Op, e.Err)
}

func (e *RouteRollbackError) Unwrap() error { return e.Err }

// RouteBatchError is the aggregate result of a failed route batch. ItemErrors
// holds one entry per request the kernel rejected (in index order);
// RollbackErrors holds the errors encountered while undoing the committed
// items, also in the order they were attempted (reverse commit order). Either
// slice may be empty: a pre-send validation failure produces neither, and a
// clean rollback leaves RollbackErrors empty.
type RouteBatchError struct {
	ItemErrors     []*RouteBatchItemError
	RollbackErrors []*RouteRollbackError
}

func (e *RouteBatchError) Error() string {
	switch {
	case len(e.ItemErrors) > 0 && len(e.RollbackErrors) > 0:
		return fmt.Sprintf("route batch failed: %d item error(s), %d rollback error(s)",
			len(e.ItemErrors), len(e.RollbackErrors))
	case len(e.ItemErrors) > 0:
		return fmt.Sprintf("route batch failed: %d item error(s)", len(e.ItemErrors))
	case len(e.RollbackErrors) > 0:
		return fmt.Sprintf("route batch aborted: %d rollback error(s)", len(e.RollbackErrors))
	default:
		return "route batch failed"
	}
}

// Unwrap returns the first item error so errors.Is/As keep working against the
// underlying kernel errno (e.g. unix.EEXIST, unix.ESRCH).
func (e *RouteBatchError) Unwrap() error {
	if len(e.ItemErrors) > 0 {
		return e.ItemErrors[0].Err
	}
	if len(e.RollbackErrors) > 0 {
		return e.RollbackErrors[0].Err
	}
	return nil
}

func (op RouteOp) String() string {
	switch op {
	case RouteOpAdd:
		return "add"
	case RouteOpReplace:
		return "replace"
	case RouteOpChange:
		return "change"
	case RouteOpDelete:
		return "delete"
	default:
		return "unknown"
	}
}

// RouteUpdate is sent when a route changes - type is RTM_NEWROUTE or RTM_DELROUTE

// NlFlags is only non-zero for RTM_NEWROUTE, the following flags can be set:
//   - unix.NLM_F_REPLACE - Replace existing matching config object with this request
//   - unix.NLM_F_EXCL - Don't replace the config object if it already exists
//   - unix.NLM_F_CREATE - Create config object if it doesn't already exist
//   - unix.NLM_F_APPEND - Add to the end of the object list
type RouteUpdate struct {
	Type    uint16
	NlFlags uint16
	Route
}

type NexthopInfo struct {
	LinkIndex int
	Hops      int
	Gw        net.IP
	Flags     int
	NewDst    Destination
	Encap     Encap
	Via       Destination
}

func (n *NexthopInfo) String() string {
	elems := []string{}
	elems = append(elems, fmt.Sprintf("Ifindex: %d", n.LinkIndex))
	if n.NewDst != nil {
		elems = append(elems, fmt.Sprintf("NewDst: %s", n.NewDst))
	}
	if n.Encap != nil {
		elems = append(elems, fmt.Sprintf("Encap: %s", n.Encap))
	}
	if n.Via != nil {
		elems = append(elems, fmt.Sprintf("Via: %s", n.Via))
	}
	elems = append(elems, fmt.Sprintf("Weight: %d", n.Hops+1))
	elems = append(elems, fmt.Sprintf("Gw: %s", n.Gw))
	elems = append(elems, fmt.Sprintf("Flags: %s", n.ListFlags()))
	return fmt.Sprintf("{%s}", strings.Join(elems, " "))
}

func (n NexthopInfo) Equal(x NexthopInfo) bool {
	return n.LinkIndex == x.LinkIndex &&
		n.Hops == x.Hops &&
		n.Gw.Equal(x.Gw) &&
		n.Flags == x.Flags &&
		(n.NewDst == x.NewDst || (n.NewDst != nil && n.NewDst.Equal(x.NewDst))) &&
		(n.Encap == x.Encap || (n.Encap != nil && n.Encap.Equal(x.Encap)))
}

type nexthopInfoSlice []*NexthopInfo

func (n nexthopInfoSlice) Equal(x []*NexthopInfo) bool {
	if len(n) != len(x) {
		return false
	}
	for i := range n {
		if n[i] == nil || x[i] == nil {
			return false
		}
		if !n[i].Equal(*x[i]) {
			return false
		}
	}
	return true
}

// ipNetEqual returns true iff both IPNet are equal
func ipNetEqual(ipn1 *net.IPNet, ipn2 *net.IPNet) bool {
	if ipn1 == ipn2 {
		return true
	}
	if ipn1 == nil || ipn2 == nil {
		return false
	}
	m1, _ := ipn1.Mask.Size()
	m2, _ := ipn2.Mask.Size()
	return m1 == m2 && ipn1.IP.Equal(ipn2.IP)
}
