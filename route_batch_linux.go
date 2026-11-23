package netlink

import (
	"context"
	"errors"
	"fmt"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// RouteReplaceBatch applies a set of route replacements transactionally.
// It is a shorthand for [Handle.RouteBatch] where every item uses
// [RouteOpReplace].
func RouteReplaceBatch(ctx context.Context, routes []*Route) error {
	return pkgHandle().RouteReplaceBatch(ctx, routes)
}

// RouteReplaceBatch applies a set of route replacements transactionally.
//
// The batch has all-or-nothing semantics:
//   - The whole batch is validated before anything is sent (duplicates,
//     conflicting route identities, and attributes that cannot be encoded).
//   - Requests are sent in stable order and kernel ACKs are correlated by
//     netlink sequence number, so a single rejected route does not leave the
//     outcome of the others ambiguous.
//   - If any item fails (or ctx is canceled while waiting for ACKs), every
//     route already committed by the batch is removed again in reverse
//     commit order.
//
// On failure the returned error, when not nil, is a [*RouteBatchError]
// (possibly joined with the context error) carrying per-item and rollback
// details. With one element the observable behavior matches [Handle.RouteReplace].
func (h *Handle) RouteReplaceBatch(ctx context.Context, routes []*Route) error {
	items := make([]RouteBatchItem, len(routes))
	for i, r := range routes {
		items[i] = RouteBatchItem{Op: RouteOpReplace, Route: r}
	}
	return h.RouteBatch(ctx, items)
}

// RouteBatch applies a mixed set of route operations (add, replace, change,
// delete) with the same transactional guarantees as [Handle.RouteReplaceBatch].
func RouteBatch(ctx context.Context, items []RouteBatchItem) error {
	return pkgHandle().RouteBatch(ctx, items)
}

// RouteBatch applies the given route operations transactionally. See
// [Handle.RouteReplaceBatch] for the failure and rollback semantics.
func (h *Handle) RouteBatch(ctx context.Context, items []RouteBatchItem) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}

	if err := validateRouteBatch(items); err != nil {
		return err
	}

	// Build every request up front: an encoding error for any single item must
	// abort the batch before the first byte reaches the kernel.
	batch := nl.NewNetlinkRequestBatch(len(items))
	for i := range items {
		req, err := h.newRouteBatchRequest(&items[i])
		if err != nil {
			return &RouteBatchError{
				ItemErrors: []*RouteBatchItemError{{
					Index: i,
					Op:    items[i].Op,
					Err:   err,
				}},
			}
		}
		batch.Add(req)
	}

	results, execErr := batch.Execute(ctx, unix.NETLINK_ROUTE)

	// Collect the kernel's per-item verdicts in stable index order.
	var itemErrs []*RouteBatchItemError
	committed := make([]int, 0, len(items))
	for i := range items {
		acked := i < len(results) && results[i].Acked
		if !acked {
			// No verdict (send stopped early, or the context was canceled
			// before the ACK arrived). Nothing was confirmed in the kernel,
			// so there is nothing to undo for this item.
			continue
		}
		if err := results[i].Err; err != nil {
			itemErrs = append(itemErrs, &RouteBatchItemError{
				Index: i,
				Op:    items[i].Op,
				Err:   err,
			})
			continue
		}
		committed = append(committed, i)
	}

	batchErr := &RouteBatchError{ItemErrors: itemErrs}
	failed := len(itemErrs) > 0 || execErr != nil

	if !failed {
		return nil
	}

	// Undo the committed items in reverse order. Only routes the batch itself
	// created or replaced can be restored to a known state: they are removed,
	// which is the inverse of add/replace/change. Delete operations have no
	// userspace inverse (the previous route content was never held here), so
	// they are skipped.
	//
	// Rollback deliberately detaches from ctx: once some routes are committed,
	// a cancellation must not abort the cleanup and leave those routes behind.
	// The detached context still ends when the process ends; socket timeouts
	// remain the bound on how long a single cleanup request can block.
	rollbackCtx := context.WithoutCancel(ctx)
	for j := len(committed) - 1; j >= 0; j-- {
		idx := committed[j]
		if items[idx].Op == RouteOpDelete {
			continue
		}
		// Use the same sequence-correlated transport as the batch itself so
		// that backlogged messages and non-kernel (test) peers are handled
		// identically. A route that is already gone is a successful cleanup.
		delReq, err := h.newRouteBatchRequest(&RouteBatchItem{
			Op:    RouteOpDelete,
			Route: items[idx].Route,
		})
		if err != nil {
			batchErr.RollbackErrors = append(batchErr.RollbackErrors, &RouteRollbackError{
				Index: idx,
				Op:    items[idx].Op,
				Err:   err,
			})
			continue
		}
		if err := delReq.ExecuteOne(rollbackCtx, unix.NETLINK_ROUTE); err != nil && !errors.Is(err, unix.ESRCH) {
			batchErr.RollbackErrors = append(batchErr.RollbackErrors, &RouteRollbackError{
				Index: idx,
				Op:    items[idx].Op,
				Err:   err,
			})
		}
	}

	if execErr != nil {
		// Keep the aggregate error discoverable via errors.Is/As while the
		// structured details remain on RouteBatchError.
		return errors.Join(batchErr, execErr)
	}
	return batchErr
}

// newRouteBatchRequest constructs (but does not send) the netlink request for
// one batch item, reusing the single-item encoding path.
func (h *Handle) newRouteBatchRequest(item *RouteBatchItem) (*nl.NetlinkRequest, error) {
	var (
		req *nl.NetlinkRequest
		msg *nl.RtMsg
	)
	switch item.Op {
	case RouteOpAdd:
		req = h.newNetlinkRequest(unix.RTM_NEWROUTE,
			unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
		msg = nl.NewRtMsg()
	case RouteOpReplace:
		req = h.newNetlinkRequest(unix.RTM_NEWROUTE,
			unix.NLM_F_CREATE|unix.NLM_F_REPLACE|unix.NLM_F_ACK)
		msg = nl.NewRtMsg()
	case RouteOpChange:
		req = h.newNetlinkRequest(unix.RTM_NEWROUTE,
			unix.NLM_F_REPLACE|unix.NLM_F_ACK)
		msg = nl.NewRtMsg()
	case RouteOpDelete:
		req = h.newNetlinkRequest(unix.RTM_DELROUTE, unix.NLM_F_ACK)
		msg = nl.NewRtDelMsg()
	default:
		return nil, fmt.Errorf("unknown route batch operation %d", item.Op)
	}
	if err := h.prepareRouteReq(item.Route, req, msg); err != nil {
		return nil, err
	}
	return req, nil
}

// routeIdentity is the kernel-visible key that makes two route items address
// the same route table entry. Two items with the same identity in one batch
// are ambiguous: only one can survive, so the batch is rejected up front.
// It mirrors the fields fib_route_hash keys on: table, destination (including
// MPLS), priority, TOS, type and the outgoing/incoming interfaces.
type routeIdentity struct {
	family   int
	table    int
	dst      string // CIDR, or empty for routes keyed only by Src/Gw
	priority int
	tos      int
	type_    int
	oif      int
	iif      int
	realm    int
	mpls     int
	hasMPLS  bool
}

func routeIdentityOf(route *Route) routeIdentity {
	id := routeIdentity{
		family:   route.Family,
		table:    route.Table,
		priority: route.Priority,
		tos:      route.Tos,
		type_:    route.Type,
		oif:      route.LinkIndex,
		iif:      route.ILinkIndex,
		realm:    route.Realm,
	}
	if route.Dst != nil && route.Dst.IP != nil {
		id.family = nl.GetIPFamily(route.Dst.IP)
		id.dst = route.Dst.String()
	}
	if route.MPLSDst != nil {
		id.hasMPLS = true
		id.mpls = *route.MPLSDst
	}
	return id
}

// validateRouteBatch runs every check that can fail without touching the
// kernel: nil entries, obvious attribute errors, in-batch duplicates and
// identity conflicts.
func validateRouteBatch(items []RouteBatchItem) error {
	seen := make(map[routeIdentity]int, len(items))
	var itemErrs []*RouteBatchItemError

	for i := range items {
		item := &items[i]
		if item.Route == nil {
			itemErrs = append(itemErrs, &RouteBatchItemError{
				Index: i,
				Op:    item.Op,
				Err:   errors.New("route is nil"),
			})
			continue
		}
		if item.Op < RouteOpAdd || item.Op > RouteOpDelete {
			itemErrs = append(itemErrs, &RouteBatchItemError{
				Index: i,
				Op:    item.Op,
				Err:   fmt.Errorf("unknown route batch operation %d", item.Op),
			})
			continue
		}
		// Mirror the check in prepareRouteReq for the obvious invalid case,
		// so an empty route is reported with its batch index.
		if (item.Route.Dst == nil || item.Route.Dst.IP == nil) &&
			item.Route.Src == nil && item.Route.Gw == nil && item.Route.MPLSDst == nil {
			itemErrs = append(itemErrs, &RouteBatchItemError{
				Index: i,
				Op:    item.Op,
				Err:   errors.New("either Dst.IP, Src.IP or Gw must be set"),
			})
			continue
		}
		if item.Route.Dst != nil && item.Route.Dst.IP != nil {
			if ip := item.Route.Dst.IP; ip.To4() == nil && ip.To16() == nil {
				itemErrs = append(itemErrs, &RouteBatchItemError{
					Index: i,
					Op:    item.Op,
					Err:   fmt.Errorf("invalid destination IP %q", ip.String()),
				})
				continue
			}
			if ones, bits := item.Route.Dst.Mask.Size(); ones > bits {
				itemErrs = append(itemErrs, &RouteBatchItemError{
					Index: i,
					Op:    item.Op,
					Err:   fmt.Errorf("invalid destination mask %s", item.Route.Dst.Mask.String()),
				})
				continue
			}
		}

		id := routeIdentityOf(item.Route)
		if prev, ok := seen[id]; ok {
			itemErrs = append(itemErrs, &RouteBatchItemError{
				Index: i,
				Op:    item.Op,
				Err:   fmt.Errorf("duplicate/conflicting route, same identity as batch item %d", prev),
			})
			continue
		}
		seen[id] = i
	}

	if len(itemErrs) > 0 {
		return &RouteBatchError{ItemErrors: itemErrs}
	}
	return nil
}
