package connection

import (
	"context"
	stdnet "net"
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/common/session"
)

// The Reality guard (Helper internal/flvx/guard.go, FLVX go-gost/x/landing
// guard.go) points a REALITY node's dest at a loopback dokodemo inbound
// tagged flvxg-<port>; allowed ClientHellos go on to the real dest through
// the flvxg-direct outbound. Without the guard, REALITY dials its dest itself
// and that socket is never tracked. With it, every new Reality connection
// added a tracked guard inbound socket and a tracked dest socket for about a
// second, counted against the share's total like user connections.
//
// The guard's hop is therefore not tracked either, so a guarded connection
// counts exactly like an unguarded one. Only a connection that arrives on an
// flvxg- inbound from a loopback address qualifies: the guard listens on
// 127.0.0.1 and only REALITY inside this Core dials it, so no remote client
// can reach the exemption, even through an inbound mistakenly tagged flvxg-.
const guardInboundTagPrefix = "flvxg-"

// GuardHopFeature names the exemption on /v1/features.
const GuardHopFeature = "flvx.reality_guard_hop_uncounted"

func guardHop(tag string, source netip.Addr) bool {
	return strings.HasPrefix(tag, guardInboundTagPrefix) && source.IsValid() && source.Unmap().IsLoopback()
}

func guardHopConn(tag string, conn stdnet.Conn) bool {
	if !strings.HasPrefix(tag, guardInboundTagPrefix) {
		return false
	}
	address, ok := tcpAddrPort(conn.RemoteAddr())
	return ok && guardHop(tag, address.Addr())
}

func guardHopContext(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || !strings.HasPrefix(inbound.Tag, guardInboundTagPrefix) || !inbound.Source.IsValid() || !inbound.Source.Address.Family().IsIP() {
		return false
	}
	address, ok := netip.AddrFromSlice(inbound.Source.Address.IP())
	return ok && guardHop(inbound.Tag, address)
}
