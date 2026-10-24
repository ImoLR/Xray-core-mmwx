package connection

import (
	"context"
	stdnet "net"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func guardContext(tag, source string) context.Context {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:     tag,
		Name:    "dokodemo-door",
		Source:  xnet.TCPDestination(xnet.ParseAddress(source), 50000),
		Gateway: xnet.TCPDestination(xnet.LocalHostIP, 39999),
	})
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{Tag: "flvxg-direct"}})
}

func coreCounts(manager *Manager) (total, inbound int64) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.coreCurrentLocked(), manager.globalInboundCurrent
}

// A share at its connection limit: the guard's loopback hop (guard inbound and
// its dest dial) is neither counted nor refused, exactly like REALITY's own
// untracked dest dial when the guard is off.
func TestGuardHopIsNotTracked(t *testing.T) {
	manager := NewManager()
	previous := Default
	Default = manager
	t.Cleanup(func() { Default = previous })
	if err := manager.ReplaceConfig(Config{MaxGlobalTotalConnections: pointer[int64](1), MaxGlobalInboundConnections: pointer[int64](1)}); err != nil {
		t.Fatal(err)
	}

	user := TrackInboundFor("flvxl-2", newAddressedConn("203.0.113.1", 31002, "198.51.100.7", 40000))
	userCtx := userContextWithSource(context.Background(), "flvxl-2", "flvxl-2", "198.51.100.7")
	if err := BindInbound(userCtx, user); err != nil {
		t.Fatal(err)
	}
	if err := AdmitInbound(userCtx); err != nil {
		t.Fatal(err)
	}
	if total, inbound := coreCounts(manager); total != 1 || inbound != 1 {
		t.Fatalf("user connection: total %d inbound %d", total, inbound)
	}

	hop := newAddressedConn("127.0.0.1", 39999, "127.0.0.1", 50000)
	if got := TrackInboundFor("flvxg-39999", hop); got != stdnet.Conn(hop) {
		t.Fatalf("guard hop wrapped for tracking: %T", got)
	}
	ctx := guardContext("flvxg-39999", "127.0.0.1")
	if err := BindInbound(ctx, hop); err != nil {
		t.Fatal(err)
	}
	if err := AdmitInbound(ctx); err != nil {
		t.Fatalf("guard hop refused at the inbound limit: %v", err)
	}
	dialed := false
	conn, err := TrackDial(ctx, xnet.TCPDestination(xnet.ParseAddress("192.0.2.80"), 443), func() (stdnet.Conn, error) {
		dialed = true
		return newAddressedConn("10.0.0.1", 50001, "192.0.2.80", 443), nil
	})
	if err != nil || !dialed {
		t.Fatalf("guard dest dial refused at the total limit: %v", err)
	}
	if _, tracked := conn.(*trackedOutboundConn); tracked {
		t.Fatal("guard dest socket tracked")
	}
	if total, inbound := coreCounts(manager); total != 1 || inbound != 1 {
		t.Fatalf("guard hop counted: total %d inbound %d", total, inbound)
	}
	if len(manager.Snapshots()) != 1 {
		t.Fatalf("guard hop created accounting state: %#v", manager.Snapshots())
	}
}

// The exemption needs both the flvxg- tag and a loopback source; anything a
// remote client can reach is tracked and limited as before.
func TestGuardHopExemptionNeedsTagAndLoopback(t *testing.T) {
	exempt := []struct{ tag, remote string }{
		{"flvxg-39999", "127.0.0.1"},
		{"flvxg-1", "127.8.9.10"},
		{"flvxg-39999", "::1"},
		{"flvxg-39999", "::ffff:127.0.0.1"},
	}
	for _, c := range exempt {
		conn := newAddressedConn("127.0.0.1", 39999, c.remote, 50000)
		if TrackInboundFor(c.tag, conn) != stdnet.Conn(conn) || !guardHopContext(guardContext(c.tag, c.remote)) {
			t.Errorf("%s from %s: not exempt", c.tag, c.remote)
		}
	}
	tracked := []struct{ tag, remote string }{
		{"flvxg-39999", "198.51.100.9"},
		{"flvxg-39999", "10.0.0.2"},
		{"flvxl-2", "127.0.0.1"},
		{"xflvxg-1", "127.0.0.1"},
		{"FLVXG-1", "127.0.0.1"},
		{"", "127.0.0.1"},
	}
	for _, c := range tracked {
		conn := newAddressedConn("0.0.0.0", 39999, c.remote, 50000)
		if _, ok := TrackInboundFor(c.tag, conn).(*trackedInboundConn); !ok || guardHopContext(guardContext(c.tag, c.remote)) {
			t.Errorf("%s from %s: exempt", c.tag, c.remote)
		}
	}
	if guardHopContext(context.Background()) {
		t.Error("context without inbound exempt")
	}

	// A remote client on an flvxg- tagged inbound still hits the share limit.
	manager := NewManager()
	previous := Default
	Default = manager
	t.Cleanup(func() { Default = previous })
	if err := manager.ReplaceConfig(Config{MaxGlobalTotalConnections: pointer[int64](1)}); err != nil {
		t.Fatal(err)
	}
	remote := guardContext("flvxg-39999", "198.51.100.9")
	dial := func() (stdnet.Conn, error) { return newAddressedConn("10.0.0.1", 50002, "192.0.2.80", 443), nil }
	if _, err := TrackDial(remote, xnet.TCPDestination(xnet.ParseAddress("192.0.2.80"), 443), dial); err != nil {
		t.Fatal(err)
	}
	_, err := TrackDial(remote, xnet.TCPDestination(xnet.ParseAddress("192.0.2.80"), 443), dial)
	requireLimitReason(t, err, GlobalTotalLimit)
}

func TestGuardHopFeatureAdvertised(t *testing.T) {
	for _, feature := range ControlFeatures {
		if feature == GuardHopFeature {
			return
		}
	}
	t.Fatalf("%s missing from %v", GuardHopFeature, ControlFeatures)
}
