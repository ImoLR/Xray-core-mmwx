package connection

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"net/netip"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func pointer[T any](value T) *T { return &value }

func userContext(tag, user string) context.Context {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:     tag,
		Name:    "shadowsocks",
		Gateway: xnet.TCPDestination(xnet.AnyIP, 12968),
		User:    &protocol.MemoryUser{Email: user},
	})
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{Tag: "direct"}})
}

func userContextWithSource(parent context.Context, tag, user, source string) context.Context {
	ctx := session.ContextWithInbound(parent, &session.Inbound{
		Tag:     tag,
		Name:    "shadowsocks",
		Source:  xnet.TCPDestination(xnet.ParseAddress(source), 45000),
		Gateway: xnet.TCPDestination(xnet.AnyIP, 12968),
		User:    &protocol.MemoryUser{Email: user},
	})
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{Tag: "direct"}})
}

func findSnapshot(t *testing.T, manager *Manager, identity Identity) Snapshot {
	t.Helper()
	for _, snapshot := range manager.Snapshots() {
		if snapshot.Identity == identity {
			return snapshot
		}
	}
	t.Fatalf("missing snapshot for %#v", identity)
	return Snapshot{}
}

func TestActiveLimitConcurrentAndCloseExactlyOnce(t *testing.T) {
	manager := NewManager()
	identity := Identity{InboundTag: "in-a", User: "user-a"}
	if err := manager.ReplaceConfig(Config{PortLimits: []PortLimit{{InboundTag: identity.InboundTag, MaxOutboundTCPActive: pointer[int64](4)}}}); err != nil {
		t.Fatal(err)
	}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	var accepted int
	var acceptedMu sync.Mutex
	var wait sync.WaitGroup
	ready := make(chan struct{})
	for i := 0; i < 20; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			lease, err := manager.acquire(userContext("in-a", "user-a"), destination)
			if err != nil {
				return
			}
			acceptedMu.Lock()
			accepted++
			acceptedMu.Unlock()
			<-ready
			lease.failed()
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(ready)
	wait.Wait()
	if accepted != 4 {
		t.Fatalf("accepted %d reservations, want 4", accepted)
	}

	lease, err := manager.acquire(userContext("in-a", "user-a"), destination)
	if err != nil {
		t.Fatal(err)
	}
	local, peer := stdnet.Pipe()
	defer peer.Close()
	conn := lease.succeeded(local)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := findSnapshot(t, manager, identity); got.OutboundActive != 0 || got.OutboundNewTotal != 1 {
		t.Fatalf("unexpected snapshot: %#v", got)
	}
}

func TestDialFailureRollbackAndRateWindow(t *testing.T) {
	manager := NewManager()
	identity := Identity{InboundTag: "in-a", User: "user-a"}
	now := time.Unix(100, 0)
	manager.now = func() time.Time { return now }
	if err := manager.ReplaceConfig(Config{PortLimits: []PortLimit{{InboundTag: identity.InboundTag, MaxOutboundTCPNewPerSecond: pointer(2)}}}); err != nil {
		t.Fatal(err)
	}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	for i := 0; i < 2; i++ {
		lease, err := manager.acquire(userContext("in-a", "user-a"), destination)
		if err != nil {
			t.Fatal(err)
		}
		lease.failed()
	}
	if _, err := manager.acquire(userContext("in-a", "user-a"), destination); err == nil {
		t.Fatal("expected rate limit rejection")
	} else {
		var limitErr *LimitError
		if !errors.As(err, &limitErr) || limitErr.Reason != NewRateLimit {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	got := findSnapshot(t, manager, identity)
	if got.OutboundPending != 0 || got.OutboundRejectedTotal != 1 {
		t.Fatalf("failed dial leaked or reject missing: %#v", got)
	}
	now = now.Add(time.Second + time.Nanosecond)
	lease, err := manager.acquire(userContext("in-a", "user-a"), destination)
	if err != nil {
		t.Fatalf("rate window did not expire: %v", err)
	}
	lease.failed()
}

func TestUDPBypassUnattributedAndUserIsolation(t *testing.T) {
	manager := NewManager()
	identityA := Identity{InboundTag: "in-a", User: "user-a"}
	if err := manager.ReplaceConfig(Config{PortLimits: []PortLimit{{InboundTag: identityA.InboundTag, MaxOutboundTCPActive: pointer[int64](1)}}}); err != nil {
		t.Fatal(err)
	}
	if lease, err := manager.acquire(userContext("in-a", "user-a"), xnet.UDPDestination(xnet.DomainAddress("example.com"), 53)); err != nil || lease != nil {
		t.Fatalf("UDP was tracked: lease=%v err=%v", lease, err)
	}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	leaseA, err := manager.acquire(userContext("in-a", "user-a"), destination)
	if err != nil {
		t.Fatal(err)
	}
	connA := leaseA.succeeded(newAddressedConn("10.0.0.1", 53000, "203.0.113.20", 443))
	defer connA.Close()
	if _, err := manager.acquire(userContext("in-a", "user-a"), destination); err == nil {
		t.Fatal("active limit must reject attributed user")
	}
	for _, ctx := range []context.Context{context.Background(), userContext("in-b", "user-b")} {
		lease, err := manager.acquire(ctx, destination)
		if err != nil {
			t.Fatalf("unrelated identity was limited: %v", err)
		}
		lease.failed()
	}
}

func TestInboundIdentityPropagationAndReset(t *testing.T) {
	manager := NewManager()
	previous := Default
	Default = manager
	t.Cleanup(func() { Default = previous })
	local, peer := stdnet.Pipe()
	defer peer.Close()
	conn := TrackInbound(local)
	BindInbound(userContext("in-a", "user-a"), conn)
	BindInbound(userContext("in-a", "user-a"), conn)
	identity := Identity{InboundTag: "in-a", User: "user-a"}
	if got := findSnapshot(t, manager, identity); got.InboundActive != 1 || got.InboundTotal != 1 || got.InboundPort != 12968 {
		t.Fatalf("identity not propagated: %#v", got)
	}
	_ = conn.Close()
	_ = conn.Close()
	if got := findSnapshot(t, manager, identity); got.InboundActive != 0 || got.InboundTotal != 1 {
		t.Fatalf("inbound close accounting failed: %#v", got)
	}
	manager.Reset()
	if len(manager.Snapshots()) != 0 {
		t.Fatal("restart/reset retained runtime state")
	}
}

func TestConfiguredInboundAndUsersExistBeforeTraffic(t *testing.T) {
	manager := NewManager()
	manager.RegisterConfiguredInbound(ConfiguredInbound{
		Tag: "ss-10015", Name: "shadowsocks-2022-multi", Port: 10015,
		Users: []string{"user-b", "user-a", "user-a", ""},
	})
	manager.RegisterConfiguredInbound(ConfiguredInbound{
		Tag: "ss-12311", Name: "shadowsocks-2022", Port: 12311,
	})

	inbounds := manager.ConfiguredInbounds()
	if len(inbounds) != 2 || inbounds[0].Port != 10015 || len(inbounds[0].Users) != 2 || inbounds[0].Users[0] != "user-a" || inbounds[1].Port != 12311 {
		t.Fatalf("configured inbounds = %#v", inbounds)
	}
	for _, user := range []string{"user-a", "user-b"} {
		got := findSnapshot(t, manager, Identity{InboundTag: "ss-10015", User: user})
		if !got.Attributed || got.InboundPort != 10015 || got.InboundActive != 0 || got.CurrentTotal != 0 {
			t.Fatalf("pre-traffic user %q = %#v", user, got)
		}
	}
	manager.Reset()
	if len(manager.ConfiguredInbounds()) != 0 || len(manager.Snapshots()) != 0 {
		t.Fatal("reset retained configured runtime metadata")
	}
}

type eofConn struct {
	closed chan struct{}
	once   sync.Once
}

type notifyingAddressedConn struct {
	*addressedConn
	closed chan struct{}
	once   sync.Once
}

func (c *notifyingAddressedConn) Close() error {
	c.addressedConn.closed = true
	c.once.Do(func() { close(c.closed) })
	return nil
}

type addressedConn struct {
	local  *stdnet.TCPAddr
	remote *stdnet.TCPAddr
	closed bool
}

func newAddressedConn(localIP string, localPort int, remoteIP string, remotePort int) *addressedConn {
	return &addressedConn{
		local:  &stdnet.TCPAddr{IP: stdnet.ParseIP(localIP), Port: localPort},
		remote: &stdnet.TCPAddr{IP: stdnet.ParseIP(remoteIP), Port: remotePort},
	}
}

func (c *addressedConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *addressedConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *addressedConn) Close() error                     { c.closed = true; return nil }
func (c *addressedConn) LocalAddr() stdnet.Addr           { return c.local }
func (c *addressedConn) RemoteAddr() stdnet.Addr          { return c.remote }
func (c *addressedConn) SetDeadline(time.Time) error      { return nil }
func (c *addressedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *addressedConn) SetWriteDeadline(time.Time) error { return nil }

func TestExactTupleAttributesInboundAndOutboundTimeWait(t *testing.T) {
	manager := NewManager()
	identity := Identity{InboundTag: "in-a", User: "user-a"}
	kernel := map[socketTuple]string{}
	manager.scanSockets = func() (map[socketTuple]string, error) { return kernel, nil }

	inboundBase := newAddressedConn("10.0.0.1", 10022, "198.51.100.10", 45000)
	inboundTuple, _ := socketTupleFromConn(inboundBase)
	inboundID, err := manager.bindInbound(identityFromContext(userContext("in-a", "user-a")), inboundTuple)
	if err != nil {
		t.Fatal(err)
	}
	kernel[inboundTuple] = tcpEstablishedState
	inboundLease, err := manager.admitInbound(identityFromContext(userContext("in-a", "user-a")), normalizedSourceIP(inboundTuple.RemoteIP))
	if err != nil {
		t.Fatal(err)
	}
	wrongTuple := inboundTuple
	wrongTuple.RemotePort++
	kernel[wrongTuple] = tcpCloseWaitState

	lease, err := manager.acquire(userContext("in-a", "user-a"), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	if err != nil {
		t.Fatal(err)
	}
	outboundBase := newAddressedConn("10.0.0.1", 53000, "203.0.113.20", 443)
	outboundTuple, _ := socketTupleFromConn(outboundBase)
	outbound := lease.succeeded(outboundBase)
	kernel[outboundTuple] = tcpEstablishedState

	got := findSnapshot(t, manager, identity)
	if got.InboundTCP.Established != 1 || got.InboundTCP.CloseWait != 0 || got.OutboundTCP.Established != 1 || len(got.InboundOnlineIPs) != 1 || got.InboundOnlineIPs[0].IP != "198.51.100.10" {
		t.Fatalf("established tuple attribution failed: %#v", got)
	}

	manager.releaseInbound(identity, inboundID, normalizedSourceIP(inboundTuple.RemoteIP))
	inboundLease.release()
	if err := outbound.Close(); err != nil {
		t.Fatal(err)
	}
	kernel[inboundTuple] = tcpTimeWaitState
	kernel[outboundTuple] = tcpTimeWaitState
	got = findSnapshot(t, manager, identity)
	if got.InboundActive != 0 || got.OutboundActive != 0 || got.InboundTCP.TimeWait != 1 || got.OutboundTCP.TimeWait != 1 || got.CurrentTotal != 2 {
		t.Fatalf("TIME_WAIT tuple attribution failed: %#v", got)
	}
}

func TestUnifiedTotalsIncludeExactStatesWithoutDuplicateSockets(t *testing.T) {
	manager := NewManager()
	identityA := Identity{InboundTag: "in-a", User: "proto-a"}
	identityB := Identity{InboundTag: "in-b", User: "proto-b"}
	if err := manager.ReplaceConfig(Config{ManagementMappings: []ManagementGroupMapping{
		{Identity: identityA, Group: "ken"}, {Identity: identityB, Group: "ken"},
	}}); err != nil {
		t.Fatal(err)
	}
	inboundA := socketTuple{LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 10001, RemoteIP: netip.MustParseAddr("198.51.100.1"), RemotePort: 41001}
	outboundA := socketTuple{LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 51001, RemoteIP: netip.MustParseAddr("203.0.113.1"), RemotePort: 443}
	inboundB := socketTuple{LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 10002, RemoteIP: netip.MustParseAddr("198.51.100.2"), RemotePort: 41002}
	unknown := socketTuple{LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 59999, RemoteIP: netip.MustParseAddr("192.0.2.99"), RemotePort: 22}
	manager.scanSockets = func() (map[socketTuple]string, error) {
		return map[socketTuple]string{
			inboundA: tcpEstablishedState, outboundA: tcpTimeWaitState,
			inboundB: tcpCloseWaitState, unknown: tcpEstablishedState,
		}, nil
	}

	manager.mu.Lock()
	manager.stateLocked(identityA, Snapshot{Identity: identityA, Attributed: true, ManagementGroup: "ken"})
	manager.stateLocked(identityB, Snapshot{Identity: identityB, Attributed: true, ManagementGroup: "ken"})
	manager.registerSocketLocked(identityA, inboundSocket, inboundA)
	oldOutbound := manager.registerSocketLocked(identityA, outboundSocket, outboundA)
	manager.closeSocketLocked(oldOutbound)
	manager.registerSocketLocked(identityA, outboundSocket, outboundA) // tuple reuse: one kernel row
	manager.registerSocketLocked(identityB, inboundSocket, inboundB)
	manager.mu.Unlock()

	users, global, groups, err := manager.FullSnapshotReport()
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, user := range users {
		total += user.CurrentTotal
	}
	if total != 3 || global.CurrentTotal != 3 {
		t.Fatalf("exact totals include unknown or duplicate sockets: users=%#v global=%#v", users, global)
	}
	if len(groups) != 1 || groups[0].CurrentTotal != 3 || groups[0].InboundTCP.Total != 2 || groups[0].OutboundTCP.TimeWait != 1 || groups[0].InboundTCP.CloseWait != 1 {
		t.Fatalf("management user total is not the sum of exact port totals: %#v", groups)
	}
}

func TestClosedSocketTombstoneAttributesLaterTimeWaitButDoesNotInventTotal(t *testing.T) {
	manager := NewManager()
	identity := Identity{InboundTag: "in-a", User: "user-a"}
	tuple := socketTuple{LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 10022, RemoteIP: netip.MustParseAddr("198.51.100.10"), RemotePort: 45000}
	kernel := map[socketTuple]string{}
	manager.scanSockets = func() (map[socketTuple]string, error) { return kernel, nil }
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	socketID, err := manager.bindInbound(Snapshot{Identity: identity, Attributed: true}, tuple)
	if err != nil {
		t.Fatal(err)
	}
	manager.releaseInbound(identity, socketID, "198.51.100.10")
	got := findSnapshot(t, manager, identity)
	if got.CurrentTotal != 0 {
		t.Fatalf("absent tombstone was exposed as a TCP Total: %#v", got)
	}

	now = now.Add(30 * time.Second)
	kernel[tuple] = tcpTimeWaitState
	got = findSnapshot(t, manager, identity)
	if got.CurrentTotal != 1 || got.InboundTCP.TimeWait != 1 {
		t.Fatalf("later TIME_WAIT lost exact identity: %#v", got)
	}

	delete(kernel, tuple)
	now = now.Add(time.Second)
	if _, _, _, err := manager.FullSnapshotReport(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(socketTombstoneRetention + time.Second)
	if _, _, _, err := manager.FullSnapshotReport(); err != nil {
		t.Fatal(err)
	}
	if len(manager.sockets) != 0 {
		t.Fatalf("expired tombstone was not pruned: %#v", manager.sockets)
	}
}

func TestTotalLimitIncludesTimeWaitAndCloseWaitAndOnlyRejectsNew(t *testing.T) {
	manager := NewManager()
	identity := Identity{InboundTag: "in-a", User: "proto-a"}
	limit := int64(2)
	if err := manager.ReplaceConfig(Config{PortLimits: []PortLimit{{InboundTag: identity.InboundTag, MaxTotalConnections: &limit}}}); err != nil {
		t.Fatal(err)
	}
	timeWaitTuple := socketTuple{LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 51001, RemoteIP: netip.MustParseAddr("203.0.113.1"), RemotePort: 443}
	closeWaitTuple := socketTuple{LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 51002, RemoteIP: netip.MustParseAddr("203.0.113.2"), RemotePort: 443}
	manager.scanSockets = func() (map[socketTuple]string, error) {
		return map[socketTuple]string{timeWaitTuple: tcpTimeWaitState, closeWaitTuple: tcpCloseWaitState}, nil
	}
	manager.mu.Lock()
	manager.stateLocked(identity, Snapshot{Identity: identity, Attributed: true})
	timeWaitID := manager.registerSocketLocked(identity, outboundSocket, timeWaitTuple)
	manager.closeSocketLocked(timeWaitID)
	manager.registerSocketLocked(identity, outboundSocket, closeWaitTuple)
	manager.mu.Unlock()

	got := findSnapshot(t, manager, identity)
	if got.CurrentTotal != 2 || got.OutboundTCP.TimeWait != 1 || got.OutboundTCP.CloseWait != 1 {
		t.Fatalf("terminal states not included in Total: %#v", got)
	}
	if _, err := manager.acquire(userContext(identity.InboundTag, identity.User), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)); err == nil {
		t.Fatal("Total limit accepted a new controlled connection")
	} else {
		requireLimitReason(t, err, PortCombinedLimit)
	}
	if len(manager.sockets) != 2 {
		t.Fatalf("Total limit removed existing sockets: %#v", manager.sockets)
	}
}

func TestAllTCPStatesRemainDistinct(t *testing.T) {
	var counts TCPStateCounts
	for _, state := range []string{
		tcpEstablishedState, tcpSynSentState, tcpSynRecvState, tcpFinWait1State,
		tcpFinWait2State, tcpTimeWaitState, tcpCloseWaitState, tcpLastAckState,
		tcpClosingState, tcpCloseState, "FF",
	} {
		addTCPState(&counts, state)
	}
	addTCPState(&counts, tcpListenState)
	if counts.Total != 11 || counts.Established != 1 || counts.SynSent != 1 || counts.SynRecv != 1 || counts.FinWait1 != 1 || counts.FinWait2 != 1 || counts.TimeWait != 1 || counts.CloseWait != 1 || counts.LastAck != 1 || counts.Closing != 1 || counts.Close != 1 || counts.Unknown != 1 {
		t.Fatalf("TCP states were collapsed or miscounted: %#v", counts)
	}
}

func TestUserAndGlobalTotalLimitsCountOnlyOwnedResources(t *testing.T) {
	manager := NewManager()
	userA := Identity{InboundTag: "in-a", User: "user-a"}
	tupleA := socketTuple{LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 10001, RemoteIP: netip.MustParseAddr("198.51.100.1"), RemotePort: 41001}
	tupleB := socketTuple{LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 10002, RemoteIP: netip.MustParseAddr("198.51.100.2"), RemotePort: 41002}
	manager.scanSockets = func() (map[socketTuple]string, error) {
		return map[socketTuple]string{tupleA: tcpEstablishedState, tupleB: tcpEstablishedState}, nil
	}
	if err := manager.ReplaceConfig(Config{
		MaxGlobalTotalConnections: pointer[int64](3),
		PortLimits:                []PortLimit{{InboundTag: userA.InboundTag, MaxOutboundTCPActive: pointer[int64](1)}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.bindInbound(identityFromContext(userContext("in-a", "user-a")), tupleA); err != nil {
		t.Fatal(err)
	}
	leaseA, err := manager.acquire(userContext("in-a", "user-a"), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.acquire(userContext("in-a", "user-a"), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)); err == nil {
		t.Fatal("user total limit did not reject a new resource")
	} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != PortTotalLimit {
		t.Fatalf("unexpected user limit error: %v", err)
	}
	if _, err := manager.bindInbound(identityFromContext(userContext("in-b", "user-b")), tupleB); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.acquire(userContext("in-b", "user-b"), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)); err == nil {
		t.Fatal("global total limit did not reject a new resource")
	} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != GlobalTotalLimit {
		t.Fatalf("unexpected global limit error: %v", err)
	}
	leaseA.failed()
	got := findSnapshot(t, manager, userA)
	if got.CurrentTotal != 1 || got.RejectedPortTotalLimit != 1 {
		t.Fatalf("user total snapshot mismatch: %#v", got)
	}
	_, global, err := manager.SnapshotReport()
	if err != nil {
		t.Fatal(err)
	}
	if global.CurrentTotal != 2 || global.RejectedGlobalTotalLimit != 1 {
		t.Fatalf("global snapshot mismatch: %#v", global)
	}
}

func requireLimitReason(t *testing.T, err error, reason LimitReason) {
	t.Helper()
	var limitErr *LimitError
	if !errors.As(err, &limitErr) || limitErr.Reason != reason {
		t.Fatalf("limit error = %v, want %s", err, reason)
	}
}

func TestBlockedIdentityAdmissionAndUnblocking(t *testing.T) {
	for _, user := range []string{"user-a", ""} {
		t.Run("user="+user, func(t *testing.T) {
			manager := NewManager()
			previous := Default
			Default = manager
			t.Cleanup(func() { Default = previous })
			identity := Identity{InboundTag: "in-a", User: user}
			if err := manager.ReplaceConfig(Config{BlockedIdentities: []Identity{identity}}); err != nil {
				t.Fatal(err)
			}
			if got := findSnapshot(t, manager, identity); !got.Blocked || !got.Attributed || got.RejectedBlocked != 0 {
				t.Fatalf("blocked identity missing before traffic: %#v", got)
			}
			ctx := userContext(identity.InboundTag, identity.User)
			conn := TrackInbound(newAddressedConn("127.0.0.1", 12345, "127.0.0.1", 45000))
			defer conn.Close()
			requireLimitReason(t, BindInbound(ctx, conn), BlockedIdentity)
			requireLimitReason(t, BindInbound(ctx, conn), BlockedIdentity)
			requireLimitReason(t, AdmitInbound(ctx), BlockedIdentity)
			if got := findSnapshot(t, manager, identity); got.RejectedBlocked != 2 || got.InboundActive != 0 || got.InboundCurrent != 0 || got.OutboundRejectedTotal != 0 {
				t.Fatalf("blocked admission counters = %#v", got)
			}
			for _, other := range []Identity{{InboundTag: "in-a", User: "user-b"}, {InboundTag: "in-b", User: user}} {
				otherCtx, cancel := context.WithCancel(userContext(other.InboundTag, other.User))
				defer cancel()
				otherConn := TrackInbound(newAddressedConn("127.0.0.1", 12345, "127.0.0.1", 45001))
				defer otherConn.Close()
				if err := BindInbound(otherCtx, otherConn); err != nil {
					t.Fatalf("unrelated identity rejected at bind: %v", err)
				}
				if err := AdmitInbound(otherCtx); err != nil {
					t.Fatalf("unrelated identity rejected at admission: %v", err)
				}
			}
			if err := manager.ReplaceConfig(Config{}); err != nil {
				t.Fatal(err)
			}
			newCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			newConn := TrackInbound(newAddressedConn("127.0.0.1", 12345, "127.0.0.1", 45002))
			defer newConn.Close()
			if err := BindInbound(newCtx, newConn); err != nil {
				t.Fatalf("unblocked identity rejected at bind: %v", err)
			}
			if err := AdmitInbound(newCtx); err != nil {
				t.Fatalf("unblocked identity rejected at admission: %v", err)
			}
			if got := findSnapshot(t, manager, identity); got.Blocked || got.RejectedBlocked != 2 {
				t.Fatalf("unblocking lost rejection history or retained block: %#v", got)
			}
		})
	}
}

func TestBlockedIdentitiesConfigValidation(t *testing.T) {
	identity := Identity{InboundTag: "in-a", User: "user-a"}
	for _, config := range []Config{
		{BlockedIdentities: []Identity{{User: "user-a"}}},
		{BlockedIdentities: []Identity{identity, identity}},
		{BlockedIdentities: []Identity{{InboundTag: "single"}, {InboundTag: "single"}}},
		{BlockedIdentities: []Identity{{InboundTag: "in-b"}}, PortLimits: []PortLimit{{}}},
	} {
		manager := NewManager()
		if err := manager.ReplaceConfig(Config{BlockedIdentities: []Identity{identity}}); err != nil {
			t.Fatal(err)
		}
		if err := manager.ReplaceConfig(config); err == nil {
			t.Fatalf("accepted invalid config: %#v", config)
		}
		if len(manager.blockedIdentities) != 1 || !findSnapshot(t, manager, identity).Blocked {
			t.Fatal("invalid config changed blocked identities")
		}
	}
	manager := NewManager()
	if err := manager.ReplaceConfig(Config{BlockedIdentities: []Identity{
		identity, {InboundTag: "in-a", User: "user-b"}, {InboundTag: "in-b", User: "user-a"}, {InboundTag: "single"},
	}}); err != nil {
		t.Fatalf("distinct identities or empty user rejected: %v", err)
	}
	manager.Reset()
	if len(manager.blockedIdentities) != 0 || len(manager.Snapshots()) != 0 {
		t.Fatal("reset retained blocked identities")
	}
}

func TestInboundGlobalUserPortPrecedenceAndCrossPortAggregation(t *testing.T) {
	identityA := Identity{InboundTag: "in-a", User: "proto-a"}
	identityB := Identity{InboundTag: "in-b", User: "proto-b"}
	for _, test := range []struct {
		name               string
		global, user, port int64
		second             Identity
		want               LimitReason
	}{
		{name: "global", global: 1, user: 3, port: 3, second: identityA, want: GlobalInboundLimit},
		{name: "user across ports", global: 3, user: 1, port: 3, second: identityB, want: UserInboundLimit},
		{name: "port", global: 3, user: 3, port: 1, second: identityA, want: PortInboundLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := NewManager()
			if err := manager.ReplaceConfig(Config{
				MaxGlobalInboundConnections: &test.global,
				ManagementMappings:          []ManagementGroupMapping{{Identity: identityA, Group: "ken"}, {Identity: identityB, Group: "ken"}},
				ManagementLimits:            []ManagementGroupLimit{{Group: "ken", MaxInboundConnections: &test.user}},
				PortLimits:                  []PortLimit{{InboundTag: "in-a", MaxInboundConnections: &test.port}, {InboundTag: "in-b", MaxInboundConnections: &test.port}},
			}); err != nil {
				t.Fatal(err)
			}
			first, err := manager.admitInbound(identityFromContext(userContext(identityA.InboundTag, identityA.User)), "198.51.100.1")
			if err != nil {
				t.Fatal(err)
			}
			defer first.release()
			if _, err := manager.admitInbound(identityFromContext(userContext(test.second.InboundTag, test.second.User)), "198.51.100.1"); err == nil {
				t.Fatal("second logical inbound exceeded a configured ceiling")
			} else {
				requireLimitReason(t, err, test.want)
			}
		})
	}
}

func TestInboundConcurrentAdmissionDoesNotExceedLimit(t *testing.T) {
	manager := NewManager()
	identity := Identity{InboundTag: "in-a", User: "proto-a"}
	limit := int64(4)
	if err := manager.ReplaceConfig(Config{MaxGlobalInboundConnections: &limit}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var leases []*inboundLease
	var wait sync.WaitGroup
	for index := 0; index < 40; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			lease, err := manager.admitInbound(identityFromContext(userContext(identity.InboundTag, identity.User)), "198.51.100.1")
			if err == nil {
				mu.Lock()
				leases = append(leases, lease)
				mu.Unlock()
			}
		}()
	}
	wait.Wait()
	if len(leases) != int(limit) {
		t.Fatalf("accepted %d logical inbounds, want %d", len(leases), limit)
	}
	for _, lease := range leases {
		lease.release()
	}
}

func TestInboundContextFailureReleasesReservation(t *testing.T) {
	manager := NewManager()
	previous := Default
	Default = manager
	t.Cleanup(func() { Default = previous })
	limit := int64(1)
	if err := manager.ReplaceConfig(Config{MaxGlobalInboundConnections: &limit}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ctx = userContextWithSource(ctx, "in-a", "proto-a", "198.51.100.1")
	if err := AdmitInbound(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.admitInbound(identityFromContext(userContext("in-a", "proto-a")), "198.51.100.1"); err == nil {
		t.Fatal("reservation was not held while processing")
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		lease, err := manager.admitInbound(identityFromContext(userContext("in-a", "proto-a")), "198.51.100.1")
		if err == nil {
			lease.release()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled processing did not release inbound reservation")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUserAndPortOnlineIPLimitsDeduplicateAcrossPorts(t *testing.T) {
	manager := NewManager()
	identityA := Identity{InboundTag: "in-a", User: "proto-a"}
	identityB := Identity{InboundTag: "in-b", User: "proto-b"}
	userLimit, portLimit := 3, 2
	if err := manager.ReplaceConfig(Config{
		ManagementMappings: []ManagementGroupMapping{{Identity: identityA, Group: "ken"}, {Identity: identityB, Group: "ken"}},
		ManagementLimits:   []ManagementGroupLimit{{Group: "ken", MaxInboundOnlineIPs: &userLimit}},
		PortLimits:         []PortLimit{{InboundTag: "in-a", MaxInboundOnlineIPs: &portLimit}, {InboundTag: "in-b", MaxInboundOnlineIPs: &portLimit}},
	}); err != nil {
		t.Fatal(err)
	}
	var leases []*inboundLease
	for _, item := range []struct {
		identity Identity
		source   string
	}{
		{identityA, "198.51.100.1"}, {identityA, "198.51.100.2"},
		{identityB, "198.51.100.2"}, {identityB, "198.51.100.3"},
	} {
		lease, err := manager.admitInbound(identityFromContext(userContext(item.identity.InboundTag, item.identity.User)), item.source)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
	}
	if _, err := manager.admitInbound(identityFromContext(userContext("in-b", "proto-b")), "198.51.100.4"); err == nil {
		t.Fatal("fourth user-level unique IP was admitted")
	} else {
		requireLimitReason(t, err, UserOnlineIPLimit)
	}
	_, _, groups, err := manager.FullSnapshotReport()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].InboundCurrent != 4 || len(groups[0].InboundOnlineIPs) != 3 {
		t.Fatalf("deduplicated management snapshot = %#v", groups)
	}
	for _, lease := range leases {
		lease.release()
	}
}

func TestPortOnlineIPLimitIsIndependent(t *testing.T) {
	manager := NewManager()
	portLimit := 1
	if err := manager.ReplaceConfig(Config{PortLimits: []PortLimit{{InboundTag: "in-a", MaxInboundOnlineIPs: &portLimit}, {InboundTag: "in-b", MaxInboundOnlineIPs: &portLimit}}}); err != nil {
		t.Fatal(err)
	}
	first, err := manager.admitInbound(identityFromContext(userContext("in-a", "a")), "198.51.100.1")
	if err != nil {
		t.Fatal(err)
	}
	defer first.release()
	if _, err := manager.admitInbound(identityFromContext(userContext("in-a", "a")), "198.51.100.2"); err == nil {
		t.Fatal("second port-level IP was admitted")
	} else {
		requireLimitReason(t, err, PortOnlineIPLimit)
	}
	second, err := manager.admitInbound(identityFromContext(userContext("in-b", "b")), "198.51.100.2")
	if err != nil {
		t.Fatalf("independent port rejected its first IP: %v", err)
	}
	second.release()
}

func TestUserOnlineIPGraceStartsAfterLastCrossPortConnection(t *testing.T) {
	manager := NewManager()
	now := time.Unix(100, 0)
	manager.now = func() time.Time { return now }
	identityA := Identity{InboundTag: "in-a", User: "a"}
	identityB := Identity{InboundTag: "in-b", User: "b"}
	limit := 1
	if err := manager.ReplaceConfig(Config{
		OnlineIPGracePeriodSeconds: 30,
		ManagementMappings:         []ManagementGroupMapping{{Identity: identityA, Group: "ken"}, {Identity: identityB, Group: "ken"}},
		ManagementLimits:           []ManagementGroupLimit{{Group: "ken", MaxInboundOnlineIPs: &limit}},
	}); err != nil {
		t.Fatal(err)
	}
	first, _ := manager.admitInbound(identityFromContext(userContext("in-a", "a")), "198.51.100.1")
	second, _ := manager.admitInbound(identityFromContext(userContext("in-b", "b")), "198.51.100.1")
	first.release()
	now = now.Add(20 * time.Second)
	if _, err := manager.admitInbound(identityFromContext(userContext("in-a", "a")), "198.51.100.2"); err == nil {
		t.Fatal("user IP was released while still active on another port")
	}
	second.release()
	now = now.Add(29 * time.Second)
	if _, err := manager.admitInbound(identityFromContext(userContext("in-a", "a")), "198.51.100.2"); err == nil {
		t.Fatal("user IP grace expired too early")
	}
	now = now.Add(2 * time.Second)
	lease, err := manager.admitInbound(identityFromContext(userContext("in-a", "a")), "198.51.100.2")
	if err != nil {
		t.Fatalf("expired user IP grace still rejected: %v", err)
	}
	lease.release()
}

func TestOnlineIPIPv6UsesSlash64AndIdentityMapping(t *testing.T) {
	manager := NewManager()
	identity := Identity{InboundTag: "in-a", User: "proto-a"}
	limit := 1
	if err := manager.ReplaceConfig(Config{
		ManagementMappings: []ManagementGroupMapping{{Identity: identity, Group: "ken"}},
		ManagementLimits:   []ManagementGroupLimit{{Group: "ken", MaxInboundOnlineIPs: &limit}},
	}); err != nil {
		t.Fatal(err)
	}
	first, err := manager.admitInbound(identityFromContext(userContext("in-a", "proto-a")), normalizedSourceIP(netip.MustParseAddr("2001:db8:1::1")))
	if err != nil {
		t.Fatal(err)
	}
	defer first.release()
	second, err := manager.admitInbound(identityFromContext(userContext("in-a", "proto-a")), normalizedSourceIP(netip.MustParseAddr("2001:db8:1::99")))
	if err != nil {
		t.Fatalf("same IPv6 /64 was counted twice: %v", err)
	}
	defer second.release()
	if _, err := manager.admitInbound(identityFromContext(userContext("in-a", "proto-a")), normalizedSourceIP(netip.MustParseAddr("2001:db8:2::1"))); err == nil {
		t.Fatal("different IPv6 /64 was admitted")
	} else {
		requireLimitReason(t, err, UserOnlineIPLimit)
	}
	if got := findSnapshot(t, manager, identity); got.ManagementGroup != "ken" || len(got.InboundOnlineIPs) != 1 {
		t.Fatalf("identity mapping or IPv6 tracking failed: %#v", got)
	}
}

func TestLegacyIdentityLimitsAreIgnoredWithoutBreakingCloseWait(t *testing.T) {
	manager := NewManager()
	identity := Identity{InboundTag: "in-a", User: "proto-a"}
	zero := int64(0)
	zeroIPs := 0
	closeWait := int64(5)
	if err := manager.ReplaceConfig(Config{Limits: []Limit{{
		Identity: identity, MaxInboundOnlineIPs: &zeroIPs, MaxTotalConnections: &zero,
		MaxOutboundTCPActive: &zero, MaxOutboundTCPNewPerSecond: &zeroIPs, CloseWaitTimeoutSeconds: &closeWait,
	}}}); err != nil {
		t.Fatalf("historic identity limit config was rejected: %v", err)
	}
	first, err := manager.admitInbound(identityFromContext(userContext("in-a", "proto-a")), "198.51.100.1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.admitInbound(identityFromContext(userContext("in-a", "proto-a")), "198.51.100.2")
	if err != nil {
		t.Fatalf("historic identity limit was still enforced: %v", err)
	}
	first.release()
	second.release()
	got := findSnapshot(t, manager, identity)
	if got.MaxInboundOnlineIPs != nil || got.MaxTotalConnections != nil || got.MaxOutboundTCPActive != nil || got.CloseWaitTimeoutSeconds == nil || *got.CloseWaitTimeoutSeconds != 5 {
		t.Fatalf("legacy identity compatibility snapshot = %#v", got)
	}
}

func TestManagementGroupAggregateLimitIsConcurrentAcrossPorts(t *testing.T) {
	manager := NewManager()
	groupLimit := int64(4)
	identities := []Identity{{InboundTag: "in-a", User: "proto-a"}, {InboundTag: "in-b", User: "proto-b"}}
	if err := manager.ReplaceConfig(Config{
		ManagementMappings: []ManagementGroupMapping{{Identity: identities[0], Group: "ken"}, {Identity: identities[1], Group: "ken"}},
		ManagementLimits:   []ManagementGroupLimit{{Group: "ken", MaxOutboundTCPActive: &groupLimit}},
	}); err != nil {
		t.Fatal(err)
	}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	var accepted int
	var acceptedMu sync.Mutex
	var leases []*lease
	var leaseMu sync.Mutex
	var wait sync.WaitGroup
	for index := 0; index < 40; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			identity := identities[index%len(identities)]
			lease, err := manager.acquire(userContext(identity.InboundTag, identity.User), destination)
			if err != nil {
				return
			}
			acceptedMu.Lock()
			accepted++
			acceptedMu.Unlock()
			leaseMu.Lock()
			leases = append(leases, lease)
			leaseMu.Unlock()
		}(index)
	}
	wait.Wait()
	if accepted != 4 {
		t.Fatalf("management aggregate admitted %d, want 4", accepted)
	}
	for _, lease := range leases {
		lease.failed()
	}
	_, _, groups, err := manager.FullSnapshotReport()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Group != "ken" || groups[0].RejectedUserTotalLimit != 36 || groups[0].OutboundPending != 0 {
		t.Fatalf("management group snapshot = %#v", groups)
	}
}

func TestGlobalManagementAndPortLimitsAllRemainHardCeilings(t *testing.T) {
	identityA := Identity{InboundTag: "in-a", User: "proto-a"}
	identityB := Identity{InboundTag: "in-b", User: "proto-b"}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	for _, test := range []struct {
		name       string
		global     int64
		management int64
		port       int64
		want       LimitReason
	}{
		{name: "global first", global: 1, management: 3, port: 3, want: GlobalTotalLimit},
		{name: "management second", global: 3, management: 1, port: 3, want: UserTotalLimit},
		{name: "port third", global: 3, management: 3, port: 1, want: PortTotalLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := NewManager()
			if err := manager.ReplaceConfig(Config{
				MaxGlobalTotalConnections: &test.global,
				ManagementMappings:        []ManagementGroupMapping{{Identity: identityA, Group: "ken"}, {Identity: identityB, Group: "ken"}},
				ManagementLimits:          []ManagementGroupLimit{{Group: "ken", MaxOutboundTCPActive: &test.management}},
				PortLimits:                []PortLimit{{InboundTag: "in-a", MaxOutboundTCPActive: &test.port}},
			}); err != nil {
				t.Fatal(err)
			}
			first, err := manager.acquire(userContext("in-a", "proto-a"), destination)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.acquire(userContext("in-a", "proto-a"), destination); err == nil {
				t.Fatal("second admission exceeded a configured ceiling")
			} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != test.want {
				t.Fatalf("rejection reason = %v, want %s", err, test.want)
			}
			first.failed()
		})
	}
}

func TestManagementAndPortLimitsHaveDistinctReasons(t *testing.T) {
	manager := NewManager()
	identityA := Identity{InboundTag: "in-a", User: "proto-a"}
	identityB := Identity{InboundTag: "in-b", User: "proto-b"}
	userLimit, portLimit := int64(1), int64(1)
	if err := manager.ReplaceConfig(Config{
		ManagementMappings: []ManagementGroupMapping{{Identity: identityA, Group: "ken"}, {Identity: identityB, Group: "ken"}},
		ManagementLimits:   []ManagementGroupLimit{{Group: "ken", MaxOutboundTCPActive: &userLimit}},
		PortLimits:         []PortLimit{{InboundTag: identityB.InboundTag, MaxOutboundTCPActive: &portLimit}},
	}); err != nil {
		t.Fatal(err)
	}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	first, err := manager.acquire(userContext("in-a", "proto-a"), destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.acquire(userContext("in-b", "proto-b"), destination); err == nil {
		t.Fatal("expected management user rejection")
	} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != UserTotalLimit || limitErr.ManagementGroup != "ken" {
		t.Fatalf("unexpected management rejection: %v", err)
	}
	first.failed()
	userLimit = 10
	if err := manager.ReplaceConfig(Config{
		ManagementMappings: []ManagementGroupMapping{{Identity: identityA, Group: "ken"}, {Identity: identityB, Group: "ken"}},
		ManagementLimits:   []ManagementGroupLimit{{Group: "ken", MaxOutboundTCPActive: &userLimit}},
		PortLimits:         []PortLimit{{InboundTag: identityB.InboundTag, MaxOutboundTCPActive: &portLimit}},
	}); err != nil {
		t.Fatal(err)
	}
	second, err := manager.acquire(userContext("in-b", "proto-b"), destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.acquire(userContext("in-b", "proto-b"), destination); err == nil {
		t.Fatal("expected port rejection")
	} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != PortTotalLimit {
		t.Fatalf("unexpected port rejection: %v", err)
	}
	second.failed()
}

func TestManagementAndPortCombinedLimitsIncludeInboundAndOutbound(t *testing.T) {
	identity := Identity{InboundTag: "in-a", User: "proto-a"}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	for _, test := range []struct {
		name   string
		config Config
		want   LimitReason
	}{
		{
			name: "management combined",
			config: Config{
				ManagementMappings: []ManagementGroupMapping{{Identity: identity, Group: "ken"}},
				ManagementLimits:   []ManagementGroupLimit{{Group: "ken", MaxTotalConnections: pointer[int64](2)}},
			},
			want: UserCombinedLimit,
		},
		{
			name:   "port combined",
			config: Config{PortLimits: []PortLimit{{InboundTag: identity.InboundTag, MaxTotalConnections: pointer[int64](2)}}},
			want:   PortCombinedLimit,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := NewManager()
			if err := manager.ReplaceConfig(test.config); err != nil {
				t.Fatal(err)
			}
			tuple := socketTuple{LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 10001, RemoteIP: netip.MustParseAddr("198.51.100.1"), RemotePort: 41001}
			socketID, err := manager.bindInbound(Snapshot{Identity: identity, Attributed: true}, tuple)
			if err != nil {
				t.Fatal(err)
			}
			first, err := manager.acquire(userContext(identity.InboundTag, identity.User), destination)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.acquire(userContext(identity.InboundTag, identity.User), destination); err == nil {
				t.Fatal("combined total limit accepted a third resource")
			} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != test.want {
				t.Fatalf("combined rejection = %v, want %s", err, test.want)
			}
			first.failed()
			manager.releaseInbound(identity, socketID, "")
		})
	}
}

func TestPortAggregateLimitCannotBeBypassedByChangingProtocolIdentity(t *testing.T) {
	manager := NewManager()
	limit := int64(3)
	if err := manager.ReplaceConfig(Config{PortLimits: []PortLimit{{InboundTag: "shared", MaxOutboundTCPActive: &limit}}}); err != nil {
		t.Fatal(err)
	}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	identities := []string{"proto-a", "proto-b"}
	leasing := []*lease{}
	for index := 0; index < 3; index++ {
		lease, err := manager.acquire(userContext("shared", identities[index%2]), destination)
		if err != nil {
			t.Fatal(err)
		}
		leasing = append(leasing, lease)
	}
	if _, err := manager.acquire(userContext("shared", "proto-b"), destination); err == nil {
		t.Fatal("second protocol identity bypassed the port aggregate limit")
	} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != PortTotalLimit {
		t.Fatalf("unexpected port aggregate rejection: %v", err)
	}
	for _, lease := range leasing {
		lease.failed()
	}
}

func TestManagementAndPortNewRateLimitsAreCrossPortAndDistinct(t *testing.T) {
	manager := NewManager()
	now := time.Unix(100, 0)
	manager.now = func() time.Time { return now }
	identityA := Identity{InboundTag: "in-a", User: "proto-a"}
	identityB := Identity{InboundTag: "in-b", User: "proto-b"}
	userRate, portRate := 2, 1
	if err := manager.ReplaceConfig(Config{
		ManagementMappings: []ManagementGroupMapping{{Identity: identityA, Group: "ken"}, {Identity: identityB, Group: "ken"}},
		ManagementLimits:   []ManagementGroupLimit{{Group: "ken", MaxOutboundTCPNewPerSecond: &userRate}},
		PortLimits:         []PortLimit{{InboundTag: identityA.InboundTag, MaxOutboundTCPNewPerSecond: &portRate}},
	}); err != nil {
		t.Fatal(err)
	}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	lease, err := manager.acquire(userContext("in-a", "proto-a"), destination)
	if err != nil {
		t.Fatal(err)
	}
	lease.failed()
	if _, err := manager.acquire(userContext("in-a", "proto-a"), destination); err == nil {
		t.Fatal("expected per-port NEW/s rejection")
	} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != PortNewRateLimit {
		t.Fatalf("unexpected per-port NEW/s rejection: %v", err)
	}
	lease, err = manager.acquire(userContext("in-b", "proto-b"), destination)
	if err != nil {
		t.Fatal(err)
	}
	lease.failed()
	if _, err := manager.acquire(userContext("in-b", "proto-b"), destination); err == nil {
		t.Fatal("expected management NEW/s rejection")
	} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != UserNewRateLimit {
		t.Fatalf("unexpected management NEW/s rejection: %v", err)
	}
}

func TestSingleSecretInboundUsesExplicitTagOnlyMapping(t *testing.T) {
	manager := NewManager()
	identity := Identity{InboundTag: "ss-12311"}
	limit := int64(1)
	manager.RegisterConfiguredInbound(ConfiguredInbound{Tag: identity.InboundTag, Port: 12311})
	if err := manager.ReplaceConfig(Config{
		ManagementMappings: []ManagementGroupMapping{{Identity: identity, Group: "imolr"}},
		ManagementLimits:   []ManagementGroupLimit{{Group: "imolr", MaxOutboundTCPActive: &limit}},
	}); err != nil {
		t.Fatal(err)
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: identity.InboundTag, Gateway: xnet.TCPDestination(xnet.AnyIP, 12311)})
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	lease, err := manager.acquire(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.acquire(ctx, destination); err == nil {
		t.Fatal("tag-only management mapping was not enforced")
	}
	lease.failed()
	got := findSnapshot(t, manager, identity)
	if !got.Attributed || got.ManagementGroup != "imolr" || got.InboundPort != 12311 {
		t.Fatalf("tag-only mapping snapshot = %#v", got)
	}
}

func TestMappingRemovalStopsManagementAttributionWithoutLosingPortState(t *testing.T) {
	manager := NewManager()
	identity := Identity{InboundTag: "in-a", User: "proto-a"}
	limit := int64(1)
	if err := manager.ReplaceConfig(Config{
		ManagementMappings: []ManagementGroupMapping{{Identity: identity, Group: "ken"}},
		ManagementLimits:   []ManagementGroupLimit{{Group: "ken", MaxOutboundTCPActive: &limit}},
	}); err != nil {
		t.Fatal(err)
	}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	first, err := manager.acquire(userContext("in-a", "proto-a"), destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.acquire(userContext("in-a", "proto-a"), destination); err == nil {
		t.Fatal("management limit did not apply")
	}
	if err := manager.ReplaceConfig(Config{}); err != nil {
		t.Fatal(err)
	}
	second, err := manager.acquire(userContext("in-a", "proto-a"), destination)
	if err != nil {
		t.Fatalf("removed mapping still limited the identity: %v", err)
	}
	if got := findSnapshot(t, manager, identity); got.ManagementGroup != "" || got.OutboundPending != 2 {
		t.Fatalf("mapping removal lost or misattributed port state: %#v", got)
	}
	first.failed()
	second.failed()
}

func stdnetIPToAddr(value string) netip.Addr {
	return netip.MustParseAddr(value)
}

func (c *eofConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *eofConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *eofConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *eofConn) LocalAddr() stdnet.Addr           { return &stdnet.TCPAddr{} }
func (c *eofConn) RemoteAddr() stdnet.Addr          { return &stdnet.TCPAddr{} }
func (c *eofConn) SetDeadline(time.Time) error      { return nil }
func (c *eofConn) SetReadDeadline(time.Time) error  { return nil }
func (c *eofConn) SetWriteDeadline(time.Time) error { return nil }

func TestCloseWaitTimeoutOwnsAndClosesSessionSocket(t *testing.T) {
	manager := NewManager()
	identity := Identity{InboundTag: "in-a", User: "user-a"}
	if err := manager.ReplaceConfig(Config{Limits: []Limit{{Identity: identity, CloseWaitTimeoutSeconds: pointer[int64](1)}}}); err != nil {
		t.Fatal(err)
	}
	lease, err := manager.acquire(userContext("in-a", "user-a"), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	if err != nil {
		t.Fatal(err)
	}
	base := &notifyingAddressedConn{
		addressedConn: newAddressedConn("10.0.0.1", 53000, "203.0.113.20", 443),
		closed:        make(chan struct{}),
	}
	tuple, _ := socketTupleFromConn(base)
	manager.scanSockets = func() (map[socketTuple]string, error) {
		return map[socketTuple]string{tuple: tcpCloseWaitState}, nil
	}
	conn := lease.succeeded(base)
	if _, err := conn.Read(nil); err != io.EOF {
		t.Fatalf("read error = %v, want EOF", err)
	}
	select {
	case <-base.closed:
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("close-wait timeout did not close owned socket")
	}
	if got := findSnapshot(t, manager, identity); got.OutboundActive != 0 {
		t.Fatalf("timeout did not release active count: %#v", got)
	}
}

func TestCloseWaitTimeoutRechecksStateAndZeroDisables(t *testing.T) {
	for _, test := range []struct {
		name       string
		timeout    *int64
		state      string
		wantClosed bool
	}{
		{name: "still close wait", timeout: pointer[int64](1), state: tcpCloseWaitState, wantClosed: true},
		{name: "changed to time wait", timeout: pointer[int64](1), state: tcpTimeWaitState, wantClosed: false},
		{name: "disabled", timeout: pointer[int64](0), state: tcpCloseWaitState, wantClosed: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := NewManager()
			if err := manager.ReplaceConfig(Config{DefaultCloseWaitTimeoutSeconds: test.timeout}); err != nil {
				t.Fatal(err)
			}
			lease, err := manager.acquire(userContext("in-a", "user-a"), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
			if err != nil {
				t.Fatal(err)
			}
			base := &notifyingAddressedConn{
				addressedConn: newAddressedConn("10.0.0.1", 53001, "203.0.113.21", 443),
				closed:        make(chan struct{}),
			}
			tuple, _ := socketTupleFromConn(base)
			manager.scanSockets = func() (map[socketTuple]string, error) {
				return map[socketTuple]string{tuple: test.state}, nil
			}
			conn := lease.succeeded(base)
			if _, err := conn.Read(nil); err != io.EOF {
				t.Fatalf("read error = %v, want EOF", err)
			}
			select {
			case <-base.closed:
				if !test.wantClosed {
					t.Fatal("timer closed a socket that was not still CLOSE_WAIT")
				}
			case <-time.After(1200 * time.Millisecond):
				if test.wantClosed {
					t.Fatal("timer did not close a socket still in CLOSE_WAIT")
				}
				_ = conn.Close()
			}
		})
	}
}
