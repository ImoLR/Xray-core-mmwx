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
	if err := manager.ReplaceConfig(Config{Limits: []Limit{{Identity: identity, MaxOutboundTCPActive: pointer[int64](4)}}}); err != nil {
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
	if err := manager.ReplaceConfig(Config{Limits: []Limit{{Identity: identity, MaxOutboundTCPNewPerSecond: pointer(2)}}}); err != nil {
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
	if err := manager.ReplaceConfig(Config{Limits: []Limit{{Identity: identityA, MaxOutboundTCPActive: pointer[int64](1)}}}); err != nil {
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
	local, peer := stdnet.Pipe()
	defer peer.Close()
	connA := leaseA.succeeded(local)
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

type eofConn struct {
	closed chan struct{}
	once   sync.Once
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
	if err := outbound.Close(); err != nil {
		t.Fatal(err)
	}
	kernel[inboundTuple] = tcpTimeWaitState
	kernel[outboundTuple] = tcpTimeWaitState
	got = findSnapshot(t, manager, identity)
	if got.InboundActive != 0 || got.OutboundActive != 0 || got.InboundTCP.TimeWait != 1 || got.OutboundTCP.TimeWait != 1 {
		t.Fatalf("TIME_WAIT tuple attribution failed: %#v", got)
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
	if err := manager.ReplaceConfig(Config{
		MaxGlobalTotalConnections: pointer[int64](3),
		Limits:                    []Limit{{Identity: userA, MaxTotalConnections: pointer[int64](2)}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.bindInbound(identityFromContext(userContext("in-a", "user-a")), socketTuple{}); err != nil {
		t.Fatal(err)
	}
	leaseA, err := manager.acquire(userContext("in-a", "user-a"), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.acquire(userContext("in-a", "user-a"), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)); err == nil {
		t.Fatal("user total limit did not reject a new resource")
	} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != UserTotalLimit {
		t.Fatalf("unexpected user limit error: %v", err)
	}
	if _, err := manager.bindInbound(identityFromContext(userContext("in-b", "user-b")), socketTuple{}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.acquire(userContext("in-b", "user-b"), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)); err == nil {
		t.Fatal("global total limit did not reject a new resource")
	} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != GlobalTotalLimit {
		t.Fatalf("unexpected global limit error: %v", err)
	}
	leaseA.failed()
	got := findSnapshot(t, manager, userA)
	if got.CurrentTotal != 1 || got.RejectedUserTotalLimit != 1 {
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

func TestOnlineIPLimitUsesAuthenticatedSourceAndGrace(t *testing.T) {
	manager := NewManager()
	now := time.Unix(100, 0)
	manager.now = func() time.Time { return now }
	identity := Identity{InboundTag: "in-a", User: "user-a"}
	if err := manager.ReplaceConfig(Config{OnlineIPGracePeriodSeconds: 30, Limits: []Limit{{Identity: identity, MaxInboundOnlineIPs: pointer(1)}}}); err != nil {
		t.Fatal(err)
	}
	first := socketTuple{LocalIP: stdnetIPToAddr("10.0.0.1"), LocalPort: 10022, RemoteIP: stdnetIPToAddr("198.51.100.1"), RemotePort: 45000}
	firstID, err := manager.bindInbound(identityFromContext(userContext("in-a", "user-a")), first)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.RemoteIP = stdnetIPToAddr("198.51.100.2")
	second.RemotePort++
	if _, err := manager.bindInbound(identityFromContext(userContext("in-a", "user-a")), second); err == nil {
		t.Fatal("online IP limit did not reject a second source")
	} else if limitErr := new(LimitError); !errors.As(err, &limitErr) || limitErr.Reason != OnlineIPLimit {
		t.Fatalf("unexpected online IP error: %v", err)
	}
	manager.releaseInbound(identity, firstID, normalizedSourceIP(first.RemoteIP))
	if _, err := manager.bindInbound(identityFromContext(userContext("in-a", "user-a")), second); err == nil {
		t.Fatal("online IP grace was not retained")
	}
	now = now.Add(31 * time.Second)
	if _, err := manager.bindInbound(identityFromContext(userContext("in-a", "user-a")), second); err != nil {
		t.Fatalf("expired online IP grace still rejected: %v", err)
	}
}

func TestRejectedInboundIsCountedOnceAcrossRepeatedDispatch(t *testing.T) {
	manager := NewManager()
	previous := Default
	Default = manager
	t.Cleanup(func() { Default = previous })
	identity := Identity{InboundTag: "in-a", User: "user-a"}
	if err := manager.ReplaceConfig(Config{Limits: []Limit{{Identity: identity, MaxTotalConnections: pointer[int64](1)}}}); err != nil {
		t.Fatal(err)
	}
	first := newAddressedConn("10.0.0.1", 10022, "198.51.100.1", 45000)
	if err := BindInbound(userContext("in-a", "user-a"), TrackInbound(first)); err != nil {
		t.Fatal(err)
	}
	second := TrackInbound(newAddressedConn("10.0.0.1", 10022, "198.51.100.2", 45001))
	for attempt := 0; attempt < 2; attempt++ {
		if err := BindInbound(userContext("in-a", "user-a"), second); err == nil {
			t.Fatal("expected repeated dispatch to retain the rejection")
		}
	}
	if got := findSnapshot(t, manager, identity); got.RejectedUserTotalLimit != 1 {
		t.Fatalf("one inbound socket produced repeated rejection counters: %#v", got)
	}
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
	base := &eofConn{closed: make(chan struct{})}
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
