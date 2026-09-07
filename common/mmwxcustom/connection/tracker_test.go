package connection

import (
	"context"
	"errors"
	"io"
	stdnet "net"
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
