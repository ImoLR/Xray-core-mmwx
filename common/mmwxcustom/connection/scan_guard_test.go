package connection

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

func intp(value int) *int { return &value }

type scanClock struct{ now time.Time }

func (c *scanClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newScanManager(t *testing.T, guard *ScanGuardConfig) (*Manager, *scanClock) {
	t.Helper()
	manager := NewManager()
	clock := &scanClock{now: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}
	manager.now = func() time.Time { return clock.now }
	manager.scanSockets = func() (map[socketTuple]string, error) { return map[socketTuple]string{}, nil }
	if err := manager.ReplaceConfig(Config{ScanGuard: guard}); err != nil {
		t.Fatal(err)
	}
	return manager, clock
}

func guardFor(identities ...string) *ScanGuardConfig {
	return &ScanGuardConfig{Enabled: true, Identities: identities}
}

func ipv4(index int) xnet.Address {
	return xnet.IPAddress([]byte{10, byte(index >> 16), byte(index >> 8), byte(index)})
}

// dial runs one TCP dial of tag/user through acquire and reports whether it
// was admitted; a refused dial must be the scan block.
func dial(t *testing.T, manager *Manager, tag, user string, address xnet.Address, port int) bool {
	t.Helper()
	lease, err := manager.acquire(userContext(tag, user), xnet.TCPDestination(address, xnet.Port(port)))
	if err != nil {
		var limitErr *LimitError
		if !errors.As(err, &limitErr) || limitErr.Reason != BlockedIdentity {
			t.Fatalf("unexpected dial error: %v", err)
		}
		return false
	}
	lease.failed()
	return true
}

func scanHits(manager *Manager, after uint64) []ScanHit {
	return manager.ScanReport(after).Hits
}

func TestScanGuardOffKeepsManagerUntouched(t *testing.T) {
	for name, guard := range map[string]*ScanGuardConfig{
		"absent": nil,
		// A disabled guard's values are not looked at.
		"disabled": {Enabled: false, Identities: []string{"in-a", "in-a"}, Horizontal: intp(0), WindowS: intp(1)},
	} {
		t.Run(name, func(t *testing.T) {
			manager, _ := newScanManager(t, guard)
			if manager.scan != nil {
				t.Fatal("guard state allocated while off")
			}
			for i := 0; i < 2000; i++ {
				if !dial(t, manager, "in-a", "in-a", ipv4(i), 22) {
					t.Fatalf("dial %d refused with the guard off", i)
				}
			}
			if manager.scan != nil || len(scanHits(manager, 0)) != 0 {
				t.Fatal("guard counted while off")
			}
			if got := findSnapshot(t, manager, Identity{InboundTag: "in-a", User: "in-a"}); got.Blocked || got.RejectedBlocked != 0 {
				t.Fatalf("snapshot changed with the guard off: %#v", got)
			}
		})
	}
}

func TestScanGuardValidation(t *testing.T) {
	bad := map[string]*ScanGuardConfig{
		"horizontal 0":       {Enabled: true, Horizontal: intp(0)},
		"horizontal_web big": {Enabled: true, HorizontalWeb: intp(100001)},
		"vertical 0":         {Enabled: true, Vertical: intp(0)},
		"total big":          {Enabled: true, Total: intp(100001)},
		"window short":       {Enabled: true, WindowS: intp(9)},
		"window long":        {Enabled: true, WindowS: intp(3601)},
		"total window short": {Enabled: true, TotalWindowS: intp(9)},
		"too many web ports": {Enabled: true, WebPorts: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}},
		"web port 0":         {Enabled: true, WebPorts: []int{0}},
		"web port 65536":     {Enabled: true, WebPorts: []int{65536}},
		"duplicate web port": {Enabled: true, WebPorts: []int{443, 443}},
		"empty identity":     {Enabled: true, Identities: []string{" "}},
		"duplicate identity": {Enabled: true, Identities: []string{"in-a", "in-a"}},
	}
	for name, guard := range bad {
		t.Run(name, func(t *testing.T) {
			manager, _ := newScanManager(t, guardFor("in-a"))
			before := manager.scan.settings
			if err := manager.ReplaceConfig(Config{ScanGuard: guard}); err == nil || !strings.Contains(err.Error(), "scan_guard") {
				t.Fatalf("bad scan_guard accepted or unclear error: %v", err)
			}
			if manager.scan.settings != before || !manager.scan.enabled {
				t.Fatal("rejected config changed the guard")
			}
		})
	}
	manager, _ := newScanManager(t, nil)
	for _, unblock := range [][]ScanUnblock{{{Identity: "", Seq: 1}}, {{Identity: "in-a"}}} {
		if err := manager.ReplaceConfig(Config{ScanUnblock: unblock}); err == nil {
			t.Fatalf("bad scan_unblock accepted: %#v", unblock)
		}
	}
	edge := &ScanGuardConfig{Enabled: true, Horizontal: intp(1), HorizontalWeb: intp(100000), Vertical: intp(100000), Total: intp(1), WindowS: intp(10), TotalWindowS: intp(3600), WebPorts: []int{}}
	if err := manager.ReplaceConfig(Config{ScanGuard: edge}); err != nil {
		t.Fatalf("edge values rejected: %v", err)
	}
	if manager.scan.settings.webPortCount != 0 {
		t.Fatal("an empty web_ports list must mean no web ports")
	}
	if err := manager.ReplaceConfig(Config{ScanGuard: guardFor()}); err != nil {
		t.Fatal(err)
	}
	if got := manager.scan.settings; got.horizontal != 100 || got.horizontalWeb != 500 || got.vertical != 30 || got.total != 1000 || got.windowS != 60 || got.totalWindowS != 300 || got.webPortCount != 2 || got.webPorts[0] != 80 || got.webPorts[1] != 443 {
		t.Fatalf("defaults = %#v", got)
	}
}

func TestScanGuardHorizontalBlocksOnlyThatIdentity(t *testing.T) {
	manager, clock := newScanManager(t, guardFor("flvxl-1", "flvxl-2"))
	previous := Default
	Default = manager
	t.Cleanup(func() { Default = previous })

	// Tracked client sockets: two of the scanning node (authenticated and
	// tag-only), one of another node on the same Core.
	owners := []Identity{{InboundTag: "flvxl-1", User: "flvxl-1"}, {InboundTag: "flvxl-1"}, {InboundTag: "flvxl-2", User: "flvxl-2"}}
	var conns []*closeCountConn
	for index, owner := range owners {
		conn := &closeCountConn{addressedConn: newAddressedConn("127.0.0.1", 30001, "198.51.100.7", 40000+index)}
		tracked := TrackInbound(conn)
		if err := BindInbound(userContext(owner.InboundTag, owner.User), tracked); err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
	}

	for i := 0; i < 99; i++ {
		if !dial(t, manager, "flvxl-1", "flvxl-1", ipv4(i), 22) {
			t.Fatalf("dial %d refused below the threshold", i)
		}
		clock.advance(100 * time.Millisecond)
	}
	if len(scanHits(manager, 0)) != 0 {
		t.Fatal("hit below the threshold")
	}
	if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(99), 22) {
		t.Fatal("the 100th distinct host on port 22 was admitted")
	}
	hits := scanHits(manager, 0)
	if len(hits) != 1 {
		t.Fatalf("hits = %#v", hits)
	}
	hit := hits[0]
	if hit.Identity != "flvxl-1" || hit.Type != "horizontal" || hit.Count != 100 || hit.Port != 22 || hit.Host != "" || hit.WindowS != 60 || !hit.At.Equal(clock.now) || hit.Seq != uint64(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC).UnixMicro())+1 {
		t.Fatalf("hit = %#v", hit)
	}
	waitClosed(t, conns, []bool{true, true, false})

	// Blocked: every dial and every new client socket of that tag is refused,
	// other identities keep working.
	if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(0), 22) || dial(t, manager, "flvxl-1", "flvxl-1", xnet.DomainAddress("example.com"), 443) {
		t.Fatal("blocked identity dialled")
	}
	if err := manager.ReplaceConfig(Config{ScanGuard: guardFor("flvxl-1", "flvxl-2")}); err != nil {
		t.Fatal(err)
	}
	if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(0), 22) {
		t.Fatal("a config without scan_unblock lifted the block")
	}
	for _, user := range []string{"flvxl-1", ""} {
		if _, err := manager.admitInbound(identityFromContext(userContext("flvxl-1", user)), "198.51.100.8"); err == nil {
			t.Fatalf("blocked identity %q admitted a new client", user)
		}
		raw := newAddressedConn("127.0.0.1", 30001, "198.51.100.8", 41000)
		conn := TrackInbound(raw)
		if err := BindInbound(userContext("flvxl-1", user), conn); err == nil {
			t.Fatalf("blocked identity %q bound a new client socket", user)
		}
		// A refused socket is closed, so a multiplexing client cannot keep
		// a session that stays refused after the unblock.
		if !raw.closed {
			t.Fatalf("socket refused by the scan block for %q left open", user)
		}
	}
	// A config block keeps today's behaviour: refused, not closed.
	configBlocked, _ := newScanManager(t, guardFor("flvxl-9"))
	if err := configBlocked.ReplaceConfig(Config{BlockedIdentities: []Identity{{InboundTag: "flvxl-9", User: "flvxl-9"}}}); err != nil {
		t.Fatal(err)
	}
	Default = configBlocked
	raw := newAddressedConn("127.0.0.1", 30009, "198.51.100.8", 41001)
	if err := BindInbound(userContext("flvxl-9", "flvxl-9"), TrackInbound(raw)); err == nil || raw.closed {
		t.Fatalf("config block changed: err=%v closed=%v", err, raw.closed)
	}
	Default = manager
	if got := findSnapshot(t, manager, Identity{InboundTag: "flvxl-1", User: "flvxl-1"}); !got.Blocked || got.RejectedBlocked == 0 {
		t.Fatalf("blocked snapshot = %#v", got)
	}
	for i := 0; i < 99; i++ {
		if !dial(t, manager, "flvxl-2", "flvxl-2", ipv4(i), 22) {
			t.Fatal("another identity was blocked")
		}
	}
	if !dial(t, manager, "in-other", "user", ipv4(5000), 22) {
		t.Fatal("an unguarded identity was refused")
	}
	if got := findSnapshot(t, manager, Identity{InboundTag: "flvxl-2", User: "flvxl-2"}); got.Blocked {
		t.Fatal("another identity reported as blocked")
	}

	// Lifting needs the blocking hit's seq; a wrong seq is ignored.
	if err := manager.ReplaceConfig(Config{ScanGuard: guardFor("flvxl-1", "flvxl-2"), ScanUnblock: []ScanUnblock{{Identity: "flvxl-1", Seq: hit.Seq - 1}}}); err != nil {
		t.Fatal(err)
	}
	if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(0), 22) {
		t.Fatal("an unblock naming another seq lifted the block")
	}
	unblock := []ScanUnblock{{Identity: "flvxl-1", Seq: hit.Seq}}
	if err := manager.ReplaceConfig(Config{ScanGuard: guardFor("flvxl-1", "flvxl-2"), ScanUnblock: unblock}); err != nil {
		t.Fatal(err)
	}
	if got := findSnapshot(t, manager, Identity{InboundTag: "flvxl-1", User: "flvxl-1"}); got.Blocked {
		t.Fatal("unblocked identity still reported as blocked")
	}
	if _, err := manager.admitInbound(identityFromContext(userContext("flvxl-1", "flvxl-1")), "198.51.100.8"); err != nil {
		t.Fatalf("unblocked identity refused: %v", err)
	}
	// Counting restarts from empty windows; the agent may keep sending the
	// same unblock entry, and it never lifts the next block.
	for i := 0; i < 99; i++ {
		if !dial(t, manager, "flvxl-1", "flvxl-1", ipv4(i), 22) {
			t.Fatalf("dial %d after unblock refused", i)
		}
	}
	if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(99), 22) {
		t.Fatal("second scan not detected")
	}
	if err := manager.ReplaceConfig(Config{ScanGuard: guardFor("flvxl-1", "flvxl-2"), ScanUnblock: unblock}); err != nil {
		t.Fatal(err)
	}
	if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(0), 22) {
		t.Fatal("a repeated old unblock lifted a newer block")
	}
	if hits := scanHits(manager, hit.Seq); len(hits) != 1 || hits[0].Seq != hit.Seq+1 {
		t.Fatalf("incremental read = %#v", hits)
	}
	// Switching the guard off neither counts nor lifts the block.
	if err := manager.ReplaceConfig(Config{}); err != nil {
		t.Fatal(err)
	}
	if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(0), 22) {
		t.Fatal("switching the guard off lifted the block")
	}
	for i := 0; i < 500; i++ {
		if !dial(t, manager, "flvxl-2", "flvxl-2", ipv4(i), 22) {
			t.Fatal("guard counted while switched off")
		}
	}
}

type closeCountConn struct {
	*addressedConn
	closes atomic.Int32
}

func (c *closeCountConn) Close() error { c.closes.Add(1); return nil }

func waitClosed(t *testing.T, conns []*closeCountConn, want []bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		done := true
		for index, conn := range conns {
			if (conn.closes.Load() > 0) != want[index] {
				done = false
			}
		}
		if done {
			// Give a wrong extra close a moment to show up.
			time.Sleep(20 * time.Millisecond)
			for index, conn := range conns {
				if (conn.closes.Load() > 0) != want[index] {
					t.Fatalf("connection %d closed = %v", index, conn.closes.Load() > 0)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			for index, conn := range conns {
				t.Logf("connection %d closes=%d want closed=%v", index, conn.closes.Load(), want[index])
			}
			t.Fatal("inbound sockets were not closed as expected")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestScanGuardWebPortsUseTheirOwnThreshold(t *testing.T) {
	manager, _ := newScanManager(t, guardFor("flvxl-1"))
	for i := 0; i < 499; i++ {
		if !dial(t, manager, "flvxl-1", "flvxl-1", ipv4(i), 443) || !dial(t, manager, "flvxl-1", "flvxl-1", ipv4(i), 80) {
			t.Fatalf("web dial %d refused below 500", i)
		}
	}
	if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(499), 443) {
		t.Fatal("500th host on 443 admitted")
	}
	if hit := scanHits(manager, 0)[0]; hit.Type != "horizontal" || hit.Port != 443 || hit.Count != 500 {
		t.Fatalf("hit = %#v", hit)
	}
	custom, _ := newScanManager(t, &ScanGuardConfig{Enabled: true, Identities: []string{"flvxl-1"}, WebPorts: []int{8443}, Horizontal: intp(5), HorizontalWeb: intp(10)})
	for i := 0; i < 9; i++ {
		if !dial(t, custom, "flvxl-1", "flvxl-1", ipv4(i), 8443) {
			t.Fatal("custom web port used the plain threshold")
		}
	}
	for i := 0; i < 4; i++ {
		if !dial(t, custom, "flvxl-1", "flvxl-1", ipv4(i), 443) {
			t.Fatal("443 refused below the plain threshold")
		}
	}
	if dial(t, custom, "flvxl-1", "flvxl-1", ipv4(4), 443) {
		t.Fatal("443 is not a web port once web_ports is set")
	}
}

func TestScanGuardVerticalCountsPortsOfOneHost(t *testing.T) {
	for name, address := range map[string]xnet.Address{"ip": xnet.ParseAddress("203.0.113.9"), "ipv4-mapped": xnet.ParseAddress("::ffff:203.0.113.9"), "domain": xnet.DomainAddress("scan.example")} {
		t.Run(name, func(t *testing.T) {
			manager, _ := newScanManager(t, guardFor("flvxl-1"))
			for port := 1; port < 30; port++ {
				if !dial(t, manager, "flvxl-1", "flvxl-1", address, port) {
					t.Fatalf("port %d refused", port)
				}
			}
			// The same ports again are not new.
			for port := 1; port < 30; port++ {
				if !dial(t, manager, "flvxl-1", "flvxl-1", address, port) {
					t.Fatal("repeat refused")
				}
			}
			if dial(t, manager, "flvxl-1", "flvxl-1", address, 30) {
				t.Fatal("30th port admitted")
			}
			want := "203.0.113.9"
			if name == "domain" {
				want = "scan.example"
			}
			if hit := scanHits(manager, 0)[0]; hit.Type != "vertical" || hit.Host != want || hit.Count != 30 || hit.Port != 0 || hit.WindowS != 60 {
				t.Fatalf("hit = %#v", hit)
			}
		})
	}
}

func TestScanGuardTotalAndSlidingWindows(t *testing.T) {
	manager, clock := newScanManager(t, guardFor("flvxl-1"))
	// 999 hosts over ~299 s, every pair on its own port: no horizontal or
	// vertical pattern, only the total window sees them.
	for i := 0; i < 999; i++ {
		if !dial(t, manager, "flvxl-1", "flvxl-1", ipv4(i), 1024+i) {
			t.Fatalf("host %d refused", i)
		}
		clock.advance(299 * time.Millisecond)
	}
	if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(999), 9) {
		t.Fatal("1000th host in 300 s admitted")
	}
	if hit := scanHits(manager, 0)[0]; hit.Type != "total" || hit.Count != 1000 || hit.WindowS != 300 || hit.Port != 0 || hit.Host != "" {
		t.Fatalf("hit = %#v", hit)
	}

	// The same 1000 hosts spread a bit wider than 300 s never hit.
	slow, clock := newScanManager(t, guardFor("flvxl-1"))
	for i := 0; i < 3000; i++ {
		if !dial(t, slow, "flvxl-1", "flvxl-1", ipv4(i), 1024+i%60000) {
			t.Fatalf("slow host %d refused", i)
		}
		clock.advance(301 * time.Millisecond)
	}
	clock.advance(301 * time.Second)
	// Horizontal window slides: 99 hosts, 61 s later 99 new hosts.
	for round := 0; round < 3; round++ {
		for i := 0; i < 99; i++ {
			if !dial(t, slow, "flvxl-1", "flvxl-1", ipv4(10000+round*1000+i), 22) {
				t.Fatalf("round %d host %d refused", round, i)
			}
		}
		clock.advance(61 * time.Second)
	}
	// ...but 99 + 1 inside one window hit.
	for i := 0; i < 99; i++ {
		dial(t, slow, "flvxl-1", "flvxl-1", ipv4(20000+i), 22)
	}
	clock.advance(59 * time.Second)
	if dial(t, slow, "flvxl-1", "flvxl-1", ipv4(20099), 22) {
		t.Fatal("100 hosts within 60 s admitted")
	}
}

func TestScanGuardKeepsCountersAcrossIdenticalConfigs(t *testing.T) {
	manager, _ := newScanManager(t, guardFor("flvxl-1"))
	for i := 0; i < 99; i++ {
		dial(t, manager, "flvxl-1", "flvxl-1", ipv4(i), 22)
	}
	// The agent re-sends its config every 10 s: counting must go on.
	for i := 0; i < 3; i++ {
		if err := manager.ReplaceConfig(Config{ScanGuard: &ScanGuardConfig{Enabled: true, Identities: []string{"flvxl-2", "flvxl-1"}, Horizontal: intp(100), WebPorts: []int{443, 80}}}); err != nil {
			t.Fatal(err)
		}
	}
	if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(99), 22) {
		t.Fatal("counters were reset by an identical config")
	}

	// A threshold change resets counters (and never unblocks).
	changed, _ := newScanManager(t, guardFor("flvxl-1"))
	for i := 0; i < 99; i++ {
		dial(t, changed, "flvxl-1", "flvxl-1", ipv4(i), 22)
	}
	if err := changed.ReplaceConfig(Config{ScanGuard: &ScanGuardConfig{Enabled: true, Identities: []string{"flvxl-1"}, Horizontal: intp(101)}}); err != nil {
		t.Fatal(err)
	}
	for i := 99; i < 99+100; i++ {
		if !dial(t, changed, "flvxl-1", "flvxl-1", ipv4(i), 22) {
			t.Fatal("old counts survived a threshold change")
		}
	}
	// Removing an identity from the list stops its counting; adding it back
	// starts empty.
	if err := changed.ReplaceConfig(Config{ScanGuard: &ScanGuardConfig{Enabled: true, Horizontal: intp(101)}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		dial(t, changed, "flvxl-1", "flvxl-1", ipv4(5000+i), 22)
	}
	if err := changed.ReplaceConfig(Config{ScanGuard: &ScanGuardConfig{Enabled: true, Identities: []string{"flvxl-1"}, Horizontal: intp(101)}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if !dial(t, changed, "flvxl-1", "flvxl-1", ipv4(9000+i), 22) {
			t.Fatal("re-listed identity did not start empty")
		}
	}
	if len(scanHits(changed, 0)) != 0 {
		t.Fatal("unexpected hit")
	}
}

func TestScanGuardIgnoresUDPAndUnlistedIdentities(t *testing.T) {
	manager, _ := newScanManager(t, guardFor("flvxl-1"))
	for i := 0; i < 5000; i++ {
		lease, err := manager.acquire(userContext("flvxl-1", "flvxl-1"), xnet.UDPDestination(ipv4(i), 53))
		if err != nil || lease != nil {
			t.Fatalf("UDP dial = %v %v", lease, err)
		}
		if !dial(t, manager, "flvxl-9", "flvxl-9", ipv4(i), 22) {
			t.Fatal("unlisted identity counted")
		}
	}
	if counter := manager.scan.guarded["flvxl-1"]; counter != nil {
		t.Fatal("UDP was counted")
	}
}

func TestScanGuardMemoryStaysBounded(t *testing.T) {
	// Raised thresholds: nothing hits, the caps hold.
	manager, clock := newScanManager(t, &ScanGuardConfig{Enabled: true, Identities: []string{"flvxl-1"}, Horizontal: intp(100000), HorizontalWeb: intp(100000), Vertical: intp(100000), Total: intp(50000), WindowS: intp(3600), TotalWindowS: intp(3600)})
	for i := 0; i < 49999; i++ {
		if !dial(t, manager, "flvxl-1", "flvxl-1", ipv4(i), 1+i%60000) {
			t.Fatal("refused below the raised thresholds")
		}
		clock.advance(time.Millisecond)
	}
	counter := manager.scan.guarded["flvxl-1"]
	if len(counter.hosts.keys) != 49999 || len(counter.pairs.keys) != scanMaxPairQueue || len(counter.pairs.queue) != scanMaxPairQueue || len(counter.byHost) != scanMaxPairQueue {
		t.Fatalf("hosts=%d pairs=%d queue=%d byHost=%d", len(counter.hosts.keys), len(counter.pairs.keys), len(counter.pairs.queue), len(counter.byHost))
	}
	if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(49999), 7) {
		t.Fatal("50000th host admitted")
	}

	// Repeats re-queue at most every window/8, and expiry drops every key.
	idle, clock := newScanManager(t, guardFor("flvxl-1"))
	for second := 0; second < 120; second++ {
		for i := 0; i < 300; i++ {
			dial(t, idle, "flvxl-1", "flvxl-1", ipv4(i), 443)
		}
		clock.advance(time.Second)
	}
	counter = idle.scan.guarded["flvxl-1"]
	if live := len(counter.pairs.queue) - counter.pairs.head; live > 300*(scanRequeue+1) || len(counter.pairs.keys) != 300 {
		t.Fatalf("pair queue = %d live entries for %d keys", live, len(counter.pairs.keys))
	}
	clock.advance(301 * time.Second)
	dial(t, idle, "flvxl-1", "flvxl-1", ipv4(0), 443)
	if len(counter.hosts.keys) != 1 || len(counter.pairs.keys) != 1 || len(counter.byPort) != 1 || len(counter.byHost) != 1 || len(counter.pairs.queue)-counter.pairs.head != 1 || len(counter.hosts.queue)-counter.hosts.head != 1 {
		t.Fatalf("expired keys kept: hosts=%d pairs=%d", len(counter.hosts.keys), len(counter.pairs.keys))
	}
}

func TestScanWindowRepeatedKeyLeavesAtMostOneRequeueEarly(t *testing.T) {
	window := newScanWindow[int]()
	second := int64(time.Second)
	window.touch(1, 0, 8*second, 10)
	for now := int64(1); now <= 7; now++ {
		window.touch(1, now*second, 8*second, 10) // not re-queued yet
	}
	window.touch(1, 8*second, 8*second, 10) // re-queued at 8 s
	window.expire(60*second-60*second, nil) // now 60 s, window 60 s
	if _, live := window.keys[1]; !live {
		t.Fatal("key re-queued at 8 s expired at 60 s")
	}
	window.expire(68*second-60*second, nil)
	if _, live := window.keys[1]; live || len(window.queue) != 0 {
		t.Fatal("key outlived its last queue time")
	}
	for key := 0; key < 10; key++ {
		window.touch(key, 0, 8*second, 10)
	}
	if window.touch(10, 0, 8*second, 10) {
		t.Fatal("full window recorded a new key")
	}
}

func TestScanGuardHitRing(t *testing.T) {
	manager, _ := newScanManager(t, &ScanGuardConfig{Enabled: true, Identities: []string{"flvxl-1"}, Total: intp(1)})
	first := uint64(0)
	for i := 0; i < scanHitRing+10; i++ {
		if dial(t, manager, "flvxl-1", "flvxl-1", ipv4(i), 22) {
			t.Fatal("total 1 admitted a dial")
		}
		report := manager.ScanReport(0)
		if len(report.Blocked) != 1 {
			t.Fatalf("blocked = %#v", report.Blocked)
		}
		if first == 0 {
			first = report.Blocked[0].Seq
		}
		if err := manager.ReplaceConfig(Config{ScanGuard: &ScanGuardConfig{Enabled: true, Identities: []string{"flvxl-1"}, Total: intp(1)}, ScanUnblock: []ScanUnblock{{Identity: "flvxl-1", Seq: report.Blocked[0].Seq}}}); err != nil {
			t.Fatal(err)
		}
	}
	hits := scanHits(manager, 0)
	if len(hits) != scanHitRing || hits[0].Seq != first+10 || hits[len(hits)-1].Seq != first+scanHitRing+9 {
		t.Fatalf("ring kept %d hits, %d..%d", len(hits), hits[0].Seq, hits[len(hits)-1].Seq)
	}
	for index := 1; index < len(hits); index++ {
		if hits[index].Seq != hits[index-1].Seq+1 {
			t.Fatal("ring out of order")
		}
	}
	if got := scanHits(manager, first+scanHitRing+5); len(got) != 4 {
		t.Fatalf("after read = %d", len(got))
	}
	if len(manager.ScanReport(0).Blocked) != 0 {
		t.Fatal("unblocked identity still listed")
	}
}

func TestControlServerScanGuard(t *testing.T) {
	manager := NewManager()
	server := newControlServer(manager)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, httptest.NewRequest(method, path, bytes.NewBufferString(body)))
		return response
	}
	response := request(http.MethodGet, "/v1/features", "")
	if !strings.Contains(response.Body.String(), `"scan_guard.v1"`) {
		t.Fatalf("features = %s", response.Body.String())
	}
	if response = request(http.MethodGet, "/v1/scan", ""); response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"version":1,"hits":[],"blocked":[]}` {
		t.Fatalf("empty scan report = %d %s", response.Code, response.Body.String())
	}
	config := `{"blocked_identities":[],"scan_guard":{"enabled":true,"identities":["flvxl-1"],"horizontal":3,"horizontal_web":500,"web_ports":[80,443],"window_s":60,"vertical":30,"total":1000,"total_window_s":300}}`
	if response = request(http.MethodPut, "/v1/config", config); response.Code != http.StatusOK {
		t.Fatalf("config = %d %s", response.Code, response.Body.String())
	}
	if response = request(http.MethodPut, "/v1/config", `{"scan_guard":{"enabled":true,"horizontal":0}}`); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "scan_guard horizontal must be between 1 and 100000") {
		t.Fatalf("bad threshold = %d %s", response.Code, response.Body.String())
	}
	if response = request(http.MethodPut, "/v1/config", `{"scan_guard":{"enabled":true,"thresholds":1}}`); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "unknown field") {
		t.Fatalf("unknown scan_guard field = %d %s", response.Code, response.Body.String())
	}
	for i := 0; i < 3; i++ {
		dial(t, manager, "flvxl-1", "flvxl-1", ipv4(i), 22)
	}
	response = request(http.MethodGet, "/v1/scan", "")
	var report ScanReport
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil || report.Version != 1 || len(report.Hits) != 1 || len(report.Blocked) != 1 || report.Blocked[0] != report.Hits[0] {
		t.Fatalf("scan report = %s", response.Body.String())
	}
	for _, field := range []string{`"identity":"flvxl-1"`, `"type":"horizontal"`, `"count":3`, `"port":22`, `"host":""`, `"window_s":60`, `"at":"`, `"seq":`} {
		if !strings.Contains(response.Body.String(), field) {
			t.Fatalf("scan report misses %s: %s", field, response.Body.String())
		}
	}
	seq := report.Hits[0].Seq
	if response = request(http.MethodGet, fmt.Sprintf("/v1/scan?after=%d", seq), ""); !strings.Contains(response.Body.String(), `"hits":[]`) {
		t.Fatalf("after = %s", response.Body.String())
	}
	if response = request(http.MethodGet, "/v1/scan?after=x", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("bad after = %d", response.Code)
	}
	if response = request(http.MethodPost, "/v1/scan", ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST scan = %d", response.Code)
	}
	if response = request(http.MethodPut, "/v1/config", fmt.Sprintf(`{"scan_unblock":[{"identity":"flvxl-1","seq":%d}]}`, seq)); response.Code != http.StatusOK {
		t.Fatalf("unblock = %d %s", response.Code, response.Body.String())
	}
	if response = request(http.MethodGet, "/v1/scan", ""); !strings.Contains(response.Body.String(), `"blocked":[]`) {
		t.Fatalf("after unblock = %s", response.Body.String())
	}
}
