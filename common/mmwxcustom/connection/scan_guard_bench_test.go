package connection

import (
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

// One outbound TCP dial through acquire (+ failed, so nothing piles up),
// as the hot path sees it. "browse" cycles 300 hosts on 443 (normal use);
// "scan" dials a new host every time with raised thresholds (worst case
// that does not hit); "flagged" is a blocked identity refused at once.
func benchmarkScanDial(b *testing.B, guard *ScanGuardConfig, next func(int) xnet.Destination, block bool) {
	manager := NewManager()
	// 2000 new dials per second, the rate the contract measures at.
	clock := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { clock = clock.Add(500 * time.Microsecond); return clock }
	if err := manager.ReplaceConfig(Config{ScanGuard: guard}); err != nil {
		b.Fatal(err)
	}
	ctx := userContext("flvxl-1", "flvxl-1")
	if block {
		for i := 0; ; i++ {
			lease, err := manager.acquire(ctx, xnet.TCPDestination(ipv4(i), 22))
			if err != nil {
				break
			}
			lease.failed()
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lease, err := manager.acquire(ctx, next(i))
		if (err != nil) != block {
			b.Fatalf("dial %d: %v", i, err)
		}
		lease.failed()
	}
}

func browse(i int) xnet.Destination { return xnet.TCPDestination(ipv4(i%300), 443) }
func scanAll(i int) xnet.Destination {
	return xnet.TCPDestination(ipv4(i), xnet.Port(1+i%60000))
}

// A new host on its own port every dial, 2000/s: 20000 hosts live in 10 s
// windows, below the raised thresholds, so the dial never hits.
var raised = &ScanGuardConfig{Enabled: true, Identities: []string{"flvxl-1"}, Horizontal: intp(100000), HorizontalWeb: intp(100000), Vertical: intp(100000), Total: intp(100000), WindowS: intp(10), TotalWindowS: intp(10)}

func BenchmarkScanGuardDialOff(b *testing.B) { benchmarkScanDial(b, nil, browse, false) }
func BenchmarkScanGuardDialOtherIdentity(b *testing.B) {
	benchmarkScanDial(b, guardFor("flvxl-2"), browse, false)
}
func BenchmarkScanGuardDialOnBrowse(b *testing.B) {
	benchmarkScanDial(b, guardFor("flvxl-1"), browse, false)
}
func BenchmarkScanGuardDialOnNewHosts(b *testing.B) { benchmarkScanDial(b, raised, scanAll, false) }
func BenchmarkScanGuardDialFlagged(b *testing.B) {
	benchmarkScanDial(b, guardFor("flvxl-1"), browse, true)
}

func BenchmarkScanCounterAdd(b *testing.B) {
	settings, err := resolveScanGuard(raised)
	if err != nil {
		b.Fatal(err)
	}
	counter := newScanCounter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host, _ := scanHostOf(ipv4(i % 300))
		if _, hit := counter.add(&settings.settings, host, 443, int64(i)*int64(500*time.Microsecond)); hit {
			b.Fatal("hit")
		}
	}
}

func BenchmarkScanHostOf(b *testing.B) {
	address := ipv4(7)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := scanHostOf(address); !ok {
			b.Fatal("no host")
		}
	}
}
