package connection

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

// Port-scan guard (FLVX landing-scan-guard-v1). Every outbound TCP dial of a
// guarded identity (an inbound tag = one FLVX landing node) is counted in
// three sliding windows:
//   - horizontal: distinct hosts on one destination port (window_s);
//   - vertical:   distinct ports on one destination host (window_s);
//   - total:      distinct destination hosts (total_window_s).
// "Host" is the destination as the dial sees it: an IP, or a domain when the
// outbound dials without resolving first (a domain counts as one host).
//
// On the first threshold hit the Core records the hit, blocks every user of
// that inbound tag like blocked_identities (tracked inbound sockets closed,
// new ones and new dials refused) and stops counting it. The block is sticky:
// configs that do not mention it keep it, and only a scan_unblock entry naming
// the blocking hit's seq lifts it, so a stale unblock can never lift a newer
// block. Nothing is persisted; after a restart the agent re-applies the block
// through blocked_identities.
//
// Off (no scan_guard, enabled false, identity not listed) costs one nil check
// per dial. On, each dial costs a few map operations: expiry walks a time-
// ordered queue, so there is no sweep, no goroutine and no per-connection log
// line, and memory per identity is bounded by the queue caps below.

const (
	ScanGuardFeature = "scan_guard.v1"

	scanHorizontalType = "horizontal"
	scanVerticalType   = "vertical"
	scanTotalType      = "total"

	scanMinThreshold = 1
	scanMaxThreshold = 100000
	scanMinWindowS   = 10
	scanMaxWindowS   = 3600
	scanMaxWebPorts  = 16

	// A repeated key is re-queued after 1/scanRequeue of its window.
	scanRequeue = 8
	// Queue caps per identity. The pair cap is above the most pairs a pattern
	// can keep live without a hit under the default thresholds ((1000-1) hosts
	// x (30-1) ports); the host cap is above the highest total threshold. A
	// full queue records no new key until old ones expire (fail open).
	scanMaxPairQueue = 32768
	scanMaxHostQueue = 2 * scanMaxThreshold
	// Hits kept for GET /v1/scan.
	scanHitRing = 256
)

var scanDefaultWebPorts = []int{80, 443}

type ScanGuardConfig struct {
	Enabled       bool     `json:"enabled"`
	Identities    []string `json:"identities"`
	Horizontal    *int     `json:"horizontal"`
	HorizontalWeb *int     `json:"horizontal_web"`
	WebPorts      []int    `json:"web_ports"`
	WindowS       *int     `json:"window_s"`
	Vertical      *int     `json:"vertical"`
	Total         *int     `json:"total"`
	TotalWindowS  *int     `json:"total_window_s"`
}

// ScanUnblock lifts the scan block of Identity when Seq is the seq of the hit
// that caused it. Any other seq (an older hit, a hit of a previous Core run)
// is ignored, so an agent may keep sending the entry.
type ScanUnblock struct {
	Identity string `json:"identity"`
	Seq      uint64 `json:"seq"`
}

type ScanHit struct {
	Identity string    `json:"identity"`
	Type     string    `json:"type"`
	Count    int       `json:"count"`
	Port     uint16    `json:"port"`
	Host     string    `json:"host"`
	WindowS  int       `json:"window_s"`
	At       time.Time `json:"at"`
	Seq      uint64    `json:"seq"`
}

type ScanReport struct {
	Version int       `json:"version"`
	Hits    []ScanHit `json:"hits"`
	// Blocked lists the identities the guard blocks right now with the hit
	// that blocked them.
	Blocked []ScanHit `json:"blocked"`
}

type scanSettings struct {
	horizontal    int
	horizontalWeb int
	vertical      int
	total         int
	windowS       int
	totalWindowS  int
	webPortCount  int
	webPorts      [scanMaxWebPorts]uint16
}

func (s *scanSettings) horizontalLimit(port uint16) int {
	for _, web := range s.webPorts[:s.webPortCount] {
		if web == port {
			return s.horizontalWeb
		}
	}
	return s.horizontal
}

type scanHost struct {
	ip     netip.Addr
	domain string
}

func (h scanHost) String() string {
	if h.ip.IsValid() {
		return h.ip.String()
	}
	return h.domain
}

type scanPair struct {
	host scanHost
	port uint16
}

// scanWindow holds the distinct keys seen within a sliding window, with a
// queue of (key, time) in time order so expiry costs O(1) per dial. A key
// keeps the time it was last queued; a repeated key is queued again only
// after window/scanRequeue, so the queue holds at most scanRequeue+1 entries
// per live key and a repeated key may leave up to 1/scanRequeue of the window
// early (a slightly lower count, never a false hit). A new key always counts
// with its exact time, which is what a scan produces.
type scanWindow[K comparable] struct {
	keys  map[K]int64
	queue []scanEntry[K]
	head  int
}

type scanEntry[K comparable] struct {
	key K
	at  int64
}

func newScanWindow[K comparable]() scanWindow[K] {
	return scanWindow[K]{keys: make(map[K]int64)}
}

// expire drops the keys last queued at or before cutoff, calling drop for each.
func (w *scanWindow[K]) expire(cutoff int64, drop func(K)) {
	for w.head < len(w.queue) && w.queue[w.head].at <= cutoff {
		entry := w.queue[w.head]
		w.queue[w.head] = scanEntry[K]{}
		w.head++
		if at, ok := w.keys[entry.key]; ok && at == entry.at {
			delete(w.keys, entry.key)
			if drop != nil {
				drop(entry.key)
			}
		}
	}
	if w.head == len(w.queue) {
		w.queue = w.queue[:0]
		w.head = 0
	} else if w.head >= 1024 && w.head*2 >= len(w.queue) {
		n := copy(w.queue, w.queue[w.head:])
		clear(w.queue[n:])
		w.queue = w.queue[:n]
		w.head = 0
	}
}

// touch records key at now and reports whether it is new to the window. A
// full queue records no new key (and re-queues none), bounding memory.
func (w *scanWindow[K]) touch(key K, now, requeue int64, capacity int) bool {
	full := len(w.queue)-w.head >= capacity
	if at, seen := w.keys[key]; seen {
		if now-at >= requeue && !full {
			w.keys[key] = now
			w.queue = append(w.queue, scanEntry[K]{key: key, at: now})
		}
		return false
	}
	if full {
		return false
	}
	w.keys[key] = now
	w.queue = append(w.queue, scanEntry[K]{key: key, at: now})
	return true
}

// scanCounter is one guarded identity's windows. Times are nanoseconds since
// scanGuard.base. byHost / byPort count the live (host, port) pairs.
type scanCounter struct {
	hosts  scanWindow[scanHost]
	pairs  scanWindow[scanPair]
	byHost map[scanHost]int32
	byPort map[uint16]int32
}

func newScanCounter() *scanCounter {
	return &scanCounter{
		hosts:  newScanWindow[scanHost](),
		pairs:  newScanWindow[scanPair](),
		byHost: make(map[scanHost]int32),
		byPort: make(map[uint16]int32),
	}
}

// add records one dial and returns the first threshold it reaches.
func (c *scanCounter) add(s *scanSettings, host scanHost, port uint16, now int64) (ScanHit, bool) {
	window := int64(s.windowS) * int64(time.Second)
	totalWindow := int64(s.totalWindowS) * int64(time.Second)
	c.pairs.expire(now-window, func(pair scanPair) {
		if c.byHost[pair.host]--; c.byHost[pair.host] <= 0 {
			delete(c.byHost, pair.host)
		}
		if c.byPort[pair.port]--; c.byPort[pair.port] <= 0 {
			delete(c.byPort, pair.port)
		}
	})
	c.hosts.expire(now-totalWindow, nil)

	if c.pairs.touch(scanPair{host: host, port: port}, now, window/scanRequeue, scanMaxPairQueue) {
		c.byHost[host]++
		c.byPort[port]++
		if count := int(c.byPort[port]); count >= s.horizontalLimit(port) {
			return ScanHit{Type: scanHorizontalType, Count: count, Port: port, WindowS: s.windowS}, true
		}
		if count := int(c.byHost[host]); count >= s.vertical {
			return ScanHit{Type: scanVerticalType, Count: count, Host: host.String(), WindowS: s.windowS}, true
		}
	}
	if _, seen := c.hosts.keys[host]; !seen && len(c.hosts.keys)+1 >= s.total {
		return ScanHit{Type: scanTotalType, Count: len(c.hosts.keys) + 1, WindowS: s.totalWindowS}, true
	}
	c.hosts.touch(host, now, totalWindow/scanRequeue, scanMaxHostQueue)
	return ScanHit{}, false
}

// scanGuard exists once a config enabled the guard; it then keeps the sticky
// blocks and the hit ring even while the guard is switched off again.
type scanGuard struct {
	enabled  bool
	settings scanSettings
	// guarded maps each listed inbound tag to its counter, nil until the
	// identity's first dial after a (re)start of counting.
	guarded map[string]*scanCounter
	blocked map[string]ScanHit
	hits    []ScanHit
	next    int
	seq     uint64
	base    time.Time
}

// newScanGuard starts seq at the start time in microseconds, so seqs keep
// increasing across Core restarts and an old hit's seq never names a new one.
func newScanGuard(now time.Time) *scanGuard {
	return &scanGuard{
		guarded: make(map[string]*scanCounter),
		blocked: make(map[string]ScanHit),
		seq:     uint64(now.UnixMicro()),
		base:    now,
	}
}

func (g *scanGuard) record(hit ScanHit) {
	if len(g.hits) < scanHitRing {
		g.hits = append(g.hits, hit)
		return
	}
	g.hits[g.next] = hit
	g.next = (g.next + 1) % scanHitRing
}

type resolvedScanGuard struct {
	settings   scanSettings
	identities map[string]struct{}
}

func scanIntSetting(name string, value *int, fallback, low, high int) (int, error) {
	if value == nil {
		return fallback, nil
	}
	if *value < low || *value > high {
		return 0, fmt.Errorf("scan_guard %s must be between %d and %d", name, low, high)
	}
	return *value, nil
}

// resolveScanGuard validates an enabled guard config; nil means off. Values of
// a disabled guard are not looked at.
func resolveScanGuard(config *ScanGuardConfig) (*resolvedScanGuard, error) {
	if config == nil || !config.Enabled {
		return nil, nil
	}
	var settings scanSettings
	var err error
	if settings.horizontal, err = scanIntSetting("horizontal", config.Horizontal, 100, scanMinThreshold, scanMaxThreshold); err != nil {
		return nil, err
	}
	if settings.horizontalWeb, err = scanIntSetting("horizontal_web", config.HorizontalWeb, 500, scanMinThreshold, scanMaxThreshold); err != nil {
		return nil, err
	}
	if settings.vertical, err = scanIntSetting("vertical", config.Vertical, 30, scanMinThreshold, scanMaxThreshold); err != nil {
		return nil, err
	}
	if settings.total, err = scanIntSetting("total", config.Total, 1000, scanMinThreshold, scanMaxThreshold); err != nil {
		return nil, err
	}
	if settings.windowS, err = scanIntSetting("window_s", config.WindowS, 60, scanMinWindowS, scanMaxWindowS); err != nil {
		return nil, err
	}
	if settings.totalWindowS, err = scanIntSetting("total_window_s", config.TotalWindowS, 300, scanMinWindowS, scanMaxWindowS); err != nil {
		return nil, err
	}
	webPorts := config.WebPorts
	if webPorts == nil {
		webPorts = scanDefaultWebPorts
	}
	if len(webPorts) > scanMaxWebPorts {
		return nil, fmt.Errorf("scan_guard web_ports allows at most %d ports", scanMaxWebPorts)
	}
	sorted := append([]int(nil), webPorts...)
	sort.Ints(sorted)
	for index, port := range sorted {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("scan_guard web_ports must be between 1 and 65535")
		}
		if index > 0 && sorted[index-1] == port {
			return nil, fmt.Errorf("duplicate scan_guard web port %d", port)
		}
		settings.webPorts[index] = uint16(port)
	}
	settings.webPortCount = len(sorted)
	identities := make(map[string]struct{}, len(config.Identities))
	for _, identity := range config.Identities {
		if strings.TrimSpace(identity) == "" {
			return nil, fmt.Errorf("scan_guard identity requires an inbound tag")
		}
		if _, exists := identities[identity]; exists {
			return nil, fmt.Errorf("duplicate scan_guard identity %q", identity)
		}
		identities[identity] = struct{}{}
	}
	return &resolvedScanGuard{settings: settings, identities: identities}, nil
}

func validateScanUnblock(entries []ScanUnblock) error {
	for _, entry := range entries {
		if strings.TrimSpace(entry.Identity) == "" || entry.Seq == 0 {
			return fmt.Errorf("scan_unblock entry requires identity and seq")
		}
	}
	return nil
}

// applyScanConfigLocked installs a validated guard config. With no guard ever
// enabled and nothing to unblock it leaves the manager untouched.
func (m *Manager) applyScanConfigLocked(resolved *resolvedScanGuard, unblock []ScanUnblock) {
	g := m.scan
	if g == nil {
		if resolved == nil {
			return
		}
		g = newScanGuard(m.now())
		m.scan = g
	}
	for _, entry := range unblock {
		if hit, blocked := g.blocked[entry.Identity]; blocked && hit.Seq == entry.Seq {
			delete(g.blocked, entry.Identity)
		}
	}
	if resolved == nil {
		g.enabled = false
		g.guarded = make(map[string]*scanCounter)
		return
	}
	keep := g.enabled && g.settings == resolved.settings
	guarded := make(map[string]*scanCounter, len(resolved.identities))
	for identity := range resolved.identities {
		if keep {
			guarded[identity] = g.guarded[identity]
		} else {
			guarded[identity] = nil
		}
	}
	g.enabled = true
	g.settings = resolved.settings
	g.guarded = guarded
}

func (m *Manager) scanBlockedLocked(tag string) bool {
	if m.scan == nil || tag == "" {
		return false
	}
	_, blocked := m.scan.blocked[tag]
	return blocked
}

func scanHostOf(address xnet.Address) (scanHost, bool) {
	if address == nil {
		return scanHost{}, false
	}
	if address.Family().IsDomain() {
		domain := address.Domain()
		return scanHost{domain: domain}, domain != ""
	}
	ip, ok := netip.AddrFromSlice(address.IP())
	if !ok {
		return scanHost{}, false
	}
	return scanHost{ip: ip.Unmap()}, true
}

// scanDialLocked counts one admitted TCP dial of inbound tag. On a hit it
// blocks the tag, closes its tracked inbound sockets and returns true; the
// caller refuses the dial.
func (m *Manager) scanDialLocked(tag string, destination xnet.Destination, now time.Time) bool {
	g := m.scan
	counter, guarded := g.guarded[tag]
	if !guarded {
		return false
	}
	host, ok := scanHostOf(destination.Address)
	if !ok {
		return false
	}
	if counter == nil {
		counter = newScanCounter()
		g.guarded[tag] = counter
	}
	hit, reached := counter.add(&g.settings, host, uint16(destination.Port), int64(now.Sub(g.base)))
	if !reached {
		return false
	}
	g.seq++
	hit.Identity = tag
	hit.At = now.UTC()
	hit.Seq = g.seq
	g.record(hit)
	g.blocked[tag] = hit
	// Stop counting: a blocked identity dials nothing until it is unblocked,
	// and then it starts from empty windows.
	g.guarded[tag] = nil
	for identity, item := range m.states {
		if identity.InboundTag == tag {
			item.snapshot.Blocked = true
		}
	}
	var toClose []*trackedInboundConn
	for conn, owner := range m.inboundConns {
		if owner.InboundTag == tag {
			toClose = append(toClose, conn)
		}
	}
	if len(toClose) > 0 {
		// The caller holds the manager lock and Close releases ownership
		// through it, so close once the dial has been refused.
		go func() {
			for _, conn := range toClose {
				_ = conn.Close()
			}
		}()
	}
	return true
}

// ScanReport returns the hits with seq > after (oldest first) and the current
// scan blocks.
func (m *Manager) ScanReport(after uint64) ScanReport {
	report := ScanReport{Version: 1, Hits: []ScanHit{}, Blocked: []ScanHit{}}
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.scan
	if g == nil {
		return report
	}
	for index := range g.hits {
		hit := g.hits[(g.next+index)%len(g.hits)]
		if hit.Seq > after {
			report.Hits = append(report.Hits, hit)
		}
	}
	for _, hit := range g.blocked {
		report.Blocked = append(report.Blocked, hit)
	}
	sort.Slice(report.Blocked, func(i, j int) bool { return report.Blocked[i].Identity < report.Blocked[j].Identity })
	return report
}
