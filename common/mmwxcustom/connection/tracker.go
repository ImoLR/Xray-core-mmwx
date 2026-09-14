// Package connection owns mmwx-custom connection attribution, accounting and
// limits. Xray packages should only call the small hooks exported here.
package connection

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/netip"
	"sort"
	"sync"
	"syscall"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

type Identity struct {
	InboundTag string `json:"inbound_tag"`
	User       string `json:"user"`
}

type Limit struct {
	Identity                   Identity `json:"identity"`
	MaxInboundOnlineIPs        *int     `json:"max_inbound_online_ips"`
	MaxTotalConnections        *int64   `json:"max_total_connections"`
	MaxOutboundTCPActive       *int64   `json:"max_outbound_tcp_active"`
	MaxOutboundTCPNewPerSecond *int     `json:"max_outbound_tcp_new_per_second"`
	CloseWaitTimeoutSeconds    *int64   `json:"close_wait_timeout_seconds"`
}

type Config struct {
	DefaultCloseWaitTimeoutSeconds *int64  `json:"default_close_wait_timeout_seconds"`
	OnlineIPGracePeriodSeconds     int64   `json:"online_ip_grace_period_seconds"`
	MaxGlobalTotalConnections      *int64  `json:"max_global_total_connections"`
	Limits                         []Limit `json:"limits"`
}

type TCPStateCounts struct {
	Total       int64 `json:"tcp_total"`
	Established int64 `json:"established"`
	SynSent     int64 `json:"syn_sent"`
	SynRecv     int64 `json:"syn_recv"`
	FinWait1    int64 `json:"fin_wait_1"`
	FinWait2    int64 `json:"fin_wait_2"`
	TimeWait    int64 `json:"time_wait"`
	CloseWait   int64 `json:"close_wait"`
	LastAck     int64 `json:"last_ack"`
	Closing     int64 `json:"closing"`
	Close       int64 `json:"close"`
	Unknown     int64 `json:"unknown"`
}

type OnlineIP struct {
	IP          string `json:"ip"`
	Connections int64  `json:"connections"`
}

// ConfiguredInbound describes an inbound known from Xray's loaded runtime
// configuration. It is kept separately from live socket accounting so a new
// Core can expose inbounds and authenticated users before their first request.
type ConfiguredInbound struct {
	Tag   string   `json:"inbound_tag"`
	Name  string   `json:"inbound_name,omitempty"`
	Port  uint32   `json:"inbound_port"`
	Users []string `json:"users"`
}

type GlobalSnapshot struct {
	CurrentTotal             int64  `json:"current_total"`
	MaxTotal                 *int64 `json:"max_total"`
	RejectedGlobalTotalLimit uint64 `json:"rejected_global_total_limit"`
}

type Snapshot struct {
	Identity                   Identity       `json:"identity"`
	InboundName                string         `json:"inbound_name,omitempty"`
	InboundPort                uint32         `json:"inbound_port,omitempty"`
	OutboundTag                string         `json:"outbound_tag,omitempty"`
	Attributed                 bool           `json:"attributed"`
	InboundActive              int64          `json:"inbound_active"`
	InboundTotal               uint64         `json:"inbound_total"`
	CurrentTotal               int64          `json:"current_total"`
	InboundTCP                 TCPStateCounts `json:"inbound_tcp"`
	InboundOnlineIPs           []OnlineIP     `json:"inbound_online_ips"`
	OutboundActive             int64          `json:"outbound_active"`
	OutboundPending            int64          `json:"outbound_pending"`
	OutboundTCP                TCPStateCounts `json:"outbound_tcp"`
	OutboundNewTotal           uint64         `json:"outbound_new_total"`
	OutboundNewRate            int            `json:"outbound_new_rate"`
	OutboundRejectedTotal      uint64         `json:"outbound_rejected_total"`
	RejectedActiveLimit        uint64         `json:"rejected_active_limit"`
	RejectedNewRateLimit       uint64         `json:"rejected_new_rate_limit"`
	RejectedUserTotalLimit     uint64         `json:"rejected_user_total_limit"`
	RejectedOnlineIPLimit      uint64         `json:"rejected_online_ip_limit"`
	RejectedGlobalTotalLimit   uint64         `json:"rejected_global_total_limit"`
	MaxInboundOnlineIPs        *int           `json:"max_inbound_online_ips"`
	MaxTotalConnections        *int64         `json:"max_total_connections"`
	MaxOutboundTCPActive       *int64         `json:"max_outbound_tcp_active"`
	MaxOutboundTCPNewPerSecond *int           `json:"max_outbound_tcp_new_per_second"`
	CloseWaitTimeoutSeconds    *int64         `json:"close_wait_timeout_seconds"`
}

type LimitReason string

const (
	ActiveLimit      LimitReason = "active_limit"
	NewRateLimit     LimitReason = "new_rate_limit"
	UserTotalLimit   LimitReason = "user_total_limit"
	OnlineIPLimit    LimitReason = "online_ip_limit"
	GlobalTotalLimit LimitReason = "global_total_limit"
)

type LimitError struct {
	Identity Identity
	Reason   LimitReason
	Limit    int64
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("connection %s reached for inbound %q user %q (limit %d)", e.Reason, e.Identity.InboundTag, e.Identity.User, e.Limit)
}

type state struct {
	snapshot     Snapshot
	attemptTimes []time.Time
	newTimes     []time.Time
	sourceActive map[string]int64
	sourceSeen   map[string]time.Time
}

type socketDirection uint8

const (
	inboundSocket socketDirection = iota + 1
	outboundSocket
)

type socketTuple struct {
	LocalIP    netip.Addr
	LocalPort  uint16
	RemoteIP   netip.Addr
	RemotePort uint16
}

type socketRecord struct {
	ID        uint64
	Identity  Identity
	Direction socketDirection
	Tuple     socketTuple
	ClosedAt  time.Time
}

type Manager struct {
	mu             sync.Mutex
	limits         map[Identity]Limit
	states         map[Identity]*state
	inbounds       map[string]ConfiguredInbound
	defaultCW      *int64
	onlineIPGrace  time.Duration
	globalLimit    *int64
	globalCurrent  int64
	globalRejected uint64
	sockets        map[uint64]socketRecord
	nextSocketID   uint64
	scanSockets    func() (map[socketTuple]string, error)
	now            func() time.Time
}

var Default = NewManager()

func NewManager() *Manager {
	return &Manager{
		limits:        make(map[Identity]Limit),
		states:        make(map[Identity]*state),
		inbounds:      make(map[string]ConfiguredInbound),
		onlineIPGrace: 30 * time.Second,
		sockets:       make(map[uint64]socketRecord),
		scanSockets:   readKernelTCPSockets,
		now:           time.Now,
	}
}

func ReplaceConfig(config Config) error {
	return Default.ReplaceConfig(config)
}

func Snapshots() []Snapshot {
	return Default.Snapshots()
}

func Reset() {
	Default.Reset()
}

func (m *Manager) Reset() {
	m.mu.Lock()
	m.limits = make(map[Identity]Limit)
	m.states = make(map[Identity]*state)
	m.inbounds = make(map[string]ConfiguredInbound)
	m.defaultCW = nil
	m.onlineIPGrace = 30 * time.Second
	m.globalLimit = nil
	m.globalCurrent = 0
	m.globalRejected = 0
	m.sockets = make(map[uint64]socketRecord)
	m.nextSocketID = 0
	m.mu.Unlock()
}

// RegisterConfiguredInbound records the inbounds and users present in the
// configuration that Xray actually instantiated. Live counters remain zero
// until traffic arrives, while identity and inbound discovery are immediate.
func RegisterConfiguredInbound(inbound ConfiguredInbound) {
	Default.RegisterConfiguredInbound(inbound)
}

func (m *Manager) RegisterConfiguredInbound(inbound ConfiguredInbound) {
	if inbound.Tag == "" || inbound.Port == 0 {
		return
	}
	seen := make(map[string]struct{}, len(inbound.Users))
	users := make([]string, 0, len(inbound.Users))
	for _, user := range inbound.Users {
		if user == "" {
			continue
		}
		if _, exists := seen[user]; exists {
			continue
		}
		seen[user] = struct{}{}
		users = append(users, user)
	}
	sort.Strings(users)
	inbound.Users = users
	key := fmt.Sprintf("%s\x00%d", inbound.Tag, inbound.Port)

	m.mu.Lock()
	if m.inbounds == nil {
		m.inbounds = make(map[string]ConfiguredInbound)
	}
	m.inbounds[key] = inbound
	for _, user := range users {
		identity := Identity{InboundTag: inbound.Tag, User: user}
		item := m.stateLocked(identity, Snapshot{
			Identity: identity, InboundName: inbound.Name, InboundPort: inbound.Port, Attributed: true,
		})
		m.applyLimitLocked(&item.snapshot, m.limits[identity])
	}
	m.mu.Unlock()
}

func (m *Manager) ConfiguredInbounds() []ConfiguredInbound {
	m.mu.Lock()
	result := make([]ConfiguredInbound, 0, len(m.inbounds))
	for _, inbound := range m.inbounds {
		copy := inbound
		copy.Users = append([]string(nil), inbound.Users...)
		result = append(result, copy)
	}
	m.mu.Unlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}
		return result[i].Tag < result[j].Tag
	})
	return result
}

func (m *Manager) ReplaceConfig(config Config) error {
	if err := validateOptionalNonNegative("default_close_wait_timeout_seconds", config.DefaultCloseWaitTimeoutSeconds); err != nil {
		return err
	}
	if config.OnlineIPGracePeriodSeconds < 0 || config.OnlineIPGracePeriodSeconds > 3600 {
		return fmt.Errorf("online_ip_grace_period_seconds must be between 0 and 3600")
	}
	if err := validateOptionalPositive("max_global_total_connections", config.MaxGlobalTotalConnections); err != nil {
		return err
	}
	replacement := make(map[Identity]Limit, len(config.Limits))
	for _, limit := range config.Limits {
		if limit.Identity.InboundTag == "" || limit.Identity.User == "" {
			return fmt.Errorf("limit identity requires inbound_tag and user")
		}
		if err := validateOptionalPositive("max_outbound_tcp_active", limit.MaxOutboundTCPActive); err != nil {
			return err
		}
		if limit.MaxInboundOnlineIPs != nil && *limit.MaxInboundOnlineIPs <= 0 {
			return fmt.Errorf("max_inbound_online_ips must be positive when set")
		}
		if err := validateOptionalPositive("max_total_connections", limit.MaxTotalConnections); err != nil {
			return err
		}
		if limit.MaxOutboundTCPNewPerSecond != nil && *limit.MaxOutboundTCPNewPerSecond <= 0 {
			return fmt.Errorf("max_outbound_tcp_new_per_second must be positive when set")
		}
		if err := validateOptionalNonNegative("close_wait_timeout_seconds", limit.CloseWaitTimeoutSeconds); err != nil {
			return err
		}
		replacement[limit.Identity] = cloneLimit(limit)
	}
	m.mu.Lock()
	m.limits = replacement
	m.defaultCW = cloneInt64(config.DefaultCloseWaitTimeoutSeconds)
	m.globalLimit = cloneInt64(config.MaxGlobalTotalConnections)
	m.onlineIPGrace = time.Duration(config.OnlineIPGracePeriodSeconds) * time.Second
	if m.onlineIPGrace <= 0 {
		m.onlineIPGrace = 30 * time.Second
	}
	for identity, item := range m.states {
		m.applyLimitLocked(&item.snapshot, replacement[identity])
	}
	m.mu.Unlock()
	return nil
}

func validateOptionalNonNegative(name string, value *int64) error {
	if value != nil && *value < 0 {
		return fmt.Errorf("%s must be non-negative", name)
	}
	return nil
}

func validateOptionalPositive(name string, value *int64) error {
	if value != nil && *value <= 0 {
		return fmt.Errorf("%s must be positive when set", name)
	}
	return nil
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneLimit(limit Limit) Limit {
	limit.MaxInboundOnlineIPs = cloneInt(limit.MaxInboundOnlineIPs)
	limit.MaxTotalConnections = cloneInt64(limit.MaxTotalConnections)
	limit.MaxOutboundTCPActive = cloneInt64(limit.MaxOutboundTCPActive)
	limit.MaxOutboundTCPNewPerSecond = cloneInt(limit.MaxOutboundTCPNewPerSecond)
	limit.CloseWaitTimeoutSeconds = cloneInt64(limit.CloseWaitTimeoutSeconds)
	return limit
}

func (m *Manager) applyLimitLocked(snapshot *Snapshot, limit Limit) {
	snapshot.MaxInboundOnlineIPs = cloneInt(limit.MaxInboundOnlineIPs)
	snapshot.MaxTotalConnections = cloneInt64(limit.MaxTotalConnections)
	snapshot.MaxOutboundTCPActive = cloneInt64(limit.MaxOutboundTCPActive)
	snapshot.MaxOutboundTCPNewPerSecond = cloneInt(limit.MaxOutboundTCPNewPerSecond)
	timeout := limit.CloseWaitTimeoutSeconds
	if timeout == nil {
		timeout = m.defaultCW
	}
	snapshot.CloseWaitTimeoutSeconds = cloneInt64(timeout)
}

func newState(snapshot Snapshot) *state {
	return &state{snapshot: snapshot, sourceActive: make(map[string]int64), sourceSeen: make(map[string]time.Time)}
}

func (m *Manager) stateLocked(identity Identity, metadata Snapshot) *state {
	item := m.states[identity]
	if item == nil {
		item = newState(metadata)
		m.states[identity] = item
	} else {
		mergeMetadata(&item.snapshot, metadata)
		if item.sourceActive == nil {
			item.sourceActive = make(map[string]int64)
		}
		if item.sourceSeen == nil {
			item.sourceSeen = make(map[string]time.Time)
		}
	}
	return item
}

func currentTotal(snapshot Snapshot) int64 {
	return snapshot.InboundActive + snapshot.OutboundActive + snapshot.OutboundPending
}

func (m *Manager) rejectLocked(item *state, identity Identity, reason LimitReason, limit int64) error {
	switch reason {
	case UserTotalLimit:
		item.snapshot.RejectedUserTotalLimit++
	case OnlineIPLimit:
		item.snapshot.RejectedOnlineIPLimit++
	case GlobalTotalLimit:
		item.snapshot.RejectedGlobalTotalLimit++
		m.globalRejected++
	case ActiveLimit:
		item.snapshot.RejectedActiveLimit++
	case NewRateLimit:
		item.snapshot.RejectedNewRateLimit++
	}
	return &LimitError{Identity: identity, Reason: reason, Limit: limit}
}

func prune(values []time.Time, cutoff time.Time) []time.Time {
	first := 0
	for first < len(values) && !values[first].After(cutoff) {
		first++
	}
	if first == 0 {
		return values
	}
	copy(values, values[first:])
	return values[:len(values)-first]
}

func identityFromContext(ctx context.Context) Snapshot {
	snapshot := Snapshot{}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		snapshot.Identity.InboundTag = inbound.Tag
		snapshot.InboundName = inbound.Name
		if inbound.Gateway.IsValid() {
			snapshot.InboundPort = uint32(inbound.Gateway.Port)
		} else if inbound.Local.IsValid() {
			snapshot.InboundPort = uint32(inbound.Local.Port)
		}
		if inbound.User != nil {
			snapshot.Identity.User = inbound.User.Email
		}
	}
	if outbounds := session.OutboundsFromContext(ctx); len(outbounds) > 0 {
		snapshot.OutboundTag = outbounds[len(outbounds)-1].Tag
	}
	snapshot.Attributed = snapshot.Identity.InboundTag != "" && snapshot.Identity.User != ""
	if !snapshot.Attributed {
		snapshot.Identity = Identity{}
	}
	return snapshot
}

type lease struct {
	manager  *Manager
	identity Identity
	timeout  time.Duration
}

func (m *Manager) acquire(ctx context.Context, destination xnet.Destination) (*lease, error) {
	if destination.Network != xnet.Network_TCP {
		return nil, nil
	}
	now := m.now()
	identity := identityFromContext(ctx)
	key := identity.Identity
	m.mu.Lock()
	defer m.mu.Unlock()
	item := m.stateLocked(key, identity)
	limit := m.limits[key]
	m.applyLimitLocked(&item.snapshot, limit)
	if identity.Attributed && limit.MaxTotalConnections != nil && currentTotal(item.snapshot) >= *limit.MaxTotalConnections {
		return nil, m.rejectLocked(item, key, UserTotalLimit, *limit.MaxTotalConnections)
	}
	if identity.Attributed && limit.MaxOutboundTCPActive != nil && item.snapshot.OutboundActive+item.snapshot.OutboundPending >= *limit.MaxOutboundTCPActive {
		return nil, m.rejectLocked(item, key, ActiveLimit, *limit.MaxOutboundTCPActive)
	}
	cutoff := now.Add(-time.Second)
	item.attemptTimes = prune(item.attemptTimes, cutoff)
	if identity.Attributed && limit.MaxOutboundTCPNewPerSecond != nil && len(item.attemptTimes) >= *limit.MaxOutboundTCPNewPerSecond {
		return nil, m.rejectLocked(item, key, NewRateLimit, int64(*limit.MaxOutboundTCPNewPerSecond))
	}
	if m.globalLimit != nil && m.globalCurrent >= *m.globalLimit {
		return nil, m.rejectLocked(item, key, GlobalTotalLimit, *m.globalLimit)
	}
	item.attemptTimes = append(item.attemptTimes, now)
	item.snapshot.OutboundPending++
	m.globalCurrent++
	return &lease{manager: m, identity: key, timeout: secondsToDuration(item.snapshot.CloseWaitTimeoutSeconds)}, nil
}

func mergeMetadata(target *Snapshot, source Snapshot) {
	if source.InboundName != "" {
		target.InboundName = source.InboundName
	}
	if source.InboundPort != 0 {
		target.InboundPort = source.InboundPort
	}
	if source.OutboundTag != "" {
		target.OutboundTag = source.OutboundTag
	}
}

func secondsToDuration(seconds *int64) time.Duration {
	if seconds == nil || *seconds <= 0 {
		return 0
	}
	return time.Duration(*seconds) * time.Second
}

func (l *lease) failed() {
	if l == nil {
		return
	}
	l.manager.mu.Lock()
	if item := l.manager.states[l.identity]; item != nil && item.snapshot.OutboundPending > 0 {
		item.snapshot.OutboundPending--
		if l.manager.globalCurrent > 0 {
			l.manager.globalCurrent--
		}
	}
	l.manager.mu.Unlock()
}

func (l *lease) succeeded(conn stdnet.Conn) stdnet.Conn {
	if l == nil || conn == nil {
		return conn
	}
	now := l.manager.now()
	l.manager.mu.Lock()
	var socketID uint64
	if item := l.manager.states[l.identity]; item != nil {
		if item.snapshot.OutboundPending > 0 {
			item.snapshot.OutboundPending--
		}
		item.snapshot.OutboundActive++
		item.snapshot.OutboundNewTotal++
		item.newTimes = append(item.newTimes, now)
		if tuple, ok := socketTupleFromConn(conn); ok {
			socketID = l.manager.registerSocketLocked(l.identity, outboundSocket, tuple)
		}
	}
	l.manager.mu.Unlock()
	return &trackedOutboundConn{Conn: conn, release: func() { l.manager.releaseOutbound(l.identity, socketID) }, closeWaitTimeout: l.timeout}
}

func (m *Manager) releaseOutbound(identity Identity, socketID uint64) {
	m.mu.Lock()
	if item := m.states[identity]; item != nil && item.snapshot.OutboundActive > 0 {
		item.snapshot.OutboundActive--
		if m.globalCurrent > 0 {
			m.globalCurrent--
		}
	}
	m.closeSocketLocked(socketID)
	m.mu.Unlock()
}

func (m *Manager) bindInbound(identity Snapshot, tuple socketTuple) (uint64, error) {
	key := identity.Identity
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	item := m.stateLocked(key, identity)
	limit := m.limits[key]
	m.applyLimitLocked(&item.snapshot, limit)
	if limit.MaxTotalConnections != nil && currentTotal(item.snapshot) >= *limit.MaxTotalConnections {
		return 0, m.rejectLocked(item, key, UserTotalLimit, *limit.MaxTotalConnections)
	}
	source := normalizedSourceIP(tuple.RemoteIP)
	m.pruneSourcesLocked(item, now)
	if source != "" && limit.MaxInboundOnlineIPs != nil && item.sourceActive[source] == 0 {
		if _, retained := item.sourceSeen[source]; !retained && len(item.sourceSeen) >= *limit.MaxInboundOnlineIPs {
			return 0, m.rejectLocked(item, key, OnlineIPLimit, int64(*limit.MaxInboundOnlineIPs))
		}
	}
	if m.globalLimit != nil && m.globalCurrent >= *m.globalLimit {
		return 0, m.rejectLocked(item, key, GlobalTotalLimit, *m.globalLimit)
	}
	item.snapshot.InboundActive++
	item.snapshot.InboundTotal++
	m.globalCurrent++
	if source != "" {
		item.sourceActive[source]++
		item.sourceSeen[source] = now
	}
	return m.registerSocketLocked(key, inboundSocket, tuple), nil
}

func (m *Manager) releaseInbound(identity Identity, socketID uint64, source string) {
	m.mu.Lock()
	if item := m.states[identity]; item != nil && item.snapshot.InboundActive > 0 {
		item.snapshot.InboundActive--
		if m.globalCurrent > 0 {
			m.globalCurrent--
		}
		if source != "" {
			if item.sourceActive[source] > 0 {
				item.sourceActive[source]--
			}
			item.sourceSeen[source] = m.now()
		}
	}
	m.closeSocketLocked(socketID)
	m.mu.Unlock()
}

func (m *Manager) registerSocketLocked(identity Identity, direction socketDirection, tuple socketTuple) uint64 {
	if !tuple.valid() {
		return 0
	}
	m.nextSocketID++
	m.sockets[m.nextSocketID] = socketRecord{ID: m.nextSocketID, Identity: identity, Direction: direction, Tuple: tuple}
	return m.nextSocketID
}

func (m *Manager) closeSocketLocked(socketID uint64) {
	if socketID == 0 {
		return
	}
	record, ok := m.sockets[socketID]
	if !ok || !record.ClosedAt.IsZero() {
		return
	}
	record.ClosedAt = m.now()
	m.sockets[socketID] = record
}

func (m *Manager) pruneSourcesLocked(item *state, now time.Time) {
	cutoff := now.Add(-m.onlineIPGrace)
	for source, seen := range item.sourceSeen {
		if item.sourceActive[source] <= 0 && !seen.After(cutoff) {
			delete(item.sourceSeen, source)
			delete(item.sourceActive, source)
		}
	}
}

func normalizedSourceIP(address netip.Addr) string {
	if !address.IsValid() || address.IsUnspecified() {
		return ""
	}
	address = address.Unmap()
	if address.Is6() {
		return netip.PrefixFrom(address, 64).Masked().String()
	}
	return address.String()
}

func socketTupleFromConn(conn stdnet.Conn) (socketTuple, bool) {
	local, localOK := tcpAddrPort(conn.LocalAddr())
	remote, remoteOK := tcpAddrPort(conn.RemoteAddr())
	if !localOK || !remoteOK {
		return socketTuple{}, false
	}
	tuple := socketTuple{LocalIP: local.Addr().Unmap(), LocalPort: local.Port(), RemoteIP: remote.Addr().Unmap(), RemotePort: remote.Port()}
	return tuple, tuple.valid()
}

func tcpAddrPort(address stdnet.Addr) (netip.AddrPort, bool) {
	tcp, ok := address.(*stdnet.TCPAddr)
	if !ok || tcp == nil {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok || tcp.Port < 1 || tcp.Port > 65535 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(tcp.Port)), true
}

func (tuple socketTuple) valid() bool {
	return tuple.LocalIP.IsValid() && tuple.RemoteIP.IsValid() && tuple.LocalPort > 0 && tuple.RemotePort > 0
}

func addTCPState(counts *TCPStateCounts, state string) {
	if state == tcpListenState {
		return
	}
	counts.Total++
	switch state {
	case tcpEstablishedState:
		counts.Established++
	case tcpSynSentState:
		counts.SynSent++
	case tcpSynRecvState, tcpNewSynRecvState:
		counts.SynRecv++
	case tcpFinWait1State:
		counts.FinWait1++
	case tcpFinWait2State:
		counts.FinWait2++
	case tcpTimeWaitState:
		counts.TimeWait++
	case tcpCloseWaitState:
		counts.CloseWait++
	case tcpLastAckState:
		counts.LastAck++
	case tcpClosingState:
		counts.Closing++
	case tcpCloseState:
		counts.Close++
	default:
		counts.Unknown++
	}
}

func (m *Manager) SnapshotReport() ([]Snapshot, GlobalSnapshot, error) {
	now := m.now()
	cutoff := now.Add(-time.Second)
	kernelSockets, err := m.scanSockets()
	if err != nil {
		return nil, GlobalSnapshot{}, fmt.Errorf("read kernel TCP states: %w", err)
	}
	m.mu.Lock()
	result := make([]Snapshot, 0, len(m.states))
	for identity, item := range m.states {
		item.newTimes = prune(item.newTimes, cutoff)
		m.pruneSourcesLocked(item, now)
		item.snapshot.InboundTCP = TCPStateCounts{}
		item.snapshot.OutboundTCP = TCPStateCounts{}
		item.snapshot.InboundOnlineIPs = nil
		item.snapshot.CurrentTotal = currentTotal(item.snapshot)
		for source, seen := range item.sourceSeen {
			if item.sourceActive[source] > 0 || seen.After(now.Add(-m.onlineIPGrace)) {
				item.snapshot.InboundOnlineIPs = append(item.snapshot.InboundOnlineIPs, OnlineIP{IP: source, Connections: item.sourceActive[source]})
			}
		}
		sort.Slice(item.snapshot.InboundOnlineIPs, func(i, j int) bool {
			return item.snapshot.InboundOnlineIPs[i].IP < item.snapshot.InboundOnlineIPs[j].IP
		})
		copy := item.snapshot
		copy.OutboundNewRate = len(item.newTimes)
		copy.OutboundRejectedTotal = copy.RejectedActiveLimit + copy.RejectedNewRateLimit + copy.RejectedUserTotalLimit + copy.RejectedOnlineIPLimit + copy.RejectedGlobalTotalLimit
		copy.MaxInboundOnlineIPs = cloneInt(copy.MaxInboundOnlineIPs)
		copy.MaxTotalConnections = cloneInt64(copy.MaxTotalConnections)
		copy.MaxOutboundTCPActive = cloneInt64(copy.MaxOutboundTCPActive)
		copy.MaxOutboundTCPNewPerSecond = cloneInt(copy.MaxOutboundTCPNewPerSecond)
		copy.CloseWaitTimeoutSeconds = cloneInt64(copy.CloseWaitTimeoutSeconds)
		copy.InboundOnlineIPs = append([]OnlineIP(nil), copy.InboundOnlineIPs...)
		result = append(result, copy)
		m.states[identity] = item
	}
	for socketID, record := range m.sockets {
		stateCode, found := kernelSockets[record.Tuple]
		if !found {
			if !record.ClosedAt.IsZero() && now.Sub(record.ClosedAt) >= 10*time.Second {
				delete(m.sockets, socketID)
			}
			continue
		}
		item := m.states[record.Identity]
		if item == nil {
			continue
		}
		if record.Direction == inboundSocket {
			addTCPState(&item.snapshot.InboundTCP, stateCode)
		} else {
			addTCPState(&item.snapshot.OutboundTCP, stateCode)
		}
	}
	// Socket-state aggregation updates the live snapshots after the first copy.
	// Refresh those two fields without disturbing the rate snapshot taken above.
	byIdentity := make(map[Identity]int, len(result))
	for index := range result {
		byIdentity[result[index].Identity] = index
	}
	for identity, item := range m.states {
		if index, ok := byIdentity[identity]; ok {
			result[index].InboundTCP = item.snapshot.InboundTCP
			result[index].OutboundTCP = item.snapshot.OutboundTCP
		}
	}
	global := GlobalSnapshot{CurrentTotal: m.globalCurrent, MaxTotal: cloneInt64(m.globalLimit), RejectedGlobalTotalLimit: m.globalRejected}
	m.mu.Unlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].Identity.InboundTag != result[j].Identity.InboundTag {
			return result[i].Identity.InboundTag < result[j].Identity.InboundTag
		}
		return result[i].Identity.User < result[j].Identity.User
	})
	return result, global, nil
}

func (m *Manager) Snapshots() []Snapshot {
	snapshots, _, _ := m.SnapshotReport()
	return snapshots
}

// TrackDial wraps the single physical TCP dial selected by Xray. UDP bypasses
// accounting and limits. A failed dial always releases its reservation.
func TrackDial(ctx context.Context, destination xnet.Destination, dial func() (stdnet.Conn, error)) (stdnet.Conn, error) {
	lease, err := Default.acquire(ctx, destination)
	if err != nil {
		return nil, err
	}
	conn, err := dial()
	if err != nil || conn == nil {
		lease.failed()
		return conn, err
	}
	return lease.succeeded(conn), nil
}

type trackedInboundConn struct {
	stdnet.Conn
	manager   *Manager
	mu        sync.Mutex
	identity  Identity
	tuple     socketTuple
	socketID  uint64
	source    string
	bound     bool
	closed    bool
	rejectErr error
	closeOnce sync.Once
}

func TrackInbound(conn stdnet.Conn) stdnet.Conn {
	if conn == nil {
		return nil
	}
	tuple, _ := socketTupleFromConn(conn)
	return &trackedInboundConn{Conn: conn, manager: Default, tuple: tuple}
}

func BindInbound(ctx context.Context, conn stdnet.Conn) error {
	tracked, ok := conn.(*trackedInboundConn)
	if !ok || tracked == nil {
		return nil
	}
	identity := identityFromContext(ctx)
	if !identity.Attributed {
		return nil
	}
	return tracked.bind(identity)
}

func (c *trackedInboundConn) bind(identity Snapshot) error {
	c.mu.Lock()
	if c.rejectErr != nil {
		err := c.rejectErr
		c.mu.Unlock()
		return err
	}
	if c.bound || c.closed {
		c.mu.Unlock()
		return nil
	}
	socketID, err := c.manager.bindInbound(identity, c.tuple)
	if err != nil {
		c.rejectErr = err
		c.mu.Unlock()
		return err
	}
	c.bound = true
	c.identity = identity.Identity
	c.socketID = socketID
	c.source = normalizedSourceIP(c.tuple.RemoteIP)
	c.mu.Unlock()
	return nil
}

func (c *trackedInboundConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		bound := c.bound
		identity := c.identity
		socketID := c.socketID
		source := c.source
		c.mu.Unlock()
		if bound {
			c.manager.releaseInbound(identity, socketID, source)
		}
	})
	return err
}

type trackedOutboundConn struct {
	stdnet.Conn
	once             sync.Once
	release          func()
	closeWaitTimeout time.Duration
	timerMu          sync.Mutex
	timer            *time.Timer
}

func (c *trackedOutboundConn) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if err == io.EOF && c.closeWaitTimeout > 0 {
		c.armCloseWaitTimer()
	}
	return n, err
}

func (c *trackedOutboundConn) armCloseWaitTimer() {
	c.timerMu.Lock()
	if c.timer == nil {
		c.timer = time.AfterFunc(c.closeWaitTimeout, func() { _ = c.Close() })
	}
	c.timerMu.Unlock()
}

func (c *trackedOutboundConn) Close() error {
	c.timerMu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timerMu.Unlock()
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func closeRead(conn stdnet.Conn) error {
	if conn, ok := conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return nil
}

func closeWrite(conn stdnet.Conn) error {
	if conn, ok := conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

func syscallConn(conn stdnet.Conn) (syscall.RawConn, error) {
	if conn, ok := conn.(syscall.Conn); ok {
		return conn.SyscallConn()
	}
	return nil, fmt.Errorf("underlying connection does not expose syscall.Conn")
}

func (c *trackedInboundConn) CloseRead() error                       { return closeRead(c.Conn) }
func (c *trackedInboundConn) CloseWrite() error                      { return closeWrite(c.Conn) }
func (c *trackedInboundConn) SyscallConn() (syscall.RawConn, error)  { return syscallConn(c.Conn) }
func (c *trackedOutboundConn) CloseRead() error                      { return closeRead(c.Conn) }
func (c *trackedOutboundConn) CloseWrite() error                     { return closeWrite(c.Conn) }
func (c *trackedOutboundConn) SyscallConn() (syscall.RawConn, error) { return syscallConn(c.Conn) }
