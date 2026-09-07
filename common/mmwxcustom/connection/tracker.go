// Package connection owns mmwx-custom connection attribution, accounting and
// limits. Xray packages should only call the small hooks exported here.
package connection

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
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
	MaxOutboundTCPActive       *int64   `json:"max_outbound_tcp_active"`
	MaxOutboundTCPNewPerSecond *int     `json:"max_outbound_tcp_new_per_second"`
	CloseWaitTimeoutSeconds    *int64   `json:"close_wait_timeout_seconds"`
}

type Config struct {
	DefaultCloseWaitTimeoutSeconds *int64  `json:"default_close_wait_timeout_seconds"`
	Limits                         []Limit `json:"limits"`
}

type Snapshot struct {
	Identity                   Identity `json:"identity"`
	InboundName                string   `json:"inbound_name,omitempty"`
	InboundPort                uint32   `json:"inbound_port,omitempty"`
	OutboundTag                string   `json:"outbound_tag,omitempty"`
	Attributed                 bool     `json:"attributed"`
	InboundActive              int64    `json:"inbound_active"`
	InboundTotal               uint64   `json:"inbound_total"`
	OutboundActive             int64    `json:"outbound_active"`
	OutboundPending            int64    `json:"outbound_pending"`
	OutboundNewTotal           uint64   `json:"outbound_new_total"`
	OutboundNewRate            int      `json:"outbound_new_rate"`
	OutboundRejectedTotal      uint64   `json:"outbound_rejected_total"`
	RejectedActiveLimit        uint64   `json:"rejected_active_limit"`
	RejectedNewRateLimit       uint64   `json:"rejected_new_rate_limit"`
	MaxOutboundTCPActive       *int64   `json:"max_outbound_tcp_active"`
	MaxOutboundTCPNewPerSecond *int     `json:"max_outbound_tcp_new_per_second"`
	CloseWaitTimeoutSeconds    *int64   `json:"close_wait_timeout_seconds"`
}

type LimitReason string

const (
	ActiveLimit  LimitReason = "active_limit"
	NewRateLimit LimitReason = "new_rate_limit"
)

type LimitError struct {
	Identity Identity
	Reason   LimitReason
	Limit    int64
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("outbound connection %s reached for inbound %q user %q (limit %d)", e.Reason, e.Identity.InboundTag, e.Identity.User, e.Limit)
}

type state struct {
	snapshot     Snapshot
	attemptTimes []time.Time
	newTimes     []time.Time
}

type Manager struct {
	mu        sync.Mutex
	limits    map[Identity]Limit
	states    map[Identity]*state
	defaultCW *int64
	now       func() time.Time
}

var Default = NewManager()

func NewManager() *Manager {
	return &Manager{
		limits: make(map[Identity]Limit),
		states: make(map[Identity]*state),
		now:    time.Now,
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
	m.defaultCW = nil
	m.mu.Unlock()
}

func (m *Manager) ReplaceConfig(config Config) error {
	if err := validateOptionalNonNegative("default_close_wait_timeout_seconds", config.DefaultCloseWaitTimeoutSeconds); err != nil {
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
	limit.MaxOutboundTCPActive = cloneInt64(limit.MaxOutboundTCPActive)
	limit.MaxOutboundTCPNewPerSecond = cloneInt(limit.MaxOutboundTCPNewPerSecond)
	limit.CloseWaitTimeoutSeconds = cloneInt64(limit.CloseWaitTimeoutSeconds)
	return limit
}

func (m *Manager) applyLimitLocked(snapshot *Snapshot, limit Limit) {
	snapshot.MaxOutboundTCPActive = cloneInt64(limit.MaxOutboundTCPActive)
	snapshot.MaxOutboundTCPNewPerSecond = cloneInt(limit.MaxOutboundTCPNewPerSecond)
	timeout := limit.CloseWaitTimeoutSeconds
	if timeout == nil {
		timeout = m.defaultCW
	}
	snapshot.CloseWaitTimeoutSeconds = cloneInt64(timeout)
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
	item := m.states[key]
	if item == nil {
		item = &state{snapshot: identity}
		m.states[key] = item
	} else {
		mergeMetadata(&item.snapshot, identity)
	}
	limit := m.limits[key]
	m.applyLimitLocked(&item.snapshot, limit)
	if identity.Attributed && limit.MaxOutboundTCPActive != nil && item.snapshot.OutboundActive+item.snapshot.OutboundPending >= *limit.MaxOutboundTCPActive {
		item.snapshot.RejectedActiveLimit++
		return nil, &LimitError{Identity: key, Reason: ActiveLimit, Limit: *limit.MaxOutboundTCPActive}
	}
	cutoff := now.Add(-time.Second)
	item.attemptTimes = prune(item.attemptTimes, cutoff)
	if identity.Attributed && limit.MaxOutboundTCPNewPerSecond != nil && len(item.attemptTimes) >= *limit.MaxOutboundTCPNewPerSecond {
		item.snapshot.RejectedNewRateLimit++
		return nil, &LimitError{Identity: key, Reason: NewRateLimit, Limit: int64(*limit.MaxOutboundTCPNewPerSecond)}
	}
	item.attemptTimes = append(item.attemptTimes, now)
	item.snapshot.OutboundPending++
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
	}
	l.manager.mu.Unlock()
}

func (l *lease) succeeded(conn stdnet.Conn) stdnet.Conn {
	if l == nil || conn == nil {
		return conn
	}
	now := l.manager.now()
	l.manager.mu.Lock()
	if item := l.manager.states[l.identity]; item != nil {
		if item.snapshot.OutboundPending > 0 {
			item.snapshot.OutboundPending--
		}
		item.snapshot.OutboundActive++
		item.snapshot.OutboundNewTotal++
		item.newTimes = append(item.newTimes, now)
	}
	l.manager.mu.Unlock()
	return &trackedOutboundConn{Conn: conn, release: func() { l.manager.release(l.identity) }, closeWaitTimeout: l.timeout}
}

func (m *Manager) release(identity Identity) {
	m.mu.Lock()
	if item := m.states[identity]; item != nil && item.snapshot.OutboundActive > 0 {
		item.snapshot.OutboundActive--
	}
	m.mu.Unlock()
}

func (m *Manager) bindInbound(identity Snapshot) {
	key := identity.Identity
	m.mu.Lock()
	item := m.states[key]
	if item == nil {
		item = &state{snapshot: identity}
		m.states[key] = item
	} else {
		mergeMetadata(&item.snapshot, identity)
	}
	item.snapshot.InboundActive++
	item.snapshot.InboundTotal++
	m.applyLimitLocked(&item.snapshot, m.limits[key])
	m.mu.Unlock()
}

func (m *Manager) releaseInbound(identity Identity) {
	m.mu.Lock()
	if item := m.states[identity]; item != nil && item.snapshot.InboundActive > 0 {
		item.snapshot.InboundActive--
	}
	m.mu.Unlock()
}

func (m *Manager) Snapshots() []Snapshot {
	now := m.now()
	cutoff := now.Add(-time.Second)
	m.mu.Lock()
	result := make([]Snapshot, 0, len(m.states))
	for _, item := range m.states {
		item.newTimes = prune(item.newTimes, cutoff)
		copy := item.snapshot
		copy.OutboundNewRate = len(item.newTimes)
		copy.OutboundRejectedTotal = copy.RejectedActiveLimit + copy.RejectedNewRateLimit
		copy.MaxOutboundTCPActive = cloneInt64(copy.MaxOutboundTCPActive)
		copy.MaxOutboundTCPNewPerSecond = cloneInt(copy.MaxOutboundTCPNewPerSecond)
		copy.CloseWaitTimeoutSeconds = cloneInt64(copy.CloseWaitTimeoutSeconds)
		result = append(result, copy)
	}
	m.mu.Unlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].Identity.InboundTag != result[j].Identity.InboundTag {
			return result[i].Identity.InboundTag < result[j].Identity.InboundTag
		}
		return result[i].Identity.User < result[j].Identity.User
	})
	return result
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
	bound     bool
	closed    bool
	closeOnce sync.Once
}

func TrackInbound(conn stdnet.Conn) stdnet.Conn {
	if conn == nil {
		return nil
	}
	return &trackedInboundConn{Conn: conn, manager: Default}
}

func BindInbound(ctx context.Context, conn stdnet.Conn) {
	tracked, ok := conn.(*trackedInboundConn)
	if !ok || tracked == nil {
		return
	}
	identity := identityFromContext(ctx)
	if !identity.Attributed {
		return
	}
	tracked.bind(identity)
}

func (c *trackedInboundConn) bind(identity Snapshot) {
	c.mu.Lock()
	if c.bound || c.closed {
		c.mu.Unlock()
		return
	}
	c.bound = true
	c.identity = identity.Identity
	c.mu.Unlock()
	c.manager.bindInbound(identity)
}

func (c *trackedInboundConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		bound := c.bound
		identity := c.identity
		c.mu.Unlock()
		if bound {
			c.manager.releaseInbound(identity)
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
