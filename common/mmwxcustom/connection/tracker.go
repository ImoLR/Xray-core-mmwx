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
	"strings"
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

// ManagementGroupMapping is an explicit controller-provided ownership edge.
// User is the protocol identity propagated by Xray and may be empty only for a
// single-secret inbound whose connections can be attributed by inbound tag.
type ManagementGroupMapping struct {
	Identity Identity `json:"identity"`
	Group    string   `json:"group"`
}

type ManagementGroupLimit struct {
	Group                      string `json:"group"`
	MaxInboundConnections      *int64 `json:"max_inbound_connections"`
	MaxInboundOnlineIPs        *int   `json:"max_inbound_online_ips"`
	MaxOutboundTCPActive       *int64 `json:"max_outbound_tcp_active"`
	MaxOutboundTCPNewPerSecond *int   `json:"max_outbound_tcp_new_per_second"`
}

type PortLimit struct {
	InboundTag                 string `json:"inbound_tag"`
	MaxInboundConnections      *int64 `json:"max_inbound_connections"`
	MaxInboundOnlineIPs        *int   `json:"max_inbound_online_ips"`
	MaxOutboundTCPActive       *int64 `json:"max_outbound_tcp_active"`
	MaxOutboundTCPNewPerSecond *int   `json:"max_outbound_tcp_new_per_second"`
}

type Config struct {
	DefaultCloseWaitTimeoutSeconds *int64                   `json:"default_close_wait_timeout_seconds"`
	OnlineIPGracePeriodSeconds     int64                    `json:"online_ip_grace_period_seconds"`
	MaxGlobalTotalConnections      *int64                   `json:"max_global_total_connections"`
	MaxGlobalInboundConnections    *int64                   `json:"max_global_inbound_connections"`
	Limits                         []Limit                  `json:"limits"`
	PortLimits                     []PortLimit              `json:"port_limits"`
	ManagementMappings             []ManagementGroupMapping `json:"management_mappings"`
	ManagementLimits               []ManagementGroupLimit   `json:"management_limits"`
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
	CurrentTotal               int64  `json:"current_total"`
	MaxTotal                   *int64 `json:"max_total"`
	CurrentInbound             int64  `json:"current_inbound"`
	MaxInbound                 *int64 `json:"max_inbound"`
	RejectedGlobalTotalLimit   uint64 `json:"rejected_global_total_limit"`
	RejectedGlobalInboundLimit uint64 `json:"rejected_global_inbound_limit"`
}

type ManagementGroupSnapshot struct {
	Group                      string         `json:"group"`
	CurrentTotal               int64          `json:"current_total"`
	InboundActive              int64          `json:"inbound_active"`
	InboundCurrent             int64          `json:"inbound_current"`
	InboundTCP                 TCPStateCounts `json:"inbound_tcp"`
	InboundOnlineIPs           []OnlineIP     `json:"inbound_online_ips"`
	OutboundActive             int64          `json:"outbound_active"`
	OutboundPending            int64          `json:"outbound_pending"`
	OutboundTCP                TCPStateCounts `json:"outbound_tcp"`
	OutboundNewRate            int            `json:"outbound_new_rate"`
	OutboundNewTotal           uint64         `json:"outbound_new_total"`
	OutboundRejectedTotal      uint64         `json:"outbound_rejected_total"`
	RejectedUserTotalLimit     uint64         `json:"rejected_user_total_limit"`
	RejectedUserNewRateLimit   uint64         `json:"rejected_user_new_rate_limit"`
	RejectedPortTotalLimit     uint64         `json:"rejected_port_total_limit"`
	RejectedPortNewRateLimit   uint64         `json:"rejected_port_new_rate_limit"`
	RejectedOnlineIPLimit      uint64         `json:"rejected_online_ip_limit"`
	RejectedGlobalTotalLimit   uint64         `json:"rejected_global_total_limit"`
	RejectedUserInboundLimit   uint64         `json:"rejected_user_inbound_limit"`
	RejectedPortInboundLimit   uint64         `json:"rejected_port_inbound_limit"`
	RejectedUserOnlineIPLimit  uint64         `json:"rejected_user_online_ip_limit"`
	RejectedPortOnlineIPLimit  uint64         `json:"rejected_port_online_ip_limit"`
	RejectedGlobalInboundLimit uint64         `json:"rejected_global_inbound_limit"`
	MaxInboundConnections      *int64         `json:"max_inbound_connections"`
	MaxInboundOnlineIPs        *int           `json:"max_inbound_online_ips"`
	MaxOutboundTCPActive       *int64         `json:"max_outbound_tcp_active"`
	MaxOutboundTCPNewPerSecond *int           `json:"max_outbound_tcp_new_per_second"`
}

type Snapshot struct {
	Identity                       Identity       `json:"identity"`
	InboundName                    string         `json:"inbound_name,omitempty"`
	InboundPort                    uint32         `json:"inbound_port,omitempty"`
	OutboundTag                    string         `json:"outbound_tag,omitempty"`
	Attributed                     bool           `json:"attributed"`
	InboundActive                  int64          `json:"inbound_active"`
	InboundCurrent                 int64          `json:"inbound_current"`
	InboundTotal                   uint64         `json:"inbound_total"`
	CurrentTotal                   int64          `json:"current_total"`
	InboundTCP                     TCPStateCounts `json:"inbound_tcp"`
	InboundOnlineIPs               []OnlineIP     `json:"inbound_online_ips"`
	OutboundActive                 int64          `json:"outbound_active"`
	OutboundPending                int64          `json:"outbound_pending"`
	OutboundTCP                    TCPStateCounts `json:"outbound_tcp"`
	OutboundNewTotal               uint64         `json:"outbound_new_total"`
	OutboundNewRate                int            `json:"outbound_new_rate"`
	OutboundRejectedTotal          uint64         `json:"outbound_rejected_total"`
	RejectedActiveLimit            uint64         `json:"rejected_active_limit"`
	RejectedNewRateLimit           uint64         `json:"rejected_new_rate_limit"`
	RejectedUserTotalLimit         uint64         `json:"rejected_user_total_limit"`
	RejectedPortTotalLimit         uint64         `json:"rejected_port_total_limit"`
	RejectedUserNewRateLimit       uint64         `json:"rejected_user_new_rate_limit"`
	RejectedPortNewRateLimit       uint64         `json:"rejected_port_new_rate_limit"`
	RejectedOnlineIPLimit          uint64         `json:"rejected_online_ip_limit"`
	RejectedGlobalTotalLimit       uint64         `json:"rejected_global_total_limit"`
	RejectedUserInboundLimit       uint64         `json:"rejected_user_inbound_limit"`
	RejectedPortInboundLimit       uint64         `json:"rejected_port_inbound_limit"`
	RejectedUserOnlineIPLimit      uint64         `json:"rejected_user_online_ip_limit"`
	RejectedPortOnlineIPLimit      uint64         `json:"rejected_port_online_ip_limit"`
	RejectedGlobalInboundLimit     uint64         `json:"rejected_global_inbound_limit"`
	MaxInboundOnlineIPs            *int           `json:"max_inbound_online_ips"`
	MaxTotalConnections            *int64         `json:"max_total_connections"`
	MaxOutboundTCPActive           *int64         `json:"max_outbound_tcp_active"`
	MaxOutboundTCPNewPerSecond     *int           `json:"max_outbound_tcp_new_per_second"`
	MaxPortOutboundTCPActive       *int64         `json:"max_port_outbound_tcp_active"`
	MaxPortOutboundTCPNewPerSecond *int           `json:"max_port_outbound_tcp_new_per_second"`
	MaxPortInboundConnections      *int64         `json:"max_port_inbound_connections"`
	MaxPortInboundOnlineIPs        *int           `json:"max_port_inbound_online_ips"`
	CloseWaitTimeoutSeconds        *int64         `json:"close_wait_timeout_seconds"`
	ManagementGroup                string         `json:"management_group,omitempty"`
}

type LimitReason string

const (
	ActiveLimit        LimitReason = "port_total_limit"
	NewRateLimit       LimitReason = "port_new_rate_limit"
	UserTotalLimit     LimitReason = "user_total_limit"
	PortTotalLimit     LimitReason = "port_total_limit"
	UserNewRateLimit   LimitReason = "user_new_rate_limit"
	PortNewRateLimit   LimitReason = "port_new_rate_limit"
	OnlineIPLimit      LimitReason = "online_ip_limit"
	GlobalTotalLimit   LimitReason = "global_total_limit"
	GlobalInboundLimit LimitReason = "global_inbound_limit"
	UserInboundLimit   LimitReason = "user_inbound_limit"
	PortInboundLimit   LimitReason = "port_inbound_limit"
	UserOnlineIPLimit  LimitReason = "user_online_ip_limit"
	PortOnlineIPLimit  LimitReason = "port_online_ip_limit"
)

type LimitError struct {
	Identity        Identity
	ManagementGroup string
	Reason          LimitReason
	Limit           int64
}

func (e *LimitError) Error() string {
	if e.ManagementGroup != "" {
		return fmt.Sprintf("connection %s reached for management group %q via inbound %q user %q (limit %d)", e.Reason, e.ManagementGroup, e.Identity.InboundTag, e.Identity.User, e.Limit)
	}
	return fmt.Sprintf("connection %s reached for inbound %q user %q (limit %d)", e.Reason, e.Identity.InboundTag, e.Identity.User, e.Limit)
}

type state struct {
	snapshot     Snapshot
	attemptTimes []time.Time
	newTimes     []time.Time
	sourceActive map[string]int64
	sourceSeen   map[string]time.Time
}

type managementGroupState struct {
	attemptTimes             []time.Time
	newTimes                 []time.Time
	outboundNewTotal         uint64
	rejectedUserTotalLimit   uint64
	rejectedUserNewRateLimit uint64
	inboundCurrent           int64
	sourceActive             map[string]int64
	sourceSeen               map[string]time.Time
	rejectedInboundLimit     uint64
	rejectedOnlineIPLimit    uint64
}

type portState struct {
	attemptTimes          []time.Time
	newTimes              []time.Time
	inboundCurrent        int64
	sourceActive          map[string]int64
	sourceSeen            map[string]time.Time
	rejectedInboundLimit  uint64
	rejectedOnlineIPLimit uint64
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
	mu                    sync.Mutex
	limits                map[Identity]Limit
	states                map[Identity]*state
	inbounds              map[string]ConfiguredInbound
	defaultCW             *int64
	onlineIPGrace         time.Duration
	globalLimit           *int64
	globalCurrent         int64
	globalRejected        uint64
	globalInboundLimit    *int64
	globalInboundCurrent  int64
	globalInboundRejected uint64
	managementMappings    map[Identity]string
	managementLimits      map[string]ManagementGroupLimit
	managementStates      map[string]*managementGroupState
	portLimits            map[string]PortLimit
	portStates            map[string]*portState
	sockets               map[uint64]socketRecord
	nextSocketID          uint64
	scanSockets           func() (map[socketTuple]string, error)
	now                   func() time.Time
}

var Default = NewManager()

func NewManager() *Manager {
	return &Manager{
		limits:             make(map[Identity]Limit),
		states:             make(map[Identity]*state),
		inbounds:           make(map[string]ConfiguredInbound),
		managementMappings: make(map[Identity]string),
		managementLimits:   make(map[string]ManagementGroupLimit),
		managementStates:   make(map[string]*managementGroupState),
		portLimits:         make(map[string]PortLimit),
		portStates:         make(map[string]*portState),
		onlineIPGrace:      30 * time.Second,
		sockets:            make(map[uint64]socketRecord),
		scanSockets:        readKernelTCPSockets,
		now:                time.Now,
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
	m.globalInboundLimit = nil
	m.globalInboundCurrent = 0
	m.globalInboundRejected = 0
	m.managementMappings = make(map[Identity]string)
	m.managementLimits = make(map[string]ManagementGroupLimit)
	m.managementStates = make(map[string]*managementGroupState)
	m.portLimits = make(map[string]PortLimit)
	m.portStates = make(map[string]*portState)
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
		item.snapshot.ManagementGroup = m.managementMappings[identity]
	}
	if len(users) == 0 {
		identity := Identity{InboundTag: inbound.Tag}
		if group := m.managementMappings[identity]; group != "" {
			item := m.stateLocked(identity, Snapshot{
				Identity: identity, InboundName: inbound.Name, InboundPort: inbound.Port, Attributed: true,
			})
			m.applyLimitLocked(&item.snapshot, m.limits[identity])
			item.snapshot.ManagementGroup = group
		}
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
	if err := validateOptionalNonNegative("max_global_inbound_connections", config.MaxGlobalInboundConnections); err != nil {
		return err
	}
	replacement := make(map[Identity]Limit, len(config.Limits))
	for _, limit := range config.Limits {
		if limit.Identity.InboundTag == "" {
			return fmt.Errorf("limit identity requires inbound_tag")
		}
		if err := validateOptionalNonNegative("close_wait_timeout_seconds", limit.CloseWaitTimeoutSeconds); err != nil {
			return err
		}
		replacement[limit.Identity] = cloneLimit(limit)
	}
	mappings := make(map[Identity]string, len(config.ManagementMappings))
	for _, mapping := range config.ManagementMappings {
		mapping.Group = strings.TrimSpace(mapping.Group)
		if mapping.Identity.InboundTag == "" || mapping.Group == "" {
			return fmt.Errorf("management mapping requires inbound_tag and group")
		}
		if existing, exists := mappings[mapping.Identity]; exists && existing != mapping.Group {
			return fmt.Errorf("identity %q/%q belongs to more than one management group", mapping.Identity.InboundTag, mapping.Identity.User)
		}
		mappings[mapping.Identity] = mapping.Group
	}
	groupLimits := make(map[string]ManagementGroupLimit, len(config.ManagementLimits))
	for _, limit := range config.ManagementLimits {
		limit.Group = strings.TrimSpace(limit.Group)
		if limit.Group == "" {
			return fmt.Errorf("management limit requires group")
		}
		if err := validateOptionalNonNegative("management max_inbound_connections", limit.MaxInboundConnections); err != nil {
			return err
		}
		if err := validateOptionalNonNegativeInt("management max_inbound_online_ips", limit.MaxInboundOnlineIPs); err != nil {
			return err
		}
		if err := validateOptionalPositive("management max_outbound_tcp_active", limit.MaxOutboundTCPActive); err != nil {
			return err
		}
		if limit.MaxOutboundTCPNewPerSecond != nil && *limit.MaxOutboundTCPNewPerSecond <= 0 {
			return fmt.Errorf("management max_outbound_tcp_new_per_second must be positive when set")
		}
		if _, exists := groupLimits[limit.Group]; exists {
			return fmt.Errorf("duplicate management limit for group %q", limit.Group)
		}
		groupLimits[limit.Group] = cloneManagementGroupLimit(limit)
	}
	portLimits := make(map[string]PortLimit, len(config.PortLimits))
	for _, limit := range config.PortLimits {
		limit.InboundTag = strings.TrimSpace(limit.InboundTag)
		if limit.InboundTag == "" {
			return fmt.Errorf("port limit requires inbound_tag")
		}
		if err := validateOptionalNonNegative("port max_inbound_connections", limit.MaxInboundConnections); err != nil {
			return err
		}
		if err := validateOptionalNonNegativeInt("port max_inbound_online_ips", limit.MaxInboundOnlineIPs); err != nil {
			return err
		}
		if err := validateOptionalPositive("port max_outbound_tcp_active", limit.MaxOutboundTCPActive); err != nil {
			return err
		}
		if limit.MaxOutboundTCPNewPerSecond != nil && *limit.MaxOutboundTCPNewPerSecond <= 0 {
			return fmt.Errorf("port max_outbound_tcp_new_per_second must be positive when set")
		}
		if _, exists := portLimits[limit.InboundTag]; exists {
			return fmt.Errorf("duplicate port limit for inbound %q", limit.InboundTag)
		}
		portLimits[limit.InboundTag] = clonePortLimit(limit)
	}
	m.mu.Lock()
	m.limits = replacement
	m.managementMappings = mappings
	m.managementLimits = groupLimits
	m.portLimits = portLimits
	m.defaultCW = cloneInt64(config.DefaultCloseWaitTimeoutSeconds)
	m.globalLimit = cloneInt64(config.MaxGlobalTotalConnections)
	m.globalInboundLimit = cloneInt64(config.MaxGlobalInboundConnections)
	m.onlineIPGrace = time.Duration(config.OnlineIPGracePeriodSeconds) * time.Second
	if m.onlineIPGrace <= 0 {
		m.onlineIPGrace = 30 * time.Second
	}
	for identity, item := range m.states {
		m.applyLimitLocked(&item.snapshot, replacement[identity])
		item.snapshot.ManagementGroup = mappings[identity]
	}
	for identity, group := range mappings {
		metadata := Snapshot{Identity: identity, Attributed: true, ManagementGroup: group}
		for _, inbound := range m.inbounds {
			if inbound.Tag == identity.InboundTag {
				metadata.InboundName = inbound.Name
				metadata.InboundPort = inbound.Port
				break
			}
		}
		item := m.stateLocked(identity, metadata)
		m.applyLimitLocked(&item.snapshot, replacement[identity])
	}
	for group := range groupLimits {
		if m.managementStates[group] == nil {
			m.managementStates[group] = &managementGroupState{}
		}
	}
	for tag := range portLimits {
		if m.portStates[tag] == nil {
			m.portStates[tag] = &portState{}
		}
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

func validateOptionalNonNegativeInt(name string, value *int) error {
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

func cloneManagementGroupLimit(limit ManagementGroupLimit) ManagementGroupLimit {
	limit.MaxInboundConnections = cloneInt64(limit.MaxInboundConnections)
	limit.MaxInboundOnlineIPs = cloneInt(limit.MaxInboundOnlineIPs)
	limit.MaxOutboundTCPActive = cloneInt64(limit.MaxOutboundTCPActive)
	limit.MaxOutboundTCPNewPerSecond = cloneInt(limit.MaxOutboundTCPNewPerSecond)
	return limit
}

func clonePortLimit(limit PortLimit) PortLimit {
	limit.MaxInboundConnections = cloneInt64(limit.MaxInboundConnections)
	limit.MaxInboundOnlineIPs = cloneInt(limit.MaxInboundOnlineIPs)
	limit.MaxOutboundTCPActive = cloneInt64(limit.MaxOutboundTCPActive)
	limit.MaxOutboundTCPNewPerSecond = cloneInt(limit.MaxOutboundTCPNewPerSecond)
	return limit
}

func (m *Manager) applyLimitLocked(snapshot *Snapshot, limit Limit) {
	// Legacy identity-scoped limit fields are intentionally ignored. Identity is
	// retained for attribution while administrator controls live at group/port.
	snapshot.MaxInboundOnlineIPs = nil
	snapshot.MaxTotalConnections = nil
	snapshot.MaxOutboundTCPActive = nil
	snapshot.MaxOutboundTCPNewPerSecond = nil
	portLimit := m.portLimits[snapshot.Identity.InboundTag]
	snapshot.MaxPortInboundConnections = cloneInt64(portLimit.MaxInboundConnections)
	snapshot.MaxPortInboundOnlineIPs = cloneInt(portLimit.MaxInboundOnlineIPs)
	snapshot.MaxPortOutboundTCPActive = cloneInt64(portLimit.MaxOutboundTCPActive)
	snapshot.MaxPortOutboundTCPNewPerSecond = cloneInt(portLimit.MaxOutboundTCPNewPerSecond)
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

func (m *Manager) groupStateLocked(group string) *managementGroupState {
	item := m.managementStates[group]
	if item == nil {
		item = &managementGroupState{sourceActive: make(map[string]int64), sourceSeen: make(map[string]time.Time)}
		m.managementStates[group] = item
	}
	if item.sourceActive == nil {
		item.sourceActive = make(map[string]int64)
	}
	if item.sourceSeen == nil {
		item.sourceSeen = make(map[string]time.Time)
	}
	return item
}

func (m *Manager) groupOutboundCurrentLocked(group string) int64 {
	var total int64
	for identity, item := range m.states {
		if m.managementMappings[identity] == group {
			total += item.snapshot.OutboundActive + item.snapshot.OutboundPending
		}
	}
	return total
}

func (m *Manager) portStateLocked(tag string) *portState {
	item := m.portStates[tag]
	if item == nil {
		item = &portState{sourceActive: make(map[string]int64), sourceSeen: make(map[string]time.Time)}
		m.portStates[tag] = item
	}
	if item.sourceActive == nil {
		item.sourceActive = make(map[string]int64)
	}
	if item.sourceSeen == nil {
		item.sourceSeen = make(map[string]time.Time)
	}
	return item
}

func (m *Manager) portOutboundCurrentLocked(tag string) int64 {
	var total int64
	for identity, item := range m.states {
		if identity.InboundTag == tag {
			total += item.snapshot.OutboundActive + item.snapshot.OutboundPending
		}
	}
	return total
}

func (m *Manager) effectiveIdentityLocked(snapshot Snapshot) Snapshot {
	if snapshot.Identity.InboundTag == "" {
		snapshot.Identity = Identity{}
		snapshot.Attributed = false
		return snapshot
	}
	if snapshot.Identity.User != "" {
		snapshot.Attributed = true
		return snapshot
	}
	if _, mapped := m.managementMappings[snapshot.Identity]; mapped {
		snapshot.Attributed = true
		return snapshot
	}
	if _, limited := m.limits[snapshot.Identity]; limited {
		snapshot.Attributed = true
		return snapshot
	}
	snapshot.Identity = Identity{}
	snapshot.Attributed = false
	return snapshot
}

func (m *Manager) rejectLocked(item *state, identity Identity, group string, reason LimitReason, limit int64) error {
	switch reason {
	case UserTotalLimit:
		item.snapshot.RejectedUserTotalLimit++
		m.groupStateLocked(group).rejectedUserTotalLimit++
	case PortTotalLimit:
		item.snapshot.RejectedPortTotalLimit++
		item.snapshot.RejectedActiveLimit++
	case UserNewRateLimit:
		item.snapshot.RejectedUserNewRateLimit++
		m.groupStateLocked(group).rejectedUserNewRateLimit++
	case PortNewRateLimit:
		item.snapshot.RejectedPortNewRateLimit++
		item.snapshot.RejectedNewRateLimit++
	case OnlineIPLimit:
		item.snapshot.RejectedOnlineIPLimit++
	case GlobalTotalLimit:
		item.snapshot.RejectedGlobalTotalLimit++
		m.globalRejected++
	case GlobalInboundLimit:
		item.snapshot.RejectedGlobalInboundLimit++
		m.globalInboundRejected++
	case UserInboundLimit:
		item.snapshot.RejectedUserInboundLimit++
		m.groupStateLocked(group).rejectedInboundLimit++
	case PortInboundLimit:
		item.snapshot.RejectedPortInboundLimit++
		m.portStateLocked(identity.InboundTag).rejectedInboundLimit++
	case UserOnlineIPLimit:
		item.snapshot.RejectedUserOnlineIPLimit++
		item.snapshot.RejectedOnlineIPLimit++
		m.groupStateLocked(group).rejectedOnlineIPLimit++
	case PortOnlineIPLimit:
		item.snapshot.RejectedPortOnlineIPLimit++
		item.snapshot.RejectedOnlineIPLimit++
		m.portStateLocked(identity.InboundTag).rejectedOnlineIPLimit++
	}
	return &LimitError{Identity: identity, ManagementGroup: group, Reason: reason, Limit: limit}
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
	return snapshot
}

func sourceFromContext(ctx context.Context) string {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || !inbound.Source.IsValid() {
		return ""
	}
	address, ok := netip.AddrFromSlice(inbound.Source.Address.IP())
	if !ok {
		return ""
	}
	return normalizedSourceIP(address)
}

type lease struct {
	manager  *Manager
	identity Identity
	group    string
	timeout  time.Duration
}

type inboundLease struct {
	manager  *Manager
	identity Identity
	group    string
	port     string
	source   string
	once     sync.Once
}

func positiveInt64(value *int64) bool { return value != nil && *value > 0 }
func positiveInt(value *int) bool     { return value != nil && *value > 0 }

func pruneSourceSet(active map[string]int64, seen map[string]time.Time, now time.Time, grace time.Duration) {
	cutoff := now.Add(-grace)
	for source, lastSeen := range seen {
		if active[source] <= 0 && !lastSeen.After(cutoff) {
			delete(active, source)
			delete(seen, source)
		}
	}
}

func sourceWouldExceed(active map[string]int64, seen map[string]time.Time, source string, limit *int) bool {
	if source == "" || !positiveInt(limit) || active[source] > 0 {
		return false
	}
	_, retained := seen[source]
	return !retained && len(seen) >= *limit
}

func (m *Manager) admitInbound(identity Snapshot, source string) (*inboundLease, error) {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	identity = m.effectiveIdentityLocked(identity)
	key := identity.Identity
	item := m.stateLocked(key, identity)
	m.applyLimitLocked(&item.snapshot, m.limits[key])
	group := m.managementMappings[key]
	port := key.InboundTag
	item.snapshot.ManagementGroup = group
	groupLimit := m.managementLimits[group]
	portLimit := m.portLimits[port]
	groupState := m.groupStateLocked(group)
	portState := m.portStateLocked(port)

	m.pruneSourcesLocked(item, now)
	pruneSourceSet(groupState.sourceActive, groupState.sourceSeen, now, m.onlineIPGrace)
	pruneSourceSet(portState.sourceActive, portState.sourceSeen, now, m.onlineIPGrace)

	if positiveInt64(m.globalInboundLimit) && m.globalInboundCurrent >= *m.globalInboundLimit {
		return nil, m.rejectLocked(item, key, group, GlobalInboundLimit, *m.globalInboundLimit)
	}
	if identity.Attributed && group != "" && positiveInt64(groupLimit.MaxInboundConnections) && groupState.inboundCurrent >= *groupLimit.MaxInboundConnections {
		return nil, m.rejectLocked(item, key, group, UserInboundLimit, *groupLimit.MaxInboundConnections)
	}
	if identity.Attributed && port != "" && positiveInt64(portLimit.MaxInboundConnections) && portState.inboundCurrent >= *portLimit.MaxInboundConnections {
		return nil, m.rejectLocked(item, key, group, PortInboundLimit, *portLimit.MaxInboundConnections)
	}
	if identity.Attributed && group != "" && sourceWouldExceed(groupState.sourceActive, groupState.sourceSeen, source, groupLimit.MaxInboundOnlineIPs) {
		return nil, m.rejectLocked(item, key, group, UserOnlineIPLimit, int64(*groupLimit.MaxInboundOnlineIPs))
	}
	if identity.Attributed && port != "" && sourceWouldExceed(portState.sourceActive, portState.sourceSeen, source, portLimit.MaxInboundOnlineIPs) {
		return nil, m.rejectLocked(item, key, group, PortOnlineIPLimit, int64(*portLimit.MaxInboundOnlineIPs))
	}

	m.globalInboundCurrent++
	item.snapshot.InboundCurrent++
	if group != "" {
		groupState.inboundCurrent++
	}
	if port != "" {
		portState.inboundCurrent++
	}
	if source != "" {
		item.sourceActive[source]++
		item.sourceSeen[source] = now
		if group != "" {
			groupState.sourceActive[source]++
			groupState.sourceSeen[source] = now
		}
		if port != "" {
			portState.sourceActive[source]++
			portState.sourceSeen[source] = now
		}
	}
	return &inboundLease{manager: m, identity: key, group: group, port: port, source: source}, nil
}

func (l *inboundLease) release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.manager.mu.Lock()
		now := l.manager.now()
		if l.manager.globalInboundCurrent > 0 {
			l.manager.globalInboundCurrent--
		}
		if item := l.manager.states[l.identity]; item != nil {
			if item.snapshot.InboundCurrent > 0 {
				item.snapshot.InboundCurrent--
			}
			if l.source != "" && item.sourceActive[l.source] > 0 {
				item.sourceActive[l.source]--
				item.sourceSeen[l.source] = now
			}
		}
		if l.group != "" {
			state := l.manager.groupStateLocked(l.group)
			if state.inboundCurrent > 0 {
				state.inboundCurrent--
			}
			if l.source != "" && state.sourceActive[l.source] > 0 {
				state.sourceActive[l.source]--
				state.sourceSeen[l.source] = now
			}
		}
		if l.port != "" {
			state := l.manager.portStateLocked(l.port)
			if state.inboundCurrent > 0 {
				state.inboundCurrent--
			}
			if l.source != "" && state.sourceActive[l.source] > 0 {
				state.sourceActive[l.source]--
				state.sourceSeen[l.source] = now
			}
		}
		l.manager.mu.Unlock()
	})
}

func (m *Manager) acquire(ctx context.Context, destination xnet.Destination) (*lease, error) {
	if destination.Network != xnet.Network_TCP {
		return nil, nil
	}
	now := m.now()
	identity := identityFromContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	identity = m.effectiveIdentityLocked(identity)
	key := identity.Identity
	item := m.stateLocked(key, identity)
	limit := m.limits[key]
	m.applyLimitLocked(&item.snapshot, limit)
	group := m.managementMappings[key]
	item.snapshot.ManagementGroup = group
	if m.globalLimit != nil && m.globalCurrent >= *m.globalLimit {
		return nil, m.rejectLocked(item, key, group, GlobalTotalLimit, *m.globalLimit)
	}
	groupLimit := m.managementLimits[group]
	groupState := m.groupStateLocked(group)
	if identity.Attributed && group != "" && groupLimit.MaxOutboundTCPActive != nil && m.groupOutboundCurrentLocked(group) >= *groupLimit.MaxOutboundTCPActive {
		return nil, m.rejectLocked(item, key, group, UserTotalLimit, *groupLimit.MaxOutboundTCPActive)
	}
	portLimit := m.portLimits[key.InboundTag]
	portState := m.portStateLocked(key.InboundTag)
	if identity.Attributed && portLimit.MaxOutboundTCPActive != nil && m.portOutboundCurrentLocked(key.InboundTag) >= *portLimit.MaxOutboundTCPActive {
		return nil, m.rejectLocked(item, key, group, PortTotalLimit, *portLimit.MaxOutboundTCPActive)
	}
	cutoff := now.Add(-time.Second)
	item.attemptTimes = prune(item.attemptTimes, cutoff)
	groupState.attemptTimes = prune(groupState.attemptTimes, cutoff)
	portState.attemptTimes = prune(portState.attemptTimes, cutoff)
	if identity.Attributed && group != "" && groupLimit.MaxOutboundTCPNewPerSecond != nil && len(groupState.attemptTimes) >= *groupLimit.MaxOutboundTCPNewPerSecond {
		return nil, m.rejectLocked(item, key, group, UserNewRateLimit, int64(*groupLimit.MaxOutboundTCPNewPerSecond))
	}
	if identity.Attributed && portLimit.MaxOutboundTCPNewPerSecond != nil && len(portState.attemptTimes) >= *portLimit.MaxOutboundTCPNewPerSecond {
		return nil, m.rejectLocked(item, key, group, PortNewRateLimit, int64(*portLimit.MaxOutboundTCPNewPerSecond))
	}
	item.attemptTimes = append(item.attemptTimes, now)
	if group != "" {
		groupState.attemptTimes = append(groupState.attemptTimes, now)
	}
	if key.InboundTag != "" {
		portState.attemptTimes = append(portState.attemptTimes, now)
	}
	item.snapshot.OutboundPending++
	m.globalCurrent++
	return &lease{manager: m, identity: key, group: group, timeout: secondsToDuration(item.snapshot.CloseWaitTimeoutSeconds)}, nil
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
		if l.identity.InboundTag != "" {
			port := l.manager.portStateLocked(l.identity.InboundTag)
			port.newTimes = append(port.newTimes, now)
		}
		if l.group != "" {
			group := l.manager.groupStateLocked(l.group)
			group.outboundNewTotal++
			group.newTimes = append(group.newTimes, now)
		}
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
	m.mu.Lock()
	defer m.mu.Unlock()
	identity = m.effectiveIdentityLocked(identity)
	key := identity.Identity
	item := m.stateLocked(key, identity)
	m.applyLimitLocked(&item.snapshot, m.limits[key])
	group := m.managementMappings[key]
	item.snapshot.ManagementGroup = group
	if m.globalLimit != nil && m.globalCurrent >= *m.globalLimit {
		return 0, m.rejectLocked(item, key, group, GlobalTotalLimit, *m.globalLimit)
	}
	item.snapshot.InboundActive++
	item.snapshot.InboundTotal++
	m.globalCurrent++
	return m.registerSocketLocked(key, inboundSocket, tuple), nil
}

func (m *Manager) releaseInbound(identity Identity, socketID uint64, source string) {
	m.mu.Lock()
	if item := m.states[identity]; item != nil && item.snapshot.InboundActive > 0 {
		item.snapshot.InboundActive--
		if m.globalCurrent > 0 {
			m.globalCurrent--
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

func addTCPCounts(target *TCPStateCounts, source TCPStateCounts) {
	target.Total += source.Total
	target.Established += source.Established
	target.SynSent += source.SynSent
	target.SynRecv += source.SynRecv
	target.FinWait1 += source.FinWait1
	target.FinWait2 += source.FinWait2
	target.TimeWait += source.TimeWait
	target.CloseWait += source.CloseWait
	target.LastAck += source.LastAck
	target.Closing += source.Closing
	target.Close += source.Close
	target.Unknown += source.Unknown
}

func (m *Manager) SnapshotReport() ([]Snapshot, GlobalSnapshot, error) {
	users, global, _, err := m.FullSnapshotReport()
	return users, global, err
}

func (m *Manager) FullSnapshotReport() ([]Snapshot, GlobalSnapshot, []ManagementGroupSnapshot, error) {
	now := m.now()
	cutoff := now.Add(-time.Second)
	kernelSockets, err := m.scanSockets()
	if err != nil {
		return nil, GlobalSnapshot{}, nil, fmt.Errorf("read kernel TCP states: %w", err)
	}
	m.mu.Lock()
	result := make([]Snapshot, 0, len(m.states))
	for identity, item := range m.states {
		item.snapshot.ManagementGroup = m.managementMappings[identity]
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
		copy.OutboundRejectedTotal = copy.RejectedUserTotalLimit + copy.RejectedPortTotalLimit + copy.RejectedUserNewRateLimit + copy.RejectedPortNewRateLimit + copy.RejectedGlobalTotalLimit
		copy.MaxInboundOnlineIPs = cloneInt(copy.MaxInboundOnlineIPs)
		copy.MaxTotalConnections = cloneInt64(copy.MaxTotalConnections)
		copy.MaxOutboundTCPActive = cloneInt64(copy.MaxOutboundTCPActive)
		copy.MaxOutboundTCPNewPerSecond = cloneInt(copy.MaxOutboundTCPNewPerSecond)
		copy.MaxPortOutboundTCPActive = cloneInt64(copy.MaxPortOutboundTCPActive)
		copy.MaxPortOutboundTCPNewPerSecond = cloneInt(copy.MaxPortOutboundTCPNewPerSecond)
		copy.MaxPortInboundConnections = cloneInt64(copy.MaxPortInboundConnections)
		copy.MaxPortInboundOnlineIPs = cloneInt(copy.MaxPortInboundOnlineIPs)
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
	global := GlobalSnapshot{
		CurrentTotal:               m.globalCurrent,
		MaxTotal:                   cloneInt64(m.globalLimit),
		CurrentInbound:             m.globalInboundCurrent,
		MaxInbound:                 cloneInt64(m.globalInboundLimit),
		RejectedGlobalTotalLimit:   m.globalRejected,
		RejectedGlobalInboundLimit: m.globalInboundRejected,
	}
	groupNames := make(map[string]struct{}, len(m.managementLimits)+len(m.managementMappings))
	for group := range m.managementLimits {
		groupNames[group] = struct{}{}
	}
	for _, group := range m.managementMappings {
		groupNames[group] = struct{}{}
	}
	groups := make([]ManagementGroupSnapshot, 0, len(groupNames))
	groupIndexes := make(map[string]int, len(groupNames))
	for group := range groupNames {
		limit := m.managementLimits[group]
		state := m.groupStateLocked(group)
		state.newTimes = prune(state.newTimes, cutoff)
		pruneSourceSet(state.sourceActive, state.sourceSeen, now, m.onlineIPGrace)
		groupIndexes[group] = len(groups)
		groupSnapshot := ManagementGroupSnapshot{
			Group:                      group,
			InboundCurrent:             state.inboundCurrent,
			OutboundNewRate:            len(state.newTimes),
			OutboundNewTotal:           state.outboundNewTotal,
			RejectedUserTotalLimit:     state.rejectedUserTotalLimit,
			RejectedUserNewRateLimit:   state.rejectedUserNewRateLimit,
			RejectedUserInboundLimit:   state.rejectedInboundLimit,
			RejectedUserOnlineIPLimit:  state.rejectedOnlineIPLimit,
			MaxInboundConnections:      cloneInt64(limit.MaxInboundConnections),
			MaxInboundOnlineIPs:        cloneInt(limit.MaxInboundOnlineIPs),
			MaxOutboundTCPActive:       cloneInt64(limit.MaxOutboundTCPActive),
			MaxOutboundTCPNewPerSecond: cloneInt(limit.MaxOutboundTCPNewPerSecond),
		}
		for source, lastSeen := range state.sourceSeen {
			if state.sourceActive[source] > 0 || lastSeen.After(now.Add(-m.onlineIPGrace)) {
				groupSnapshot.InboundOnlineIPs = append(groupSnapshot.InboundOnlineIPs, OnlineIP{IP: source, Connections: state.sourceActive[source]})
			}
		}
		sort.Slice(groupSnapshot.InboundOnlineIPs, func(i, j int) bool {
			return groupSnapshot.InboundOnlineIPs[i].IP < groupSnapshot.InboundOnlineIPs[j].IP
		})
		groups = append(groups, groupSnapshot)
	}
	for _, user := range result {
		if user.ManagementGroup == "" {
			continue
		}
		index, exists := groupIndexes[user.ManagementGroup]
		if !exists {
			continue
		}
		group := &groups[index]
		group.CurrentTotal += user.CurrentTotal
		group.InboundActive += user.InboundActive
		group.OutboundActive += user.OutboundActive
		group.OutboundPending += user.OutboundPending
		group.RejectedPortTotalLimit += user.RejectedPortTotalLimit
		group.RejectedPortNewRateLimit += user.RejectedPortNewRateLimit
		group.RejectedPortInboundLimit += user.RejectedPortInboundLimit
		group.RejectedPortOnlineIPLimit += user.RejectedPortOnlineIPLimit
		group.RejectedGlobalTotalLimit += user.RejectedGlobalTotalLimit
		group.RejectedGlobalInboundLimit += user.RejectedGlobalInboundLimit
		addTCPCounts(&group.InboundTCP, user.InboundTCP)
		addTCPCounts(&group.OutboundTCP, user.OutboundTCP)
	}
	for index := range groups {
		groups[index].RejectedOnlineIPLimit = groups[index].RejectedUserOnlineIPLimit + groups[index].RejectedPortOnlineIPLimit
		groups[index].OutboundRejectedTotal = groups[index].RejectedUserTotalLimit + groups[index].RejectedUserNewRateLimit + groups[index].RejectedPortTotalLimit + groups[index].RejectedPortNewRateLimit + groups[index].RejectedGlobalTotalLimit
	}
	m.mu.Unlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].Identity.InboundTag != result[j].Identity.InboundTag {
			return result[i].Identity.InboundTag < result[j].Identity.InboundTag
		}
		return result[i].Identity.User < result[j].Identity.User
	})
	sort.Slice(groups, func(i, j int) bool { return groups[i].Group < groups[j].Group })
	return result, global, groups, nil
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
	if identity.Identity.InboundTag == "" {
		return nil
	}
	return tracked.bind(identity)
}

// AdmitInbound applies Custom-owned logical inbound and online-IP limits after
// authentication but before routing or outbound selection. Its lease is
// released when the per-request context ends, so Mux streams are counted as
// independent logical connections rather than as one physical socket.
func AdmitInbound(ctx context.Context) error {
	lease, err := Default.admitInbound(identityFromContext(ctx), sourceFromContext(ctx))
	if err != nil || lease == nil {
		return err
	}
	context.AfterFunc(ctx, lease.release)
	return nil
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
