package connection

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestControlServerSnapshotAndConfig(t *testing.T) {
	manager := NewManager()
	manager.RegisterConfiguredInbound(ConfiguredInbound{Tag: "in-a", Name: "shadowsocks-2022-multi", Port: 10015, Users: []string{"user-a"}})
	server := newControlServer(manager)
	request := httptest.NewRequest(http.MethodGet, "/v1/snapshot", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("snapshot status = %d", response.Code)
	}

	body := []byte(`{"online_ip_grace_period_seconds":45,"max_global_total_connections":30,"limits":[{"identity":{"inbound_tag":"in-a","user":"user-a"},"max_inbound_online_ips":2,"max_total_connections":9,"max_outbound_tcp_active":3}],"port_limits":[{"inbound_tag":"in-a","max_outbound_tcp_active":7}],"management_mappings":[{"identity":{"inbound_tag":"in-a","user":"user-a"},"group":"ken"}],"management_limits":[{"group":"ken","max_outbound_tcp_active":11}]}`)
	request = httptest.NewRequest(http.MethodPut, "/v1/config", bytes.NewReader(body))
	response = httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("config status = %d body=%s", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	limit := manager.limits[Identity{InboundTag: "in-a", User: "user-a"}]
	portLimit := manager.portLimits["in-a"]
	managementLimit := manager.managementLimits["ken"]
	managementGroup := manager.managementMappings[Identity{InboundTag: "in-a", User: "user-a"}]
	globalLimit := manager.globalLimit
	grace := manager.onlineIPGrace
	manager.mu.Unlock()
	if limit.MaxOutboundTCPActive == nil || *limit.MaxOutboundTCPActive != 3 || limit.MaxTotalConnections == nil || *limit.MaxTotalConnections != 9 || limit.MaxInboundOnlineIPs == nil || *limit.MaxInboundOnlineIPs != 2 || portLimit.MaxOutboundTCPActive == nil || *portLimit.MaxOutboundTCPActive != 7 || managementLimit.MaxOutboundTCPActive == nil || *managementLimit.MaxOutboundTCPActive != 11 || managementGroup != "ken" || globalLimit == nil || *globalLimit != 30 || grace.Seconds() != 45 {
		t.Fatalf("config was not applied: %#v", limit)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/snapshot", nil)
	response = httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if !bytes.Contains(response.Body.Bytes(), []byte(`"version":3`)) || !bytes.Contains(response.Body.Bytes(), []byte(`"max_total":30`)) || !bytes.Contains(response.Body.Bytes(), []byte(`"inbound_port":10015`)) || !bytes.Contains(response.Body.Bytes(), []byte(`"user":"user-a"`)) || !bytes.Contains(response.Body.Bytes(), []byte(`"group":"ken"`)) {
		t.Fatalf("v3 snapshot/global fields missing: %s", response.Body.String())
	}
}

func TestControlServerRejectsMalformedConfig(t *testing.T) {
	server := newControlServer(NewManager())
	request := httptest.NewRequest(http.MethodPut, "/v1/config", bytes.NewBufferString(`{"unknown":true}`))
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}

func TestControlSnapshotFailsClosedWhenKernelStatesUnavailable(t *testing.T) {
	manager := NewManager()
	manager.scanSockets = func() (map[socketTuple]string, error) { return nil, errors.New("unavailable") }
	server := newControlServer(manager)
	request := httptest.NewRequest(http.MethodGet, "/v1/snapshot", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", response.Code, response.Body.String())
	}
}

func TestListenUnixDoesNotReplaceRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if listener, err := listenUnix(path); err == nil {
		listener.Close()
		t.Fatal("regular file was replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatalf("regular file changed: %q err=%v", data, err)
	}
}

func TestUnixSocketIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := listenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("socket mode = %o, want 600", got)
	}
	if _, ok := listener.(*net.UnixListener); !ok {
		t.Fatalf("listener type = %T", listener)
	}
}

func TestSnapshotJSONUsesNullForUnlimited(t *testing.T) {
	data, err := json.Marshal(Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"\"max_inbound_online_ips\":null", "\"max_total_connections\":null", "\"max_outbound_tcp_active\":null", "\"max_outbound_tcp_new_per_second\":null", "\"max_port_outbound_tcp_active\":null", "\"max_port_outbound_tcp_new_per_second\":null", "\"close_wait_timeout_seconds\":null"} {
		if !bytes.Contains(data, []byte(field)) {
			t.Fatalf("snapshot %s does not contain %s", data, field)
		}
	}
}
