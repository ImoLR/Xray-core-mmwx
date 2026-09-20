package connection

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	ControlSocketEnv = "MMWXC_CORE_CONTROL_SOCKET"
	maxConfigBytes   = 1 << 20
)

type controlSnapshot struct {
	Version          int                       `json:"version"`
	StartedAt        time.Time                 `json:"started_at"`
	Global           GlobalSnapshot            `json:"global"`
	Inbounds         []ConfiguredInbound       `json:"inbounds"`
	Users            []Snapshot                `json:"proxy_users"`
	ManagementGroups []ManagementGroupSnapshot `json:"management_groups"`
}

var controlRuntime struct {
	sync.Mutex
	path string
}

// EnsureControlServerFromEnvironment starts the opt-in, root-local bridge used
// by mmwxc-helper. With no environment variable, upstream behavior is unchanged.
func EnsureControlServerFromEnvironment() error {
	path := os.Getenv(ControlSocketEnv)
	if path == "" {
		return nil
	}
	path = filepath.Clean(path)
	controlRuntime.Lock()
	defer controlRuntime.Unlock()
	if controlRuntime.path == path {
		return nil
	}
	if controlRuntime.path != "" {
		return fmt.Errorf("connection control already listening on %s", controlRuntime.path)
	}
	listener, err := listenUnix(path)
	if err != nil {
		return err
	}
	server := newControlServer(Default)
	controlRuntime.path = path
	go func() {
		_ = server.Serve(listener)
	}()
	return nil
}

func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return listener, nil
}

func newControlServer(manager *Manager) *http.Server {
	startedAt := time.Now().UTC()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		writeControlJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": 3})
	})
	mux.HandleFunc("/v1/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		users, global, groups, err := manager.FullSnapshotReport()
		if err != nil {
			writeControlJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
			return
		}
		writeControlJSON(w, http.StatusOK, controlSnapshot{Version: 3, StartedAt: startedAt, Global: global, Inbounds: manager.ConfiguredInbounds(), Users: users, ManagementGroups: groups})
	})
	mux.HandleFunc("/v1/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		defer r.Body.Close()
		var config Config
		decoder := json.NewDecoder(io.LimitReader(r.Body, maxConfigBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			writeControlJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := manager.ReplaceConfig(config); err != nil {
			writeControlJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeControlJSON(w, http.StatusOK, map[string]any{"success": true})
	})
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       10 * time.Second,
	}
}

func writeControlJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
