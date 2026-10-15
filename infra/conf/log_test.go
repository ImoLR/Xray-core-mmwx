package conf

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/app/log"
	clog "github.com/xtls/xray-core/common/log"
)

func TestCustomAccessLogDefaults(t *testing.T) {
	for _, tt := range []struct {
		name, input, env, path string
		kind                   log.LogType
	}{
		{name: "absent", input: `{"loglevel":"error"}`, kind: log.LogType_None},
		{name: "empty", input: `{"access":"","loglevel":"error"}`, kind: log.LogType_None},
		{name: "console debug", input: `{"loglevel":"error"}`, env: "console", kind: log.LogType_Console},
		{name: "file debug", input: `{"loglevel":"error"}`, env: "/tmp/debug.log", path: "/tmp/debug.log", kind: log.LogType_File},
		{name: "explicit file", input: `{"access":"/tmp/access.log","loglevel":"error"}`, env: "console", path: "/tmp/access.log", kind: log.LogType_File},
		{name: "explicit none", input: `{"access":"none","loglevel":"error"}`, env: "console", kind: log.LogType_None},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MMWXC_CORE_ACCESS_LOG", tt.env)
			var input LogConfig
			if err := json.Unmarshal([]byte(tt.input), &input); err != nil {
				t.Fatal(err)
			}
			got := input.Build()
			if got.AccessLogType != tt.kind || got.AccessLogPath != tt.path {
				t.Fatalf("access: %v", got)
			}
			if got.ErrorLogType != log.LogType_Console || got.ErrorLogLevel != clog.Severity_Error {
				t.Fatalf("error behavior changed: %v", got)
			}
		})
	}
}

func TestCustomAccessLogWithoutLogSection(t *testing.T) {
	for _, env := range []string{"", "console", "/tmp/debug.log"} {
		t.Setenv("MMWXC_CORE_ACCESS_LOG", env)
		got := DefaultLogConfig()
		want := (&LogConfig{}).Build()
		if got.AccessLogType != want.AccessLogType || got.AccessLogPath != want.AccessLogPath || got.ErrorLogLevel != want.ErrorLogLevel {
			t.Fatalf("default mismatch: %v != %v", got, want)
		}
	}
}
