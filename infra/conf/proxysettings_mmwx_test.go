package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	. "github.com/xtls/xray-core/infra/conf"
)

// 出站的 "proxySettings" 官方已移除(整份配置拒绝加载),fork 换成 sockopt.dialerProxy 照常加载。
// 用户以前手写 / 老版本留下的链式出站(warp-out 等)在 agent 升级后不能让整台 xray 起不来。
func TestOutboundProxySettingsMigratesToDialerProxy(t *testing.T) {
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"只有 proxySettings", `{"protocol":"freedom","tag":"warp-out","proxySettings":{"tag":"warp"}}`, "warp"},
		{"带 transportLayer", `{"protocol":"freedom","tag":"a","proxySettings":{"tag":"b","transportLayer":true},"streamSettings":{"network":"tcp"}}`, "b"},
		{"两个都写且一致", `{"protocol":"freedom","tag":"a","proxySettings":{"tag":"b"},"streamSettings":{"sockopt":{"dialerProxy":"b"}}}`, "b"},
		{"冲突时以 dialerProxy 为准", `{"protocol":"freedom","tag":"a","proxySettings":{"tag":"b"},"streamSettings":{"sockopt":{"dialerProxy":"c"}}}`, "c"},
		{"空 tag 忽略", `{"protocol":"freedom","tag":"a","proxySettings":{}}`, ""},
	} {
		var c OutboundDetourConfig
		if err := json.Unmarshal([]byte(tc.raw), &c); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		out, err := c.Build()
		if err != nil {
			t.Fatalf("%s: proxySettings 不该让配置加载失败,得到 %v", tc.name, err)
		}
		inst, err := out.SenderSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		got := inst.(*proxyman.SenderConfig).GetStreamSettings().GetSocketSettings().GetDialerProxy()
		if got != tc.want {
			t.Errorf("%s: dialerProxy = %q, 期望 %q", tc.name, got, tc.want)
		}
	}
}
