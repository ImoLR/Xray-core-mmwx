package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
)

// 公网地址上的明文 VLESS / Trojan 出站:官方会拒绝整份配置,fork 只打警告照常加载。
// 面板的中转 / 路由出站会连到用户自己的明文 VLESS 落地,拒绝等于整台 xray 起不来。
func TestPlainOutboundOnPublicAddressStillBuilds(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"vless 简写", `{"protocol":"vless","tag":"relay-out-1","settings":{"address":"8.8.8.8","port":40000,"id":"27848739-7e62-4138-9fd3-098a63964b6b","encryption":"none"}}`},
		{"vless vnext", `{"protocol":"vless","tag":"routed-1","settings":{"vnext":[{"address":"example.com","port":40000,"users":[{"id":"27848739-7e62-4138-9fd3-098a63964b6b","encryption":"none"}]}]}}`},
		{"trojan", `{"protocol":"trojan","tag":"tj-1","settings":{"servers":[{"address":"8.8.8.8","port":443,"password":"p"}]}}`},
	} {
		var c OutboundDetourConfig
		if err := json.Unmarshal([]byte(tc.raw), &c); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if _, err := c.Build(); err != nil {
			t.Errorf("%s: 明文出站不该让配置加载失败,得到 %v", tc.name, err)
		}
	}
}
