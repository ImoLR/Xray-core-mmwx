package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

// 主控下发的 SS 入站 settings 顶层 obfsMode/obfsHost(simple-obfs),三种服务端配置都要带上。
func TestShadowsocksServerObfsConfig(t *testing.T) {
	build := func(raw string) (interface{}, error) {
		var c ShadowsocksServerConfig
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatal(err)
		}
		return c.Build()
	}
	msg, err := build(`{"method":"aes-128-gcm","password":"p","obfsMode":"tls","obfsHost":"bing.com","obfsPath":"/x"}`)
	if err != nil {
		t.Fatal(err)
	}
	if c := msg.(*shadowsocks.ServerConfig); c.ObfsMode != "tls" || c.ObfsHost != "bing.com" {
		t.Fatalf("legacy SS 应带上混淆: %+v", c)
	}
	msg, err = build(`{"method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA==","obfsMode":"http","obfsHost":"a.com"}`)
	if err != nil {
		t.Fatal(err)
	}
	if c := msg.(*shadowsocks_2022.ServerConfig); c.ObfsMode != "http" || c.ObfsHost != "a.com" {
		t.Fatalf("SS-2022 单用户应带上混淆: %+v", c)
	}
	msg, err = build(`{"method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA==","obfsMode":"tls","obfsHost":"b.com","clients":[{"password":"AAAAAAAAAAAAAAAAAAAAAA==","email":"u"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if c := msg.(*shadowsocks_2022.MultiUserServerConfig); c.ObfsMode != "tls" || c.ObfsHost != "b.com" {
		t.Fatalf("SS-2022 多用户应带上混淆: %+v", c)
	}
	if _, err := build(`{"method":"aes-128-gcm","password":"p","obfsMode":"websocket"}`); err == nil || !strings.Contains(err.Error(), "obfsMode") {
		t.Fatalf("不认识的混淆模式应拒绝,得到 %v", err)
	}
	if _, err := build(`{"method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA==","obfsMode":"tls","clients":[{"password":"AAAAAAAAAAAAAAAAAAAAAA==","address":"1.1.1.1","port":443}]}`); err == nil {
		t.Fatal("relay 模式不支持混淆,应拒绝")
	}
}
