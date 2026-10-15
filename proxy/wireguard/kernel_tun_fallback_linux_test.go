package wireguard_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/wireguard"
)

// LXC / OpenVZ 容器里 root 有 CAP_NET_ADMIN,却没有 /dev/net/tun。合并上游后 WireGuard 设备在创建出站时就建,
// 选了内核 TUN 必然失败,整个 xray 起不来(用户实报:升级后带 WARP 出站的机器 xray 无法启动)。
// 没有设备节点时要判成不支持内核 TUN,走 gVisor,xray 照常启动。
func TestWireGuardOutboundWithoutTunDevice(t *testing.T) {
	defer wireguard.SetKernelTunDevicePathForTest("/nonexistent/dev/net/tun")()
	if ok, _ := wireguard.KernelTunSupported(); ok {
		t.Fatal("没有 /dev/net/tun 时不应判成支持内核 TUN")
	}
	cfgJSON := `{
		"log": {"loglevel": "none"},
		"outbounds": [{
			"tag": "warp-v4", "protocol": "wireguard",
			"settings": {
				"secretKey": "kHT7xVqU8C6jbmDUd8m6wqFzNt4P0q8F1QUo2CGk8Fo=",
				"address": ["172.16.0.2/32"],
				"peers": [{"publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "endpoint": "127.0.0.1:2408"}],
				"mtu": 1420, "noKernelTun": false
			}
		}]
	}`
	config, err := serial.LoadJSONConfig(bytes.NewBufferString(cfgJSON))
	if err != nil {
		t.Fatalf("加载配置: %v", err)
	}
	inst, err := core.New(config)
	if err != nil {
		t.Fatalf("没有 /dev/net/tun 时 WireGuard 出站应退回 gVisor,xray 照常创建: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	_ = inst.Close()
}
