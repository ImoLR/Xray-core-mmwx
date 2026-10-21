package scenarios

import (
	"encoding/base64"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	transtcp "github.com/xtls/xray-core/transport/internet/tcp"
)

// mmwx:third_party/reality 的补丁(MMWX_PATCH.md)要让不带 X25519MLKEM768 的 Client Hello 也能通过 REALITY 认证 ——
// mihomo 系客户端(Clash Verge、FlClash、MeowX Android / Windows)默认就是这样。官方 reality 从 20260908 起拒绝它们。
// iOS 14 / Edge 85 这两个 uTLS 预设只带 X25519,用来模拟(Android OkHttp 预设在补丁前后、reality 新旧两版下都连不上,与此无关,不放进来);同时开 XTLS Vision(2026-10-14 曾在
// REALITY + Vision 上 SIGSEGV)。去掉补丁这里应当失败。
func TestVlessRealityVisionClientWithoutMLKEM(t *testing.T) {
	TestFingerprint := func(fingerprint string) error {
		tcpServer := tcp.Server{
			MsgProcessor: xor,
		}
		dest, err := tcpServer.Start()
		common.Must(err)
		defer tcpServer.Close()

		userID := protocol.NewID(uuid.New())
		serverPort := tcp.PickPort()
		privateKey, _ := base64.RawURLEncoding.DecodeString("aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks")
		publicKey, _ := base64.RawURLEncoding.DecodeString("E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM")
		shortIds := make([][]byte, 1)
		shortIds[0] = make([]byte, 8)
		hex.Decode(shortIds[0], []byte("0123456789abcdef"))
		serverConfig := &core.Config{
			App: []*serial.TypedMessage{
				serial.ToTypedMessage(&log.Config{
					ErrorLogType: log.LogType_None,
				}),
			},
			Inbound: []*core.InboundHandlerConfig{
				{
					ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
						PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
						Listen:   net.NewIPOrDomain(net.LocalHostIP),
						StreamSettings: &internet.StreamConfig{
							ProtocolName: "tcp",
							SecurityType: serial.GetMessageType(&reality.Config{}),
							SecuritySettings: []*serial.TypedMessage{
								serial.ToTypedMessage(&reality.Config{
									Show:        false,
									Dest:        "www.google.com:443", // use google for now, may fail in some region
									ServerNames: []string{"www.google.com"},
									PrivateKey:  privateKey,
									ShortIds:    shortIds,
									Type:        "tcp",
								}),
							},
						},
					}),
					ProxySettings: serial.ToTypedMessage(&inbound.Config{
						Users: []*protocol.User{
							{
								Account: serial.ToTypedMessage(&vless.Account{
									Id:   userID.String(),
									Flow: vless.XRV,
								}),
							},
						},
					}),
				},
			},
			Outbound: []*core.OutboundHandlerConfig{
				{
					ProxySettings: serial.ToTypedMessage(&freedom.Config{
						FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
					}),
				},
			},
		}

		clientPort := tcp.PickPort()
		clientConfig := &core.Config{
			App: []*serial.TypedMessage{
				serial.ToTypedMessage(&log.Config{
					ErrorLogType: log.LogType_None,
				}),
			},
			Inbound: []*core.InboundHandlerConfig{
				{
					ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
						PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
						Listen:   net.NewIPOrDomain(net.LocalHostIP),
					}),
					ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
						RewriteAddress:  net.NewIPOrDomain(dest.Address),
						RewritePort:     uint32(dest.Port),
						AllowedNetworks: []net.Network{net.Network_TCP},
					}),
				},
			},
			Outbound: []*core.OutboundHandlerConfig{
				{
					ProxySettings: serial.ToTypedMessage(&outbound.Config{
						Vnext: &protocol.ServerEndpoint{
							Address: net.NewIPOrDomain(net.LocalHostIP),
							Port:    uint32(serverPort),
							User: &protocol.User{
								Account: serial.ToTypedMessage(&vless.Account{
									Id:   userID.String(),
									Flow: vless.XRV,
								}),
							},
						},
					}),
					SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
						StreamSettings: &internet.StreamConfig{
							ProtocolName: "tcp",
							TransportSettings: []*internet.TransportConfig{
								{
									ProtocolName: "tcp",
									Settings:     serial.ToTypedMessage(&transtcp.Config{}),
								},
							},
							SecurityType: serial.GetMessageType(&reality.Config{}),
							SecuritySettings: []*serial.TypedMessage{
								serial.ToTypedMessage(&reality.Config{
									Show:        false,
									Fingerprint: fingerprint,
									ServerName:  "www.google.com",
									PublicKey:   publicKey,
									ShortId:     shortIds[0],
									SpiderX:     "/",
								}),
							},
						},
					}),
				},
			},
		}

		servers, err := InitializeServerConfigs(serverConfig, clientConfig)
		common.Must(err)
		defer CloseAllServers(servers)

		err = testTCPConn(clientPort, 1024*1024, time.Second*15)()
		if err != nil {
			return err
		}
		return nil
	}
	fingerPrints := []string{"ios", "edge"}
	wg := sync.WaitGroup{}
	wg.Add(len(fingerPrints))
	for _, fp := range fingerPrints {
		go func() {
			err := TestFingerprint(fp)
			if err != nil {
				t.Errorf("Fingerprint %s test failed: %v", fp, err)
			} else {
				t.Logf("Fingerprint %s test passed", fp)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
