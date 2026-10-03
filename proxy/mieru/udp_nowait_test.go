package mieru

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// recordingDispatcher 记下被拨的目标,并把会话写进来的上行数据收集起来。
type recordingDispatcher struct {
	mu    sync.Mutex
	dests []net.Destination
	up    *pipe.Reader
}

func (d *recordingDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *recordingDispatcher) Start() error      { return nil }
func (d *recordingDispatcher) Close() error      { return nil }
func (d *recordingDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

func (d *recordingDispatcher) Dispatch(_ context.Context, dest net.Destination) (*transport.Link, error) {
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, _ := pipe.New(pipe.WithoutSizeLimit())
	d.mu.Lock()
	d.dests = append(d.dests, dest)
	d.up = upR
	d.mu.Unlock()
	return &transport.Link{Reader: downR, Writer: upW}, nil
}

func (d *recordingDispatcher) snapshot() ([]net.Destination, *pipe.Reader) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]net.Destination(nil), d.dests...), d.up
}

// #1078(与 #673 同源,TCP 路径已在 9b5bc50d 修过,UDP 路径漏了):
// NO_WAIT 客户端没有应用数据时先发空 openSessionRequest。UDP underlay 上官方客户端要等
// openSessionResponse 才会把装着 socks5 CONNECT + 首包的 data 段发出来(mihomo 实测:
// 空 open 之后一直憋着 seq 1/2 不发,直到超时)。所以服务端必须先回响应、再等 socks5。
// 以前 UDP 会话把空 open 判成失败当场关掉,HTTPS(含 mihomo 默认延迟测试)全部超时。
func TestUDPSessionNoWaitOpenWaitsForSocks5(t *testing.T) {
	key, _ := deriveKey(hashPassword("alice", "secret123"), timeSalt(1784817120))
	aead, _ := newAEAD(key)
	disp := &recordingDispatcher{}
	var sentMu sync.Mutex
	var sent []*segment
	writePkt := func(pkt []byte) error {
		seg, err := decodeUDPSegment(pkt, aead)
		if err != nil {
			t.Errorf("服务端发出的包解不开: %v", err)
			return nil
		}
		sentMu.Lock()
		sent = append(sent, seg)
		sentMu.Unlock()
		return nil
	}
	sentTypes := func() []uint8 {
		sentMu.Lock()
		defer sentMu.Unlock()
		out := make([]uint8, 0, len(sent))
		for _, s := range sent {
			out = append(out, s.protocolType)
		}
		return out
	}
	hasType := func(want uint8) bool {
		for _, p := range sentTypes() {
			if p == want {
				return true
			}
		}
		return false
	}

	user := &protocol.MemoryUser{Email: "alice"}
	us := newUDPServerSession(context.Background(), 7, user, "alice", aead, writePkt, nil, disp)
	defer us.shutdown()
	go us.consume()

	// ① 空 openSessionRequest(NO_WAIT):还没有 socks5,就得先回 openSessionResponse
	us.arq.onSegment(&segment{protocolType: protoOpenSessionRequest, sessionID: 7, seq: 0})
	for deadline := time.Now().Add(2 * time.Second); !hasType(protoOpenSessionResponse); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("收到空 open 后没回 openSessionResponse(已发 %v)—— UDP 上客户端会一直憋着 socks5 不发", sentTypes())
		}
	}
	// ② data 段:socks5 CONNECT 1.2.3.4:443 被拆成两段送来 + 首包数据
	connect := []byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPIPv4, 1, 2, 3, 4, 0x01, 0xbb}
	us.arq.onSegment(&segment{protocolType: protoDataClientToServer, sessionID: 7, seq: 1, payload: connect[:4]})
	us.arq.onSegment(&segment{protocolType: protoDataClientToServer, sessionID: 7, seq: 2, payload: append(append([]byte(nil), connect[4:]...), []byte("hello")...)})

	deadline := time.Now().Add(2 * time.Second)
	for {
		dests, up := disp.snapshot()
		if len(dests) == 1 && up != nil {
			if dests[0].Port != 443 || dests[0].Address.String() != "1.2.3.4" {
				t.Fatalf("拨号目标 = %v, want 1.2.3.4:443", dests[0])
			}
			mb, err := up.ReadMultiBufferTimeout(2 * time.Second)
			if err != nil {
				t.Fatalf("没收到首包数据: %v", err)
			}
			if got := string(mbToBytes(mb)); got != "hello" {
				t.Fatalf("首包数据 = %q, want hello", got)
			}
			break
		}
		select {
		case <-us.ctx.Done():
			t.Fatal("空 openSessionRequest 之后会话被关掉了 —— NO_WAIT 客户端在 UDP 上永远连不上")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("2 秒内没有拨号,dests=%v", dests)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// openSessionResponse 只能回一次;socks5 成功回复作为 data 段跟在后面
	for deadline := time.Now().Add(2 * time.Second); !hasType(protoDataServerToClient); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("没回 socks5 成功回复(已发 %v)", sentTypes())
		}
	}
	n := 0
	for _, p := range sentTypes() {
		if p == protoOpenSessionResponse {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("openSessionResponse 发了 %d 次,应为 1", n)
	}
}

// 不是 socks5 的垃圾数据照样要关会话,不能无限攒。
func TestUDPSessionRejectsNonSocks5(t *testing.T) {
	key, _ := deriveKey(hashPassword("alice", "secret123"), timeSalt(1784817120))
	aead, _ := newAEAD(key)
	disp := &recordingDispatcher{}
	us := newUDPServerSession(context.Background(), 8, &protocol.MemoryUser{Email: "alice"}, "alice", aead, func([]byte) error { return nil }, nil, disp)
	go us.consume()
	us.arq.onSegment(&segment{protocolType: protoOpenSessionRequest, sessionID: 8, seq: 0, payload: []byte{0x47, 0x45, 0x54, 0x20}})
	select {
	case <-us.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("非 socks5 的 open 应当关掉会话")
	}
	if dests, _ := disp.snapshot(); len(dests) != 0 {
		t.Fatalf("不该拨号: %v", dests)
	}
}
