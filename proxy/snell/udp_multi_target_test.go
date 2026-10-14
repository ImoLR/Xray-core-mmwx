package snell

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// fullConeDispatcher 模拟直连出站的全锥行为:整个会话只建一条链路,写进来的数据报原样回显,
// 回包来源取数据报自己标的目标(b.UDP)—— 与直连出站按 b.UDP 各发各的、回包带真实来源一致。
// 数据报没标目标时,回显来源就是建链时的那个目标,也就是修复前「全被送到第一个目标」的样子。
type fullConeDispatcher struct{ dispatched chan xnet.Destination }

func (fullConeDispatcher) Type() interface{} { return nil }
func (fullConeDispatcher) Start() error      { return nil }
func (fullConeDispatcher) Close() error      { return nil }
func (fullConeDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return nil
}

func (d fullConeDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	d.dispatched <- dest
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	go func() {
		defer downW.Close()
		for {
			mb, err := upR.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				if b.UDP == nil {
					first := dest
					b.UDP = &first
				}
			}
			if err := downW.WriteMultiBuffer(mb); err != nil {
				return
			}
		}
	}()
	return &transport.Link{Reader: downR, Writer: upW}, nil
}

// 同一条 Snell UDP 会话发往多个目标:每个数据报都要到它自己的目标,回包来源也要是那个目标。
// 修复前所有数据报都被送到第一个目标(真机复现:发给 1.1.1.1 的 DNS 查询由 8.8.8.8 回答)。
func TestSnellUDPSessionReachesEveryTarget(t *testing.T) {
	disp := fullConeDispatcher{dispatched: make(chan xnet.Destination, 8)}
	srv := &Server{
		policyManager: policy.DefaultManager{},
		users:         []*protocol.MemoryUser{snellUser("u@x", "psk-udp", 4)},
		version:       4,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		ictx := session.ContextWithInbound(ctx, &session.Inbound{Source: xnet.DestinationFromAddr(c.RemoteAddr())})
		_ = srv.Process(ictx, xnet.Network_TCP, c, disp)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	w := newRecordWriter(conn, []byte("psk-udp"))
	var req bytes.Buffer
	if err := (request{command: commandUDP}).writeTo(&req); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}
	pw := &udpPacketWriter{writer: w}
	targets := []xnet.Destination{
		xnet.UDPDestination(xnet.ParseAddress("8.8.8.8"), 53),
		xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53),
		xnet.UDPDestination(xnet.ParseAddress("162.159.200.1"), 123),
		xnet.UDPDestination(xnet.ParseAddress("2001:4860:4860::8888"), 53),
	}
	for i, d := range targets {
		if err := pw.writePacket([]byte{byte('a' + i)}, d); err != nil {
			t.Fatal(err)
		}
	}

	r := newRecordReader(conn, []byte("psk-udp"))
	if err := readServerReply(r); err != nil {
		t.Fatal(err)
	}
	for i, want := range targets {
		rec, err := r.nextRecord()
		if err != nil {
			t.Fatalf("第 %d 个回包: %v", i+1, err)
		}
		src, payload, err := readUDPResponseAddress(rec)
		if err != nil {
			t.Fatal(err)
		}
		if string(payload) != string(rune('a'+i)) || src.NetAddr() != want.NetAddr() {
			t.Fatalf("第 %d 个数据报:回包来自 %s(内容 %q),应来自 %s", i+1, src.NetAddr(), payload, want.NetAddr())
		}
	}
	// 整个会话只建一条链路(路由按第一个目标定),这是 udp.Dispatcher 的既有行为,修复不改它
	if got := len(disp.dispatched); got != 1 {
		t.Fatalf("应只建 1 条链路,实际 %d", got)
	}
}
