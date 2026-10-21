package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	sessionctx "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// 下行计费:inbound worker 把连接包成 stat.CounterConnection,入站的 downlink 统计就是它的
// WriteCounter。从前会话写用 buf.NewWriter(conn),它把计数连接拆掉、BufferedWriter 刷新时直接写
// 裸连接,结果 AnyTLS 用户下载多少都记 0(面板只计上行)。这里走真实 Process:服务端写给客户端的
// 每个字节都必须记进 WriteCounter。
func TestProcessCountsDownlinkOnInboundCounter(t *testing.T) {
	const password = "downlinkCounterPassword24"
	user := &protocol.MemoryUser{Email: "flvxl-41", Account: &MemoryAccount{Password: password}}
	sum := sha256.Sum256([]byte(password))
	srv := &Server{
		policyManager: policy.DefaultManager{},
		users:         map[[32]byte]*protocol.MemoryUser{sum: user},
		usersByEmail:  map[string]*protocol.MemoryUser{user.Email: user},
	}

	const payload = 256 << 10
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	go func() {
		chunk := make([]byte, 8<<10)
		for sent := 0; sent < payload; sent += len(chunk) {
			b := buf.New()
			b.Write(chunk)
			if err := downW.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				return
			}
		}
		downW.Close()
	}()
	disp := &holDispatcher{links: map[xnet.Port]*transport.Link{443: {Reader: downR, Writer: nopWriter{}}}}

	// 真 TCP 连接:net.Pipe 不实现 syscall.Conn,buf.NewWriter 会把它当包连接走 SequentialWriter,
	// 恰好绕开这个 bug;线上的 TCP / TLS 连接走的是 BufferToBytesWriter。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sc, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer sc.Close()
	up, down := new(stats.Counter), new(stats.Counter)
	conn := &stat.CounterConnection{Connection: sc, ReadCounter: up, WriteCounter: down}
	ctx := sessionctx.ContextWithContent(sessionctx.ContextWithOutbounds(sessionctx.ContextWithInbound(context.Background(),
		&sessionctx.Inbound{Source: xnet.TCPDestination(xnet.ParseAddress("203.0.113.9"), 40000)}),
		[]*sessionctx.Outbound{{}}), &sessionctx.Content{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		_ = srv.Process(ctx, xnet.Network_TCP, conn, disp)
	}()

	// 客户端:鉴权头(sha256(password) + 0 填充),settings,开一条到 :443 的流。
	var auth [34]byte
	copy(auth[:32], sum[:])
	binary.BigEndian.PutUint16(auth[32:], 0)
	p := &holPeer{conn: cc, rx: make(chan rxFrame, 1024)}
	received := 0
	go func() {
		defer close(p.rx)
		var h [7]byte
		for {
			if _, err := io.ReadFull(cc, h[:]); err != nil {
				return
			}
			data := make([]byte, binary.BigEndian.Uint16(h[5:7]))
			if _, err := io.ReadFull(cc, data); err != nil {
				return
			}
			received += len(h) + len(data)
			p.rx <- rxFrame{cmd: h[0], sid: binary.BigEndian.Uint32(h[1:5]), data: data}
		}
	}()
	p.sendAsync(auth[:], holFrame(cmdSettings, 0, []byte("v=2\nclient=mihomo/test\npadding-md5=00")))
	if !p.expect(cmdServerSettings, 0, 2*time.Second) {
		t.Fatal("no ServerSettings after client settings")
	}
	p.sendAsync(holFrame(cmdSYN, 1, nil), holFrame(cmdPSH, 1, holAddr(t, "198.51.100.7:443")))

	got := 0
	deadline := time.After(5 * time.Second)
	for got < payload {
		select {
		case f, ok := <-p.rx:
			if !ok {
				t.Fatalf("connection closed after %d of %d downlink bytes", got, payload)
			}
			if f.cmd == cmdPSH && f.sid == 1 {
				got += len(f.data)
			}
		case <-deadline:
			t.Fatalf("timed out after %d of %d downlink bytes", got, payload)
		}
	}
	if !p.expect(cmdFIN, 1, 2*time.Second) {
		t.Fatal("no FIN after the downlink ended")
	}
	cc.Close()
	for range p.rx { // 读 goroutine 退出后 received 才稳定
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("Process did not return after the client closed the connection")
	}

	if down.Value() < payload {
		t.Fatalf("downlink counter %d < %d payload bytes delivered: AnyTLS downloads are not billed", down.Value(), payload)
	}
	if down.Value() != int64(received) {
		t.Fatalf("downlink counter %d != %d bytes the client received", down.Value(), received)
	}
	if up.Value() == 0 {
		t.Fatal("uplink counter stayed 0")
	}
}
