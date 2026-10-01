package anytls

// 新流分发被拒(限速的并发连接上限、禁令等)时,只结束这一条流,会话上其它流照常。

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

// rejectingDispatcher:目标端口在 reject 里的一律拒绝,错误文本同 agent 限速器(带 email);其余交给 holDispatcher。
type rejectingDispatcher struct {
	*holDispatcher
	reject map[xnet.Port]bool
}

func (d *rejectingDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	if d.reject[dest.Port] {
		return nil, errors.New("connection limit reached: alice@example")
	}
	return d.holDispatcher.Dispatch(ctx, dest)
}

// v2 客户端(sing-anytls / mihomo):被拒的流拿到带错误信息的 SYNACK + FIN,只关这一条;
// 客户端不等 SYNACK 就发出的首包被丢掉,不能当成新流地址去解析、把会话的帧读乱。
// 从前什么都不回,客户端 3 秒等不到 SYNACK 就把整条会话连同其它在跑的流一起关掉。
func TestRejectedStreamOnlyClosesThatStream(t *testing.T) {
	one, three := newGateWriter(), newGateWriter()
	one.release()
	three.release()
	oneLink, _ := gateLink(one)
	threeLink, _ := gateLink(three)
	disp := &rejectingDispatcher{
		holDispatcher: &holDispatcher{links: map[xnet.Port]*transport.Link{1001: oneLink, 1003: threeLink}},
		reject:        map[xnet.Port]bool{9999: true},
	}
	s, p, exited := startHOLSessionWith(t, disp, "v=2\nclient=mihomo/test\npadding-md5=00")

	p.sendAsync(
		holFrame(cmdSYN, 1, nil),
		holFrame(cmdPSH, 1, holAddr(t, "1.1.1.1:1001")),
		holFrame(cmdPSH, 1, []byte("one")),
	)
	if !p.expect(cmdSYNACK, 1, 2*time.Second) {
		t.Fatal("no SYNACK for stream 1")
	}

	// 首包模仿 TLS ClientHello 开头:0x16 不是合法的地址类型,被当成地址解析会报错并留下半帧。
	p.sendAsync(
		holFrame(cmdSYN, 2, nil),
		holFrame(cmdPSH, 2, holAddr(t, "1.1.1.1:9999")),
		holFrame(cmdPSH, 2, []byte{0x16, 0x03, 0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}),
	)
	ack, ok := p.next(cmdSYNACK, 2, 2*time.Second)
	if !ok {
		t.Fatal("rejected stream got no SYNACK: the client waits 3s and then closes the whole session")
	}
	if len(ack.data) == 0 {
		t.Fatal("SYNACK of a rejected stream must carry an error, otherwise the client treats the stream as open")
	}
	if bytes.Contains(ack.data, []byte("alice")) {
		t.Fatalf("dispatcher error text (with email) leaked to the client: %q", ack.data)
	}
	if !p.expect(cmdFIN, 2, 2*time.Second) {
		t.Fatal("rejected stream got no FIN")
	}

	p.sendAsync(
		holFrame(cmdSYN, 3, nil),
		holFrame(cmdPSH, 3, holAddr(t, "1.1.1.1:1003")),
		holFrame(cmdPSH, 3, []byte("three")),
		holFrame(cmdPSH, 1, []byte("more")),
	)
	ack3, ok := p.next(cmdSYNACK, 3, 2*time.Second)
	if !ok || len(ack3.data) != 0 {
		t.Fatalf("stream opened after a rejected one should get a plain SYNACK (ok=%v data=%q)", ok, ack3.data)
	}
	waitFor(t, 2*time.Second, "stream 3 uplink data", func() bool {
		d, _ := three.snapshot()
		return string(d) == "three"
	})
	waitFor(t, 2*time.Second, "stream 1 still carrying data", func() bool {
		d, _ := one.snapshot()
		return string(d) == "onemore"
	})

	s.streamsMu.Lock()
	_, left := s.streams[2]
	s.streamsMu.Unlock()
	if left {
		t.Fatal("rejected stream is still registered on the session")
	}
	select {
	case <-exited:
		t.Fatal("session closed because one stream was rejected")
	default:
	}
}

// v1 对端不认 SYNACK:带帧体的未知命令会把它的帧读乱,只能发 FIN。
func TestRejectedStreamV1PeerGetsOnlyFin(t *testing.T) {
	disp := &rejectingDispatcher{holDispatcher: &holDispatcher{}, reject: map[xnet.Port]bool{9999: true}}
	_, p, _ := startHOLSessionWith(t, disp, "client=mihomo/test\npadding-md5=00")

	p.sendAsync(
		holFrame(cmdSYN, 1, nil),
		holFrame(cmdPSH, 1, holAddr(t, "1.1.1.1:9999")),
	)
	deadline := time.After(2 * time.Second)
	for {
		select {
		case f, ok := <-p.rx:
			if !ok {
				t.Fatal("connection closed before the FIN of the rejected stream")
			}
			if f.sid != 1 {
				continue
			}
			if f.cmd == cmdSYNACK && len(f.data) > 0 {
				t.Fatalf("v1 peer got a SYNACK with a body: %q", f.data)
			}
			if f.cmd == cmdFIN {
				return
			}
		case <-deadline:
			t.Fatal("rejected stream got no FIN")
		}
	}
}

// UoT 流的 SYNACK 在读到 uot 请求之前就回了,分发被拒只能靠 FIN 告诉客户端,
// 否则客户端这条 UDP 一直往里发、收不到回应,直到它自己的空闲超时。
func TestRejectedUoTStreamGetsFin(t *testing.T) {
	disp := &rejectingDispatcher{holDispatcher: &holDispatcher{}, reject: map[xnet.Port]bool{9999: true}}
	_, p, exited := startHOLSessionWith(t, disp, "v=2\nclient=mihomo/test\npadding-md5=00")

	p.sendAsync(holUoTOpen(t, 1, "1.1.1.1:9999", 1)...)
	if !p.expect(cmdSYNACK, 1, 2*time.Second) {
		t.Fatal("no SYNACK for the UoT stream")
	}
	if !p.expect(cmdFIN, 1, 2*time.Second) {
		t.Fatal("rejected UoT stream got no FIN")
	}
	select {
	case <-exited:
		t.Fatal("session closed because one stream was rejected")
	default:
	}
}
