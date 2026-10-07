package mieru

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/policy"
	"testing"
	"time"
)

// socks5 UDP ASSOCIATE(客户端声明的地址 0.0.0.0:0,mieru 里只是个占位)。
var socks5AssociateRequest = []byte{socks5Version, socks5CmdUDPAssociate, 0x00, socks5ATYPIPv4, 0, 0, 0, 0, 0, 0}

// socks5UDPPacket 拼一个 socks5 UDP 包:RSV RSV FRAG ATYP(IPv4) 地址 端口 数据。
func socks5UDPPacket(ip [4]byte, port uint16, data []byte) []byte {
	b := []byte{0, 0, 0, socks5ATYPIPv4}
	b = append(b, ip[:]...)
	b = binary.BigEndian.AppendUint16(b, port)
	return append(b, data...)
}

func TestSplitUDPFrames(t *testing.T) {
	a, b := []byte("first"), []byte("second packet")
	stream := append(encodeUDPFrame(a), encodeUDPFrame(b)...)
	// 截在第二帧中间:第一帧出来,第二帧留着等
	frames, rest, err := splitUDPFrames(stream[:len(stream)-3])
	if err != nil || len(frames) != 1 || !bytes.Equal(frames[0], a) || len(rest) != len(encodeUDPFrame(b))-3 {
		t.Fatalf("frames=%q rest=%d err=%v", frames, len(rest), err)
	}
	frames, rest, err = splitUDPFrames(append(rest, stream[len(stream)-3:]...))
	if err != nil || len(frames) != 1 || !bytes.Equal(frames[0], b) || len(rest) != 0 {
		t.Fatalf("frames=%q rest=%d err=%v", frames, len(rest), err)
	}
	bad := encodeUDPFrame(a)
	bad[len(bad)-1] = 0x00
	if _, _, err := splitUDPFrames(bad); err == nil {
		t.Fatal("尾标记不对应判错")
	}
}

// 端到端:真实走 Process,会话里发两个去不同目标的 UDP 包,回程逐个原样回来、带各自的源地址。
// echoDispatcher 把发出去的包原样当回包,所以回包的地址就是 payload.UDP(目标)。
func TestMieruUDPAssociateOverTCP(t *testing.T) {
	srv := &Server{policyManager: policy.DefaultManager{}, users: []*protocol.MemoryUser{mieruUser(t, "alice@x", "alice", "secret123")}}
	addr, stop := startMieruServer(t, srv)
	defer stop()

	ms, err := dialMieruWith(addr, "alice", "secret123", socks5AssociateRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()

	p1 := socks5UDPPacket([4]byte{8, 8, 8, 8}, 53, []byte("dns query"))
	p2 := socks5UDPPacket([4]byte{1, 1, 1, 1}, 443, []byte("quic initial"))
	if _, err := ms.Write(append(encodeUDPFrame(p1), encodeUDPFrame(p2)...)); err != nil {
		t.Fatal(err)
	}

	_ = ms.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got []byte
	var frames [][]byte
	buf := make([]byte, 4096)
	for len(frames) < 2 {
		n, err := ms.Read(buf)
		if err != nil {
			t.Fatalf("读回程: %v(已收到 %d 帧)", err, len(frames))
		}
		got = append(got, buf[:n]...)
		var fs [][]byte
		fs, got, err = splitUDPFrames(got)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, fs...)
	}
	if !bytes.Equal(frames[0], p1) || !bytes.Equal(frames[1], p2) {
		t.Fatalf("回包不对:\n got %x\n     %x\nwant %x\n     %x", frames[0], frames[1], p1, p2)
	}
}

// BIND 等不支持的命令:回 REP=7 并关会话,而不是让客户端挂到超时。
func TestMieruRejectsUnsupportedCommand(t *testing.T) {
	srv := &Server{policyManager: policy.DefaultManager{}, users: []*protocol.MemoryUser{mieruUser(t, "alice@x", "alice", "secret123")}}
	addr, stop := startMieruServer(t, srv)
	defer stop()

	bind := []byte{socks5Version, 0x02, 0x00, socks5ATYPIPv4, 1, 2, 3, 4, 0, 80}
	_, err := dialMieruWith(addr, "alice", "secret123", bind)
	if !errors.Is(err, errSocks5Rejected) {
		t.Fatalf("BIND 应被明确拒绝, got %v", err)
	}
	_ = io.EOF
}
