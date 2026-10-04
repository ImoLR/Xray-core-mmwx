// udp_associate.go:mieru 会话里的 socks5 UDP ASSOCIATE。依据 docs/protocol.md「UDP Associate Encapsulation」。
//
// 客户端发 socks5 UDP ASSOCIATE 开会话,之后会话里的字节流是一串封装好的 socks5 UDP 包:
//
//	| 0x00 | 长度(2,大端) | socks5 UDP 包(RSV(2) FRAG(1) ATYP 地址 端口 数据) | 0xff |
//
// 回程同样封装。这里把它做成一个 transport.Link:会话层(TCP 的 serverSession / UDP 的 ARQ 会话)
// 照旧把客户端字节写进 Link.Writer、从 Link.Reader 读回程字节,完全不用知道这是 UDP。
// 中间由 xray 自己的 udp.Dispatcher 转发,和 socks 入站的 UDP 走同一条路,统计 / 限速照常按用户生效。
package mieru

import (
	"context"
	"encoding/binary"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
)

const (
	udpFrameHead = 0x00
	udpFrameTail = 0xff
	// maxUDPAssocBuffered 客户端字节流里攒着解不出完整帧的上限:一帧最长 3+65535+1。
	maxUDPAssocBuffered = 3 + 65535 + 1
	// udpAssocDownlinkLimit 回程管道上限。客户端读得慢时宁可丢包(UDP 语义),也不能把内存吃干。
	udpAssocDownlinkLimit = 512 * 1024
)

// socks5ReplyCommandNotSupported:REP=7(command not supported)。BIND 等不支持的命令用它拒绝。
var socks5ReplyCommandNotSupported = []byte{socks5Version, 0x07, 0x00, socks5ATYPIPv4, 0, 0, 0, 0, 0, 0}

// newUDPAssociateLink 建一条 UDP ASSOCIATE 会话的 Link。ctx 必须已带认证用户的 Inbound(统计归属)。
// Link 被 Interrupt / Close 后,内部 goroutine 自行退出并释放 udp.Dispatcher。
func newUDPAssociateLink(ctx context.Context, dispatcher routing.Dispatcher) *transport.Link {
	upReader, upWriter := pipe.New(pipe.WithoutSizeLimit())
	downReader, downWriter := pipe.New(pipe.WithSizeLimit(udpAssocDownlinkLimit), pipe.DiscardOverflow())
	a := &udpAssociation{down: downWriter}
	a.udp = udp.NewDispatcher(dispatcher, a.onResponse)
	go a.run(ctx, upReader)
	return &transport.Link{Reader: downReader, Writer: upWriter}
}

type udpAssociation struct {
	udp  *udp.Dispatcher
	down *pipe.Writer
	// first 是第一个包的目标:udp.Dispatcher 一个关联只开一条出站(full-cone),
	// 每个包的真实目标放在 payload.UDP 里,与 socks 入站的 cone 模式一致。
	first *xnet.Destination
}

// run 从客户端字节流里切帧、解 socks5 UDP 头、经 udp.Dispatcher 发出去。
func (a *udpAssociation) run(ctx context.Context, up *pipe.Reader) {
	defer func() {
		a.udp.RemoveRay()
		_ = a.down.Close()
	}()
	var pending []byte
	for {
		mb, err := up.ReadMultiBuffer()
		if err != nil {
			return
		}
		for _, b := range mb {
			pending = append(pending, b.Bytes()...)
		}
		buf.ReleaseMulti(mb)

		frames, rest, ferr := splitUDPFrames(pending)
		if ferr != nil {
			errors.LogInfoInner(ctx, ferr, "mieru: bad UDP associate stream")
			return
		}
		pending = append(pending[:0], rest...)
		if len(pending) > maxUDPAssocBuffered {
			return
		}
		for _, f := range frames {
			a.send(ctx, f)
		}
	}
}

// send 解一个 socks5 UDP 包并发往目标。解不出来的包丢掉(UDP 语义),不影响整条关联。
func (a *udpAssociation) send(ctx context.Context, frame []byte) {
	payload := buf.New()
	if _, err := payload.Write(frame); err != nil {
		payload.Release()
		return // 超过单个 buffer 的包:丢
	}
	request, err := socks.DecodeUDPPacket(payload)
	if err != nil || payload.IsEmpty() {
		payload.Release()
		return
	}
	dest := request.Destination()
	payload.UDP = &dest
	if a.first == nil {
		a.first = &dest
	}
	// 与 socks 入站一致:访问日志按包的真实目标记(udp.Dispatcher 只在建出站时用 ctx)
	a.udp.Dispatch(accessLogCtx(ctx, dest), *a.first, payload)
}

// onResponse 把目标的回包封成 socks5 UDP 包 + 帧,写进回程管道。
func (a *udpAssociation) onResponse(ctx context.Context, packet *udp_proto.Packet) {
	payload := packet.Payload
	defer payload.Release()
	from := packet.Source
	if payload.UDP != nil {
		from = *payload.UDP
	}
	msg, err := socks.EncodeUDPPacket(&protocol.RequestHeader{Address: from.Address, Port: from.Port}, payload.Bytes())
	if err != nil {
		return
	}
	defer msg.Release()
	if msg.IsEmpty() {
		return // 太大装不下,EncodeUDPPacket 已丢
	}
	_ = a.down.WriteMultiBuffer(bytesToMultiBuffer(encodeUDPFrame(msg.Bytes())))
}

// encodeUDPFrame 套上 0x00 | 长度 | ... | 0xff。
func encodeUDPFrame(data []byte) []byte {
	out := make([]byte, 0, 3+len(data)+1)
	out = append(out, udpFrameHead)
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	out = append(out, data...)
	return append(out, udpFrameTail)
}

// splitUDPFrames 从字节流里切出完整帧,返回帧内容与剩下不完整的尾巴。标记不对即流已错乱,返回错误。
func splitUDPFrames(b []byte) (frames [][]byte, rest []byte, err error) {
	for {
		if len(b) < 3 {
			return frames, b, nil
		}
		if b[0] != udpFrameHead {
			return nil, nil, errors.New("mieru: bad UDP frame head ", int(b[0]))
		}
		n := int(binary.BigEndian.Uint16(b[1:3]))
		if len(b) < 3+n+1 {
			return frames, b, nil
		}
		if b[3+n] != udpFrameTail {
			return nil, nil, errors.New("mieru: bad UDP frame tail ", int(b[3+n]))
		}
		frames = append(frames, append([]byte(nil), b[3:3+n]...))
		b = b[3+n+1:]
	}
}
