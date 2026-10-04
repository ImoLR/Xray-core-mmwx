// server_udp.go:mieru UDP underlay 入站。xray proxyman 的 udpWorker 已按客户端源地址解复用,
// 每个客户端一次 Process(Network_UDP, conn);conn.ReadMultiBuffer 保留数据报边界(每 buffer=一个 UDP 包=一个段),
// conn.Write 发一个数据报。这里在此之上:定位用户 → 按 sessionID 解复用到 per-session ARQ(arq.go)→
// 会话逻辑(socks5+dispatch+relay,与 TCP 同)。可靠性由 ARQ 提供。
package mieru

import (
	"context"
	"crypto/cipher"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// resolveUDPUser 用首包(nonce 末 4 字节 userTag + 3 timeSalt 试解)定位用户,返回派生 AEAD。
func (s *Server) resolveUDPUser(firstPkt []byte) (*protocol.MemoryUser, cipher.AEAD, error) {
	if len(firstPkt) < nonceLen {
		return nil, nil, errors.New("mieru udp: short first packet")
	}
	nonce := firstPkt[:nonceLen]
	salts := candidateRoundedTimes(time.Now().Unix())
	tryUser := func(u *protocol.MemoryUser) cipher.AEAD {
		acc := u.Account.(*MemoryAccount)
		for _, r := range salts {
			aead, aerr := cachedAEAD(acc.hashedPassword, r)
			if aerr != nil {
				continue
			}
			if _, derr := decodeUDPSegment(firstPkt, aead); derr == nil {
				return aead
			}
		}
		return nil
	}
	users := s.snapshotUsers()
	for _, u := range users {
		if nonceMatchesUser(u.Account.(*MemoryAccount).Username, nonce) {
			if aead := tryUser(u); aead != nil {
				return u, aead, nil
			}
		}
	}
	for _, u := range users {
		if aead := tryUser(u); aead != nil {
			return u, aead, nil
		}
	}
	return nil, nil, errors.New("mieru udp: no user matched")
}

func (s *Server) processUDP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// udpWorker 给的 udpConn 实现 buf.Reader,且 Read([]byte) 会 panic → 必须走 ReadMultiBuffer(每 buffer=一个 UDP 包)。
	reader, ok := conn.(buf.Reader)
	if !ok {
		return errors.New("mieru udp: connection is not a buf.Reader")
	}
	firstMB, err := reader.ReadMultiBuffer()
	if err != nil {
		return nil
	}
	pkts := splitPackets(firstMB)
	if len(pkts) == 0 {
		return nil
	}
	user, aead, uerr := s.resolveUDPUser(pkts[0])
	if uerr != nil {
		return errors.New("mieru udp: handshake").Base(uerr)
	}
	username := user.Account.(*MemoryAccount).Username

	var writeMu sync.Mutex
	writePkt := func(pkt []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_, e := conn.Write(pkt)
		return e
	}

	base := session.InboundFromContext(ctx)
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	var mu sync.Mutex
	// 会话结束后换成 nil 墓碑:释放 ARQ 等状态,又能认出同一 sessionID 迟到的重传包
	// (尤其是重传的 openSessionRequest,不能再拨一次落地)。从前结束的会话一直留在表里,
	// 一个长期复用的 UDP 连接上会话越积越多。
	sessions := make(map[uint32]*udpServerSession)
	defer func() {
		mu.Lock()
		live := make([]*udpServerSession, 0, len(sessions))
		for _, us := range sessions {
			if us != nil {
				live = append(live, us)
			}
		}
		mu.Unlock()
		for _, us := range live {
			us.shutdown()
		}
	}()

	hashedPassword := user.Account.(*MemoryAccount).hashedPassword
	handle := func(pkt []byte) {
		seg, derr := decodeUDPSegment(pkt, aead)
		if derr != nil {
			// UDP 底层连接可以活很久,timeSalt 每 2 分钟换一档:客户端换了档,后面的包用当前
			// AEAD 就解不开了。只在解不开时试一下其余两档,能解就换过去;真是坏包照旧丢掉。
			next, nseg := retryUDPKey(pkt, hashedPassword, aead)
			if next == nil {
				return
			}
			aead, seg = next, nseg
		}
		mu.Lock()
		us, seen := sessions[seg.sessionID]
		if !seen && seg.protocolType == protoOpenSessionRequest && s.replayed(pkt[:nonceLen]) {
			mu.Unlock()
			return // 原样重放的开会话包:不再替它拨落地
		}
		if !seen && seg.protocolType == protoOpenSessionRequest {
			us = newUDPServerSession(connCtx, seg.sessionID, user, username, aead, writePkt, base, dispatcher)
			id, self := seg.sessionID, us
			us.onShutdown = func() {
				mu.Lock()
				if sessions[id] == self {
					sessions[id] = nil
				}
				mu.Unlock()
			}
			sessions[seg.sessionID] = us
			go us.consume()
		}
		mu.Unlock()
		if us != nil {
			us.arq.onSegment(seg)
		}
	}

	for _, p := range pkts {
		handle(p)
	}
	for {
		mb, rerr := reader.ReadMultiBuffer()
		if rerr != nil {
			return nil
		}
		for _, p := range splitPackets(mb) {
			handle(p)
		}
	}
}

// retryUDPKey 用当前 ±2 分钟的三个 timeSalt 重新试解,跳过已经失败的那个 AEAD。
func retryUDPKey(pkt, hashedPassword []byte, failed cipher.AEAD) (cipher.AEAD, *segment) {
	for _, r := range candidateRoundedTimes(time.Now().Unix()) {
		a, err := cachedAEAD(hashedPassword, r)
		if err != nil || a == failed {
			continue
		}
		if seg, derr := decodeUDPSegment(pkt, a); derr == nil {
			return a, seg
		}
	}
	return nil, nil
}

// splitPackets 把一次 ReadMultiBuffer 的每个 buffer 取成独立字节切片(每 buffer=一个 UDP 包)。
func splitPackets(mb buf.MultiBuffer) [][]byte {
	var out [][]byte
	for _, b := range mb {
		if b.Len() > 0 {
			cp := make([]byte, b.Len())
			copy(cp, b.Bytes())
			out = append(out, cp)
		}
	}
	buf.ReleaseMulti(mb)
	return out
}

// udpServerSession 是 UDP underlay 上的一条会话。可靠性由 arq 提供,业务逻辑与 TCP 同。
type udpServerSession struct {
	id         uint32
	arq        *arqSession
	ctx        context.Context
	cancel     context.CancelFunc
	base       *session.Inbound
	user       *protocol.MemoryUser
	dispatcher routing.Dispatcher
	link       *transport.Link
	closeOnce  sync.Once
	onShutdown func()

	// socks5 请求还没到齐时攒在这里(NO_WAIT 客户端的 openSessionRequest 是空的,
	// 目标地址在随后的 data 段里)。与 TCP 路径(server.go 的 pendingOpen)同一套处理。
	awaitingOpen  bool
	pendingOpen   []byte
	openResponded bool // openSessionResponse 已经提前回过
}

func newUDPServerSession(ctx context.Context, id uint32, user *protocol.MemoryUser, username string,
	aead cipher.AEAD, writePkt func([]byte) error, base *session.Inbound, dispatcher routing.Dispatcher) *udpServerSession {
	sctx, cancel := context.WithCancel(ctx)
	us := &udpServerSession{
		id: id, ctx: sctx, cancel: cancel, base: base, user: user, dispatcher: dispatcher,
	}
	us.arq = newARQSession(id, username, aead, writePkt)
	return us
}

// consume 按 ARQ 有序交付处理会话流:首段=openSessionRequest(socks5+初始数据),后续=数据/关闭。
func (us *udpServerSession) consume() {
	for {
		var seg *segment
		select {
		case seg = <-us.arq.delivered:
		case <-us.ctx.Done():
			return
		case <-us.arq.closed:
			return
		}
		switch seg.protocolType {
		case protoOpenSessionRequest:
			if us.link == nil && !us.awaitingOpen {
				if !us.tryOpen(seg.payload) {
					us.shutdown()
					return
				}
			}
		case protoDataClientToServer:
			if us.link != nil && len(seg.payload) > 0 {
				if werr := us.link.Writer.WriteMultiBuffer(bytesToMultiBuffer(seg.payload)); werr != nil {
					us.shutdown()
					return
				}
			} else if us.link == nil && us.awaitingOpen {
				us.pendingOpen = append(us.pendingOpen, seg.payload...)
				if len(us.pendingOpen) > maxPendingSocks5Bytes || !us.tryOpen(us.pendingOpen) {
					us.shutdown()
					return
				}
			}
		case protoCloseSessionRequest:
			_ = us.sendSession(protoCloseSessionResponse)
			us.shutdown()
			return
		}
	}
}

// tryOpen 用目前攒到的字节尝试建会话。socks5 请求还不完整时记下来等后续 data 段,返回 true;
// 只有确定建不起来(不是 socks5 CONNECT、dispatch 失败、回包失败)才返回 false。
//
// NO_WAIT 客户端(mihomo 等)没有应用数据时先发一个空 openSessionRequest。UDP underlay 上
// 官方客户端要等到 openSessionResponse 才会把后面的 data 段(socks5 请求 + 首包)发出来,
// 所以这时必须**先回 openSessionResponse**,再等 socks5 请求;等 socks5 到齐再回响应就成了
// 互相等待。从前更糟:空 open 直接判失败关掉会话。两种情况下 HTTPS(含 mihomo 默认的延迟
// 测试)都是超时,表现为「mieru 节点 ping 不通」(#1078)。TCP underlay 的客户端不等这个响应。
func (us *udpServerSession) tryOpen(payload []byte) bool {
	opened, needMore := us.handleOpen(payload)
	if opened {
		us.awaitingOpen, us.pendingOpen = false, nil
		return true
	}
	if needMore {
		if !us.awaitingOpen {
			us.awaitingOpen = true
			us.pendingOpen = append([]byte(nil), payload...)
			if err := us.sendSession(protoOpenSessionResponse); err != nil {
				return false
			}
			us.openResponded = true
		}
		return true
	}
	return false
}

// handleOpen 解析 socks5 目标 → dispatch → 回 openSessionResponse + socks5 成功回复 + 初始数据 → 启动 pump。
// needMore=true 表示 socks5 请求还没到齐。
func (us *udpServerSession) handleOpen(payload []byte) (opened, needMore bool) {
	dest, cmd, consumed, perr := parseSocks5Request(payload)
	if perr != nil {
		return false, perr == errSocks5Incomplete
	}
	switch cmd {
	case socks5CmdConnect, socks5CmdUDPAssociate:
	default:
		// BIND 等:回 socks5「命令不支持」再由调用方关会话(返回 false → shutdown 发 closeSession)。
		if !us.openResponded {
			_ = us.sendSession(protoOpenSessionResponse)
			us.openResponded = true
		}
		_ = us.sendData(socks5ReplyCommandNotSupported)
		return false, false
	}
	ib := session.Inbound{}
	if us.base != nil {
		ib = *us.base
	}
	ib.User = us.user
	ib.Name = "mieru"
	ib.CanSpliceCopy = 3
	sctx := session.ContextWithInbound(us.ctx, &ib)
	if cmd == socks5CmdUDPAssociate {
		us.link = newUDPAssociateLink(sctx, us.dispatcher)
	} else {
		link, derr := us.dispatcher.Dispatch(accessLogCtx(sctx, dest), dest)
		if derr != nil {
			return false, false
		}
		us.link = link
	}

	if !us.openResponded {
		if err := us.sendSession(protoOpenSessionResponse); err != nil {
			return false, false
		}
	}
	if err := us.sendData(socks5SuccessReplyIPv4); err != nil {
		return false, false
	}
	if consumed < len(payload) {
		if err := us.link.Writer.WriteMultiBuffer(bytesToMultiBuffer(payload[consumed:])); err != nil {
			return false, false
		}
	}
	go us.pump()
	return true, false
}

// pump 读落地响应,分片成 dataServerToClient 段经 ARQ 可靠发出。
func (us *udpServerSession) pump() {
	reader := us.link.Reader
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			break
		}
		data := mbToBytes(mb)
		for _, frag := range bytesToUDPFragments(data) {
			if werr := us.sendData(frag); werr != nil {
				us.notifyClose()
				return
			}
		}
	}
	us.notifyClose()
}

// sendSession 经 ARQ 发一个会话控制段(open/close response)。
func (us *udpServerSession) sendSession(protoType uint8) error {
	return us.arq.sendSegment(func(seq, _ uint32, _ uint16) []byte {
		return sessionMeta{protocolType: protoType, sessionID: us.id, seq: seq}.encode()
	}, nil)
}

// sendData 经 ARQ 发一个 dataServerToClient 段(捎带累积 ack + window)。
func (us *udpServerSession) sendData(payload []byte) error {
	return us.arq.sendSegment(func(seq, unack uint32, win uint16) []byte {
		return dataMeta{
			protocolType: protoDataServerToClient,
			sessionID:    us.id,
			seq:          seq,
			unackSeq:     unack,
			window:       win,
			payloadLen:   uint16(len(payload)),
		}.encode()
	}, payload)
}

// notifyClose 落地关闭时通知客户端关闭会话。
func (us *udpServerSession) notifyClose() {
	_ = us.sendSession(protoCloseSessionRequest)
	us.shutdown()
}

func (us *udpServerSession) shutdown() {
	us.closeOnce.Do(func() {
		us.cancel()
		us.arq.close()
		if us.link != nil {
			common.Interrupt(us.link.Reader)
			common.Interrupt(us.link.Writer)
		}
		if us.onShutdown != nil {
			us.onShutdown()
		}
	})
}
