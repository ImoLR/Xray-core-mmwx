// udp.go:mieru UDP underlay 的段编解码。与 TCP 的差异(黑盒抓包字节级验证,见 [[mieru-port-cleanroom]]):
//   - 每个 UDP 包 = 一个段,自带 24 字节 nonce(不像 TCP 每方向只首段带一次)。
//   - 段内 metadata 与 payload 的 AEAD **共用同一 nonce**(不递增;TCP 是 nonce、nonce+1)。
//   - 段须装进单个 UDP 包(≤MTU)。nonce 末 4 字节仍是 userTag,服务端可逐包定位用户。
//
// 可靠性(seq/ack/window/重传)在 arq.go 之上;本文件只管单包的加解密。
package mieru

import (
	"crypto/cipher"
	crand "crypto/rand"

	"github.com/xtls/xray-core/common/errors"
)

// decodeUDPSegment 解一个 UDP 包为 segment。aead 已由调用方按用户/timeSalt 派生;nonce 取自包首 24 字节。
func decodeUDPSegment(packet []byte, aead cipher.AEAD) (*segment, error) {
	if len(packet) < nonceLen+metadataLen+aeadTagLen {
		return nil, errors.New("mieru udp: packet too short")
	}
	nonce := packet[:nonceLen]
	off := nonceLen

	meta, err := aead.Open(nil, nonce, packet[off:off+metadataLen+aeadTagLen], nil)
	if err != nil {
		return nil, errors.New("mieru udp: open metadata failed").Base(err)
	}
	off += metadataLen + aeadTagLen

	pt := metaProtocolType(meta)
	seg := &segment{protocolType: plainDataType(pt)}
	var prefixLen, payloadLen int
	var dm *dataMeta
	switch {
	case isSessionMeta(pt):
		m, _ := decodeSessionMeta(meta)
		seg.sessionID, seg.seq, seg.statusCode = m.sessionID, m.seq, m.statusCode
		payloadLen = int(m.payloadLen)
	case isDataMeta(pt) || isLowEntropyDataMeta(pt):
		m, _ := decodeDataMeta(meta)
		dm = &m
		seg.sessionID, seg.seq, seg.unackSeq, seg.window = m.sessionID, m.seq, m.unackSeq, m.window
		prefixLen, payloadLen = int(m.prefixLen), int(m.payloadLen)
	default:
		return nil, errors.New("mieru udp: unsupported metadata protocol type ", int(pt))
	}

	off += prefixLen // pad1
	if payloadLen > 0 {
		if off+payloadLen+aeadTagLen > len(packet) {
			return nil, errors.New("mieru udp: payload out of range")
		}
		// UDP:payload 与 metadata 共用同一 nonce(不递增)。
		pl, err := openPayload(func(sealed []byte) ([]byte, error) {
			return aead.Open(nil, nonce, sealed, nil)
		}, packet[off:off+payloadLen+aeadTagLen], dm)
		if err != nil {
			return nil, errors.New("mieru udp: open payload failed").Base(err)
		}
		seg.payload = pl
	}
	// pad2 忽略
	return seg, nil
}

// encodeUDPSegment 把一个段封成一个 UDP 包,随机加 padding 1 / 2(addPadding)。每包生成新随机 nonce(末 4 字节带 userTag)。
// metaBytes 的 payloadLen 须与 payload 一致,prefix/suffix 由这里填。
func encodeUDPSegment(metaBytes, payload []byte, aead cipher.AEAD, username string) ([]byte, error) {
	nonce := make([]byte, nonceLen)
	if _, err := crand.Read(nonce); err != nil {
		return nil, err
	}
	applyUserTag(nonce, username)

	pad1, pad2 := addPadding(metaBytes)
	out := make([]byte, 0, nonceLen+metadataLen+aeadTagLen+len(pad1)+len(payload)+aeadTagLen+len(pad2))
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, metaBytes, nil)
	out = append(out, pad1...)
	if len(payload) > 0 {
		out = aead.Seal(out, nonce, payload, nil) // 同 nonce
	}
	return append(out, pad2...), nil
}
