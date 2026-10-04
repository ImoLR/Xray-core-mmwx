// metadata.go:mieru 段元数据(定长 32 字节)编解码。依据 docs/protocol.md「Metadata Format」。
// 三类:
//
//	Session(2..5):| type | _ | timestamp(4) | sessionID(4) | seq(4) | status(1) | payloadLen(2) | suffixLen(1) | _(14) |
//	Data   (6..9):| type | _ | timestamp(4) | sessionID(4) | seq(4) | unackSeq(4) | window(2) | frag(1) | prefixLen(1) | payloadLen(2) | suffixLen(1) | _(7) |
//	低熵 (10/11):与 Data 相同,b[1]=低熵模式,末 7 字节 = 掩码(4) | 解码后载荷长度(2) | 掩码旋转(1)
package mieru

import (
	"encoding/binary"

	"github.com/xtls/xray-core/common/errors"
)

const metadataLen = 32

// protocol type 取值(规范定义)。
const (
	protoOpenSessionRequest   = 2
	protoOpenSessionResponse  = 3
	protoCloseSessionRequest  = 4
	protoCloseSessionResponse = 5
	protoDataClientToServer   = 6
	protoDataServerToClient   = 7
	protoAckClientToServer    = 8
	protoAckServerToClient    = 9
	// 低熵扩展:载荷按 lowentropy.go 解码,其余语义同 6/7
	protoDataClientToServerLowEntropy = 10
	protoDataServerToClientLowEntropy = 11
)

// sessionMeta 对应 Session Metadata(protocol type 2..5)。
type sessionMeta struct {
	protocolType uint8
	timestamp    uint32 // 距 epoch 的分钟数
	sessionID    uint32
	seq          uint32
	statusCode   uint8
	payloadLen   uint16 // ≤1024
	suffixLen    uint8  // padding 2 长度
}

func (m sessionMeta) encode() []byte {
	b := make([]byte, metadataLen)
	b[0] = m.protocolType
	// b[1] unused
	binary.BigEndian.PutUint32(b[2:6], m.timestamp)
	binary.BigEndian.PutUint32(b[6:10], m.sessionID)
	binary.BigEndian.PutUint32(b[10:14], m.seq)
	b[14] = m.statusCode
	binary.BigEndian.PutUint16(b[15:17], m.payloadLen)
	b[17] = m.suffixLen
	// b[18:32] unused
	return b
}

func decodeSessionMeta(b []byte) (sessionMeta, error) {
	if len(b) < metadataLen {
		return sessionMeta{}, errors.New("mieru: session metadata too short")
	}
	return sessionMeta{
		protocolType: b[0],
		timestamp:    binary.BigEndian.Uint32(b[2:6]),
		sessionID:    binary.BigEndian.Uint32(b[6:10]),
		seq:          binary.BigEndian.Uint32(b[10:14]),
		statusCode:   b[14],
		payloadLen:   binary.BigEndian.Uint16(b[15:17]),
		suffixLen:    b[17],
	}, nil
}

// dataMeta 对应 Data Metadata(protocol type 6..9)。
type dataMeta struct {
	protocolType uint8
	timestamp    uint32
	sessionID    uint32
	seq          uint32
	unackSeq     uint32
	window       uint16
	fragment     uint8
	prefixLen    uint8 // padding 1 长度
	payloadLen   uint16
	suffixLen    uint8 // padding 2 长度

	// 低熵扩展(仅 protocol type 10/11 有意义;6..9 时这些字节是 unused、恒为 0)
	leMode      uint8
	leMask      uint32
	leExtracted uint16
	leRotation  uint8
}

func (m dataMeta) encode() []byte {
	b := make([]byte, metadataLen)
	b[0] = m.protocolType
	// b[1] unused
	binary.BigEndian.PutUint32(b[2:6], m.timestamp)
	binary.BigEndian.PutUint32(b[6:10], m.sessionID)
	binary.BigEndian.PutUint32(b[10:14], m.seq)
	binary.BigEndian.PutUint32(b[14:18], m.unackSeq)
	binary.BigEndian.PutUint16(b[18:20], m.window)
	b[20] = m.fragment
	b[21] = m.prefixLen
	binary.BigEndian.PutUint16(b[22:24], m.payloadLen)
	b[24] = m.suffixLen
	// b[25:32] unused
	return b
}

func decodeDataMeta(b []byte) (dataMeta, error) {
	if len(b) < metadataLen {
		return dataMeta{}, errors.New("mieru: data metadata too short")
	}
	return dataMeta{
		protocolType: b[0],
		timestamp:    binary.BigEndian.Uint32(b[2:6]),
		sessionID:    binary.BigEndian.Uint32(b[6:10]),
		seq:          binary.BigEndian.Uint32(b[10:14]),
		unackSeq:     binary.BigEndian.Uint32(b[14:18]),
		window:       binary.BigEndian.Uint16(b[18:20]),
		fragment:     b[20],
		prefixLen:    b[21],
		payloadLen:   binary.BigEndian.Uint16(b[22:24]),
		suffixLen:    b[24],
		leMode:       b[1],
		leMask:       binary.BigEndian.Uint32(b[25:29]),
		leExtracted:  binary.BigEndian.Uint16(b[29:31]),
		leRotation:   b[31],
	}, nil
}

// isLowEntropyDataMeta 判断是不是低熵数据段(10/11)。
func isLowEntropyDataMeta(t uint8) bool {
	return t == protoDataClientToServerLowEntropy || t == protoDataServerToClientLowEntropy
}

// plainDataType 把低熵数据段映射回普通数据段类型:解码之后两者对会话层完全一样。
func plainDataType(t uint8) uint8 {
	switch t {
	case protoDataClientToServerLowEntropy:
		return protoDataClientToServer
	case protoDataServerToClientLowEntropy:
		return protoDataServerToClient
	}
	return t
}

// openPayload 解出段载荷。普通段:payload 就是 AEAD 密文 + tag;低熵段(模式非 0):
// 前 payloadLen 字节是编码后的密文体,先还原成 leExtracted 字节的密文,再拼上原样的 tag 解密。
func openPayload(open func(sealed []byte) ([]byte, error), wire []byte, m *dataMeta) ([]byte, error) {
	if m == nil || !isLowEntropyDataMeta(m.protocolType) || m.leMode == 0 {
		return open(wire)
	}
	body := wire[:len(wire)-aeadTagLen]
	tag := wire[len(wire)-aeadTagLen:]
	cipherBody, err := decodeLowEntropy(body, m.leMode, m.leMask, m.leRotation, int(m.leExtracted))
	if err != nil {
		return nil, err
	}
	return open(append(cipherBody, tag...))
}

// metaProtocolType 从已解密的 32 字节元数据里取 protocol type(用于分派 session/data 解码)。
func metaProtocolType(b []byte) uint8 {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

// isDataMeta / isSessionMeta 判断 protocol type 属于哪类元数据。
func isSessionMeta(t uint8) bool {
	return t >= protoOpenSessionRequest && t <= protoCloseSessionResponse
}
func isDataMeta(t uint8) bool { return t >= protoDataClientToServer && t <= protoAckServerToClient }
