package mieru

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestReplayFilter(t *testing.T) {
	f := newReplayFilter(50 * time.Millisecond)
	n := make([]byte, nonceLen)
	_, _ = rand.Read(n)
	if f.seen(n) {
		t.Fatal("第一次不应算重放")
	}
	if !f.seen(n) {
		t.Fatal("同一 nonce 第二次应算重放")
	}
	time.Sleep(60 * time.Millisecond) // 换一代后仍在 prev 里
	if !f.seen(n) {
		t.Fatal("换代后一个窗口内仍应认出")
	}
}

// 握手重放:同一个首段原样再发一次,服务端不再接受。
func TestMieruRejectsReplayedHandshake(t *testing.T) {
	srv := &Server{replay: newReplayFilter(5 * time.Minute)}
	n := make([]byte, nonceLen)
	_, _ = rand.Read(n)
	if srv.replayed(n) || !srv.replayed(n) {
		t.Fatal("首次放行、重放拒绝")
	}
	if (&Server{}).replayed(n) {
		t.Fatal("没有过滤器时不检查")
	}
}

func TestCachedAEADReusesDerivation(t *testing.T) {
	hp := hashPassword("alice", "secret123")
	now := roundedUnixTime(time.Now().Unix()) // 太旧的时间档会被顺手清掉,用当前档
	a1, err := cachedAEAD(hp, now)
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := cachedAEAD(hp, now)
	if a1 != a2 {
		t.Fatal("同一 (密码, 时间档) 应命中缓存")
	}
	a3, _ := cachedAEAD(hp, now+saltRoundSecs)
	if a3 == a1 {
		t.Fatal("不同时间档不能共用")
	}
}

// 服务端发出的段带随机 padding,自己的读段逻辑(与规范一致)照样解得开,载荷不变。
func TestOutboundPaddingDecodes(t *testing.T) {
	aead, nonce := testAEAD(t)
	var wire bytes.Buffer
	sw := newSegmentWriter(&wire, aead, nonce)
	payload := []byte("padded payload")
	sawPadding := false
	for i := 0; i < 50; i++ {
		before := wire.Len()
		meta := dataMeta{protocolType: protoDataServerToClient, sessionID: 1, seq: uint32(i), payloadLen: uint16(len(payload))}.encode()
		if err := sw.write(meta, payload); err != nil {
			t.Fatal(err)
		}
		if wire.Len()-before > metadataLen+aeadTagLen+len(payload)+aeadTagLen+nonceLen {
			sawPadding = true
		}
	}
	sr := newSegmentReader(bytes.NewReader(wire.Bytes()[nonceLen:]), aead, nonce)
	for i := 0; i < 50; i++ {
		seg, err := sr.read()
		if err != nil || !bytes.Equal(seg.payload, payload) || seg.seq != uint32(i) {
			t.Fatalf("第 %d 段: err=%v payload=%q", i, err, seg.payload)
		}
	}
	if !sawPadding {
		t.Fatal("50 段一个 padding 都没有")
	}

	pkt, err := encodeUDPSegment(dataMeta{protocolType: protoDataServerToClient, sessionID: 2, payloadLen: uint16(len(payload))}.encode(), payload, aead, "alice")
	if err != nil {
		t.Fatal(err)
	}
	seg, err := decodeUDPSegment(pkt, aead)
	if err != nil || !bytes.Equal(seg.payload, payload) {
		t.Fatalf("UDP 带 padding 解错: %v", err)
	}
}

// UDP 长连接跨 timeSalt 档:当前 AEAD 解不开时换到能解开的那一档。
func TestRetryUDPKeyAcrossSaltWindow(t *testing.T) {
	hp := hashPassword("alice", "secret123")
	salts := candidateRoundedTimes(time.Now().Unix())
	old, _ := cachedAEAD(hp, salts[1]) // 上一档
	cur, _ := cachedAEAD(hp, salts[0])
	pkt, _ := encodeUDPSegment(dataMeta{protocolType: protoDataClientToServer, sessionID: 9, payloadLen: 3}.encode(), []byte("abc"), cur, "alice")
	if _, err := decodeUDPSegment(pkt, old); err == nil {
		t.Fatal("前提:旧档解不开新档的包")
	}
	next, seg := retryUDPKey(pkt, hp, old)
	if next != cur || seg == nil || string(seg.payload) != "abc" {
		t.Fatal("应换到当前档并解出")
	}
}
