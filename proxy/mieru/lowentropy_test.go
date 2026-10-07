package mieru

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// docs/protocol.md 给出的 LOW_ENTROPY_MODE_32 完整例子。
func TestLowEntropySpecExample(t *testing.T) {
	src, _ := hex.DecodeString("12345678")
	for _, tc := range []struct {
		pad     uint64
		encoded string
	}{
		{0, "0102030405060708"},
		{1, "f1f2f3f4f5f6f7f8"},
	} {
		enc, _ := hex.DecodeString(tc.encoded)
		got, err := decodeLowEntropy(enc, 1, 0x0f0f0f0f, 0, 4)
		if err != nil || !bytes.Equal(got, src) {
			t.Fatalf("pad=%d decode=%x err=%v, want %x", tc.pad, got, err, src)
		}
		if again := encodeLowEntropy(src, 1, 0x0f0f0f0f, 0, tc.pad); !bytes.Equal(again, enc) {
			t.Fatalf("pad=%d encode=%x, want %x", tc.pad, again, enc)
		}
	}
}

// 四种模式 × 左右旋转 × 末块不满,往返一致。
func TestLowEntropyRoundTrip(t *testing.T) {
	masks := map[uint8]uint32{1: 0x0f0f0f0f, 2: 0x3e3e3e3e, 3: 0xfff0fff0, 4: 0xfffffff0}
	for mode, mask := range masks {
		if _, pop, _ := lowEntropyCapacity(mode); popcount(mask) != pop {
			t.Fatalf("测试掩码 1 的个数不对: mode=%d mask=%08x", mode, mask)
		}
		for _, rot := range []uint8{0, 3, 15, 0x10, 0x70} {
			for _, n := range []int{1, 6, 7, 64, 1001} {
				body := make([]byte, n)
				_, _ = rand.Read(body)
				for _, pad := range []uint64{0, 1} {
					enc := encodeLowEntropy(body, mode, mask, rot, pad)
					got, err := decodeLowEntropy(enc, mode, mask, rot, n)
					if err != nil || !bytes.Equal(got, body) {
						t.Fatalf("mode=%d rot=%#x n=%d pad=%d: err=%v", mode, rot, n, pad, err)
					}
				}
			}
		}
	}
}

func TestLowEntropyRejectsInvalid(t *testing.T) {
	body := []byte("hello low entropy")
	enc := encodeLowEntropy(body, 1, 0x0f0f0f0f, 0, 0)

	mixed := append([]byte(nil), enc...)
	mixed[9] |= 0x80 // 第二块的一个填充位翻成 1
	cases := map[string]func() error{
		"填充位不统一": func() error { _, err := decodeLowEntropy(mixed, 1, 0x0f0f0f0f, 0, len(body)); return err },
		"模式非法":   func() error { _, err := decodeLowEntropy(enc, 5, 0x0f0f0f0f, 0, len(body)); return err },
		"掩码个数不对": func() error { _, err := decodeLowEntropy(enc, 1, 0x0f0f0f0e, 0, len(body)); return err },
		"旋转非法":   func() error { _, err := decodeLowEntropy(enc, 1, 0x0f0f0f0f, 0x11, len(body)); return err },
		"长度对不上":  func() error { _, err := decodeLowEntropy(enc, 1, 0x0f0f0f0f, 0, len(body)+8); return err },
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s: 应拒绝", name)
		}
	}
}

// 低熵数据段走完整的 TCP 段读取:解出的载荷与普通段一致,类型映射回 6。
func TestSegmentReaderLowEntropy(t *testing.T) {
	aead, nonce := testAEAD(t)
	plain := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	n := append([]byte(nil), nonce...)
	var wire bytes.Buffer
	meta := dataMeta{protocolType: protoDataClientToServerLowEntropy, sessionID: 7, seq: 3, window: 4096}
	sealedPayload := aead.Seal(nil, nextNonce(n, 1), plain, nil)
	body, tag := sealedPayload[:len(plain)], sealedPayload[len(plain):]
	enc := encodeLowEntropy(body, 2, 0x3e3e3e3e, 0x05, 1)
	m := meta.encode()
	m[1] = 2
	m[22], m[23] = byte(len(enc)>>8), byte(len(enc))
	putLowEntropyExt(m, 0x3e3e3e3e, uint16(len(plain)), 0x05)
	wire.Write(aead.Seal(nil, n, m, nil))
	wire.Write(enc)
	wire.Write(tag)

	seg, err := newSegmentReader(&wire, aead, nonce).read()
	if err != nil {
		t.Fatal(err)
	}
	if seg.protocolType != protoDataClientToServer || seg.sessionID != 7 || !bytes.Equal(seg.payload, plain) {
		t.Fatalf("低熵段解错: type=%d sid=%d payload=%q", seg.protocolType, seg.sessionID, seg.payload)
	}
}

func popcount(v uint32) int {
	n := 0
	for ; v != 0; v &= v - 1 {
		n++
	}
	return n
}

func putLowEntropyExt(m []byte, mask uint32, extracted uint16, rotation uint8) {
	m[25], m[26], m[27], m[28] = byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask)
	m[29], m[30] = byte(extracted>>8), byte(extracted)
	m[31] = rotation
}

// nextNonce 返回 nonce+k 的副本(TCP 段:meta 用 n,payload 用 n+1)。
func nextNonce(n []byte, k int) []byte {
	out := append([]byte(nil), n...)
	for i := 0; i < k; i++ {
		incrementNonce(out)
	}
	return out
}

func testAEAD(t *testing.T) (cipher.AEAD, []byte) {
	t.Helper()
	key, err := deriveKey(hashPassword("alice", "secret123"), timeSalt(1784804880))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, nonceLen)
	_, _ = rand.Read(nonce)
	return aead, nonce
}
