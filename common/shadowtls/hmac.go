package shadowtls

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding"
	"hash"
)

// hmacLen ShadowTLS 只取 HMAC-SHA1 的前 4 个字节。
const hmacLen = 4

// streamHMAC 是可以一边追加数据、一边随时取当前 HMAC 值的 HMAC-SHA1。
//
// ShadowTLS 的数据封装把同一个 HMAC 实例当作「流」用:每帧先喂数据、取 4 字节,再把这 4 字节也喂进去。
// 标准库的 hmac 取值后不能继续写(Sum 之后状态仍可用,但没有克隆),这里自己拼:
// 内层 sha1 的 Sum 不改变状态,外层每次重新算;克隆走 sha1 的 MarshalBinary。
type streamHMAC struct {
	inner hash.Hash
	opad  [sha1.BlockSize]byte
}

func newStreamHMAC(key []byte, init ...[]byte) *streamHMAC {
	if len(key) > sha1.BlockSize {
		sum := sha1.Sum(key)
		key = sum[:]
	}
	var ipad [sha1.BlockSize]byte
	h := &streamHMAC{inner: sha1.New()}
	copy(ipad[:], key)
	copy(h.opad[:], key)
	for i := range ipad {
		ipad[i] ^= 0x36
		h.opad[i] ^= 0x5c
	}
	h.inner.Write(ipad[:])
	for _, b := range init {
		h.inner.Write(b)
	}
	return h
}

func (h *streamHMAC) write(p []byte) { h.inner.Write(p) }

// sum4 当前已写入数据的 HMAC 前 4 字节,不改变状态。
func (h *streamHMAC) sum4() [hmacLen]byte {
	innerSum := h.inner.Sum(nil)
	outer := sha1.New()
	outer.Write(h.opad[:])
	outer.Write(innerSum)
	var out [hmacLen]byte
	copy(out[:], outer.Sum(nil))
	return out
}

func (h *streamHMAC) clone() *streamHMAC {
	state, err := h.inner.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic(err) // sha1 的 MarshalBinary 不会失败
	}
	inner := sha1.New()
	if err := inner.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		panic(err)
	}
	return &streamHMAC{inner: inner, opad: h.opad}
}

// xorKey 握手阶段改写握手服务器 ApplicationData 用的密钥流:SHA256(password || ServerRandom),循环使用。
func xorKey(password string, serverRandom []byte) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write(serverRandom)
	return h.Sum(nil)
}

func xorCycle(data, key []byte) {
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
}
