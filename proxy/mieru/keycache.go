// keycache.go:派生密钥缓存与防重放。
//
// 每次握手都要对「候选用户 × 3 个 timeSalt」各做一次 PBKDF2;userTag 对不上时候选是全部用户,
// 用户一多、再被灌垃圾包(每个 UDP 源地址都算一次握手),CPU 就被打满。timeSalt 每 2 分钟才变一次,
// 按 (hashedPassword, 取整时间) 缓存 AEAD 即可 —— XChaCha20-Poly1305 的 AEAD 无状态、可并发使用。
package mieru

import (
	"crypto/cipher"
	"sync"
	"time"
)

type aeadCacheKey struct {
	hashedPassword string
	rounded        int64
}

var aeadCache = struct {
	sync.Mutex
	m         map[aeadCacheKey]cipher.AEAD
	lastPurge int64
}{m: make(map[aeadCacheKey]cipher.AEAD)}

// aeadCacheKeep 缓存保留多久:候选时间是 now±2min,往前留 10 分钟足够,过期的顺手清掉。
const aeadCacheKeep = 10 * 60

// cachedAEAD 返回 (hashedPassword, rounded) 对应的 AEAD,没有就派生并缓存。
func cachedAEAD(hashedPassword []byte, rounded int64) (cipher.AEAD, error) {
	k := aeadCacheKey{string(hashedPassword), rounded}
	aeadCache.Lock()
	if a, ok := aeadCache.m[k]; ok {
		aeadCache.Unlock()
		return a, nil
	}
	aeadCache.Unlock()

	key, err := deriveKey(hashedPassword, timeSalt(rounded))
	if err != nil {
		return nil, err
	}
	a, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	aeadCache.Lock()
	aeadCache.m[k] = a
	if now-aeadCache.lastPurge > 60 {
		aeadCache.lastPurge = now
		for kk := range aeadCache.m {
			if kk.rounded < now-aeadCacheKeep {
				delete(aeadCache.m, kk)
			}
		}
	}
	aeadCache.Unlock()
	return a, nil
}

// replayFilter 记下认证通过的握手 nonce,同一个 nonce 再来一次就拒绝 —— 否则别人抓下首段原样
// 重放,服务端会照常替它拨一次落地,等于给主动探测一个确认。
//
// 两代 map 轮换:每 window 换一代,查两代。一个 nonce 至少保留 window、至多 2*window。
// 首段只在 ±2 分钟 timeSalt 窗口内能通过认证(最长约 4 分钟),window=5 分钟足够覆盖;
// 内存随握手速率线性增长,不会无界。
type replayFilter struct {
	mu        sync.Mutex
	cur, prev map[[nonceLen]byte]struct{}
	rotatedAt time.Time
	window    time.Duration
}

func newReplayFilter(window time.Duration) *replayFilter {
	return &replayFilter{
		cur: make(map[[nonceLen]byte]struct{}), prev: make(map[[nonceLen]byte]struct{}),
		rotatedAt: time.Now(), window: window,
	}
}

// seen 报告 nonce 是否已经出现过;没出现过则记下。
func (f *replayFilter) seen(nonce []byte) bool {
	var k [nonceLen]byte
	copy(k[:], nonce)
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.rotatedAt) > f.window {
		f.prev, f.cur = f.cur, make(map[[nonceLen]byte]struct{})
		f.rotatedAt = time.Now()
	}
	if _, ok := f.cur[k]; ok {
		return true
	}
	if _, ok := f.prev[k]; ok {
		return true
	}
	f.cur[k] = struct{}{}
	return false
}
