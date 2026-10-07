// lowentropy.go:低熵数据段(protocol type 10/11)的载荷解码。依据 docs/protocol.md
// 「Data Metadata (Low Entropy Extension)」与「Low Entropy Payload Encoding」。
//
// 发送方先照常做 AEAD,把密文拆成密文体 + 16 字节 tag,只编码密文体:每 C 个源字节按大端
// 放进低位,再把这些位依次「存放」到 64 位块里掩码为 1 的位置(即 PDEP),其余位置全部填同一个
// 填充位(0 或 1)。块 i 用初始掩码旋转 i*R 位。tag 原样跟在编码体后面。
//
// 服务端只需要**接收**(我们从不发 11),所以这里只实现解码;编码只给单测用。
package mieru

import (
	"encoding/binary"
	"math/bits"

	"github.com/xtls/xray-core/common/errors"
)

// lowEntropyCapacity 返回模式对应的每块源字节数 C 与 32 位半掩码里应有的 1 的个数。
func lowEntropyCapacity(mode uint8) (c int, halfPop int, ok bool) {
	switch mode {
	case 1:
		return 4, 16, true
	case 2:
		return 5, 20, true
	case 3:
		return 6, 24, true
	case 4:
		return 7, 28, true
	}
	return 0, 0, false
}

// lowEntropyMaskAt 返回第 i 块用的掩码:初始掩码按 rotation 编码的方向旋转 i*R 位。
// rotation 低 4 位 1..15 = 右旋 R 位;高 4 位 1..15(值为 16 的倍数)= 左旋 R 位;0 = 不旋转。
// 两个半字节同时非零是非法值。
func lowEntropyMaskAt(initial uint64, rotation uint8, i int) (uint64, bool) {
	right, left := int(rotation&0x0f), int(rotation>>4)
	switch {
	case right != 0 && left != 0:
		return 0, false
	case right != 0:
		return bits.RotateLeft64(initial, -((i * right) % 64)), true
	case left != 0:
		return bits.RotateLeft64(initial, (i*left)%64), true
	}
	return initial, true
}

// pext 把 x 里 mask 为 1 的那些位,按从低到高的顺序收拢到结果的低位。
func pext(x, mask uint64) uint64 {
	var out uint64
	k := 0
	for m := mask; m != 0; m &= m - 1 {
		pos := bits.TrailingZeros64(m)
		out |= ((x >> pos) & 1) << k
		k++
	}
	return out
}

// pdep 是 pext 的逆:把 src 的低位依次放到 mask 为 1 的位置。
func pdep(src, mask uint64) uint64 {
	var out uint64
	k := 0
	for m := mask; m != 0; m &= m - 1 {
		pos := bits.TrailingZeros64(m)
		out |= ((src >> k) & 1) << pos
		k++
	}
	return out
}

// decodeLowEntropy 把编码体还原成密文体(长度 extracted)。任何不一致都判非法:
// 模式/旋转非法、掩码 1 的个数不对、编码长度与 extracted 对不上、填充位不统一。
func decodeLowEntropy(encoded []byte, mode uint8, halfMask uint32, rotation uint8, extracted int) ([]byte, error) {
	c, halfPop, ok := lowEntropyCapacity(mode)
	if !ok {
		return nil, errors.New("mieru: invalid low entropy mode ", int(mode))
	}
	if bits.OnesCount32(halfMask) != halfPop {
		return nil, errors.New("mieru: low entropy mask population mismatch")
	}
	if extracted <= 0 || len(encoded)%8 != 0 || len(encoded)/8 != (extracted+c-1)/c {
		return nil, errors.New("mieru: low entropy length mismatch")
	}
	initial := uint64(halfMask)<<32 | uint64(halfMask)
	if _, ok := lowEntropyMaskAt(initial, rotation, 0); !ok {
		return nil, errors.New("mieru: invalid low entropy rotation")
	}

	// 填充位从第一块推断:取初始掩码最低的一个 0 位上的值。
	first := binary.BigEndian.Uint64(encoded[:8])
	padBit := (first >> bits.TrailingZeros64(^initial)) & 1
	var padFill uint64
	if padBit == 1 {
		padFill = ^uint64(0)
	}

	out := make([]byte, 0, extracted)
	for i := 0; i*8 < len(encoded); i++ {
		v := binary.BigEndian.Uint64(encoded[i*8 : i*8+8])
		mask, _ := lowEntropyMaskAt(initial, rotation, i)
		if v&^mask != padFill&^mask {
			return nil, errors.New("mieru: low entropy padding mismatch")
		}
		src := pext(v, mask) // 低 c*8 位
		n := min(c, extracted-len(out))
		// 末块不满时,掩码选中但没用上的高位也必须是填充位。
		if n < c {
			unused := src >> (8 * n)
			want := uint64(0)
			if padBit == 1 {
				want = (uint64(1) << (8 * (c - n))) - 1
			}
			if unused != want {
				return nil, errors.New("mieru: low entropy tail padding mismatch")
			}
		}
		for b := n - 1; b >= 0; b-- {
			out = append(out, byte(src>>(8*b)))
		}
	}
	return out, nil
}

// encodeLowEntropy 仅供单测:按规范把密文体编码成低熵块。
func encodeLowEntropy(body []byte, mode uint8, halfMask uint32, rotation uint8, padBit uint64) []byte {
	c, _, _ := lowEntropyCapacity(mode)
	initial := uint64(halfMask)<<32 | uint64(halfMask)
	var out []byte
	for i := 0; i*c < len(body); i++ {
		chunk := body[i*c : min(len(body), (i+1)*c)]
		var src uint64
		for _, b := range chunk {
			src = src<<8 | uint64(b)
		}
		if padBit == 1 && len(chunk) < c {
			src |= ((uint64(1) << (8 * (c - len(chunk)))) - 1) << (8 * len(chunk))
		}
		mask, _ := lowEntropyMaskAt(initial, rotation, i)
		v := pdep(src, mask)
		if padBit == 1 {
			v |= ^mask
		}
		out = binary.BigEndian.AppendUint64(out, v)
	}
	return out
}
