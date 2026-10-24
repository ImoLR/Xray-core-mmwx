package bittorrent

import (
	"bytes"
)

// UDP BitTorrent besides uTP: Mainline DHT (BEP 5 KRPC) and UDP trackers (BEP 15).
// Both report as "bittorrent", so the existing protocol:["bittorrent"] rules
// cover them. Every check is exact; a datagram that does not match returns
// errNotBittorrent at once, so other UDP traffic waits for nothing.

const (
	// maxKRPCPayload bounds the work per sniff. Real KRPC messages fit in one
	// unfragmented datagram (BEP 44 caps a stored value at 1000 bytes).
	maxKRPCPayload = 4096
	// maxKRPCMessages is how many complete messages may arrive back to back:
	// the sniffer sees every datagram cached for the flow so far, concatenated.
	maxKRPCMessages = 8
	// maxBencodeDepth bounds recursion; KRPC itself needs 3 levels, BEP 44
	// values may nest a little deeper.
	maxBencodeDepth = 16
	maxKRPCTxIDLen  = 32
	maxKRPCMethod   = 32
	krpcNodeIDLen   = 20
)

// SniffDHT reports Mainline DHT traffic. The payload must consist only of
// complete KRPC messages, each one bencoded dictionary that carries
//   - "t": the transaction ID, a 1–32 byte string;
//   - "y": "q" (query), "r" (response) or "e" (error);
//   - for a query, "q" naming the method ([a-z0-9_], 1–32 bytes) and "a", a
//     dictionary with the sender's 20-byte "id";
//   - for a response, "r", a dictionary with the sender's 20-byte "id";
//   - for an error, "e", the list [code, message].
//
// The bencoding is checked strictly (canonical integers and string lengths,
// nothing after the last message) without allocating.
func SniffDHT(b []byte) (*SniffHeader, error) {
	if len(b) == 0 || len(b) > maxKRPCPayload || b[0] != 'd' {
		return nil, errNotBittorrent
	}
	for messages := 0; len(b) > 0; messages++ {
		if messages == maxKRPCMessages {
			return nil, errNotBittorrent
		}
		n, ok := parseKRPC(b)
		if !ok {
			return nil, errNotBittorrent
		}
		b = b[n:]
	}
	return &SniffHeader{}, nil
}

// udpTrackerConnect is protocol_id 0x41727101980 followed by action 0 (connect).
var udpTrackerConnect = []byte{0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80, 0x00, 0x00, 0x00, 0x00}

// SniffUDPTracker reports the first datagram of a BEP 15 UDP tracker exchange:
// a connect request is exactly 16 bytes, the 64-bit protocol_id 0x41727101980,
// action 0 (connect) and a random 32-bit transaction ID.
func SniffUDPTracker(b []byte) (*SniffHeader, error) {
	if len(b) != 16 || !bytes.Equal(b[:12], udpTrackerConnect) {
		return nil, errNotBittorrent
	}
	return &SniffHeader{}, nil
}

// parseKRPC validates one KRPC message at the start of b and returns its length.
func parseKRPC(b []byte) (int, bool) {
	d := bdecoder{b: b}
	if !d.consume('d') {
		return 0, false
	}
	var y byte
	var hasT, hasY, hasQ, hasA, hasR, hasE bool
	var prevKey []byte
	for !d.consume('e') {
		key, ok := d.str()
		if !ok {
			return 0, false
		}
		// Bencoded dictionaries are sorted by raw key bytes, so a repeated or
		// out-of-order key is malformed.
		if prevKey != nil && bytes.Compare(prevKey, key) >= 0 {
			return 0, false
		}
		prevKey = key
		switch string(key) {
		case "t":
			t, ok := d.str()
			if !ok || len(t) == 0 || len(t) > maxKRPCTxIDLen {
				return 0, false
			}
			hasT = true
		case "y":
			v, ok := d.str()
			if !ok || len(v) != 1 || (v[0] != 'q' && v[0] != 'r' && v[0] != 'e') {
				return 0, false
			}
			y, hasY = v[0], true
		case "q":
			m, ok := d.str()
			if !ok || !validKRPCMethod(m) {
				return 0, false
			}
			hasQ = true
		case "a", "r":
			if !d.nodeDict() {
				return 0, false
			}
			if key[0] == 'a' {
				hasA = true
			} else {
				hasR = true
			}
		case "e":
			if !d.errorList() {
				return 0, false
			}
			hasE = true
		default:
			if !d.skip(1) {
				return 0, false
			}
		}
	}
	if !hasT || !hasY {
		return 0, false
	}
	switch y {
	case 'q':
		if !hasQ || !hasA {
			return 0, false
		}
	case 'r':
		if !hasR {
			return 0, false
		}
	case 'e':
		if !hasE {
			return 0, false
		}
	}
	return d.pos, true
}

func validKRPCMethod(m []byte) bool {
	if len(m) == 0 || len(m) > maxKRPCMethod {
		return false
	}
	for _, c := range m {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// bdecoder walks bencoded data in place. Every step consumes at least one
// byte and nesting is capped, so work is linear in the input and bounded.
type bdecoder struct {
	b   []byte
	pos int
}

func (d *bdecoder) consume(c byte) bool {
	if d.pos < len(d.b) && d.b[d.pos] == c {
		d.pos++
		return true
	}
	return false
}

// str reads a byte string "<length>:<bytes>"; the length has no leading zeros.
func (d *bdecoder) str() ([]byte, bool) {
	start, n := d.pos, 0
	for d.pos < len(d.b) && d.b[d.pos] >= '0' && d.b[d.pos] <= '9' {
		if d.pos-start == 5 {
			return nil, false // longer than any payload this sniffer accepts
		}
		n = n*10 + int(d.b[d.pos]-'0')
		d.pos++
	}
	digits := d.pos - start
	if digits == 0 || (digits > 1 && d.b[start] == '0') || !d.consume(':') || n > len(d.b)-d.pos {
		return nil, false
	}
	s := d.b[d.pos : d.pos+n]
	d.pos += n
	return s, true
}

// integer reads "i<digits>e": no leading zeros, no "-0", at most 18 digits.
func (d *bdecoder) integer() (int64, bool) {
	if !d.consume('i') {
		return 0, false
	}
	neg := d.consume('-')
	start := d.pos
	var v int64
	for d.pos < len(d.b) && d.b[d.pos] >= '0' && d.b[d.pos] <= '9' {
		if d.pos-start == 18 {
			return 0, false
		}
		v = v*10 + int64(d.b[d.pos]-'0')
		d.pos++
	}
	digits := d.pos - start
	if digits == 0 || (d.b[start] == '0' && (digits > 1 || neg)) || !d.consume('e') {
		return 0, false
	}
	if neg {
		v = -v
	}
	return v, true
}

// skip validates and passes over any value; depth counts enclosing containers.
func (d *bdecoder) skip(depth int) bool {
	if d.pos >= len(d.b) || depth > maxBencodeDepth {
		return false
	}
	switch c := d.b[d.pos]; {
	case c == 'i':
		_, ok := d.integer()
		return ok
	case c >= '0' && c <= '9':
		_, ok := d.str()
		return ok
	case c == 'l':
		d.pos++
		for !d.consume('e') {
			if !d.skip(depth + 1) {
				return false
			}
		}
		return true
	case c == 'd':
		d.pos++
		var prev []byte
		for !d.consume('e') {
			key, ok := d.str()
			if !ok || (prev != nil && bytes.Compare(prev, key) >= 0) || !d.skip(depth+1) {
				return false
			}
			prev = key
		}
		return true
	}
	return false
}

// nodeDict reads the "a" or "r" dictionary, which must hold a 20-byte "id".
func (d *bdecoder) nodeDict() bool {
	if !d.consume('d') {
		return false
	}
	hasID := false
	var prev []byte
	for !d.consume('e') {
		key, ok := d.str()
		if !ok || (prev != nil && bytes.Compare(prev, key) >= 0) {
			return false
		}
		prev = key
		if string(key) == "id" {
			id, ok := d.str()
			if !ok || len(id) != krpcNodeIDLen {
				return false
			}
			hasID = true
			continue
		}
		if !d.skip(2) {
			return false
		}
	}
	return hasID
}

// errorList reads the "e" value: exactly [integer code, string message].
func (d *bdecoder) errorList() bool {
	if !d.consume('l') {
		return false
	}
	if _, ok := d.integer(); !ok {
		return false
	}
	if _, ok := d.str(); !ok {
		return false
	}
	return d.consume('e')
}
