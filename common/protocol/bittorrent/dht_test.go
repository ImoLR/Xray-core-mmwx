package bittorrent

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

const (
	nodeA = "abcdefghij0123456789"
	nodeB = "mnopqrstuvwxyz123456"
)

// krpcMessages are BEP 5's examples (lengths fixed where the spec elides
// them) plus the BEP 44 / BEP 51 / BEP 42 / BEP 43 shapes real clients send.
var krpcMessages = map[string]string{
	"ping query":              "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t2:aa1:y1:qe",
	"ping response":           "d1:rd2:id20:" + nodeB + "e1:t2:aa1:y1:re",
	"find_node query":         "d1:ad2:id20:" + nodeA + "6:target20:" + nodeB + "e1:q9:find_node1:t2:aa1:y1:qe",
	"find_node response":      "d1:rd2:id20:0123456789abcdefghij5:nodes26:" + nodeB + "\x0a\x00\x00\x01\x1a\xe1e1:t2:aa1:y1:re",
	"get_peers query":         "d1:ad2:id20:" + nodeA + "9:info_hash20:" + nodeB + "e1:q9:get_peers1:t2:aa1:y1:qe",
	"get_peers values":        "d1:rd2:id20:" + nodeA + "5:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re",
	"announce_peer query":     "d1:ad2:id20:" + nodeA + "12:implied_porti1e9:info_hash20:" + nodeB + "4:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe",
	"error":                   "d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee",
	"query with version":      "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t4:\x00\x01\x02\x031:v4:LT\x02\x001:y1:qe",
	"response with BEP42 ip":  "d2:ip6:\x0a\x00\x00\x02\x1a\xe11:rd2:id20:" + nodeB + "e1:t2:aa1:v4:UT\x01\x001:y1:re",
	"read-only query BEP43":   "d1:ad2:id20:" + nodeA + "e1:q4:ping2:roi1e1:t2:aa1:y1:qe",
	"BEP44 put nested value":  "d1:ad3:casi1e2:id20:" + nodeA + "1:k32:" + strings.Repeat("k", 32) + "3:seqi4e3:sig64:" + strings.Repeat("s", 64) + "5:token3:abc1:vld1:xli1ei2eeeee1:q3:put1:t2:aa1:y1:qe",
	"BEP51 sample_infohashes": "d1:ad2:id20:" + nodeA + "6:target20:" + nodeB + "e1:q17:sample_infohashes1:t2:aa1:y1:qe",
	"negative error code":     "d1:eli-1e0:e1:t1:x1:y1:ee",
}

func TestSniffDHTAcceptsKRPC(t *testing.T) {
	for name, m := range krpcMessages {
		if _, err := SniffDHT([]byte(m)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSniffDHTAcceptsBackToBackMessages(t *testing.T) {
	// The sniffer sees every datagram cached for the flow, concatenated.
	two := krpcMessages["ping query"] + krpcMessages["get_peers query"]
	if _, err := SniffDHT([]byte(two)); err != nil {
		t.Fatal(err)
	}
	if _, err := SniffDHT([]byte(two + "x")); err == nil {
		t.Fatal("trailing byte after the last message must not match")
	}
	many := strings.Repeat(krpcMessages["ping query"], maxKRPCMessages+1)
	if _, err := SniffDHT([]byte(many)); err == nil {
		t.Fatal("more than maxKRPCMessages messages must not match")
	}
}

// Every rule on its own: each message differs from a valid one in one place.
var krpcNearMisses = map[string]string{
	"empty":                     "",
	"not a dictionary":          "l1:t2:aae",
	"bare dictionary":           "de",
	"no transaction ID":         "d1:ad2:id20:" + nodeA + "e1:q4:ping1:y1:qe",
	"empty transaction ID":      "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t0:1:y1:qe",
	"transaction ID too long":   "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t33:" + strings.Repeat("t", 33) + "1:y1:qe",
	"no message type":           "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t2:aae",
	"unknown message type":      "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t2:aa1:y1:xe",
	"two-byte message type":     "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t2:aa1:y2:qqe",
	"integer message type":      "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t2:aa1:yi1ee",
	"query without method":      "d1:ad2:id20:" + nodeA + "e1:t2:aa1:y1:qe",
	"query without arguments":   "d1:q4:ping1:t2:aa1:y1:qe",
	"method with upper case":    "d1:ad2:id20:" + nodeA + "e1:q4:Ping1:t2:aa1:y1:qe",
	"method with space":         "d1:ad2:id20:" + nodeA + "e1:q5:pi ng1:t2:aa1:y1:qe",
	"empty method":              "d1:ad2:id20:" + nodeA + "e1:q0:1:t2:aa1:y1:qe",
	"method too long":           "d1:ad2:id20:" + nodeA + "e1:q33:" + strings.Repeat("m", 33) + "1:t2:aa1:y1:qe",
	"arguments without id":      "d1:ad6:target20:" + nodeB + "e1:q4:ping1:t2:aa1:y1:qe",
	"19-byte node id":           "d1:ad2:id19:" + nodeA[:19] + "e1:q4:ping1:t2:aa1:y1:qe",
	"21-byte node id":           "d1:ad2:id21:" + nodeA + "xe1:q4:ping1:t2:aa1:y1:qe",
	"integer node id":           "d1:ad2:idi1ee1:q4:ping1:t2:aa1:y1:qe",
	"arguments not a dict":      "d1:al2:id20:" + nodeA + "e1:q4:ping1:t2:aa1:y1:qe",
	"response without r":        "d1:t2:aa1:y1:re",
	"response without id":       "d1:rd5:nodes0:e1:t2:aa1:y1:re",
	"error without e":           "d1:t2:aa1:y1:ee",
	"error code not integer":    "d1:el3:2011:xe1:t2:aa1:y1:ee",
	"error with three items":    "d1:eli201e1:xi1ee1:t2:aa1:y1:ee",
	"error with one item":       "d1:eli201ee1:t2:aa1:y1:ee",
	"unsorted keys":             "d1:t2:aa1:ad2:id20:" + nodeA + "e1:q4:ping1:y1:qe",
	"duplicate key":             "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t2:aa1:t2:bb1:y1:qe",
	"unsorted inner keys":       "d1:ad6:target20:" + nodeB + "2:id20:" + nodeA + "e1:q9:find_node1:t2:aa1:y1:qe",
	"leading zero length":       "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t02:aa1:y1:qe",
	"leading zero integer":      "d1:ad2:id20:" + nodeA + "e1:q4:ping2:roi01e1:t2:aa1:y1:qe",
	"negative zero":             "d1:ad2:id20:" + nodeA + "e1:q4:ping2:roi-0e1:t2:aa1:y1:qe",
	"empty integer":             "d1:ad2:id20:" + nodeA + "e1:q4:ping2:roie1:t2:aa1:y1:qe",
	"overlong integer":          "d1:ad2:id20:" + nodeA + "e1:q4:ping2:roi1234567890123456789e1:t2:aa1:y1:qe",
	"string past the end":       "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t9:aa",
	"truncated":                 "d1:ad2:id20:" + nodeA + "e1:q4:ping1:t2:aa1:y1:q",
	"trailing garbage":          krpcMessages["ping query"] + "\x00",
	"JSON lookalike":            `{"t":"aa","y":"q","q":"ping","a":{"id":"abcdefghij0123456789"}}`,
	"bencode without KRPC keys": "d8:announce35:udp://tracker.example.org:6969/annee4:infod6:lengthi1e4:name1:xee",
}

func TestSniffDHTRejectsNearMisses(t *testing.T) {
	for name, m := range krpcNearMisses {
		if _, err := SniffDHT([]byte(m)); err == nil {
			t.Errorf("%s: matched %q", name, m)
		}
	}
}

func TestSniffDHTBounds(t *testing.T) {
	// Nesting deeper than maxBencodeDepth is refused, not recursed into.
	deep := "d1:ad2:id20:" + nodeA + "1:v" + strings.Repeat("l", maxBencodeDepth) + strings.Repeat("e", maxBencodeDepth) + "e1:q3:put1:t2:aa1:y1:qe"
	if _, err := SniffDHT([]byte(deep)); err == nil {
		t.Fatal("over-deep value matched")
	}
	shallow := "d1:ad2:id20:" + nodeA + "1:v" + strings.Repeat("l", 4) + strings.Repeat("e", 4) + "e1:q3:put1:t2:aa1:y1:qe"
	if _, err := SniffDHT([]byte(shallow)); err != nil {
		t.Fatal(err)
	}
	// A huge nesting bomb returns quickly without recursing.
	bomb := "d1:ad2:id20:" + nodeA + "1:v" + strings.Repeat("l", 4000)
	if _, err := SniffDHT([]byte(bomb)); err == nil {
		t.Fatal("bomb matched")
	}
	padding := strings.Repeat("x", maxKRPCPayload)
	big := "d1:ad2:id20:" + nodeA + "1:p" + itoa(len(padding)) + ":" + padding + "e1:q4:ping1:t2:aa1:y1:qe"
	if _, err := SniffDHT([]byte(big)); err == nil {
		t.Fatal("payload over maxKRPCPayload matched")
	}
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			return string(b[i:])
		}
	}
}

func trackerConnect(tx uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b, 0x41727101980)
	binary.BigEndian.PutUint32(b[12:], tx)
	return b
}

func TestSniffUDPTracker(t *testing.T) {
	for _, tx := range []uint32{0, 1, 0xdeadbeef, 0xffffffff} {
		if _, err := SniffUDPTracker(trackerConnect(tx)); err != nil {
			t.Fatalf("connect %08x: %v", tx, err)
		}
	}
	ok := trackerConnect(7)
	misses := map[string][]byte{
		"15 bytes":         ok[:15],
		"17 bytes":         append(append([]byte{}, ok...), 0),
		"announce action":  func() []byte { b := bytes.Clone(ok); b[11] = 1; return b }(),
		"scrape action":    func() []byte { b := bytes.Clone(ok); b[11] = 2; return b }(),
		"magic off by one": func() []byte { b := bytes.Clone(ok); b[7] ^= 1; return b }(),
		"magic high byte":  func() []byte { b := bytes.Clone(ok); b[0] = 1; return b }(),
		"all zero":         make([]byte, 16),
		// A real announce: the connection ID replaces the magic.
		"announce request": func() []byte {
			b := make([]byte, 98)
			rand.Read(b[:8])
			binary.BigEndian.PutUint32(b[8:], 1)
			return b
		}(),
	}
	for name, b := range misses {
		if _, err := SniffUDPTracker(b); err == nil {
			t.Errorf("%s matched", name)
		}
	}
}

// The DHT and tracker sniffers never claim uTP SYNs, QUIC or other real UDP
// first datagrams from testdata, and vice versa uTP never claims KRPC.
func TestSniffDHTAndTrackerAgainstOtherRealPackets(t *testing.T) {
	for _, p := range loadRealPackets(t) {
		if _, err := SniffDHT(p.data); err == nil {
			t.Errorf("SniffDHT matched %s", p.name)
		}
		if _, err := SniffUDPTracker(p.data); err == nil {
			t.Errorf("SniffUDPTracker matched %s", p.name)
		}
	}
	for name, m := range krpcMessages {
		if _, err := SniffUTP([]byte(m)); err == nil {
			t.Errorf("SniffUTP matched KRPC %s", name)
		}
	}
}

func FuzzSniffDHT(f *testing.F) {
	for _, m := range krpcMessages {
		f.Add([]byte(m))
	}
	for _, m := range krpcNearMisses {
		f.Add([]byte(m))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, err := SniffDHT(b)
		if err != nil && err != errNotBittorrent {
			t.Fatalf("unexpected error %v", err)
		}
	})
}

type realPacket struct {
	name string
	data []byte
}

// loadPackets reads "<name>|<hex>" lines from a testdata file.
func loadPackets(t *testing.T, path string) []realPacket {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var packets []realPacket
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, encoded, ok := strings.Cut(line, "|")
		if !ok {
			t.Fatalf("malformed line %q", line)
		}
		data, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		packets = append(packets, realPacket{name, data})
	}
	return packets
}

// loadRealPackets returns the uTP SYNs and the non-BitTorrent first datagrams
// captured for TestSniffUTPRealPackets.
func loadRealPackets(t *testing.T) []realPacket {
	return loadPackets(t, "testdata/udp_first_packets.txt")
}

// TestSniffDHTAndTrackerRealPackets runs the datagrams captured from libtorrent
// 2.0.11 and Transmission 4.1.0-beta.2 (testdata/udp_bt_first_packets.txt):
// every DHT message and UDP tracker connect request must be recognised by its
// sniffer and by no other; uTP datagrams and tracker replies by neither.
func TestSniffDHTAndTrackerRealPackets(t *testing.T) {
	counts := map[string]int{}
	for _, p := range loadPackets(t, "testdata/udp_bt_first_packets.txt") {
		kind, _, _ := strings.Cut(p.name, " ")
		counts[kind]++
		_, dhtErr := SniffDHT(p.data)
		_, trackerErr := SniffUDPTracker(p.data)
		switch kind {
		case "dht":
			if dhtErr != nil || trackerErr == nil {
				t.Errorf("%s: dht=%v tracker=%v", p.name, dhtErr, trackerErr)
			}
		case "tracker":
			if trackerErr != nil || dhtErr == nil {
				t.Errorf("%s: tracker=%v dht=%v", p.name, trackerErr, dhtErr)
			}
		case "not":
			if dhtErr == nil || trackerErr == nil {
				t.Errorf("%s: classified as BitTorrent DHT / tracker", p.name)
			}
		default:
			t.Fatalf("unknown label %q", p.name)
		}
	}
	if counts["dht"] < 6 || counts["tracker"] < 2 || counts["not"] < 4 {
		t.Fatalf("testdata incomplete: %v", counts)
	}
}
