package bittorrent

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"os"
	"strings"
	"testing"
)

// TestSniffUTPRealPackets runs SniffUTP over datagrams captured from real programs
// (testdata/udp_first_packets.txt): the ST_SYN of every BitTorrent client must be
// recognised (libtorrent and Transmission 4 send no extension, Transmission 2.94 /
// old libutp sends extension 2), and nothing else may be: other uTP packet types,
// QUIC, DNS, WireGuard, STUN and NTP first packets.
func TestSniffUTPRealPackets(t *testing.T) {
	f, err := os.Open("testdata/udp_first_packets.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	syn, other := 0, 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, encoded, ok := strings.Cut(line, "|")
		if !ok {
			t.Fatalf("malformed line %q", line)
		}
		payload, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		isSYN := strings.HasPrefix(name, "syn ")
		if isSYN {
			syn++
		} else {
			other++
		}
		t.Run(name, func(t *testing.T) {
			h, err := SniffUTP(payload)
			if isSYN && (err != nil || h == nil) {
				t.Fatalf("uTP SYN not recognised: %v", err)
			}
			if !isSYN && err == nil {
				t.Fatal("classified as BitTorrent")
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if syn < 9 || other < 12 {
		t.Fatalf("testdata incomplete: %d SYNs, %d others", syn, other)
	}
}

// TestSniffUTPIgnoresOtherUDP feeds common non-BitTorrent first packets that have no
// fixed capture: RTP / RTCP voice, game queries, random game-like datagrams and the
// DNS queries whose header looks most like uTP (transaction id 0x41xx, no EDNS).
func TestSniffUTPIgnoresOtherUDP(t *testing.T) {
	r := rand.New(rand.NewSource(6667))
	random := func(n int) []byte {
		b := make([]byte, n)
		r.Read(b)
		return b
	}
	var cases [][]byte
	for i := 0; i < 2000; i++ {
		rtp := []byte{0x80, byte(r.Intn(128))}
		rtp = binary.BigEndian.AppendUint16(rtp, uint16(r.Uint32()))
		rtp = binary.BigEndian.AppendUint32(rtp, r.Uint32())
		rtp = binary.BigEndian.AppendUint32(rtp, r.Uint32())
		cases = append(cases, append(rtp, random(20+r.Intn(300))...))
		cases = append(cases, append([]byte{0x81, 201, 0, 7}, random(28)...)) // RTCP receiver report
	}
	cases = append(cases,
		append([]byte{0xff, 0xff, 0xff, 0xff}, []byte("TSource Engine Query\x00")...),
		append(append([]byte{0x01, 0, 0, 0, 0, 0, 0, 0x12, 0x34}, []byte{0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78}...), random(8)...), // RakNet ping
	)
	for i := 0; i < 100000; i++ {
		cases = append(cases, random(8+r.Intn(1400)))
	}
	// Not covered on purpose: a query for a bare two-letter TLD ("co.") with transaction id
	// exactly 0x4100 and no EDNS is 20 bytes and byte for byte a valid ST_SYN.
	names := [][]byte{{1, 'a', 0}, {2, 't', 'w', 2, 'c', 'o', 0}, {1, 't', 2, 'c', 'o', 0}, {6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0}}
	for txid := 0x4100; txid <= 0x41ff; txid++ {
		for _, flags := range []uint16{0x0100, 0x0000} {
			for _, name := range names {
				for _, qtype := range []uint16{1, 28, 65} {
					q := binary.BigEndian.AppendUint16(nil, uint16(txid))
					q = binary.BigEndian.AppendUint16(q, flags)
					q = append(q, 0, 1, 0, 0, 0, 0, 0, 0)
					q = append(q, name...)
					q = binary.BigEndian.AppendUint16(q, qtype)
					cases = append(cases, binary.BigEndian.AppendUint16(q, 1))
				}
			}
		}
	}
	for _, payload := range cases {
		if _, err := SniffUTP(payload); err == nil {
			t.Fatalf("classified as BitTorrent: %x", payload)
		}
	}
}
