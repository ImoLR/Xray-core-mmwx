package dispatcher

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

// The UDP sniffer chain reports Mainline DHT messages and UDP tracker connect
// requests as "bittorrent", the protocol the existing routing rules match.
func TestSnifferReportsUDPBitTorrent(t *testing.T) {
	connect := make([]byte, 16)
	binary.BigEndian.PutUint64(connect, 0x41727101980)
	binary.BigEndian.PutUint32(connect[12:], 0x1234)
	cases := map[string][]byte{
		"DHT ping":            []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"),
		"DHT response":        []byte("d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"),
		"UDP tracker connect": connect,
	}
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	for name, payload := range cases {
		result, err := NewSniffer(ctx).Sniff(ctx, payload, net.Network_UDP)
		if err != nil || result.Protocol() != "bittorrent" {
			t.Errorf("%s: %v %v", name, result, err)
		}
		// TCP never runs the UDP sniffers.
		if result, err := NewSniffer(ctx).Sniff(ctx, payload, net.Network_TCP); err == nil && result.Protocol() == "bittorrent" {
			t.Errorf("%s classified as bittorrent over TCP", name)
		}
	}
	// An ordinary DNS query is decided at once, without waiting for more data.
	dns := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := NewSniffer(ctx).Sniff(ctx, dns, net.Network_UDP); err != errUnknownContent {
		t.Fatalf("DNS query: %v", err)
	}
}
