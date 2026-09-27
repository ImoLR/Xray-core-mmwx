//go:build linux

package connection

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseProcTCPPreservesExactFourTupleAndState(t *testing.T) {
	fixture := `  sl  local_address rem_address   st
   0: 0164330A:CF08 147100CB:01BB 06 00000000:00000000 03:00001770 00000000
`
	result := map[socketTuple]string{}
	if err := parseProcTCP(strings.NewReader(fixture), false, result); err != nil {
		t.Fatal(err)
	}
	tuple := socketTuple{
		LocalIP: netip.MustParseAddr("10.51.100.1"), LocalPort: 53000,
		RemoteIP: netip.MustParseAddr("203.0.113.20"), RemotePort: 443,
	}
	if got := result[tuple]; got != tcpTimeWaitState {
		t.Fatalf("state for %#v = %q, want %q; all=%#v", tuple, got, tcpTimeWaitState, result)
	}
}

func TestParseProcTCP6NormalizesIPv6AndMappedIPv4(t *testing.T) {
	fixture := `  sl  local_address rem_address   st
   0: B80D0120000000000000000001000000:CF08 B80D0120000000000000000002000000:01BB 06 00000000:00000000 03:00001770 00000000
   1: 0000000000000000FFFF0000010200C0:CF09 0000000000000000FFFF0000026433C6:01BB 06 00000000:00000000 03:00001770 00000000
`
	result := map[socketTuple]string{}
	if err := parseProcTCP(strings.NewReader(fixture), true, result); err != nil {
		t.Fatal(err)
	}
	ipv6 := socketTuple{
		LocalIP: netip.MustParseAddr("2001:db8::1"), LocalPort: 53000,
		RemoteIP: netip.MustParseAddr("2001:db8::2"), RemotePort: 443,
	}
	if got := result[ipv6]; got != tcpTimeWaitState {
		t.Fatalf("IPv6 tuple was not normalized: got=%q all=%#v", got, result)
	}
	mapped := socketTuple{
		LocalIP: netip.MustParseAddr("192.0.2.1"), LocalPort: 53001,
		RemoteIP: netip.MustParseAddr("198.51.100.2"), RemotePort: 443,
	}
	if got := result[mapped]; got != tcpTimeWaitState {
		t.Fatalf("IPv4-mapped IPv6 tuple was not unmapped: got=%q all=%#v", got, result)
	}
}
