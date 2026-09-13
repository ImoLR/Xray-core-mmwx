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
