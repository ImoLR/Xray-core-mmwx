package inbound

import "testing"

type namedConnectionInbound string

func (n namedConnectionInbound) ConnectionInboundName() string { return string(n) }

func TestConfiguredInboundNameRequiresInstrumentedDataPlane(t *testing.T) {
	if name, ok := configuredInboundName(struct{}{}); ok || name != "" {
		t.Fatalf("untracked handler returned name=%q ok=%v", name, ok)
	}
	if name, ok := configuredInboundName(namedConnectionInbound("")); ok || name != "" {
		t.Fatalf("empty tracked name returned name=%q ok=%v", name, ok)
	}
	if name, ok := configuredInboundName(namedConnectionInbound("shadowsocks-2022-multi")); !ok || name != "shadowsocks-2022-multi" {
		t.Fatalf("tracked handler returned name=%q ok=%v", name, ok)
	}
}
