package observatory

import (
	"slices"
	"testing"
)

func TestProbeURLs(t *testing.T) {
	def := "https://www.google.com/generate_204"
	if got := ProbeURLs("", def); !slices.Equal(got, []string{def, FallbackProbeURL}) {
		t.Fatalf("没配时先试默认地址再试 Cloudflare: %v", got)
	}
	if got := ProbeURLs("http://www.gstatic.com/generate_204", def); !slices.Equal(got, []string{"http://www.gstatic.com/generate_204", FallbackProbeURL}) {
		t.Fatalf("配了的地址优先: %v", got)
	}
	if got := ProbeURLs(FallbackProbeURL, def); !slices.Equal(got, []string{FallbackProbeURL}) {
		t.Fatalf("配的就是 Cloudflare 时不重复试: %v", got)
	}
}
