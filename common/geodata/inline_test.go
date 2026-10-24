package geodata

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
)

func writeGeoFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)
	cidr := func(s string) *CIDR {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		ones, _ := n.Mask.Size()
		ip := n.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		return &CIDR{Ip: ip, Prefix: uint32(ones)}
	}
	ips := &GeoIPList{Entry: []*GeoIP{
		{Code: "CN", Cidr: []*CIDR{cidr("1.0.1.0/24"), cidr("1.0.2.0/23"), cidr("2400:da00::/32")}},
		{Code: "HK", Cidr: []*CIDR{cidr("5.0.0.0/8")}},
		{Code: "EMPTY"},
	}}
	sites := &GeoSiteList{Entry: []*GeoSite{
		{Code: "CN", Domain: []*Domain{
			{Type: Domain_Domain, Value: "qq.com", Attribute: []*Domain_Attribute{{Key: "cn"}}},
			{Type: Domain_Full, Value: "www.baidu.com"},
			{Type: Domain_Regex, Value: `^img\d+\.example\.cn$`},
			{Type: Domain_Substr, Value: "taobao"},
		}},
		{Code: "OPENAI", Domain: []*Domain{{Type: Domain_Domain, Value: "openai.com"}, {Type: Domain_Full, Value: "chatgpt.com"}}},
		{Code: "EMPTY"},
	}}
	for name, msg := range map[string]proto.Message{"geoip.dat": ips, "geosite.dat": sites} {
		raw, err := proto.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Inlined rules match exactly what the references match.
func TestInlineIPRulesMatchesLikeReferences(t *testing.T) {
	writeGeoFiles(t)
	cases := [][]string{
		{"geoip:cn"},
		{"geoip:cn", "geoip:hk", "8.8.8.8"},
		{"geoip:!cn"},
		{"geoip:!cn", "geoip:!hk"},
		{"geoip:!cn", "!8.8.8.0/24"}, // negated CIDR present: the negated reference stays
		{"geoip:cn", "!8.8.8.0/24"},
		{"geoip:empty"},
		{"geoip:!empty"},
		{"geoip:empty", "9.9.9.9"},
	}
	r := rand.New(rand.NewSource(1))
	probes := []string{"1.0.1.7", "1.0.2.255", "1.0.3.1", "1.0.4.1", "5.6.7.8", "8.8.8.8", "8.8.8.200", "9.9.9.9", "2400:da00::1", "2400:db00::1"}
	for i := 0; i < 2000; i++ {
		probes = append(probes, fmt.Sprintf("%d.%d.%d.%d", []int{1, 5, 8, 9, 100}[r.Intn(5)], r.Intn(256), r.Intn(256), r.Intn(256)))
	}
	for _, c := range cases {
		original, err := ParseIPRules(c)
		if err != nil {
			t.Fatal(err)
		}
		inlined, err := InlineIPRules(original)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range inlined {
			if g, ok := rule.Value.(*IPRule_Geoip); ok && g.Geoip.Code != "EMPTY" && !(g.Geoip.ReverseMatch && len(c) > 1 && c[1][0] == '!') {
				t.Fatalf("%v: reference left after inlining: %v", c, g.Geoip)
			}
		}
		want, err := IPReg.BuildIPMatcher(original)
		if err != nil {
			t.Fatal(err)
		}
		got, err := IPReg.BuildIPMatcher(inlined)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range probes {
			ip := net.ParseIP(p)
			if want.Match(ip) != got.Match(ip) {
				t.Fatalf("%v: %s matched %v by reference, %v inlined", c, p, want.Match(ip), got.Match(ip))
			}
		}
	}
}

func TestInlineDomainRulesMatchesLikeReferences(t *testing.T) {
	writeGeoFiles(t)
	cases := [][]string{
		{"geosite:cn"},
		{"geosite:cn@cn"},
		{"geosite:openai", "geosite:cn", "full:example.org"},
		{"geosite:empty"},
		{"geosite:empty", "domain:example.net"},
	}
	probes := []string{"qq.com", "www.qq.com", "qq.com.evil", "www.baidu.com", "baidu.com", "img12.example.cn", "imgx.example.cn",
		"shop.taobao.com", "openai.com", "api.openai.com", "chatgpt.com", "www.chatgpt.com", "example.org", "www.example.org", "example.net", "other.test"}
	for _, c := range cases {
		original, err := ParseDomainRules(c, Domain_Substr)
		if err != nil {
			t.Fatal(err)
		}
		inlined, err := InlineDomainRules(original)
		if err != nil {
			t.Fatal(err)
		}
		want, err := DomainReg.BuildDomainMatcher(original)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DomainReg.BuildDomainMatcher(inlined)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range probes {
			if want.MatchAny(p) != got.MatchAny(p) {
				t.Fatalf("%v: %s matched %v by reference, %v inlined", c, p, want.MatchAny(p), got.MatchAny(p))
			}
		}
	}
}

func TestInlineRulesMissingFile(t *testing.T) {
	t.Setenv("xray.location.asset", t.TempDir())
	if _, err := InlineIPRules([]*IPRule{{Value: &IPRule_Geoip{Geoip: &GeoIPRule{File: "geoip.dat", Code: "CN"}}}}); err == nil {
		t.Fatal("missing geoip.dat not reported")
	}
	if _, err := InlineDomainRules([]*DomainRule{{Value: &DomainRule_Geosite{Geosite: &GeoSiteRule{File: "geosite.dat", Code: "CN"}}}}); err == nil {
		t.Fatal("missing geosite.dat not reported")
	}
}
