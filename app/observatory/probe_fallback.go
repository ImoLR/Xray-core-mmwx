package observatory

// FallbackProbeURL 探测地址不通时补试的地址:Cloudflare 的 204。
//
// 有的机房 / 线路封了 google、gstatic:经这些出站探测默认地址一律失败,整组出站被判死,
// 设了兜底出站的负载均衡于是全走兜底(妙妙屋X #1367)。补试一个 Cloudflare 的地址,
// 任一个通就算活着。用 http:少一次 TLS 握手,慢线路上不至于卡在 5 秒超时上。
const FallbackProbeURL = "http://cp.cloudflare.com/generate_204"

// ProbeURLs 依次要试的探测地址:先用配置的(空时用 def),不通再试 FallbackProbeURL。
func ProbeURLs(configured, def string) []string {
	primary := configured
	if primary == "" {
		primary = def
	}
	if primary == FallbackProbeURL {
		return []string{primary}
	}
	return []string{primary, FallbackProbeURL}
}
