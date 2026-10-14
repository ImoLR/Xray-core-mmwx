# MMWX 对 github.com/xtls/reality v0.0.0-20260908062103-8cdf7bf9c7f0 的补丁

版本锁在 v26.10.10 用的这一版,**不要**跟官方 main 升到 20261014101318:那一版把 `Conn.rawInput` 从
`bytes.Buffer` 改成了 `*bytes.Buffer`(空闲时还给池子),而 xray 的 XTLS Vision(proxy/vless/inbound、proxy/proxy.go)
仍按值去取这个字段(reflect + unsafe),REALITY + Vision 一有数据就 SIGSEGV / 读到垃圾长度把内存吃光
(2026-10-14 在测试机 AgentB 上实测:agent 先崩、再被 OOM 杀)。等官方 xray 把 Vision 的取法跟上再一起升。

补丁只改 `tls.go` 的 `Server()` 里挑 key share 的一段(搜 `MMWX:`)。

上游从这一版起拒绝**不带 X25519MLKEM768 的 Client Hello**(「reject outdated/strange Client Hello」)。
而 mihomo(到 2026-10-12 的上游版本都是)默认在 REALITY 里把 X25519MLKEM768 去掉,只有 `reality-opts` 里显式写
`support-x25519mlkem768: true` 才带 —— 照上游的服务端,基于 mihomo 的客户端(Clash Verge、FlClash、MeowX Android /
Windows 等)连 REALITY 节点一律失败(客户端报 `REALITY authentication failed`)。

补丁恢复上游之前的选择逻辑:有 X25519 就用它,没有再用 X25519MLKEM768 里的 X25519 部分;只有 X25519 的 Client Hello 也接受。
key share 重复出现这种畸形 Client Hello 仍按上游拒绝(上游用 `peerPub2 = nil` 同时表达「没有 MLKEM」和「重复」,这里拆成单独的 `strange`)。

等客户端普遍带上 X25519MLKEM768 之后可以去掉这个补丁(删 third_party/reality、去掉 go.mod 里的 replace)。
升级 reality 版本时:换掉整个目录,再把 `tls.go` 这一段照样改回来。
