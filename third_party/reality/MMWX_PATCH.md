# MMWX 对 github.com/xtls/reality v0.0.0-20261014101318-83f621788ca8 的补丁

与官方 Xray-core v26.10.21 用的是同一版。这一版跟上了 Go 1.27 的 crypto/tls(此前的 20260908 停在 2025-05 的 Go 开发版,
缺 CVE-2025-61730 / CVE-2026-32283 / CVE-2026-56862 / CVE-2025-58189 的修复)。

`Conn.rawInput` 在这一版是 `*bytes.Buffer`:XTLS Vision 从 v26.10.21 起用 `vless.AccessTLSBuffers` 按字段类型取,
两种布局都认。2026-10-14 曾因 Vision 还按值读而 SIGSEGV(AgentB 实测先崩再被 OOM 杀),所以当时锁在 20260908 ——
升这个目录前先确认 Vision 的取法能认新布局(`proxy/vless/inbound/vision_layout_test.go`)。

补丁只改 `tls.go` 的 `Server()` 里挑 key share 的一段(搜 `MMWX:`)。

上游从 20260908 起拒绝**不带 X25519MLKEM768 的 Client Hello**(「reject outdated/strange Client Hello」)。
而 mihomo(到 2026-10-12 的上游版本都是)默认在 REALITY 里把 X25519MLKEM768 去掉,只有 `reality-opts` 里显式写
`support-x25519mlkem768: true` 才带 —— 照上游的服务端,基于 mihomo 的客户端(Clash Verge、FlClash、MeowX Android /
Windows 等)连 REALITY 节点一律失败(客户端报 `REALITY authentication failed`)。

补丁恢复上游之前的选择逻辑:有 X25519 就用它,没有再用 X25519MLKEM768 里的 X25519 部分;只有 X25519 的 Client Hello 也接受。
key share 重复出现这种畸形 Client Hello 仍按上游拒绝(上游用 `peerPub2 = nil` 同时表达「没有 MLKEM」和「重复」,这里拆成单独的 `strange`)。

等客户端普遍带上 X25519MLKEM768 之后可以去掉这个补丁(删 third_party/reality、去掉 go.mod 里的 replace)。
升级 reality 版本时:换掉整个目录,再把 `tls.go` 这一段照样改回来。
