package conf

import "strings"

// RegisterInboundConfigCreator 让外部包(不在本仓库内的协议实现)把自己的 JSON 配置类型挂到
// inbound 的 "protocol" 名下,之后 InboundDetourConfig.Build 就能认出 "protocol": "<name>"。
//
// 内置协议都直接写在 xray.go 的两张表里;外部协议没法改那两张表,只能走这里。
// 表是普通 map、没有锁,所以只能在 init() 里调用(包级变量先于 init 初始化,顺序是安全的)。
func RegisterInboundConfigCreator(protocol string, creator ConfigCreator) error {
	return inboundConfigLoader.cache.RegisterCreator(strings.ToLower(protocol), creator)
}

// RegisterOutboundConfigCreator 同 RegisterInboundConfigCreator,作用于 outbound 表。
func RegisterOutboundConfigCreator(protocol string, creator ConfigCreator) error {
	return outboundConfigLoader.cache.RegisterCreator(strings.ToLower(protocol), creator)
}
