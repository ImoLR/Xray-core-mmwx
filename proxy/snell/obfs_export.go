package snell

import "net"

// simple-obfs(http / tls)是 Surge / mihomo 共用的一套协议:snell 的 obfs 与 Shadowsocks 的
// `plugin: obfs` 用的是同一个实现。这里把服务端包装导出给 shadowsocks 入站复用,避免两份实现漂移。

// ValidObfsMode 校验混淆模式:"" / none / http / tls。
func ValidObfsMode(mode string) error {
	_, err := parseObfsMode(mode)
	return err
}

// NewObfsServerConn 服务端混淆包装;mode 为 "" / none 时原样返回 conn。
func NewObfsServerConn(conn net.Conn, mode, host string) (net.Conn, error) {
	m, err := parseObfsMode(mode)
	if err != nil {
		return nil, err
	}
	return obfsConfig{mode: m, host: host}.serverConn(conn), nil
}

// NewObfsClientConn 客户端混淆包装(供测试与出站使用);mode 为 "" / none 时原样返回 conn。
func NewObfsClientConn(conn net.Conn, mode, host string) (net.Conn, error) {
	m, err := parseObfsMode(mode)
	if err != nil {
		return nil, err
	}
	return obfsConfig{mode: m, host: host}.clientConn(conn), nil
}
