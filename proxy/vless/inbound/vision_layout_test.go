package inbound

import (
	"bytes"
	gotls "crypto/tls"
	"net"
	"reflect"
	"testing"

	"github.com/xtls/reality"
	"github.com/xtls/xray-core/proxy/vless"
)

// XTLS Vision 要直接取 TLS / REALITY 连接里的 input、rawInput(见 Process 里的 Flow 分支)。
// 取法是 vless.AccessTLSBuffers:rawInput 是 bytes.Buffer(旧布局)或 *bytes.Buffer(reality 20261014 起)都认。
// 2026-10-14 曾因 Vision 只按值读、reality 换成指针而 SIGSEGV(测试机先崩再被 OOM 杀)。
// 字段改名或换成第三种类型时这里先红,别等到线上。
func TestVisionConnFieldLayout(t *testing.T) {
	for name, conn := range map[string]net.Conn{
		"crypto/tls.Conn": &gotls.Conn{},
		"reality.Conn":    &reality.Conn{},
	} {
		typ := reflect.TypeOf(conn).Elem()
		in, ok := typ.FieldByName("input")
		if !ok || in.Type != reflect.TypeOf(bytes.Reader{}) {
			t.Fatalf("%s.input 不是 bytes.Reader(%v),XTLS Vision 取不到它", name, in.Type)
		}
		raw, ok := typ.FieldByName("rawInput")
		if !ok || (raw.Type != reflect.TypeOf(bytes.Buffer{}) && raw.Type != reflect.TypeOf(&bytes.Buffer{})) {
			t.Fatalf("%s.rawInput 的类型是 %v,AccessTLSBuffers 只认 bytes.Buffer / *bytes.Buffer —— 要先改取法再升级", name, raw.Type)
		}
		input, rawInput := vless.AccessTLSBuffers(conn)
		if input == nil || rawInput == nil {
			t.Fatalf("%s: AccessTLSBuffers 返回了 nil", name)
		}
	}
}
