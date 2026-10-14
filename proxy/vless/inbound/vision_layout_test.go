package inbound

import (
	"bytes"
	gotls "crypto/tls"
	"reflect"
	"testing"

	"github.com/xtls/reality"
)

// XTLS Vision 用 reflect + unsafe 直接取 TLS / REALITY 连接里的 input、rawInput(见 Process 里的 Flow 分支),
// 按 bytes.Reader / bytes.Buffer 的值去读。上游 reality 20261014 把 rawInput 改成了 *bytes.Buffer,
// 照旧去读就是把指针当结构体 —— REALITY + Vision 一有数据就 SIGSEGV(测试机实测先崩再被 OOM 杀)。
// 字段类型一变,这里先红,别等到线上。
func TestVisionConnFieldLayout(t *testing.T) {
	for name, typ := range map[string]reflect.Type{
		"crypto/tls.Conn": reflect.TypeOf(gotls.Conn{}),
		"reality.Conn":    reflect.TypeOf(reality.Conn{}),
	} {
		for field, want := range map[string]reflect.Type{
			"input":    reflect.TypeOf(bytes.Reader{}),
			"rawInput": reflect.TypeOf(bytes.Buffer{}),
		} {
			f, ok := typ.FieldByName(field)
			if !ok {
				t.Fatalf("%s 没有字段 %s,XTLS Vision 取不到它", name, field)
			}
			if f.Type != want {
				t.Fatalf("%s.%s 的类型是 %v,XTLS Vision 按 %v 去读 —— 要先改 Vision 的取法再升级", name, field, f.Type, want)
			}
		}
	}
}
