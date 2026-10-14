package singbridge

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type discardWriter struct{}

func (discardWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

// 单向活跃的连接(上行一直有心跳、下行静默)不能被读超时断掉(#1228);两个方向都静默才算空闲。
func TestPipeReadIdleCountsBothDirections(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	conn := &PipeConnWrapper{R: r, W: discardWriter{}, Idle: 300 * time.Millisecond}
	conn.touch()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := conn.Read(make([]byte, 16))
		done <- err
	}()

	// 上行每 100ms 一次心跳,持续 1.2s:远超 Idle,下行读不该超时
	for i := 0; i < 12; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			t.Fatalf("上行仍有心跳时下行读被断了(%v 后): %v", time.Since(start), err)
		default:
		}
	}
	// 心跳停了:Idle 之后应超时
	select {
	case err := <-done:
		if err != buf.ErrReadTimeout {
			t.Fatalf("应报读超时, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("两个方向都静默后迟迟没有超时")
	}
}

func TestPipeReadIdleTimesOutWhenSilent(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	conn := &PipeConnWrapper{R: r, W: discardWriter{}, Idle: 200 * time.Millisecond}
	conn.touch()
	start := time.Now()
	_, err := conn.Read(make([]byte, 16))
	if err != buf.ErrReadTimeout {
		t.Fatalf("应报读超时, got %v", err)
	}
	if el := time.Since(start); el < 150*time.Millisecond || el > time.Second {
		t.Fatalf("超时时间应约等于 Idle(200ms), 实际 %v", el)
	}
}

// 读到数据照常返回,并刷新活跃时间
func TestPipeReadPassesData(t *testing.T) {
	r, w := io.Pipe()
	conn := &PipeConnWrapper{R: r, W: discardWriter{}, Idle: time.Second}
	go func() { _, _ = w.Write([]byte("hello")) }()
	b := make([]byte, 16)
	n, err := conn.Read(b)
	if err != nil || string(b[:n]) != "hello" {
		t.Fatalf("got %q %v", b[:n], err)
	}
	if conn.lastActive.Load() == 0 {
		t.Fatal("读到数据后应刷新活跃时间")
	}
}
