package anytls

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

func queueFrame(fill byte, n int) buf.MultiBuffer {
	var mb buf.MultiBuffer
	for n > 0 {
		b := buf.New()
		size := n
		if size > buf.Size {
			size = buf.Size
		}
		for i, p := 0, b.Extend(int32(size)); i < len(p); i++ {
			p[i] = fill
		}
		mb = append(mb, b)
		n -= size
	}
	return mb
}

func pushAsync(q *uplinkQueue, mb buf.MultiBuffer) <-chan error {
	done := make(chan error, 1)
	go func() { done <- q.push(mb) }()
	return done
}

// 按帧保序;放不下时 push 等到消费方取走一帧才返回;空队列总是收下,单帧再大也不会死等。
func TestUplinkQueueOrderAndLimit(t *testing.T) {
	q := newUplinkQueue()
	const frame = 60000 // 占 8 个 8KiB 池缓冲
	n := uplinkQueueLimit / (8 * buf.Size)
	for i := 0; i < n; i++ {
		if err := q.push(queueFrame(byte(i), frame)); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	blocked := pushAsync(q, queueFrame(byte(n), frame))
	select {
	case err := <-blocked:
		t.Fatalf("push beyond the limit returned early: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	for i := 0; i <= n; i++ {
		mb, err := q.ReadMultiBuffer()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if mb.Len() != frame || mb[0].Byte(0) != byte(i) {
			t.Fatalf("frame %d out of order: len=%d first=%d", i, mb.Len(), mb[0].Byte(0))
		}
		buf.ReleaseMulti(mb)
		if i == 0 {
			select {
			case err := <-blocked:
				if err != nil {
					t.Fatalf("blocked push: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("push still blocked after the consumer took a frame")
			}
		}
	}

	big := newUplinkQueue()
	select {
	case err := <-pushAsync(big, queueFrame('x', 2*uplinkQueueLimit)):
		if err != nil {
			t.Fatalf("oversized push into an empty queue: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("oversized push into an empty queue blocked forever")
	}
}

// 按缓冲实际占用记账:1 字节的小帧每个也占一个 8KiB 池缓冲,队列装满 uplinkQueueLimit/8KiB 个就得等,
// 不能按有效字节算成能装几十万个(那样实际占用是上限的几千倍)。
func TestUplinkQueueBoundsMemoryOfTinyFrames(t *testing.T) {
	q := newUplinkQueue()
	defer q.abort()
	for i := 0; i < uplinkQueueLimit/buf.Size; i++ {
		if err := q.push(queueFrame('t', 1)); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	select {
	case err := <-pushAsync(q, queueFrame('t', 1)):
		t.Fatalf("tiny frame admitted beyond the memory limit (err=%v)", err)
	case <-time.After(100 * time.Millisecond):
	}
}

// closeWrite(FIN)之后:已入队的照常按序取完,然后 io.EOF;再 push 失败并释放帧体。
func TestUplinkQueueCloseWriteDrainsThenEOF(t *testing.T) {
	q := newUplinkQueue()
	for i := 0; i < 3; i++ {
		if err := q.push(queueFrame(byte('a'+i), 100)); err != nil {
			t.Fatal(err)
		}
	}
	q.closeWrite()
	for i := 0; i < 3; i++ {
		mb, err := q.ReadMultiBuffer()
		if err != nil || mb[0].Byte(0) != byte('a'+i) {
			t.Fatalf("read %d after closeWrite: err=%v", i, err)
		}
		buf.ReleaseMulti(mb)
	}
	if _, err := q.ReadMultiBuffer(); err != io.EOF {
		t.Fatalf("after draining got %v, want io.EOF", err)
	}
	late := queueFrame('z', 100)
	lateBuf := late[0] // ReleaseMulti 会把切片里的指针清成 nil,先留一份
	if err := q.push(late); err == nil {
		t.Fatal("push after closeWrite succeeded")
	}
	if lateBuf.Bytes() != nil {
		t.Fatal("rejected frame was not released")
	}
}

// abort 叫醒卡在满队列上的 push 和卡在空队列上的读,并释放队列里剩下的全部缓冲。
func TestUplinkQueueAbortWakesAndReleases(t *testing.T) {
	empty := newUplinkQueue()
	readErr := make(chan error, 1)
	go func() {
		_, err := empty.ReadMultiBuffer()
		readErr <- err
	}()
	time.Sleep(20 * time.Millisecond)
	empty.abort()
	select {
	case err := <-readErr:
		if err != io.ErrClosedPipe {
			t.Fatalf("read on aborted queue: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("abort did not wake a blocked reader")
	}

	q := newUplinkQueue()
	var queued []*buf.Buffer
	for i := 0; i < uplinkQueueLimit/(8*buf.Size); i++ {
		mb := queueFrame('q', 60000)
		queued = append(queued, mb...)
		if err := q.push(mb); err != nil {
			t.Fatal(err)
		}
	}
	pending := queueFrame('p', 60000)
	queued = append(queued, pending...) // ReleaseMulti 会把切片里的指针清成 nil,先留一份
	blocked := pushAsync(q, pending)
	time.Sleep(20 * time.Millisecond)
	q.abort()
	select {
	case err := <-blocked:
		if err != io.ErrClosedPipe {
			t.Fatalf("blocked push after abort: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("abort did not wake a push blocked on a full queue")
	}
	for i, b := range queued {
		if b.Bytes() != nil {
			t.Fatalf("buffer %d not released by abort", i)
		}
	}
	if _, err := q.ReadMultiBuffer(); err != io.ErrClosedPipe {
		t.Fatalf("read after abort: %v", err)
	}
	q.abort() // 幂等
}
