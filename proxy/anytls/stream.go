package anytls

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

// uplinkQueueLimit 是服务端每条流上行队列最多占住的内存(按缓冲实际大小记账,见 push)。
//
// AnyTLS 没有逐流的流控窗口,队列满了只能让 readLoop 停下来等(丢数据会把 TCP 流写乱),
// 所以这个值同时决定两件事:一条流被限速 / 出站慢卡住时,同会话别的流还能照常收发的余量;
// 以及一条流最多压多少内存(另加消费方手里正在写的一帧)。取 512KiB:请求、握手、小上传这类
// 突发远小于它,不会顶满;与 xray 在 amd64 上每条连接的默认缓冲(policy buffer)同量级,
// 一条 anytls 流不会比一条普通连接多占一个数量级的内存。持续超速的上传放多大都会顶满,
// 那时让整条会话跟着它的速度走,是没有流控窗口的协议里唯一的背压办法,再大也只是推迟。
const uplinkQueueLimit = 512 << 10

// uplinkQueue 是服务端一条流的有界上行队列:readLoop 按帧 push,消费方按帧取,同一条流严格保序。
//
//   - 队列满时 push 阻塞,直到消费方取走一帧或队列被 abort;空队列总是收下,单帧再大也不会死等。
//   - closeWrite(客户端 FIN):不再有新数据,消费方把已入队的取完后拿到 io.EOF。
//   - abort(流被结束):丢弃并释放还没取走的帧体,两端都立刻返回 io.ErrClosedPipe。
type uplinkQueue struct {
	mu    sync.Mutex
	cond  *sync.Cond
	items []buf.MultiBuffer
	size  int32
	eof   bool
	dead  bool
}

func newUplinkQueue() *uplinkQueue {
	q := &uplinkQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// push 把一帧的帧体入队。按缓冲实际大小(Cap)记账而不是有效字节:readMultiBufferExact 每帧
// 至少占一个 8KiB 的池缓冲,按字节记的话,客户端对着被限速的流狂发 1 字节的小帧,
// 队列实际占用能超出上限几千倍。失败(队列已结束)时 mb 已释放。
func (q *uplinkQueue) push(mb buf.MultiBuffer) error {
	n := bufMem(mb)
	q.mu.Lock()
	for !q.dead && !q.eof && q.size > 0 && q.size+n > uplinkQueueLimit {
		q.cond.Wait()
	}
	if q.dead || q.eof {
		q.mu.Unlock()
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	q.items = append(q.items, mb)
	q.size += n
	q.mu.Unlock()
	q.cond.Broadcast()
	return nil
}

// ReadMultiBuffer 取出最早入队的一帧,队列空时阻塞。实现 buf.Reader:UoT 路径拿它套
// buf.BufferedReader 逐字节解析。一次只取一帧而不是全部取走,限速时每帧拿到令牌就先写出去,
// 腾出的位置也能马上让给 readLoop。
func (q *uplinkQueue) ReadMultiBuffer() (buf.MultiBuffer, error) {
	q.mu.Lock()
	for !q.dead && !q.eof && len(q.items) == 0 {
		q.cond.Wait()
	}
	if q.dead {
		q.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	if len(q.items) == 0 {
		q.mu.Unlock()
		return nil, io.EOF
	}
	mb := q.items[0]
	q.items[0] = nil
	q.items = q.items[1:]
	q.size -= bufMem(mb)
	q.mu.Unlock()
	q.cond.Broadcast()
	return mb, nil
}

func (q *uplinkQueue) closeWrite() {
	q.mu.Lock()
	q.eof = true
	q.mu.Unlock()
	q.cond.Broadcast()
}

func bufMem(mb buf.MultiBuffer) int32 {
	var n int32
	for _, b := range mb {
		n += b.Cap()
	}
	return n
}

// abort 幂等;释放在锁外做。
func (q *uplinkQueue) abort() {
	q.mu.Lock()
	q.dead = true
	items := q.items
	q.items = nil
	q.size = 0
	q.mu.Unlock()
	q.cond.Broadcast()
	for _, mb := range items {
		buf.ReleaseMulti(mb)
	}
}

type stream struct {
	sid  uint32
	link *transport.Link

	// cancel 取消本条流专属的 dispatch ctx。dispatcher 在 Dispatch 时对该 ctx 注册了
	// online-IP 的 RemoveIP(AfterFunc),所以流结束时必须调它,否则在线 IP 直到整个
	// anytls 会话(可能被客户端连接池长期保活)关闭才清 —— 表现为「断连后面板仍记录连接」(#731)。
	// context.CancelFunc 幂等,可从 close()/pumpDownlink 多处安全调用。
	cancel context.CancelFunc

	// up 是服务端这条流的上行队列(普通 TCP 流、UoT 流、fork 客户端的 raw UDP 流都有;
	// 客户端侧的流没有,仍在 readLoop 里同步写)。readLoop 读完 PSH 帧体入队就去读下一帧,
	// 由这条流自己的 goroutine 按序写进出站,等限速令牌、等出站腾缓冲都只卡这一条流。
	up *uplinkQueue
	// finRecv:客户端已发 FIN,up 正在排空(流还留在 map 里,会话关闭时照样能中止它)。只由 readLoop 读写。
	finRecv bool

	done     chan struct{}
	doneOnce sync.Once
	errMu    sync.Mutex
	err      error
	dieHook  func()

	isUDP     bool
	udpTarget *xnet.Destination

	// udpPipe 为 true 时走 canonical full-cone 路径:PSH 帧体进 up,由 handleUDPStream
	// 逐包解目标写进单条 freedom link;fork 自身客户端(client=xray)不置此位,仍走 raw 透传。
	udpPipe      bool
	uotConnected bool
	uotDest      xnet.Destination
}

func newStream(sid uint32, link *transport.Link) *stream {
	return &stream{
		sid:  sid,
		link: link,
		done: make(chan struct{}),
	}
}

func (st *stream) close(err error) {
	// 流结束即取消其 dispatch ctx → 触发 dispatcher 注册的 RemoveIP,让在线 IP 按活跃流实时清理(#731)。
	if st.cancel != nil {
		st.cancel()
	}
	// 中止上行队列:释放还没写出去的帧体,叫醒卡在入队上的 readLoop 和卡在取队上的消费方
	// (writeUplink / handleUDPStream)。消费方若正卡在往 link 里写,靠上面的 cancel(RateWriter
	// 等令牌认 ctx)和关 link.Writer(出站 pipe 满时的等待;UoT 流的由 handleUDPStream 挂在 ctx 上关)打断。
	if st.up != nil {
		st.up.abort()
	}
	if st.done == nil {
		if st.link != nil {
			common.Close(st.link.Reader)
			common.Close(st.link.Writer)
		}
		return
	}
	st.doneOnce.Do(func() {
		st.errMu.Lock()
		st.err = err
		st.errMu.Unlock()
		if st.link != nil {
			common.Close(st.link.Reader)
			common.Close(st.link.Writer)
		}
		close(st.done)
		if st.dieHook != nil {
			st.dieHook()
		}
	})
}

func (st *stream) result() error {
	st.errMu.Lock()
	defer st.errMu.Unlock()
	return st.err
}
