package anytls

// 服务端上行「每条流一个有界队列 + 独立写 goroutine」的行为测试:用 net.Pipe 跑真实的 readLoop,
// 测试这头按 AnyTLS 帧格式扮演 canonical 客户端(mihomo / sing-box)。
// 被限速卡住的出站用 gateWriter 模拟:写入一直阻塞,直到放行或 link 被关(同 pipe)。

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	sessionctx "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

// ---- 测试用出站 ----

// gateWriter:写入先阻塞到 release(放行)或 Close(关 link;阻塞中的写返回 ErrClosedPipe,同 pipe)。
// 记下写进来的全部字节,以及 Close 那一刻已经写了多少。
type gateWriter struct {
	entered   chan struct{}
	enterOnce sync.Once
	open      chan struct{}
	openOnce  sync.Once
	closed    chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	data     []byte
	closedAt int // Close 时 len(data);-1 = 还没 Close
}

func newGateWriter() *gateWriter {
	return &gateWriter{entered: make(chan struct{}), open: make(chan struct{}), closed: make(chan struct{}), closedAt: -1}
}

func (w *gateWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.enterOnce.Do(func() { close(w.entered) })
	select {
	case <-w.closed:
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	default:
	}
	select {
	case <-w.open:
	case <-w.closed:
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	w.mu.Lock()
	for _, b := range mb {
		w.data = append(w.data, b.Bytes()...)
	}
	w.mu.Unlock()
	buf.ReleaseMulti(mb)
	return nil
}

func (w *gateWriter) release() { w.openOnce.Do(func() { close(w.open) }) }

func (w *gateWriter) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closedAt = len(w.data)
		w.mu.Unlock()
		close(w.closed)
	})
	return nil
}

func (w *gateWriter) snapshot() (data []byte, closedAt int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.data...), w.closedAt
}

// failWriter 模拟 link 已被踢掉 / 关掉:写一律失败。
type failWriter struct{}

func (failWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return io.ErrClosedPipe
}

// holDispatcher 按目标端口给出预先登记的 link;没登记的端口给一条直接吞数据、没有下行的 link。
type holDispatcher struct {
	links map[xnet.Port]*transport.Link
}

func (*holDispatcher) Type() interface{} { return nil }
func (*holDispatcher) Start() error      { return nil }
func (*holDispatcher) Close() error      { return nil }
func (d *holDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	if l := d.links[dest.Port]; l != nil {
		return l, nil
	}
	return &transport.Link{Reader: &blockingReader{done: make(chan struct{})}, Writer: nopWriter{}}, nil
}
func (d *holDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return nil
}

func gateLink(w buf.Writer) (*transport.Link, *blockingReader) {
	r := &blockingReader{done: make(chan struct{})}
	return &transport.Link{Reader: r, Writer: w}, r
}

// ---- 测试用客户端 ----

func holFrame(cmd byte, sid uint32, data []byte) []byte {
	b := make([]byte, 7+len(data))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(data)))
	copy(b[7:], data)
	return b
}

func holAddr(t *testing.T, dest string) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := M.SocksaddrSerializer.WriteAddrPort(&b, M.ParseSocksaddr(dest)); err != nil {
		t.Fatalf("encode dest: %v", err)
	}
	return b.Bytes()
}

// holUoTOpen:一条 not-connected UoT 流的 SYN、魔术地址、uot 请求头,外加 pkts 个发往 dest 的包。
func holUoTOpen(t *testing.T, sid uint32, dest string, pkts int) [][]byte {
	t.Helper()
	var req bytes.Buffer
	if err := uot.WriteRequest(&req, uot.Request{IsConnect: false, Destination: M.ParseSocksaddr(dest)}); err != nil {
		t.Fatalf("encode uot request: %v", err)
	}
	frames := [][]byte{
		holFrame(cmdSYN, sid, nil),
		holFrame(cmdPSH, sid, holAddr(t, "sp.v2.udp-over-tcp.arpa:0")),
		holFrame(cmdPSH, sid, req.Bytes()),
	}
	for i := 0; i < pkts; i++ {
		var pkt bytes.Buffer
		if err := uot.AddrParser.WriteAddrPort(&pkt, M.ParseSocksaddr(dest)); err != nil {
			t.Fatalf("encode packet addr: %v", err)
		}
		payload := []byte("udp-payload")
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(payload)))
		pkt.Write(lb[:])
		pkt.Write(payload)
		frames = append(frames, holFrame(cmdPSH, sid, pkt.Bytes()))
	}
	return frames
}

type rxFrame struct {
	cmd  byte
	sid  uint32
	data []byte
}

type holPeer struct {
	conn net.Conn
	rx   chan rxFrame
}

func (p *holPeer) recvLoop() {
	defer close(p.rx)
	var h [7]byte
	for {
		if _, err := io.ReadFull(p.conn, h[:]); err != nil {
			return
		}
		data := make([]byte, binary.BigEndian.Uint16(h[5:7]))
		if _, err := io.ReadFull(p.conn, data); err != nil {
			return
		}
		p.rx <- rxFrame{cmd: h[0], sid: binary.BigEndian.Uint32(h[1:5]), data: data}
	}
}

// sendAsync 在后台按序写出这些帧。服务端读循环被卡住时 net.Pipe 的写会一直阻塞,
// 放在后台测试才能用超时判定「卡住了」,而不是自己跟着挂死。
func (p *holPeer) sendAsync(frames ...[]byte) <-chan error {
	done := make(chan error, 1)
	go func() {
		for _, f := range frames {
			if _, err := p.conn.Write(f); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	return done
}

// next 等一帧 cmd、sid 都对得上的服务端帧,途中别的帧丢掉。
func (p *holPeer) next(cmd byte, sid uint32, timeout time.Duration) (rxFrame, bool) {
	deadline := time.After(timeout)
	for {
		select {
		case f, ok := <-p.rx:
			if !ok {
				return rxFrame{}, false
			}
			if f.cmd == cmd && f.sid == sid {
				return f, true
			}
		case <-deadline:
			return rxFrame{}, false
		}
	}
}

func (p *holPeer) expect(cmd byte, sid uint32, timeout time.Duration) bool {
	_, ok := p.next(cmd, sid, timeout)
	return ok
}

// startHOLSession 起一个服务端会话:真实 readLoop,返回后同 Process 一样 close 整条会话;先做完 settings 握手。
func startHOLSession(t *testing.T, disp *holDispatcher) (*session, *holPeer, <-chan struct{}) {
	t.Helper()
	return startHOLSessionWith(t, disp, "v=2\nclient=mihomo/test\npadding-md5=00")
}

func startHOLSessionWith(t *testing.T, disp routing.Dispatcher, settings string) (*session, *holPeer, <-chan struct{}) {
	t.Helper()
	sc, cc := net.Pipe()
	s := &session{
		conn:       sc,
		br:         &buf.BufferedReader{Reader: buf.NewReader(sc)},
		bw:         buf.NewBufferedWriter(buf.NewWriter(sc)),
		streams:    make(map[uint32]*stream),
		dispatcher: disp,
	}
	s.fw = newFrameWriter(s.bw)
	s.peerVersion = 1
	// 同 inbound worker:连接 ctx 里带一份 Outbound 与 Content,会话上所有流都从它派生。
	ctx := sessionctx.ContextWithContent(sessionctx.ContextWithOutbounds(context.Background(), []*sessionctx.Outbound{{}}), &sessionctx.Content{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		s.close(s.readLoop(ctx))
	}()
	p := &holPeer{conn: cc, rx: make(chan rxFrame, 1024)}
	go p.recvLoop()
	p.sendAsync(holFrame(cmdSettings, 0, []byte(settings)))
	if !p.expect(cmdServerSettings, 0, 2*time.Second) {
		t.Fatal("no ServerSettings after client settings")
	}
	t.Cleanup(func() {
		cc.Close()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Error("server readLoop did not exit after the client closed the connection")
		}
	})
	return s, p, exited
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, timeout time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("timed out after %v waiting for %s", timeout, what)
	}
}

// ---- 队头阻塞 ----

// 一条流的上行写被卡住(限速把用户的桶打成负债)时,同会话新开的流必须照常拿到 SYNACK、上行数据照常送达。
// 从前 readLoop 同步写,新流的 SYN 排在卡住的写后面,sing-anytls 客户端 3 秒等不到 SYNACK 就关整条会话。
func TestNewStreamNotBlockedBySlowStreamUplink(t *testing.T) {
	slow := newGateWriter()
	fast := newGateWriter()
	fast.release()
	slowLink, _ := gateLink(slow)
	fastLink, _ := gateLink(fast)
	_, p, _ := startHOLSession(t, &holDispatcher{links: map[xnet.Port]*transport.Link{1001: slowLink, 1002: fastLink}})
	t.Cleanup(slow.release)

	p.sendAsync(
		holFrame(cmdSYN, 1, nil),
		holFrame(cmdPSH, 1, holAddr(t, "1.1.1.1:1001")),
		holFrame(cmdPSH, 1, []byte("stuck")),
	)
	if !p.expect(cmdSYNACK, 1, 2*time.Second) {
		t.Fatal("no SYNACK for stream 1")
	}
	waitClosed(t, slow.entered, 2*time.Second, "stream 1 uplink write to start")

	start := time.Now()
	p.sendAsync(
		holFrame(cmdSYN, 2, nil),
		holFrame(cmdPSH, 2, holAddr(t, "1.1.1.1:1002")),
		holFrame(cmdPSH, 2, []byte("hello")),
	)
	if !p.expect(cmdSYNACK, 2, time.Second) {
		t.Fatalf("SYNACK of a new stream is stuck behind another stream's blocked uplink write (waited %v)", time.Since(start))
	}
	waitFor(t, time.Second, "stream 2 uplink data", func() bool {
		d, _ := fast.snapshot()
		return string(d) == "hello"
	})
}

// UoT 流同理:handleUDPStream 写 link 被卡住时,readLoop 不能跟着停(从前卡在往 io.Pipe 喂下一个包上)。
func TestNewStreamNotBlockedBySlowUoTUplink(t *testing.T) {
	slow := newGateWriter()
	fast := newGateWriter()
	fast.release()
	slowLink, _ := gateLink(slow)
	fastLink, _ := gateLink(fast)
	_, p, _ := startHOLSession(t, &holDispatcher{links: map[xnet.Port]*transport.Link{53: slowLink, 1002: fastLink}})
	t.Cleanup(slow.release)

	p.sendAsync(holUoTOpen(t, 1, "8.8.8.8:53", 3)...)
	if !p.expect(cmdSYNACK, 1, 2*time.Second) {
		t.Fatal("no SYNACK for UoT stream 1")
	}
	waitClosed(t, slow.entered, 2*time.Second, "UoT uplink write to start")

	start := time.Now()
	p.sendAsync(
		holFrame(cmdSYN, 2, nil),
		holFrame(cmdPSH, 2, holAddr(t, "1.1.1.1:1002")),
		holFrame(cmdPSH, 2, []byte("hello")),
	)
	if !p.expect(cmdSYNACK, 2, time.Second) {
		t.Fatalf("SYNACK of a new stream is stuck behind a blocked UoT uplink (waited %v)", time.Since(start))
	}
	waitFor(t, time.Second, "stream 2 uplink data", func() bool {
		d, _ := fast.snapshot()
		return string(d) == "hello"
	})
}

// fork 自身客户端(client=xray)的 raw UDP 流同样走上行队列:handleFirstUDPFrame 之后的包入队即返回。
func TestNewStreamNotBlockedBySlowRawUDPUplink(t *testing.T) {
	slow := newGateWriter()
	fast := newGateWriter()
	fast.release()
	slowLink, _ := gateLink(slow)
	fastLink, _ := gateLink(fast)
	_, p, _ := startHOLSessionWith(t, &holDispatcher{links: map[xnet.Port]*transport.Link{53: slowLink, 1002: fastLink}},
		"v=2\nclient=xray\npadding-md5=00")
	t.Cleanup(slow.release)

	var req bytes.Buffer
	if err := uot.WriteRequest(&req, uot.Request{Destination: M.ParseSocksaddr("8.8.8.8:53")}); err != nil {
		t.Fatalf("encode uot request: %v", err)
	}
	p.sendAsync(
		holFrame(cmdSYN, 1, nil),
		holFrame(cmdPSH, 1, holAddr(t, "sp.v2.udp-over-tcp.arpa:0")),
		holFrame(cmdPSH, 1, req.Bytes()),
		holFrame(cmdPSH, 1, []byte("pkt-1")),
		holFrame(cmdPSH, 1, []byte("pkt-2")),
		holFrame(cmdPSH, 1, []byte("pkt-3")),
	)
	if !p.expect(cmdSYNACK, 1, 2*time.Second) {
		t.Fatal("no SYNACK for raw UDP stream 1")
	}
	waitClosed(t, slow.entered, 2*time.Second, "raw UDP uplink write to start")

	start := time.Now()
	p.sendAsync(
		holFrame(cmdSYN, 2, nil),
		holFrame(cmdPSH, 2, holAddr(t, "1.1.1.1:1002")),
		holFrame(cmdPSH, 2, []byte("hello")),
	)
	if !p.expect(cmdSYNACK, 2, time.Second) {
		t.Fatalf("SYNACK of a new stream is stuck behind a blocked raw UDP uplink (waited %v)", time.Since(start))
	}
	waitFor(t, time.Second, "stream 2 uplink data", func() bool {
		d, _ := fast.snapshot()
		return string(d) == "hello"
	})
}

// ---- 保序 / FIN ----

// 同一条流的上行严格保序:帧大小参差、总量超过队列上限(走到队列满、readLoop 等待的分支),
// 出站写得慢。FIN 之后已入队的数据全部写完才关 link.Writer。
func TestUplinkKeepsOrderUnderBackpressure(t *testing.T) {
	w := newGateWriter()
	w.release()
	slowLink, _ := gateLink(&slowWriter{w: w, delay: time.Millisecond})
	_, p, _ := startHOLSession(t, &holDispatcher{links: map[xnet.Port]*transport.Link{1001: slowLink}})

	p.sendAsync(holFrame(cmdSYN, 1, nil), holFrame(cmdPSH, 1, holAddr(t, "1.1.1.1:1001")))
	if !p.expect(cmdSYNACK, 1, 2*time.Second) {
		t.Fatal("no SYNACK for stream 1")
	}

	const total = 3 * uplinkQueueLimit
	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte(i ^ i>>8 ^ i>>16)
	}
	var frames [][]byte
	seed := uint32(1)
	for off := 0; off < total; {
		seed = seed*1664525 + 1013904223
		n := int(seed>>16)%maxFramePayload + 1
		if off+n > total {
			n = total - off
		}
		frames = append(frames, holFrame(cmdPSH, 1, payload[off:off+n]))
		off += n
	}
	frames = append(frames, holFrame(cmdFIN, 1, nil))
	p.sendAsync(frames...)

	waitFor(t, 10*time.Second, "link.Writer to be closed after FIN", func() bool {
		_, closedAt := w.snapshot()
		return closedAt >= 0
	})
	data, closedAt := w.snapshot()
	if closedAt != total {
		t.Fatalf("link.Writer closed after %d of %d bytes: FIN dropped queued uplink data", closedAt, total)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("uplink data reordered or corrupted (%d frames, %d bytes)", len(frames)-1, total)
	}
}

// slowWriter 每次写先睡一会儿,再交给内层;Close 透传。
type slowWriter struct {
	w     *gateWriter
	delay time.Duration
}

func (s *slowWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	time.Sleep(s.delay)
	return s.w.WriteMultiBuffer(mb)
}
func (s *slowWriter) Close() error { return s.w.Close() }

// FIN 不在 readLoop 里等排空:出站卡住时 FIN 照样立刻被读走,同会话的新流不受影响;
// FIN 之后还在路上的 PSH 丢弃;出站放行后已入队的数据写完才关 link,再回 FIN。
func TestFinDrainsQueuedUplinkWithoutBlockingSession(t *testing.T) {
	w := newGateWriter()
	link, _ := gateLink(w)
	_, p, _ := startHOLSession(t, &holDispatcher{links: map[xnet.Port]*transport.Link{1001: link}})
	t.Cleanup(w.release)

	p.sendAsync(holFrame(cmdSYN, 1, nil), holFrame(cmdPSH, 1, holAddr(t, "1.1.1.1:1001")))
	if !p.expect(cmdSYNACK, 1, 2*time.Second) {
		t.Fatal("no SYNACK for stream 1")
	}
	var want []byte
	frames := [][]byte{}
	for i := 0; i < 5; i++ {
		chunk := bytes.Repeat([]byte{byte('a' + i)}, 10000)
		want = append(want, chunk...)
		frames = append(frames, holFrame(cmdPSH, 1, chunk))
	}
	frames = append(frames, holFrame(cmdFIN, 1, nil))
	select {
	case err := <-p.sendAsync(frames...):
		if err != nil {
			t.Fatalf("send: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("readLoop did not consume the stream's data + FIN while its outbound was blocked")
	}

	p.sendAsync(
		holFrame(cmdPSH, 1, []byte("late-after-fin")),
		holFrame(cmdSYN, 2, nil),
		holFrame(cmdPSH, 2, holAddr(t, "1.1.1.1:1002")),
	)
	if !p.expect(cmdSYNACK, 2, time.Second) {
		t.Fatal("new stream blocked while a FIN'd stream is still draining")
	}
	if _, closedAt := w.snapshot(); closedAt >= 0 {
		t.Fatalf("link.Writer closed before queued uplink was written (closedAt=%d)", closedAt)
	}

	w.release()
	waitFor(t, 2*time.Second, "link.Writer to be closed after draining", func() bool {
		_, closedAt := w.snapshot()
		return closedAt >= 0
	})
	data, closedAt := w.snapshot()
	if !bytes.Equal(data, want) || closedAt != len(want) {
		t.Fatalf("after FIN got %d bytes (closedAt=%d), want exactly the %d bytes sent before FIN", len(data), closedAt, len(want))
	}
	if !p.expect(cmdFIN, 1, 2*time.Second) {
		t.Fatal("server did not FIN stream 1 after draining")
	}
}

// ---- 分发 ----

// targetDispatcher 学真实 dispatcher 的做法:Dispatch 把目标写进 ctx 里的 Outbound,出站在自己的 goroutine
// 里过一会儿才读 ob.Target 去连。记下每条流的出站最终连向哪里。
type targetDispatcher struct {
	mu  sync.Mutex
	got map[xnet.Port]xnet.Port
	wg  sync.WaitGroup
}

func (*targetDispatcher) Type() interface{} { return nil }
func (*targetDispatcher) Start() error      { return nil }
func (*targetDispatcher) Close() error      { return nil }
func (d *targetDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	obs := sessionctx.OutboundsFromContext(ctx)
	ob := obs[len(obs)-1]
	ob.Target = dest
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		time.Sleep(50 * time.Millisecond) // 路由、解析、拨号前的准备
		d.mu.Lock()
		d.got[dest.Port] = ob.Target.Port
		d.mu.Unlock()
	}()
	return &transport.Link{Reader: &blockingReader{done: make(chan struct{})}, Writer: nopWriter{}}, nil
}
func (d *targetDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return nil
}

// 同一会话上紧挨着开的几条流(含在自己 goroutine 里分发的 UoT 流)各连各的目标。
// 共用连接 ctx 里那一个 Outbound 时,出站读到的是最后一次分发写进去的目标,前面的流全被连错。
func TestBackToBackStreamsKeepTheirOwnTarget(t *testing.T) {
	d := &targetDispatcher{got: map[xnet.Port]xnet.Port{}}
	_, p, _ := startHOLSessionWith(t, d, "v=2\nclient=mihomo/test\npadding-md5=00")

	var frames [][]byte
	for sid := uint32(1); sid <= 6; sid++ {
		frames = append(frames, holFrame(cmdSYN, sid, nil), holFrame(cmdPSH, sid, holAddr(t, fmt.Sprintf("1.1.1.1:%d", 2000+sid))))
	}
	frames = append(frames, holUoTOpen(t, 7, "8.8.8.8:53", 1)...)
	frames = append(frames, holFrame(cmdSYN, 8, nil), holFrame(cmdPSH, 8, holAddr(t, "1.1.1.1:2008")))
	p.sendAsync(frames...)
	for sid := uint32(1); sid <= 8; sid++ {
		if !p.expect(cmdSYNACK, sid, 2*time.Second) {
			t.Fatalf("no SYNACK for stream %d", sid)
		}
	}
	waitFor(t, 2*time.Second, "all 8 outbounds to read their target", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return len(d.got) == 8
	})
	d.wg.Wait()
	for want, got := range d.got {
		if got != want {
			t.Errorf("stream dispatched to port %d was connected to port %d", want, got)
		}
	}
}

// ---- 流 / 会话结束 ----

// 写失败(link 已被踢掉)只结束这一条流:服务端回 FIN,会话照常;之后这条流还在路上的数据丢弃。
func TestUplinkWriteErrorEndsOnlyThatStream(t *testing.T) {
	failLink, _ := gateLink(failWriter{})
	ok := newGateWriter()
	ok.release()
	okLink, _ := gateLink(ok)
	_, p, exited := startHOLSession(t, &holDispatcher{links: map[xnet.Port]*transport.Link{1001: failLink, 1002: okLink}})

	p.sendAsync(
		holFrame(cmdSYN, 1, nil),
		holFrame(cmdPSH, 1, holAddr(t, "1.1.1.1:1001")),
		holFrame(cmdPSH, 1, []byte("kicked")),
	)
	if !p.expect(cmdFIN, 1, 2*time.Second) {
		t.Fatal("server did not FIN the stream whose uplink write failed")
	}
	p.sendAsync(
		holFrame(cmdPSH, 1, []byte("still-in-flight")),
		holFrame(cmdSYN, 2, nil),
		holFrame(cmdPSH, 2, holAddr(t, "1.1.1.1:1002")),
		holFrame(cmdPSH, 2, []byte("ok")),
	)
	if !p.expect(cmdSYNACK, 2, time.Second) {
		t.Fatal("session unusable after one stream's uplink write failed")
	}
	waitFor(t, time.Second, "stream 2 uplink data", func() bool {
		d, _ := ok.snapshot()
		return string(d) == "ok"
	})
	select {
	case <-exited:
		t.Fatal("whole session torn down by one stream's write error")
	default:
	}
}

// fillQueueFrames:足够把一条被卡住的流的队列顶满、让 readLoop 在入队上等住的数据帧。
func fillQueueFrames(sid uint32) [][]byte {
	chunk := bytes.Repeat([]byte{'x'}, 60000)
	var frames [][]byte
	for n := 0; n <= uplinkQueueLimit+2*len(chunk); n += len(chunk) {
		frames = append(frames, holFrame(cmdPSH, sid, chunk))
	}
	return frames
}

// 队列满时 readLoop 在入队上等(背压);这条流一结束(这里是下行结束,同目标关闭 / 被踢),等待立刻被打断,
// readLoop 接着处理后面的帧。
func TestFullQueueBackpressureInterruptedByStreamEnd(t *testing.T) {
	w := newGateWriter()
	link, downlink := gateLink(w)
	_, p, _ := startHOLSession(t, &holDispatcher{links: map[xnet.Port]*transport.Link{1001: link}})

	frames := [][]byte{holFrame(cmdSYN, 1, nil), holFrame(cmdPSH, 1, holAddr(t, "1.1.1.1:1001"))}
	frames = append(frames, fillQueueFrames(1)...)
	frames = append(frames, holFrame(cmdSYN, 2, nil), holFrame(cmdPSH, 2, holAddr(t, "1.1.1.1:1002")))
	p.sendAsync(frames...)
	if !p.expect(cmdSYNACK, 1, 2*time.Second) {
		t.Fatal("no SYNACK for stream 1")
	}
	if p.expect(cmdSYNACK, 2, 300*time.Millisecond) {
		t.Fatal("readLoop was not back-pressured by a full uplink queue")
	}

	downlink.Close()
	if !p.expect(cmdSYNACK, 2, time.Second) {
		t.Fatal("readLoop still blocked on the full queue after its stream ended")
	}
	waitFor(t, time.Second, "stream 1's link.Writer to be closed", func() bool {
		_, closedAt := w.snapshot()
		return closedAt >= 0
	})
}

// 同上,打断者换成会话关闭:readLoop 必须立刻退出,不能卡在满队列上。
func TestFullQueueBackpressureInterruptedBySessionClose(t *testing.T) {
	w := newGateWriter()
	link, _ := gateLink(w)
	s, p, exited := startHOLSession(t, &holDispatcher{links: map[xnet.Port]*transport.Link{1001: link}})

	frames := [][]byte{holFrame(cmdSYN, 1, nil), holFrame(cmdPSH, 1, holAddr(t, "1.1.1.1:1001"))}
	frames = append(frames, fillQueueFrames(1)...)
	frames = append(frames, holFrame(cmdSYN, 2, nil), holFrame(cmdPSH, 2, holAddr(t, "1.1.1.1:1002")))
	p.sendAsync(frames...)
	if !p.expect(cmdSYNACK, 1, 2*time.Second) {
		t.Fatal("no SYNACK for stream 1")
	}
	if p.expect(cmdSYNACK, 2, 300*time.Millisecond) {
		t.Fatal("readLoop was not back-pressured by a full uplink queue")
	}

	s.close(errors.New("closed by test"))
	waitClosed(t, exited, time.Second, "readLoop to return after session close while blocked on a full queue")
}

// 会话断开(客户端断网,不逐流发 FIN)时:卡在出站上的写 goroutine、正在排空的 FIN 流、UoT 流的
// handleUDPStream / udpDownlink 全部退出,各 link 被关,队列里剩下的缓冲全部释放。
func TestUplinkGoroutinesExitOnSessionClose(t *testing.T) {
	runtime.GC()
	base := runtime.NumGoroutine()

	links := map[xnet.Port]*transport.Link{}
	var gates []*gateWriter
	for _, port := range []xnet.Port{1001, 1002, 1003, 53, 54} {
		g := newGateWriter()
		gates = append(gates, g)
		links[port], _ = gateLink(g)
	}
	s, p, exited := startHOLSession(t, &holDispatcher{links: links})

	var frames [][]byte
	for i, port := range []string{"1001", "1002", "1003"} {
		sid := uint32(i + 1)
		frames = append(frames, holFrame(cmdSYN, sid, nil), holFrame(cmdPSH, sid, holAddr(t, "1.1.1.1:"+port)))
		for j := 0; j < 4; j++ {
			frames = append(frames, holFrame(cmdPSH, sid, bytes.Repeat([]byte{'d'}, 20000)))
		}
	}
	frames = append(frames, holFrame(cmdFIN, 3, nil)) // 流 3:FIN 了但出站卡住,正在排空
	frames = append(frames, holUoTOpen(t, 4, "8.8.8.8:53", 4)...)
	frames = append(frames, holUoTOpen(t, 5, "8.8.4.4:54", 4)...)
	select {
	case err := <-p.sendAsync(frames...):
		if err != nil {
			t.Fatalf("send: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop stuck while streams' outbounds are blocked")
	}
	for i, g := range gates {
		waitClosed(t, g.entered, 2*time.Second, fmt.Sprintf("uplink write of stream %d to start", i+1))
	}

	s.streamsMu.Lock()
	var streams []*stream
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streamsMu.Unlock()
	if len(streams) != 5 {
		t.Fatalf("expected 5 live streams (incl. the draining FIN'd one), got %d", len(streams))
	}

	p.conn.Close()
	waitClosed(t, exited, 2*time.Second, "readLoop to exit after the client dropped the connection")

	for i, g := range gates {
		waitFor(t, 2*time.Second, fmt.Sprintf("link.Writer of stream %d to be closed", i+1), func() bool {
			_, closedAt := g.snapshot()
			return closedAt >= 0
		})
	}
	for _, st := range streams {
		st.up.mu.Lock()
		dead, left, size := st.up.dead, len(st.up.items), st.up.size
		st.up.mu.Unlock()
		if !dead || left != 0 || size != 0 {
			t.Fatalf("stream %d uplink queue not aborted/released: dead=%v items=%d size=%d", st.sid, dead, left, size)
		}
	}
	waitFor(t, 2*time.Second, "per-stream goroutines to exit", func() bool {
		return runtime.NumGoroutine() <= base
	})
}
