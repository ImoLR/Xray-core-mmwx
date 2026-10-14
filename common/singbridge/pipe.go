package singbridge

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/bufio"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

func CopyConn(ctx context.Context, inboundConn net.Conn, link *transport.Link, serverConn net.Conn) error {
	conn := &PipeConnWrapper{
		W:    link.Writer,
		Conn: inboundConn,
		Idle: connIdleFromContext(ctx),
	}
	conn.touch()
	if ir, ok := link.Reader.(io.Reader); ok {
		conn.R = ir
	} else {
		conn.R = &buf.BufferedReader{Reader: link.Reader}
	}
	return ReturnError(bufio.CopyConn(ctx, conn, serverConn))
}

type PipeConnWrapper struct {
	R io.Reader
	W buf.Writer
	net.Conn
	// Idle 两个方向都没有数据超过这么久才算超时;0 = defaultPipeIdle。
	Idle time.Duration
	// lastActive 最近一次任一方向有数据的时刻(unix 纳秒)
	lastActive atomic.Int64
}

// defaultPipeIdle 拿不到 policy 时的空闲超时,与 xray 默认 connIdle 一致。
const defaultPipeIdle = 300 * time.Second

// connIdleFromContext 取当前入站用户等级的 connIdle(policy 里的 Timeouts.ConnectionIdle)。
func connIdleFromContext(ctx context.Context) time.Duration {
	if v := core.FromContext(ctx); v != nil {
		if pm, ok := v.GetFeature(policy.ManagerType()).(policy.Manager); ok {
			level := uint32(0)
			if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
				level = inbound.User.Level
			}
			if idle := pm.ForLevel(level).Timeouts.ConnectionIdle; idle > 0 {
				return idle
			}
		}
	}
	return defaultPipeIdle
}

func (w *PipeConnWrapper) touch() { w.lastActive.Store(time.Now().UnixNano()) }

func (w *PipeConnWrapper) idle() time.Duration {
	if w.Idle > 0 {
		return w.Idle
	}
	return defaultPipeIdle
}

// Close 必须真的把 link 两端拆掉。
//
// 原实现返回 nil 什么都不做,于是 sing 的 CopyConn 在一个方向出错时调的
// common.Close(source) 完全落空 —— 另一个方向仍卡在下面 Read 里那个
// 硬编码 300s 超时上,inbound worker 的 ctx 也就跟着 300s 不 cancel。
func (w *PipeConnWrapper) Close() error {
	common.Interrupt(w.R)
	common.Close(w.W)
	return nil
}

// CloseWrite 上行方向读完(客户端不再发数据)时被 sing 的 CopyConn 调到,
// 必须把 link.Writer 关掉,出站才知道请求已发完、进而对目标 CloseWrite,
// 目标关闭连接后下行才拿得到 EOF。
//
// 不实现它的后果不是"少个优化":PipeConnWrapper 只嵌了 net.Conn(客户端连接),
// sing 的 N.CloseWrite 会解包到客户端连接的写端 —— 关的是**反方向**,link 毫发无损。
// 于是下行 Read 干等满 300s,期间 ctx 不 cancel,依赖 ctx 释放的连接数计数
// (dispatcher 里的 context.AfterFunc → ReleaseConn)整整滞后 5 分钟:
// 面板连接数虚高,用户的并发连接上限被已关闭的连接占着,短连接一密集就被误判超限。
func (w *PipeConnWrapper) CloseWrite() error {
	return common.Close(w.W)
}

// Read 带空闲超时,防止对端挂死时 goroutine 泄漏。
//
// 超时按「两个方向都没有数据」算,时长取 policy 的 connIdle。原来是固定 300s、只看这一个方向
// (下行):SSH 这类上行有心跳、下行长时间静默的连接,满 5 分钟就被断,把 connIdle 调大也没用(#1228)。
func (w *PipeConnWrapper) Read(b []byte) (n int, err error) {
	type readResult struct {
		n   int
		err error
	}
	c := make(chan readResult, 1)
	go func() {
		n, err := w.R.Read(b)
		c <- readResult{n: n, err: err}
	}()
	idle := w.idle()
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case result := <-c:
			if result.n > 0 {
				w.touch()
			}
			return result.n, result.err
		case <-timer.C:
			// 另一个方向(上行 Write)在这段时间里有过数据:连接还活着,接着等
			if since := time.Since(time.Unix(0, w.lastActive.Load())); since < idle {
				timer.Reset(idle - since)
				continue
			}
			common.Close(w.R)
			common.Interrupt(w.R)
			return 0, buf.ErrReadTimeout
		}
	}
}

func (w *PipeConnWrapper) Write(p []byte) (n int, err error) {
	if len(p) > 0 {
		w.touch()
	}
	n = len(p)
	var mb buf.MultiBuffer
	pLen := len(p)
	for pLen > 0 {
		buffer := buf.New()
		if pLen > buf.Size {
			_, err = buffer.Write(p[:buf.Size])
			p = p[buf.Size:]
		} else {
			buffer.Write(p)
		}
		pLen -= int(buffer.Len())
		mb = append(mb, buffer)
	}
	err = w.W.WriteMultiBuffer(mb)
	if err != nil {
		n = 0
		buf.ReleaseMulti(mb)
	}
	return
}
