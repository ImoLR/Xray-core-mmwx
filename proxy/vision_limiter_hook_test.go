package proxy

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// sinkConn 吞掉所有写入、读即 EOF,只用来给 Vision 读写器一个可替换的底层 conn。
type sinkConn struct{}

func (sinkConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (sinkConn) Write(b []byte) (int, error)      { return len(b), nil }
func (sinkConn) Close() error                     { return nil }
func (sinkConn) LocalAddr() stdnet.Addr           { return nil }
func (sinkConn) RemoteAddr() stdnet.Addr          { return nil }
func (sinkConn) SetDeadline(time.Time) error      { return nil }
func (sinkConn) SetReadDeadline(time.Time) error  { return nil }
func (sinkConn) SetWriteDeadline(time.Time) error { return nil }

// onceReader 第一次返回给定的 MultiBuffer,之后 EOF。
type onceReader struct{ mb buf.MultiBuffer }

func (r *onceReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.mb == nil {
		return nil, io.EOF
	}
	mb := r.mb
	r.mb = nil
	return mb, nil
}

// recordVisionHook 安装一个记录调用的钩子,测试结束时恢复原钩子。
func recordVisionHook(t *testing.T) *[]string {
	t.Helper()
	prev := visionLimiterHook
	t.Cleanup(func() { visionLimiterHook = prev })
	var calls []string
	SetVisionLimiterHook(func(email string, rawConn stdnet.Conn) stdnet.Conn {
		calls = append(calls, email)
		return sinkConn{}
	})
	return &calls
}

func ctxWithInboundUser(email string) context.Context {
	return session.ContextWithInbound(context.Background(), &session.Inbound{
		User: &protocol.MemoryUser{Email: email},
	})
}

// 钩子只能包 vless 入站面向客户端的那条连接。出站侧(vless-vision 出站连落地)的读写器
// 拿到的 ctx 里同样有入站用户 email;过去也被包,于是非 vision 入站经 vision 出站时,
// dispatcher 的 RateWriter 和钩子扣的是同一个 bucket,实际速率只剩一半。
func TestVisionWriterHookOnlyOnClientSide(t *testing.T) {
	for _, tc := range []struct {
		name     string
		isUplink bool
		wantWrap bool
	}{
		{"inbound-writer-to-client", false, true},
		{"outbound-writer-to-server", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := recordVisionHook(t)
			state := NewTrafficState(make([]byte, 16))
			state.NumberOfPacketToFilter = 0
			if tc.isUplink {
				state.Outbound.IsPadding = false
				state.Outbound.UplinkWriterDirectCopy = true
			} else {
				state.Inbound.IsPadding = false
				state.Inbound.DownlinkWriterDirectCopy = true
			}
			w := NewVisionWriter(buf.Discard, state, tc.isUplink, ctxWithInboundUser("alice"), sinkConn{}, nil, nil)

			b := buf.New()
			b.WriteString("payload")
			if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				t.Fatalf("WriteMultiBuffer: %v", err)
			}
			if gotWrap := len(*calls) == 1 && (*calls)[0] == "alice"; gotWrap != tc.wantWrap || len(*calls) > 1 {
				t.Fatalf("hook calls = %q, want wrapped=%v", *calls, tc.wantWrap)
			}
		})
	}
}

func TestVisionReaderHookOnlyOnClientSide(t *testing.T) {
	for _, tc := range []struct {
		name     string
		isUplink bool
		wantWrap bool
	}{
		{"inbound-reader-from-client", true, true},
		{"outbound-reader-from-server", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := recordVisionHook(t)
			uuid := []byte("0123456789abcdef")
			state := NewTrafficState(uuid)
			ctx := ctxWithInboundUser("alice")

			// 对端发来一个带 CommandPaddingDirect 的 vision 块:读完即切换到 direct copy,
			// 这正是钩子被调用的时刻。
			content := buf.New()
			content.WriteString("hello")
			once := append([]byte(nil), uuid...)
			padded := XtlsPadding(content, CommandPaddingDirect, &once, false, ctx, []uint32{900, 500, 900, 256})

			r := NewVisionReader(&onceReader{mb: buf.MultiBuffer{padded}}, state, tc.isUplink, ctx, sinkConn{},
				bytes.NewReader(nil), new(bytes.Buffer), nil)
			mb, err := r.ReadMultiBuffer()
			if err != nil {
				t.Fatalf("ReadMultiBuffer: %v", err)
			}
			if got := mb.String(); got != "hello" {
				t.Fatalf("content = %q, want hello", got)
			}
			switched := state.Inbound.UplinkReaderDirectCopy
			if !tc.isUplink {
				switched = state.Outbound.DownlinkReaderDirectCopy
			}
			if !switched {
				t.Fatal("reader did not switch to direct copy; test setup is wrong")
			}
			if gotWrap := len(*calls) == 1 && (*calls)[0] == "alice"; gotWrap != tc.wantWrap || len(*calls) > 1 {
				t.Fatalf("hook calls = %q, want wrapped=%v", *calls, tc.wantWrap)
			}
		})
	}
}

type visionLimitedConn struct {
	stdnet.Conn
	bytes *appstats.Counter
}

func (c *visionLimitedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.bytes.Add(int64(n))
	return n, err
}

func (c *visionLimitedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.bytes.Add(int64(n))
	return n, err
}

func TestVisionRawCopyHonorsLimiter(t *testing.T) {
	previous := visionLimiterHook
	t.Cleanup(func() { visionLimiterHook = previous })
	pair := func(t *testing.T) (*stdnet.TCPConn, *stdnet.TCPConn) {
		t.Helper()
		listener, err := stdnet.ListenTCP("tcp4", &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		peer, err := stdnet.DialTCP("tcp4", nil, listener.Addr().(*stdnet.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { peer.Close() })
		conn, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		peer.SetDeadline(time.Now().Add(5 * time.Second))
		return conn, peer
	}
	for _, limited := range []bool{false, true} {
		for _, upload := range []bool{false, true} {
			name := "download"
			if upload {
				name = "upload"
			}
			if limited {
				name += "/limited"
			} else {
				name += "/unlimited"
			}
			t.Run(name, func(t *testing.T) {
				throttled := new(appstats.Counter)
				SetVisionLimiterHook(func(email string, conn stdnet.Conn) stdnet.Conn {
					if limited && email == "alice" {
						return &visionLimitedConn{Conn: conn, bytes: throttled}
					}
					return conn
				})
				reader, source := pair(t)
				writer, destination := pair(t)
				readCounter, writeCounter, userCounter := new(appstats.Counter), new(appstats.Counter), new(appstats.Counter)
				readConn := &stat.CounterConnection{Connection: reader, ReadCounter: readCounter}
				writeConn := &stat.CounterConnection{Connection: writer, WriteCounter: writeCounter}
				ctx := ctxWithInboundUser("alice")
				inbound := session.InboundFromContext(ctx)
				inbound.Conn, inbound.CanSpliceCopy = writeConn, 1
				ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{CanSpliceCopy: 1}})
				var fallback buf.Writer = buf.NewWriter(writeConn)
				if upload {
					inbound.Conn = readConn
				} else {
					state := NewTrafficState(make([]byte, 16))
					state.NumberOfPacketToFilter = 0
					state.Inbound.IsPadding = false
					state.Inbound.DownlinkWriterDirectCopy = true
					fallback = NewVisionWriter(buf.Discard, state, false, ctx, writeConn, nil, nil)
				}
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				timer := signal.CancelAfterInactivity(ctx, cancel, 5*time.Second)
				defer timer.SetTimeout(0)
				copied := make(chan error, 1)
				go func() {
					copied <- CopyRawConnIfExist(ctx, readConn, writeConn, &dispatcher.SizeStatWriter{Writer: fallback, Counter: userCounter}, timer, nil)
				}()
				payload := bytes.Repeat([]byte("limited Vision"), 4096)
				written := make(chan error, 1)
				go func() {
					_, err := source.Write(payload)
					source.CloseWrite()
					written <- err
				}()
				received := make([]byte, len(payload))
				if _, err := io.ReadFull(destination, received); err != nil {
					t.Fatal(err)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
				if err := <-copied; err != nil {
					t.Fatal(err)
				}
				want := int64(len(payload))
				if !bytes.Equal(received, payload) || readCounter.Value() != want || writeCounter.Value() != want || userCounter.Value() != want {
					t.Fatal("raw copy lost payload or accounting")
				}
				if limited && throttled.Value() != want || !limited && throttled.Value() != 0 {
					t.Fatalf("limiter saw %d bytes, limited=%v, payload=%d", throttled.Value(), limited, want)
				}
			})
		}
	}
}
