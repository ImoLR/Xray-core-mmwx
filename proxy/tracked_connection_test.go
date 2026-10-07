package proxy_test

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	rawreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/app/dispatcher"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	customconnection "github.com/xtls/xray-core/common/mmwxcustom/connection"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func trackedTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	for _, c := range []*net.TCPConn{conn, peer} {
		if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return conn, peer
}

func trackedSecurityConn(name string, conn net.Conn) net.Conn {
	switch name {
	case "tls":
		return &tls.Conn{Conn: gotls.Client(conn, &gotls.Config{ServerName: "localhost"})}
	case "reality":
		return &reality.Conn{Conn: rawreality.Client(conn, &rawreality.Config{ServerName: "localhost"})}
	default:
		return conn
	}
}

func TestTrackedConnectionUnwrapping(t *testing.T) {
	if got := stat.TryUnwrapStatsConn(nil); got != nil {
		t.Fatalf("nil stats connection = %v", got)
	}
	if raw, read, write := proxy.UnwrapRawConn(nil); raw != nil || read != nil || write != nil {
		t.Fatal("nil raw connection retained a connection or counters")
	}
	for _, security := range []string{"raw", "tls", "reality"} {
		for _, withStats := range []bool{false, true} {
			name := security
			if withStats {
				name += "/stats"
			}
			t.Run(name, func(t *testing.T) {
				raw, _ := trackedTCPPair(t)
				inner := trackedSecurityConn(security, raw)
				tracked := customconnection.TrackInbound(inner)
				t.Cleanup(func() { tracked.Close() })
				var conn net.Conn = tracked
				readCounter, writeCounter := new(appstats.Counter), new(appstats.Counter)
				if withStats {
					conn = &stat.CounterConnection{Connection: tracked, ReadCounter: readCounter, WriteCounter: writeCounter}
				}
				if got := stat.TryUnwrapStatsConn(conn); got != inner {
					t.Fatalf("transport connection = %T, want original %T", got, inner)
				}
				got, read, write := proxy.UnwrapRawConn(conn)
				if got != raw {
					t.Fatalf("raw connection = %T, want original TCP connection", got)
				}
				if withStats {
					if read != readCounter || write != writeCounter {
						t.Fatal("raw unwrapping lost statistics counters")
					}
				} else if read != nil || write != nil {
					t.Fatal("raw unwrapping invented statistics counters")
				}
				if got := proxy.IsRAWTransportWithoutSecurity(conn); got != (security == "raw") {
					t.Fatalf("RAW transport = %v for %s", got, security)
				}
				if got := stat.TryUnwrapStatsConn(inner); got != inner {
					t.Fatal("untracked transport was changed")
				}
			})
		}
	}
	// Unknown protocol wrappers must not be treated as transparent transports.
	raw, _ := trackedTCPPair(t)
	opaque := &struct{ net.Conn }{raw}
	if stat.TryUnwrapStatsConn(opaque) != opaque || proxy.IsRAWTransportWithoutSecurity(opaque) {
		t.Fatal("unknown connection wrapper was penetrated")
	}
	// Keep an inner statistics wrapper responsible for its own accounting.
	innerCounter := &stat.CounterConnection{Connection: raw, ReadCounter: new(appstats.Counter)}
	outerCounter := &stat.CounterConnection{Connection: innerCounter, ReadCounter: new(appstats.Counter)}
	if conn, read, _ := proxy.UnwrapRawConn(outerCounter); conn != innerCounter || read != outerCounter.ReadCounter {
		t.Fatal("raw unwrapping bypassed an inner statistics counter")
	}
}

func trackedCopyContext(conn net.Conn, user string) context.Context {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag: "vision", Name: "vless", Conn: conn, CanSpliceCopy: 1,
		Gateway: xnet.TCPDestination(xnet.LocalHostIP, 10020),
		Source:  xnet.DestinationFromAddr(conn.RemoteAddr()),
		User:    &protocol.MemoryUser{Email: user},
	})
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{Tag: "direct", CanSpliceCopy: 1}})
}

func trackedSnapshot(t *testing.T, manager *customconnection.Manager, user string) customconnection.Snapshot {
	t.Helper()
	for _, snapshot := range manager.Snapshots() {
		if snapshot.Identity == (customconnection.Identity{InboundTag: "vision", User: user}) {
			return snapshot
		}
	}
	t.Fatalf("missing tracked identity %s", user)
	return customconnection.Snapshot{}
}

type rejectTrackedCopyFallback struct{}

func (rejectTrackedCopyFallback) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return errors.New("tracked connection unexpectedly used the userspace copy fallback")
}

func TestTrackedVisionRawCopyCloseAndBlock(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		t.Skip("CopyRawConnIfExist selects splice only on Linux and Android")
	}
	for _, security := range []string{"tls", "reality"} {
		for _, block := range []bool{false, true} {
			name := security + "/close"
			if block {
				name = security + "/block"
			}
			t.Run(name, func(t *testing.T) {
				manager := customconnection.NewManager()
				previous := customconnection.Default
				customconnection.Default = manager
				t.Cleanup(func() { customconnection.Default = previous })
				reader, source := trackedTCPPair(t)
				writer, client := trackedTCPPair(t)
				// Handshakes are covered by the VLESS integration test. These wrappers
				// exercise the raw TCP path selected after Vision switches to direct copy.
				tracked := customconnection.TrackInbound(trackedSecurityConn(security, writer))
				t.Cleanup(func() { tracked.Close() })
				ctx := trackedCopyContext(tracked, "vision-user")
				if err := customconnection.BindInbound(ctx, tracked); err != nil {
					t.Fatal(err)
				}
				if got := trackedSnapshot(t, manager, "vision-user"); got.InboundActive != 1 || got.InboundTotal != 1 {
					t.Fatalf("initial ownership = %+v", got)
				}

				readCounter, writeCounter, userCounter := new(appstats.Counter), new(appstats.Counter), new(appstats.Counter)
				readerConn := &stat.CounterConnection{Connection: reader, ReadCounter: readCounter}
				writerConn := &stat.CounterConnection{Connection: tracked, WriteCounter: writeCounter}
				statWriter := &dispatcher.SizeStatWriter{Counter: userCounter, Writer: rejectTrackedCopyFallback{}}
				copyCtx, cancel := context.WithCancel(ctx)
				t.Cleanup(cancel)
				timer := signal.CancelAfterInactivity(copyCtx, cancel, 10*time.Second)
				t.Cleanup(func() { timer.SetTimeout(0) })
				copied := make(chan error, 1)
				go func() {
					copied <- proxy.CopyRawConnIfExist(copyCtx, readerConn, writerConn, statWriter, timer, nil)
				}()

				payload := bytes.Repeat([]byte("vision-splice"), 90000)
				written := make(chan error, 1)
				go func() {
					_, err := source.Write(payload)
					written <- err
				}()
				received := make([]byte, len(payload))
				if _, err := io.ReadFull(client, received); err != nil {
					t.Fatalf("raw copy did not deliver payload: %v", err)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(received, payload) {
					t.Fatal("raw copy corrupted payload")
				}
				if readCounter.Value() == 0 || writeCounter.Value() == 0 || userCounter.Value() == 0 {
					t.Fatal("splice did not account traffic while the connection remained open")
				}
				select {
				case err := <-copied:
					t.Fatalf("copy stopped before source EOF: %v", err)
				default:
				}

				if block {
					other, otherPeer := trackedTCPPair(t)
					otherTracked := customconnection.TrackInbound(other)
					t.Cleanup(func() { otherTracked.Close() })
					if err := customconnection.BindInbound(trackedCopyContext(otherTracked, "other-user"), otherTracked); err != nil {
						t.Fatal(err)
					}
					identity := customconnection.Identity{InboundTag: "vision", User: "vision-user"}
					if err := manager.ReplaceConfig(customconnection.Config{BlockedIdentities: []customconnection.Identity{identity}}); err != nil {
						t.Fatal(err)
					}
					if _, err := client.Read(make([]byte, 1)); err != io.EOF {
						t.Fatalf("blocked raw client was not closed: %v", err)
					}
					if got := trackedSnapshot(t, manager, "vision-user"); !got.Blocked || got.InboundActive != 0 {
						t.Fatalf("block did not release tracked ownership: %+v", got)
					}
					newConn, _ := trackedTCPPair(t)
					newTracked := customconnection.TrackInbound(newConn)
					t.Cleanup(func() { newTracked.Close() })
					newCtx := trackedCopyContext(newTracked, "vision-user")
					for _, err := range []error{customconnection.BindInbound(newCtx, newTracked), customconnection.AdmitInbound(newCtx)} {
						var limitErr *customconnection.LimitError
						if !errors.As(err, &limitErr) || limitErr.Reason != customconnection.BlockedIdentity {
							t.Fatalf("blocked identity was admitted: %v", err)
						}
					}
					if _, err := otherTracked.Write([]byte("ok")); err != nil {
						t.Fatal(err)
					}
					if _, err := io.ReadFull(otherPeer, make([]byte, 2)); err != nil {
						t.Fatalf("unrelated identity was closed: %v", err)
					}
					if got := trackedSnapshot(t, manager, "other-user"); got.InboundActive != 1 {
						t.Fatalf("block changed unrelated ownership: %+v", got)
					}
				}
				if err := source.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-copied:
					if !block && err != nil {
						t.Fatalf("raw copy failed: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("raw copy did not finish after source EOF")
				}
				for name, counter := range map[string]*appstats.Counter{"read": readCounter, "write": writeCounter, "user": userCounter} {
					if got := counter.Value(); got != int64(len(payload)) {
						t.Fatalf("%s accounting = %d, want %d", name, got, len(payload))
					}
				}
				if !block {
					if got := trackedSnapshot(t, manager, "vision-user"); got.InboundActive != 1 {
						t.Fatal("raw copy discarded tracker ownership before Close")
					}
				}
				_ = tracked.Close()
				_ = tracked.Close()
				if got := trackedSnapshot(t, manager, "vision-user"); got.InboundActive != 0 || got.InboundTotal != 1 {
					t.Fatalf("Close leaked or double-released tracked ownership: %+v", got)
				}
			})
		}
	}
}
