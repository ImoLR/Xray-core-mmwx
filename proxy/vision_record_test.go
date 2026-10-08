package proxy

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type visionRecordConn struct {
	sinkConn
	bytes.Buffer
}

func (c *visionRecordConn) Write(p []byte) (int, error) { return c.Buffer.Write(p) }
func (c *visionRecordConn) Read(p []byte) (int, error)  { return c.sinkConn.Read(p) }

func testTLSRecord(kind byte, size int) []byte {
	record := []byte{kind, 3, 3, byte(size >> 8), byte(size)}
	return append(record, bytes.Repeat([]byte{0x17, 3, 3, 0xff, 0xff}, (size+4)/5)[:size]...)
}

// Decode just the padding frames, leaving the bytes following the end command.
func decodeVisionRecords(t *testing.T, wire []byte) ([]byte, byte, []byte) {
	t.Helper()
	if len(wire) < 16 {
		t.Fatal("missing Vision UUID")
	}
	wire = wire[16:]
	var content []byte
	for len(wire) > 0 {
		if len(wire) < 5 {
			t.Fatal("truncated Vision header")
		}
		command := wire[0]
		n, padding := int(wire[1])<<8|int(wire[2]), int(wire[3])<<8|int(wire[4])
		if 5+n+padding > len(wire) {
			t.Fatal("truncated Vision frame")
		}
		content = append(content, wire[5:5+n]...)
		wire = wire[5+n+padding:]
		if command != CommandPaddingContinue {
			return content, command, wire
		}
	}
	return content, CommandPaddingContinue, nil
}

func TestVisionWriterFragmentedTLSRecords(t *testing.T) {
	// The first application record spans buffers; the same write can include
	// its end plus only part of the next record. Neither is a complete read.
	prefix := append(testTLSRecord(22, 91), testTLSRecord(20, 1)...)
	prefix = append(prefix, testTLSRecord(23, 16384)...)
	tail := append(testTLSRecord(23, 16384), testTLSRecord(23, 777)...)
	payload := append(append([]byte(nil), prefix...), tail...)
	for _, uplink := range []bool{false, true} {
		for _, chunk := range []int{1, 2, 3, 4, 5, 1200, 8192, len(payload)} {
			t.Run(fmt.Sprintf("uplink=%v/chunk=%d", uplink, chunk), func(t *testing.T) {
				state := NewTrafficState(make([]byte, 16))
				state.IsTLS, state.IsTLS12orAbove, state.EnableXtls = true, true, true
				state.NumberOfPacketToFilter = 0
				inbound := &session.Inbound{CanSpliceCopy: 2}
				ctx := session.ContextWithInbound(context.Background(), inbound)
				raw := &visionRecordConn{}
				counter, userCounter := new(appstats.Counter), new(appstats.Counter)
				conn := &stat.CounterConnection{Connection: raw, WriteCounter: counter}
				var outer bytes.Buffer
				vision := NewVisionWriter(buf.NewWriter(&outer), state, uplink, ctx, conn, nil, []uint32{1, 1, 1, 1})
				writer := &dispatcher.SizeStatWriter{Writer: vision, Counter: userCounter}
				for start := 0; start < len(payload); start += chunk {
					end := min(start+chunk, len(payload))
					if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, payload[start:end])); err != nil {
						t.Fatal(err)
					}
					if end <= len(prefix) && (raw.Len() != 0 || inbound.CanSpliceCopy != 2) {
						t.Fatal("direct copy started before a complete record")
					}
				}
				content, command, remaining := decodeVisionRecords(t, outer.Bytes())
				if !bytes.Equal(content, prefix) || command != CommandPaddingDirect || len(remaining) != 0 {
					t.Fatalf("padding boundary: content=%d, command=%d, remaining=%d", len(content), command, len(remaining))
				}
				if !bytes.Equal(raw.Bytes(), tail) {
					t.Fatalf("direct bytes = %d, want %d", raw.Len(), len(tail))
				}
				if counter.Value() != int64(len(tail)) || userCounter.Value() != int64(len(payload)) {
					t.Fatalf("counters: direct=%d user=%d", counter.Value(), userCounter.Value())
				}
				if !uplink && inbound.CanSpliceCopy != 1 {
					t.Fatal("completed direct write did not enable splice")
				}
			})
		}
	}
}

func TestVisionWriterKeepsNonDirectTraffic(t *testing.T) {
	app := testTLSRecord(23, 100)
	for _, tc := range []struct {
		name    string
		payload []byte
		enable  bool
		command byte
	}{
		{"incomplete-record", app[:len(app)-1], true, CommandPaddingContinue},
		{"malformed-record", append([]byte{23, 1, 3, 0, 1, 0}, app...), true, CommandPaddingContinue},
		{"plaintext", []byte("HTTP/1.1 200 OK\r\n\r\n"), false, CommandPaddingContinue},
		{"tls12-or-unsupported-cipher", append(append([]byte(nil), app...), app...), false, CommandPaddingEnd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := NewTrafficState(make([]byte, 16))
			state.IsTLS, state.IsTLS12orAbove, state.EnableXtls = true, true, tc.enable
			state.NumberOfPacketToFilter = 0
			inbound := &session.Inbound{CanSpliceCopy: 2}
			ctx := session.ContextWithInbound(context.Background(), inbound)
			var outer bytes.Buffer
			raw := &visionRecordConn{}
			writer := NewVisionWriter(buf.NewWriter(&outer), state, false, ctx, raw, nil, []uint32{1, 1, 1, 1})
			for _, b := range tc.payload {
				if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte{b})); err != nil {
					t.Fatal(err)
				}
			}
			content, command, remaining := decodeVisionRecords(t, outer.Bytes())
			if command != tc.command || !bytes.Equal(append(content, remaining...), tc.payload) {
				t.Fatalf("content/command changed: command=%d", command)
			}
			if raw.Len() != 0 || inbound.CanSpliceCopy != 2 {
				t.Fatal("ineligible traffic switched to direct copy")
			}
		})
	}
}
