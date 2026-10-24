package shadowtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// 测试用的 ShadowTLS v3 客户端,同样只按协议文档写:
// SessionID 末 4 字节放 HMAC(password, ClientHello);读端认出被标记的 ApplicationData 就去掉标记、XOR 回去交给 TLS;
// 握手完成后改为自己的数据封装(HMAC_ServerRandomC 写、HMAC_ServerRandomS 读,跳过 HMAC_ServerRandom 的残帧)。

const testPassword = "test-shadowtls-password"

// startHandshakeServer 起一个只讲 TLS 1.3 的本地握手服务器,收到什么就回什么(TLS 内)。
func startHandshakeServer(t *testing.T) (addr string, certDER []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "handshake.test"},
		DNSNames:     []string{"handshake.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String(), certDER
}

// startServer 起 ShadowTLS 服务端:认证通过后把内层数据原样回显(代替 Snell)。
func startServer(t *testing.T, cfg *Config) (addr string, errs chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	errs = make(chan error, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				inner, err := Accept(context.Background(), c, cfg)
				errs <- err
				if err != nil {
					return
				}
				buf := make([]byte, 64<<10)
				for {
					n, err := inner.Read(buf)
					if err != nil {
						errs <- err
						return
					}
					if _, err := inner.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), errs
}

// clientReadWrapper 握手阶段 TLS 客户端读的那一层。
type clientReadWrapper struct {
	net.Conn
	password string

	mu           sync.Mutex
	serverRandom []byte
	hmacSR       *streamHMAC
	key          []byte
	verified     bool // 至少有一帧 ApplicationData 带着正确标记
	pending      []byte
}

func (w *clientReadWrapper) Read(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(w.pending) == 0 {
		rec, err := readRecord(w.Conn)
		if err != nil {
			return 0, err
		}
		switch {
		case rec[0] == typeHandshake && w.serverRandom == nil:
			if sr, ok := extractServerRandom(rec); ok {
				w.serverRandom = sr
				w.hmacSR = newStreamHMAC([]byte(w.password), sr)
				w.key = xorKey(w.password, sr)
			}
		case rec[0] == typeApplicationData && w.hmacSR != nil && len(rec) >= recordHeaderLen+hmacLen:
			data := rec[recordHeaderLen+hmacLen:]
			w.hmacSR.write(data)
			sum := w.hmacSR.sum4()
			if bytes.Equal(sum[:], rec[recordHeaderLen:recordHeaderLen+hmacLen]) {
				w.verified = true
				xorCycle(data, w.key)
				out := make([]byte, recordHeaderLen+len(data))
				copy(out, rec[:recordHeaderLen])
				binary.BigEndian.PutUint16(out[3:5], uint16(len(data)))
				copy(out[recordHeaderLen:], data)
				rec = out
			}
		}
		w.pending = rec
	}
	n := copy(p, w.pending)
	w.pending = w.pending[n:]
	return n, nil
}

type testClient struct {
	raw       net.Conn
	hmacRead  *streamHMAC
	hmacSkip  *streamHMAC // 残帧检测,遇到第一帧不是残帧就关掉
	hmacWrite *streamHMAC
	pending   []byte
}

func dialClient(t *testing.T, addr, password string, certDER []byte) (*testClient, error) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	rw := &clientReadWrapper{Conn: raw, password: password}
	pool := x509.NewCertPool()
	cert, _ := x509.ParseCertificate(certDER)
	pool.AddCert(cert)
	uconn := utls.UClient(rw, &utls.Config{ServerName: "handshake.test", RootCAs: pool}, utls.HelloChrome_Auto)
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	sid := make([]byte, sessionIDLen)
	_, _ = rand.Read(sid[:sessionIDLen-hmacLen])
	uconn.HandshakeState.Hello.SessionId = sid
	if err := uconn.MarshalClientHello(); err != nil {
		return nil, err
	}
	// Raw 是去掉记录头的 ClientHello,此刻 SessionID 末 4 字节为 0,正好是 HMAC 的输入。
	h := newStreamHMAC([]byte(password))
	h.write(uconn.HandshakeState.Hello.Raw)
	sum := h.sum4()
	copy(sid[sessionIDLen-hmacLen:], sum[:])
	uconn.HandshakeState.Hello.SessionId = sid
	if err := uconn.MarshalClientHello(); err != nil {
		return nil, err
	}
	if err := uconn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	if !rw.verified {
		raw.Close()
		return nil, errNotVerified
	}
	sr := rw.serverRandom
	pw := []byte(password)
	return &testClient{
		raw:       raw,
		hmacRead:  newStreamHMAC(pw, sr, []byte("S")),
		hmacSkip:  rw.hmacSR,
		hmacWrite: newStreamHMAC(pw, sr, []byte("C")),
		pending:   rw.pending,
	}, nil
}

var errNotVerified = io.ErrUnexpectedEOF

func (c *testClient) write(p []byte) error {
	rec := make([]byte, recordHeaderLen+hmacLen+len(p))
	rec[0], rec[1], rec[2] = typeApplicationData, 0x03, 0x03
	binary.BigEndian.PutUint16(rec[3:5], uint16(hmacLen+len(p)))
	c.hmacWrite.write(p)
	sum := c.hmacWrite.sum4()
	c.hmacWrite.write(sum[:])
	copy(rec[recordHeaderLen:], sum[:])
	copy(rec[recordHeaderLen+hmacLen:], p)
	_, err := c.raw.Write(rec)
	return err
}

func (c *testClient) readRecord() ([]byte, error) {
	if len(c.pending) > 0 {
		r := io.MultiReader(bytes.NewReader(c.pending), c.raw)
		c.pending = nil
		return readRecord(r)
	}
	return readRecord(c.raw)
}

func (c *testClient) read() ([]byte, error) {
	for {
		rec, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		if rec[0] != typeApplicationData || len(rec) < recordHeaderLen+hmacLen {
			continue
		}
		data := rec[recordHeaderLen+hmacLen:]
		mark := rec[recordHeaderLen : recordHeaderLen+hmacLen]
		if c.hmacSkip != nil {
			tmp := c.hmacSkip.clone()
			tmp.write(data)
			if sum := tmp.sum4(); bytes.Equal(sum[:], mark) {
				c.hmacSkip = tmp
				continue
			}
			c.hmacSkip = nil
		}
		c.hmacRead.write(data)
		sum := c.hmacRead.sum4()
		c.hmacRead.write(sum[:])
		if !bytes.Equal(sum[:], mark) {
			return nil, io.ErrUnexpectedEOF
		}
		return data, nil
	}
}

func TestShadowTLSRoundTrip(t *testing.T) {
	hsAddr, cert := startHandshakeServer(t)
	addr, errs := startServer(t, &Config{Password: testPassword, Handshake: hsAddr, Strict: true})

	c, err := dialClient(t, addr, testPassword, cert)
	if err != nil {
		t.Fatalf("握手失败: %v", err)
	}
	defer c.raw.Close()
	// 服务端要收到客户端第一帧数据才算切换完成,Accept 才返回 —— 所以先发、再看 Accept 的结果。
	for i, size := range []int{1, 1000, 40000} {
		msg := make([]byte, size)
		_, _ = rand.Read(msg)
		if err := c.write(msg); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := <-errs; err != nil {
				t.Fatalf("服务端 Accept: %v", err)
			}
		}
		var got []byte
		for len(got) < size {
			d, err := c.read()
			if err != nil {
				t.Fatalf("读回显(%d): %v", size, err)
			}
			got = append(got, d...)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("回显内容不对(%d 字节)", size)
		}
	}
}

// 认不出的连接(普通 TLS 客户端 / 主动探测)整条转给握手服务器:对方拿到的是握手服务器的证书,能正常收发。
func TestShadowTLSFallbackToHandshakeServer(t *testing.T) {
	hsAddr, cert := startHandshakeServer(t)
	addr, errs := startServer(t, &Config{Password: testPassword, Handshake: hsAddr, Strict: true})

	pool := x509.NewCertPool()
	c, _ := x509.ParseCertificate(cert)
	pool.AddCert(c)
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "handshake.test", RootCAs: pool})
	if err != nil {
		t.Fatalf("普通 TLS 客户端应能和握手服务器完成握手: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("经转发应收到握手服务器的回显: %q %v", buf, err)
	}
	conn.Close()
	if err := <-errs; err != ErrFallback {
		t.Fatalf("应返回 ErrFallback,得到 %v", err)
	}
}

// 密码不对:服务端当作探测转发,客户端校验不到标记、拒绝继续。
func TestShadowTLSWrongPassword(t *testing.T) {
	hsAddr, cert := startHandshakeServer(t)
	addr, errs := startServer(t, &Config{Password: testPassword, Handshake: hsAddr, Strict: true})
	c, err := dialClient(t, addr, "wrong-password", cert)
	if err == nil {
		c.raw.Close()
		t.Fatal("密码错误不应认证成功")
	}
	if err := <-errs; err != ErrFallback {
		t.Fatalf("应返回 ErrFallback,得到 %v", err)
	}
}

// 切换后被篡改的数据帧:服务端校验失败、断开。
func TestShadowTLSTamperedRecord(t *testing.T) {
	hsAddr, cert := startHandshakeServer(t)
	addr, errs := startServer(t, &Config{Password: testPassword, Handshake: hsAddr, Strict: true})
	c, err := dialClient(t, addr, testPassword, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer c.raw.Close()
	if err := c.write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if _, err := c.read(); err != nil {
		t.Fatal(err)
	}
	// 手工造一帧标记错误的数据
	rec := []byte{typeApplicationData, 0x03, 0x03, 0, hmacLen + 3, 1, 2, 3, 4, 'b', 'a', 'd'}
	if _, err := c.raw.Write(rec); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("篡改的帧应让服务端报错")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("服务端没有拒绝篡改的帧")
	}
}

func TestStreamHMACMatchesStdlib(t *testing.T) {
	// streamHMAC 在一次性计算上必须与 HMAC-SHA1 一致(前 4 字节)。
	for _, key := range [][]byte{[]byte("k"), bytes.Repeat([]byte("x"), 100)} {
		h := newStreamHMAC(key, []byte("ab"))
		h.write([]byte("cd"))
		got := h.sum4()
		want := stdHMAC4(key, []byte("abcd"))
		if got != want {
			t.Fatalf("key len %d: %x != %x", len(key), got, want)
		}
		// clone 后两边独立
		c := h.clone()
		c.write([]byte("e"))
		if h.sum4() != want {
			t.Fatal("clone 改动了原实例")
		}
	}
}

func stdHMAC4(key, msg []byte) [hmacLen]byte {
	m := hmac.New(sha1.New, key)
	m.Write(msg)
	var out [hmacLen]byte
	copy(out[:], m.Sum(nil))
	return out
}
