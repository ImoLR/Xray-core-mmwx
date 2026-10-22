package burst

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// 探测地址不通(机房封了 gstatic)时补试备用地址,通了就不算失败(妙妙屋X #1367)。
func TestPingClientFallsBackWhenPrimaryFails(t *testing.T) {
	var hits atomic.Int32
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + l.Addr().String() + "/generate_204"
	l.Close() // 端口关掉:连不上

	c := &pingClient{destination: dead, fallbacks: []string{good.URL}, httpClient: &http.Client{Timeout: 2 * time.Second}}
	if _, err := c.MeasureDelay(http.MethodHead); err != nil {
		t.Fatalf("主地址不通时应改试备用地址: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("备用地址应被试 1 次,实际 %d", hits.Load())
	}

	// 主地址通时不碰备用地址
	c = &pingClient{destination: good.URL, fallbacks: []string{dead}, httpClient: &http.Client{Timeout: 2 * time.Second}}
	if _, err := c.MeasureDelay(http.MethodHead); err != nil {
		t.Fatal(err)
	}
	// 都不通才算失败
	c = &pingClient{destination: dead, fallbacks: []string{dead}, httpClient: &http.Client{Timeout: 2 * time.Second}}
	if _, err := c.MeasureDelay(http.MethodHead); err == nil {
		t.Fatal("都不通时应返回错误")
	}
}
