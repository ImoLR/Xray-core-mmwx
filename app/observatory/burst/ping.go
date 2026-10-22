package burst

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

type pingClient struct {
	destination string
	// fallbacks destination 不通时依次补试的地址(经出站探测时才有,见 observatory.FallbackProbeURL)
	fallbacks  []string
	httpClient *http.Client
}

func newPingClient(ctx context.Context, dispatcher routing.Dispatcher, destination string, timeout time.Duration, handler string) *pingClient {
	urls := observatory.ProbeURLs(destination, destination)
	return &pingClient{
		destination: destination,
		fallbacks:   urls[1:],
		httpClient:  newHTTPClient(ctx, dispatcher, handler, timeout),
	}
}

func newDirectPingClient(destination string, timeout time.Duration) *pingClient {
	return &pingClient{
		destination: destination,
		httpClient:  &http.Client{Timeout: timeout},
	}
}

func newHTTPClient(ctxv context.Context, dispatcher routing.Dispatcher, handler string, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			return tagged.Dialer(ctxv, dispatcher, dest, handler)
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// don't follow redirect
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// MeasureDelay returns the delay time of the request to dest
// (dest 不通时依次补试 fallbacks,任一个通就返回它的延迟)
func (s *pingClient) MeasureDelay(httpMethod string) (time.Duration, error) {
	d, err := s.measure(httpMethod, s.destination)
	for _, u := range s.fallbacks {
		if err == nil {
			break
		}
		d, err = s.measure(httpMethod, u)
	}
	return d, err
}

func (s *pingClient) measure(httpMethod, destination string) (time.Duration, error) {
	if s.httpClient == nil {
		panic("pingClient not initialized")
	}

	req, err := http.NewRequest(httpMethod, destination, nil)
	if err != nil {
		return rttFailed, err
	}
	utils.TryDefaultHeadersWith(req.Header, "nav")

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return rttFailed, err
	}
	if httpMethod == http.MethodGet {
		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil {
			return rttFailed, err
		}
	}
	resp.Body.Close()

	return time.Since(start), nil
}
