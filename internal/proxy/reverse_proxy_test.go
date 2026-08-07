package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestReverseProxyWebSocketOutlivesRequestTimeout(t *testing.T) {
	backendCanceled := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking is not supported", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		if err := rw.Flush(); err != nil {
			return
		}

		select {
		case <-r.Context().Done():
			close(backendCanceled)
		case <-time.After(100 * time.Millisecond):
		}
	}))
	defer backend.Close()

	upstream, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	gateway := httptest.NewServer(New(upstream, 10*time.Millisecond, false))
	defer gateway.Close()

	conn, err := net.Dial("tcp", gateway.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))

	_, err = fmt.Fprintf(conn, "GET /rest/push?pushRef=test HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", gateway.Listener.Addr().String())
	if err != nil {
		t.Fatalf("write websocket request: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read websocket status: %v", err)
	}
	if !strings.Contains(statusLine, "101 Switching Protocols") {
		t.Fatalf("unexpected websocket status: %q", statusLine)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read websocket headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	select {
	case <-backendCanceled:
		t.Fatal("websocket backend was canceled by request timeout")
	case <-time.After(50 * time.Millisecond):
	}
}
