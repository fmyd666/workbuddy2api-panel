package panel

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func startProxyEcho(t *testing.T, mode string) (string, <-chan error, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if mode == "http" {
			req, err := http.ReadRequest(reader)
			if err != nil {
				result <- err
				return
			}
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte("probe-user:probe-pass"))
			if req.Header.Get("Proxy-Authorization") != want {
				result <- io.ErrUnexpectedEOF
				return
			}
			if req.URL.Host != "echo.example" {
				result <- io.ErrUnexpectedEOF
				return
			}
		} else {
			var greeting [2]byte
			if _, err := io.ReadFull(reader, greeting[:]); err != nil {
				result <- err
				return
			}
			methods := make([]byte, int(greeting[1]))
			if _, err := io.ReadFull(reader, methods); err != nil {
				result <- err
				return
			}
			if _, err := conn.Write([]byte{5, 2}); err != nil {
				result <- err
				return
			}
			var authHead [2]byte
			if _, err := io.ReadFull(reader, authHead[:]); err != nil {
				result <- err
				return
			}
			user := make([]byte, int(authHead[1]))
			if _, err := io.ReadFull(reader, user); err != nil {
				result <- err
				return
			}
			var plen [1]byte
			if _, err := io.ReadFull(reader, plen[:]); err != nil {
				result <- err
				return
			}
			pass := make([]byte, int(plen[0]))
			if _, err := io.ReadFull(reader, pass); err != nil {
				result <- err
				return
			}
			if string(user) != "probe-user" || string(pass) != "probe-pass" {
				result <- io.ErrUnexpectedEOF
				return
			}
			if _, err := conn.Write([]byte{1, 0}); err != nil {
				result <- err
				return
			}
			var request [4]byte
			if _, err := io.ReadFull(reader, request[:]); err != nil {
				result <- err
				return
			}
			if request[0] != 5 || request[1] != 1 {
				result <- io.ErrUnexpectedEOF
				return
			}
			switch request[3] {
			case 1:
				var addr [4]byte
				if _, err := io.ReadFull(reader, addr[:]); err != nil {
					result <- err
					return
				}
			case 3:
				var n [1]byte
				if _, err := io.ReadFull(reader, n[:]); err != nil {
					result <- err
					return
				}
				if _, err := io.CopyN(io.Discard, reader, int64(n[0])); err != nil {
					result <- err
					return
				}
			case 4:
				if _, err := io.CopyN(io.Discard, reader, 16); err != nil {
					result <- err
					return
				}
			default:
				result <- io.ErrUnexpectedEOF
				return
			}
			var port [2]byte
			if _, err := io.ReadFull(reader, port[:]); err != nil {
				result <- err
				return
			}
			if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
				result <- err
				return
			}
			req, err := http.ReadRequest(reader)
			if err != nil {
				result <- err
				return
			}
			if req.Host != "echo.example" {
				result <- io.ErrUnexpectedEOF
				return
			}
		}
		body := "8.8.8.8"
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\nConnection: close\r\n\r\n"+body)
		result <- nil
	}()
	return ln.Addr().String(), result, func() { _ = ln.Close() }
}

func TestProbeProxyExitIPHTTPProxyAuth(t *testing.T) {
	addr, serverResult, closeServer := startProxyEcho(t, "http")
	defer closeServer()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ip, err := probeProxyExitIPTo(ctx, "http://probe-user:probe-pass@"+addr, "http://echo.example/")
	if err != nil || ip != "8.8.8.8" {
		t.Fatalf("probe ip=%q err=%v", ip, err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("proxy did not receive authenticated request")
	}
}

func TestProbeProxyExitIPSocks5Auth(t *testing.T) {
	addr, serverResult, closeServer := startProxyEcho(t, "socks")
	defer closeServer()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ip, err := probeProxyExitIPTo(ctx, "socks5h://probe-user:probe-pass@"+addr, "http://echo.example/")
	if err != nil || ip != "8.8.8.8" {
		t.Fatalf("probe ip=%q err=%v", ip, err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("SOCKS proxy did not receive authenticated request")
	}
}

func TestProbeProxyExitIPDoesNotFallBackDirect(t *testing.T) {
	directHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { directHits++; _, _ = io.WriteString(w, "8.8.8.8") }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := probeProxyExitIPTo(ctx, "http://user:pass@127.0.0.1:1", server.URL)
	if err == nil || directHits != 0 {
		t.Fatalf("proxy failure fell back direct: err=%v direct=%d", err, directHits)
	}
}

func TestProxyImportKeepsTrulyUnsupportedMetadataOnly(t *testing.T) {
	entries, unsupported, errs := parseProxyImport("ss://YWVzOnBhc3M@proxy.example:8388#node")
	if len(entries) != 0 || len(unsupported) != 1 || len(errs) != 0 {
		t.Fatalf("entries=%v unsupported=%v errors=%v", entries, unsupported, errs)
	}
	if text := unsupported[0]["type"]; text != "ss" {
		t.Fatalf("unsupported type=%v", text)
	}
	entries, unsupported, errs = parseProxyImport("vless://uuid@proxy.example:443?security=tls")
	if len(entries) != 0 || len(unsupported) != 1 || len(errs) != 0 {
		t.Fatalf("entries=%v unsupported=%v errors=%v", entries, unsupported, errs)
	}
}
