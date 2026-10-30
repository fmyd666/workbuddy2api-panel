package upstream

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// selfSignedTLS 生成测试用自签证书（真实节点也是自签 + SNI 伪装）。
func selfSignedTLS(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// startEcho 启动本地目标服务：收到连接后立刻写回固定 banner。
func startEcho(t *testing.T, banner string) (host string, port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(banner))
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { _ = ln.Close() }
}

// startTrojanServer 实现 trojan 服务端的最小校验与转发。
func startTrojanServer(t *testing.T, password string) (host string, port int, stop func()) {
	t.Helper()
	cert := selfSignedTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum224([]byte(password))
	want := hex.EncodeToString(digest[:])
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line := make([]byte, len(want))
				if _, err := io.ReadFull(c, line); err != nil {
					return
				}
				if string(line) != want {
					return // 认证失败：直接断连（与真实实现一致）
				}
				crlf := make([]byte, 2)
				if _, err := io.ReadFull(c, crlf); err != nil {
					return
				}
				if string(crlf) != "\r\n" {
					return
				}
				cmd := make([]byte, 1)
				if _, err := io.ReadFull(c, cmd); err != nil || cmd[0] != 0x01 {
					return
				}
				atyp := make([]byte, 1)
				if _, err := io.ReadFull(c, atyp); err != nil {
					return
				}
				var host string
				switch atyp[0] {
				case 0x01:
					ip := make([]byte, 4)
					if _, err := io.ReadFull(c, ip); err != nil {
						return
					}
					host = net.IP(ip).String()
				case 0x03:
					length := make([]byte, 1)
					if _, err := io.ReadFull(c, length); err != nil {
						return
					}
					name := make([]byte, int(length[0]))
					if _, err := io.ReadFull(c, name); err != nil {
						return
					}
					host = string(name)
				default:
					return
				}
				portBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, portBuf); err != nil {
					return
				}
				if _, err := io.ReadFull(c, crlf); err != nil {
					return
				}
				target := net.JoinHostPort(host, itoa(int(binary.BigEndian.Uint16(portBuf))))
				upstream, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer upstream.Close()
				go func() { _, _ = io.Copy(upstream, c) }()
				_, _ = io.Copy(c, upstream)
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { _ = ln.Close() }
}

// startAnyTLSServer 实现 anytls 服务端的最小认证、帧解析与转发。
func startAnyTLSServer(t *testing.T, password string) (host string, port int, stop func()) {
	t.Helper()
	cert := selfSignedTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(password))
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				authDigest := make([]byte, 32)
				if _, err := io.ReadFull(c, authDigest); err != nil {
					return
				}
				if !bytes.Equal(authDigest, want[:]) {
					return
				}
				padLen := make([]byte, 2)
				if _, err := io.ReadFull(c, padLen); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(padLen))); err != nil {
					return
				}
				var target string
				streamID := uint32(0)
				header := make([]byte, 7)
				var upstream net.Conn
				for {
					if _, err := io.ReadFull(c, header); err != nil {
						return
					}
					cmd := header[0]
					sid := binary.BigEndian.Uint32(header[1:5])
					length := int(binary.BigEndian.Uint16(header[5:7]))
					payload := make([]byte, length)
					if length > 0 {
						if _, err := io.ReadFull(c, payload); err != nil {
							return
						}
					}
					switch cmd {
					case anytlsCmdSettings:
						continue
					case anytlsCmdSYN:
						streamID = sid
						continue
					case anytlsCmdPSH:
						if upstream == nil {
							host, portStr, err := decodeSocksAddr(payload)
							if err != nil {
								return
							}
							target = net.JoinHostPort(host, portStr)
							upstream, err = net.Dial("tcp", target)
							if err != nil {
								_ = c.Close()
								return
							}
							defer upstream.Close()
							_, _ = c.Write(anytlsFrame(anytlsCmdSYNACK, streamID, nil))
							go func(u net.Conn, id uint32) {
								buf := make([]byte, 16000)
								for {
									n, err := u.Read(buf)
									if n > 0 {
										_, _ = c.Write(anytlsFrame(anytlsCmdPSH, id, buf[:n]))
									}
									if err != nil {
										_, _ = c.Write(anytlsFrame(anytlsCmdFIN, id, nil))
										return
									}
								}
							}(upstream, streamID)
							continue
						}
						_, _ = upstream.Write(payload)
					}
				}
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { _ = ln.Close() }
}

func decodeSocksAddr(b []byte) (string, string, error) {
	if len(b) < 2 {
		return "", "", io.ErrUnexpectedEOF
	}
	switch b[0] {
	case 0x01:
		if len(b) < 7 {
			return "", "", io.ErrUnexpectedEOF
		}
		port := binary.BigEndian.Uint16(b[5:7])
		return net.IP(b[1:5]).String(), itoa(int(port)), nil
	case 0x03:
		length := int(b[1])
		if len(b) < 2+length+2 {
			return "", "", io.ErrUnexpectedEOF
		}
		port := binary.BigEndian.Uint16(b[2+length : 4+length])
		return string(b[2 : 2+length]), itoa(int(port)), nil
	default:
		return "", "", io.ErrUnexpectedEOF
	}
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

func TestProxyTunnelDialerTrojan(t *testing.T) {
	targetHost, targetPort, stopEcho := startEcho(t, "trojan-ok")
	defer stopEcho()
	nodeHost, nodePort, stopNode := startTrojanServer(t, "s3cret")
	defer stopNode()

	dial, err := ProxyTunnelDialer("trojan://s3cret@" + net.JoinHostPort(nodeHost, itoa(nodePort)) + "?sni=test.local")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort(targetHost, itoa(targetPort)))
	if err != nil {
		t.Fatalf("dial through trojan: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); !strings.HasPrefix(got, "trojan-ok") {
		t.Fatalf("banner=%q", got)
	}
}

func TestProxyTunnelDialerTrojanRejectsWrongPassword(t *testing.T) {
	nodeHost, nodePort, stopNode := startTrojanServer(t, "right-password")
	defer stopNode()
	targetHost, targetPort, stopEcho := startEcho(t, "never")
	defer stopEcho()

	dial, err := ProxyTunnelDialer("trojan://wrong-password@" + net.JoinHostPort(nodeHost, itoa(nodePort)) + "?sni=test.local")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort(targetHost, itoa(targetPort)))
	if err != nil {
		return // 有的实现直接断连，等价于失败
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	if n, _ := conn.Read(buf); n > 0 {
		t.Fatalf("wrong password still got data: %q", buf[:n])
	}
}

func TestProxyTunnelDialerAnyTLS(t *testing.T) {
	targetHost, targetPort, stopEcho := startEcho(t, "anytls-ok")
	defer stopEcho()
	nodeHost, nodePort, stopNode := startAnyTLSServer(t, "anytls-pass")
	defer stopNode()

	dial, err := ProxyTunnelDialer("anytls://anytls-pass@" + net.JoinHostPort(nodeHost, itoa(nodePort)) + "?sni=test.local")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort(targetHost, itoa(targetPort)))
	if err != nil {
		t.Fatalf("dial through anytls: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); !strings.HasPrefix(got, "anytls-ok") {
		t.Fatalf("banner=%q", got)
	}
}

func TestProxyTunnelDialerRejectsPlainSchemes(t *testing.T) {
	for _, raw := range []string{"socks5h://1.2.3.4:1080", "http://1.2.3.4:8080", "trojan://host:443"} {
		if _, err := ProxyTunnelDialer(raw); err == nil {
			t.Fatalf("%q should not produce a tunnel dialer", raw)
		}
	}
}
