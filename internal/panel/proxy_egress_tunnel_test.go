package panel

import (
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
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// 面板“测试连接”必须能经 trojan 隧道真的取到出口 IP（不是只看端口通不通）。
func TestProbeProxyExitIPThroughTrojan(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "8.8.4.4")
	}))
	defer echo.Close()

	password := "probe-pass"
	nodeHost, nodePort, stopNode := startFakeTrojan(t, password)
	defer stopNode()
	raw := "trojan://" + password + "@" + net.JoinHostPort(nodeHost, strconv.Itoa(nodePort)) + "?sni=test.local"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ip, err := probeProxyExitIPTo(ctx, raw, echo.URL)
	if err != nil {
		t.Fatalf("probe through trojan: %v", err)
	}
	if ip != "8.8.4.4" {
		t.Fatalf("exit ip=%q want 8.8.4.4", ip)
	}
}

func panelTestCert(t *testing.T) tls.Certificate {
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
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// startFakeTrojan 起一个最小 trojan 服务端：校验密码后按目标地址转发。
func startFakeTrojan(t *testing.T, password string) (string, int, func()) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{panelTestCert(t)}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum224([]byte(password))
	want := hex.EncodeToString(digest[:])
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				head := make([]byte, len(want))
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				if string(head) != want {
					return
				}
				crlf := make([]byte, 2)
				if _, err := io.ReadFull(c, crlf); err != nil {
					return
				}
				cmd := make([]byte, 1)
				if _, err := io.ReadFull(c, cmd); err != nil {
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
				target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf))))
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
	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { _ = listener.Close() }
}
