package upstream

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

// 本文件实现 trojan / anytls 两种加密出站协议（标准库实现，无第三方依赖）。
//
// 为什么需要：机场订阅绝大多数节点是 trojan / anytls，而 HTTP 客户端只能直连
// http/https/socks5。有了这两个拨号器，订阅节点可以被账号直接绑定，
// 不必再在本机另外跑一个协议转换进程（少一跳、少一个会挂的单点）。
//
// 证书校验：这类节点的服务端普遍使用自签证书 + 域名伪装（SNI 指向真实站点），
// 链式校验必然失败，因此默认「不校验证书」，可以用 ?verify=1 / ?allowInsecure=0
// 打开校验（对接正规证书的节点时更安全）。

const (
	anytlsCmdWaste               = 0
	anytlsCmdSYN                 = 1
	anytlsCmdPSH                 = 2
	anytlsCmdFIN                 = 3
	anytlsCmdSettings            = 4
	anytlsCmdAlert               = 5
	anytlsCmdUpdatePaddingScheme = 6
	anytlsCmdSYNACK              = 7
	anytlsCmdHeartRequest        = 8
	anytlsCmdHeartResponse       = 9
)

// anytlsDefaultPaddingScheme 是协议文档给出的默认填充方案（首包 padding0=30）。
const anytlsDefaultPaddingScheme = "stop=8\n0=30-30\n1=100-400\n" +
	"2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n" +
	"3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"

const anytlsClientName = "workbuddy2api-panel/1"

type anytlsPaddingState struct {
	mu     sync.RWMutex
	scheme string
}

var anytlsPaddingScheme = anytlsPaddingState{scheme: anytlsDefaultPaddingScheme}

func currentAnyTLSPaddingScheme() string {
	anytlsPaddingScheme.mu.RLock()
	defer anytlsPaddingScheme.mu.RUnlock()
	return anytlsPaddingScheme.scheme
}

// ProxyTunnelDialer 为 trojan / anytls 代理构造拨号函数；其它 scheme 返回错误。
// 返回的 DialContext 语义与 http.Transport.DialContext 一致：拨到 addr 时，
// 流量会经加密隧道从代理节点出去。
func ProxyTunnelDialer(rawProxy string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	stored, _, err := auth.NormalizeProxy(rawProxy)
	if err != nil || stored == "" {
		return nil, errors.New("invalid tunnel proxy")
	}
	u, err := url.Parse(stored)
	if err != nil || u.Host == "" {
		return nil, errors.New("invalid tunnel proxy")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "trojan" && scheme != "anytls" {
		return nil, fmt.Errorf("scheme %q is not a tunnel protocol", scheme)
	}
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	if password == "" {
		return nil, fmt.Errorf("%s proxy requires a password", scheme)
	}
	nodeAddr := u.Host
	sni := firstNonEmpty(u.Query().Get("sni"), u.Query().Get("peer"), u.Hostname())
	// 默认不校验证书：机场节点普遍是自签证书 + SNI 伪装（链式校验必然失败）。
	// 注意 verify 与 allowInsecure 语义相反，不能混用同一个取值分支。
	verify := false
	switch strings.ToLower(strings.TrimSpace(u.Query().Get("verify"))) {
	case "1", "true", "yes", "on":
		verify = true
	case "0", "false", "no", "off":
		verify = false
	}
	switch strings.ToLower(strings.TrimSpace(u.Query().Get("allowinsecure"))) {
	case "1", "true", "yes", "on":
		verify = false
	case "0", "false", "no", "off":
		verify = true
	}
	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: !verify, MinVersion: tls.VersionTLS12}

	dialTunnel := func(ctx context.Context, target string) (*tls.Conn, error) {
		d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
		raw, err := d.DialContext(ctx, "tcp", nodeAddr)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, cfg)
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		return conn, nil
	}

	switch scheme {
	case "trojan":
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, fmt.Errorf("trojan supports tcp only")
			}
			conn, err := dialTunnel(ctx, addr)
			if err != nil {
				return nil, err
			}
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			header, err := trojanHeader(password, host, port)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			if _, err := conn.Write(header); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		}, nil
	case "anytls":
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, fmt.Errorf("anytls supports tcp only")
			}
			conn, err := dialTunnel(ctx, addr)
			if err != nil {
				return nil, err
			}
			stream, err := anytlsOpenStream(ctx, conn, password, addr)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return stream, nil
		}, nil
	}
	return nil, errors.New("unsupported tunnel protocol")
}

// trojanHeader 构造 RFC 一致的请求头：hex(sha224(password)) CRLF cmd atyp addr port CRLF。
func trojanHeader(password, host string, port int) ([]byte, error) {
	sum := sha256.Sum224([]byte(password))
	header := make([]byte, 0, 32+64)
	header = append(header, hex.EncodeToString(sum[:])...)
	header = append(header, 0x0d, 0x0a, 0x01)
	socks, err := socksAddrBytes(host, port)
	if err != nil {
		return nil, err
	}
	header = append(header, socks...)
	header = append(header, 0x0d, 0x0a)
	return header, nil
}

// socksAddrBytes 编出 RFC1928 目标地址（atyp + addr + port）。
func socksAddrBytes(host string, port int) ([]byte, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}
	out := make([]byte, 0, 1+16+2)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, 0x01)
			out = append(out, v4...)
		} else {
			out = append(out, 0x04)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("host too long")
		}
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
	}
	return append(out, byte(port>>8), byte(port&0xff)), nil
}

func anytlsFrame(cmd byte, streamID uint32, data []byte) []byte {
	out := make([]byte, 7+len(data))
	out[0] = cmd
	binary.BigEndian.PutUint32(out[1:5], streamID)
	binary.BigEndian.PutUint16(out[5:7], uint16(len(data)))
	copy(out[7:], data)
	return out
}

// anytlsPadding0Length 从 padding scheme 的 "0=a-b" 行取出首包填充长度（缺省 30）。
func anytlsPadding0Length(scheme string) int {
	for _, line := range strings.Split(scheme, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "0=") {
			continue
		}
		span := strings.TrimPrefix(line, "0=")
		if idx := strings.IndexByte(span, ','); idx >= 0 {
			span = span[:idx]
		}
		parts := strings.SplitN(span, "-", 2)
		lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || lo < 0 || lo > 4096 {
			return 30
		}
		return lo
	}
	return 30
}

// anytlsOpenStream 在已握手的 TLS 连接上认证并打开一条 stream。
func anytlsOpenStream(ctx context.Context, conn *tls.Conn, password, target string) (net.Conn, error) {
	scheme := currentAnyTLSPaddingScheme()
	padding0 := anytlsPadding0Length(scheme)
	sum := sha256.Sum256([]byte(password))
	authPacket := make([]byte, 0, 34+padding0)
	authPacket = append(authPacket, sum[:]...)
	authPacket = append(authPacket, byte(padding0>>8), byte(padding0&0xff))
	authPacket = append(authPacket, make([]byte, padding0)...)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	} else {
		_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	}
	if _, err := conn.Write(authPacket); err != nil {
		return nil, fmt.Errorf("anytls auth: %w", err)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	targetAddr, err := socksAddrBytes(host, port)
	if err != nil {
		return nil, err
	}
	digest := md5.Sum([]byte(scheme))
	settings := "v=2\nclient=" + anytlsClientName + "\npadding-md5=" + hex.EncodeToString(digest[:])
	const streamID = uint32(1)
	buf := append(anytlsFrame(anytlsCmdSettings, 0, []byte(settings)), anytlsFrame(anytlsCmdSYN, streamID, nil)...)
	buf = append(buf, anytlsFrame(anytlsCmdPSH, streamID, targetAddr)...)
	if _, err := conn.Write(buf); err != nil {
		return nil, fmt.Errorf("anytls open stream: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	stream := &anytlsStream{
		conn:     conn,
		streamID: streamID,
		incoming: make(chan []byte, 32),
		failed:   make(chan error, 1),
		closed:   make(chan struct{}),
	}
	go stream.readLoop()
	return stream, nil
}

// anytlsStream 把 anytls 的一条 stream 包装成 net.Conn。
// 每次拨号独立一条 TLS 会话（不做跨连接复用）：HTTP 层本身有 keep-alive，
// 复用收益有限，换来的是实现简单、出错面小。
type anytlsStream struct {
	conn     *tls.Conn
	streamID uint32

	writeMu sync.Mutex

	pending  []byte
	incoming chan []byte
	failed   chan error

	closeOnce sync.Once
	closed    chan struct{}
}

func (s *anytlsStream) readLoop() {
	defer close(s.incoming)
	header := make([]byte, 7)
	for {
		if _, err := io.ReadFull(s.conn, header); err != nil {
			s.fail(err)
			return
		}
		cmd := header[0]
		streamID := binary.BigEndian.Uint32(header[1:5])
		length := int(binary.BigEndian.Uint16(header[5:7]))
		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				s.fail(err)
				return
			}
		}
		switch cmd {
		case anytlsCmdPSH:
			if streamID == s.streamID && length > 0 {
				select {
				case s.incoming <- payload:
				case <-s.closed:
					return
				}
			}
		case anytlsCmdFIN:
			if streamID == s.streamID {
				return
			}
		case anytlsCmdSYNACK:
			if length > 0 {
				s.fail(fmt.Errorf("anytls server rejected stream: %s", truncateForError(payload)))
				return
			}
		case anytlsCmdAlert:
			s.fail(fmt.Errorf("anytls server alert: %s", truncateForError(payload)))
			return
		case anytlsCmdHeartRequest:
			s.writeMu.Lock()
			_, _ = s.conn.Write(anytlsFrame(anytlsCmdHeartResponse, 0, payload))
			s.writeMu.Unlock()
		case anytlsCmdUpdatePaddingScheme:
			if text := strings.TrimSpace(string(payload)); text != "" {
				anytlsPaddingScheme.mu.Lock()
				anytlsPaddingScheme.scheme = text
				anytlsPaddingScheme.mu.Unlock()
			}
		}
	}
}

func (s *anytlsStream) fail(err error) {
	select {
	case s.failed <- err:
	default:
	}
}

func truncateForError(b []byte) string {
	const limit = 120
	if len(b) > limit {
		return string(b[:limit]) + "…"
	}
	return string(b)
}

func (s *anytlsStream) Read(p []byte) (int, error) {
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}
	select {
	case data, ok := <-s.incoming:
		if !ok {
			select {
			case err := <-s.failed:
				return 0, err
			default:
			}
			return 0, io.EOF
		}
		n := copy(p, data)
		if n < len(data) {
			s.pending = data[n:]
		}
		return n, nil
	case err := <-s.failed:
		return 0, err
	case <-s.closed:
		return 0, io.EOF
	}
}

func (s *anytlsStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := len(p)
		if chunk > 16000 {
			chunk = 16000
		}
		if _, err := s.conn.Write(anytlsFrame(anytlsCmdPSH, s.streamID, p[:chunk])); err != nil {
			return written, err
		}
		written += chunk
		p = p[chunk:]
	}
	return written, nil
}

func (s *anytlsStream) Close() error {
	s.closeOnce.Do(func() {
		if s.closed != nil {
			close(s.closed)
		}
		s.writeMu.Lock()
		_, _ = s.conn.Write(anytlsFrame(anytlsCmdFIN, s.streamID, nil))
		s.writeMu.Unlock()
		_ = s.conn.Close()
	})
	return nil
}

func (s *anytlsStream) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *anytlsStream) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

func (s *anytlsStream) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *anytlsStream) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *anytlsStream) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
