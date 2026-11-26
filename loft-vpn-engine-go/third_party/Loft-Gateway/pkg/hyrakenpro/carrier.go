package hyrakenpro

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

const (
	maxGRPCMessage = 128 << 10
	// A single RPC carries all logical streams on a physical connection. Keep
	// its bounded receive credit separate from the inner mux's RX accounting.
	h2ReceiveStreamBytes     = 4 << 20
	h2ReceiveConnectionBytes = 8 << 20
	h2MaxReadFrameBytes      = 64 << 10
)

var inboundSlots = make(chan struct{}, 128)

type firstAuthenticationKey struct{}

func serverALPN(transport string) []string {
	if transport == TransportTCP {
		// Standard HTTP/2 remains available for finance cover. The handler below
		// keeps this ALPN from enabling the gRPC Pro carrier on a TCP-only shell.
		return []string{rawALPN, "h2", "http/1.1"}
	}
	return append(clientALPN(transport), "http/1.1")
}

// HTTP2Settings records the public HTTP/2 configuration. The same bounds apply
// to both carriers; the inner mux has its own independent memory accounting.
func HTTP2Settings() *http.HTTP2Config {
	return &http.HTTP2Config{MaxConcurrentStreams: 1, MaxReadFrameSize: h2MaxReadFrameBytes, MaxReceiveBufferPerConnection: h2ReceiveConnectionBytes, MaxReceiveBufferPerStream: h2ReceiveStreamBytes, SendPingTimeout: 30 * time.Second, PingTimeout: 10 * time.Second, WriteByteTimeout: 45 * time.Second}
}

func dialPhysical(ctx context.Context, cfg ClientConfig, u *url.URL) (physicalConn, string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(u.Hostname(), port)
	dial := cfg.DialContext
	if dial == nil {
		d := &net.Dialer{Timeout: handshakeTimeout, Control: TCPControlFor(cfg.Congestion)}
		dial = d.DialContext
	}
	raw, e := dial(dialCtx, "tcp", address)
	if e != nil {
		return nil, "", e
	}
	if e = ApplyTCPWithCongestion(raw, cfg.Congestion); e != nil {
		raw.Close()
		return nil, "", e
	}
	raw = WrapChameleonTCP(raw, cfg.Profile)
	tlsConfig, e := clientTLSConfig(cfg, u)
	if e != nil {
		raw.Close()
		return nil, "", e
	}
	conn := tls.Client(raw, tlsConfig)
	if e = conn.HandshakeContext(dialCtx); e != nil {
		conn.Close()
		return nil, "", e
	}
	switch conn.ConnectionState().NegotiatedProtocol {
	case rawALPN:
		return conn, TransportTCP, nil
	case "h2":
		p, e := dialGRPC(ctx, cfg.owner, conn, u)
		return p, TransportGRPC, e
	default:
		conn.Close()
		return nil, "", errors.New("hyrakenpro: required ALPN was not negotiated")
	}
}

// grpcPhysical implements a gRPC custom byte codec. Every write is one uncompressed
// gRPC Length-Prefixed-Message; reads preserve arbitrary message fragmentation.
// The outer HTTP/2 implementation owns SETTINGS, HPACK, flow control and PING.
type grpcPhysical struct {
	reader          io.ReadCloser
	writer          io.Writer
	flush           func() error
	close           func() error
	readMu, writeMu sync.Mutex
	remaining       int
	writeBuf        []byte // Owned by writeMu; capacity never exceeds maxGRPCMessage+5.
	mu              sync.Mutex
	timer           *time.Timer
	closed          bool
	once            sync.Once
	done            chan struct{}
}

func (g *grpcPhysical) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	g.readMu.Lock()
	defer g.readMu.Unlock()
	for g.remaining == 0 {
		var h [5]byte
		if _, e := io.ReadFull(g.reader, h[:]); e != nil {
			return 0, e
		}
		n := binary.BigEndian.Uint32(h[1:])
		if h[0] != 0 || n > maxGRPCMessage {
			return 0, errors.New("hyrakenpro: invalid gRPC message")
		}
		g.remaining = int(n)
	}
	n, e := g.reader.Read(p[:min(len(p), g.remaining)])
	g.remaining -= n
	if n == 0 && e == nil {
		return 0, io.ErrNoProgress
	}
	return n, e
}
func (g *grpcPhysical) Write(p []byte) (int, error) {
	g.writeMu.Lock()
	defer g.writeMu.Unlock()
	if len(p) > maxGRPCMessage {
		return 0, errors.New("hyrakenpro: oversized gRPC message")
	}
	n := 5 + len(p)
	if len(g.writeBuf) < n {
		clear(g.writeBuf)
		g.writeBuf = make([]byte, n)
	}
	wire := g.writeBuf[:n]
	defer clear(wire)
	wire[0] = 0
	binary.BigEndian.PutUint32(wire[1:5], uint32(len(p)))
	copy(wire[5:], p)
	if e := writeFull(g.writer, wire); e != nil {
		return 0, e
	}
	if g.flush != nil {
		if e := g.flush(); e != nil {
			return 0, e
		}
	}
	return len(p), nil
}
func (g *grpcPhysical) Close() error {
	var e error
	g.once.Do(func() {
		g.mu.Lock()
		g.closed = true
		if g.timer != nil {
			g.timer.Stop()
		}
		g.mu.Unlock()
		e = g.close()
		close(g.done)
	})
	return e
}
func (g *grpcPhysical) SetDeadline(deadline time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return net.ErrClosed
	}
	if g.timer != nil {
		g.timer.Stop()
	}
	if !deadline.IsZero() {
		g.timer = time.AfterFunc(time.Until(deadline), func() { _ = g.Close() })
	}
	return nil
}

func dialGRPC(ctx, owner context.Context, conn *tls.Conn, u *url.URL) (physicalConn, error) {
	// A transport per physical session prevents implicit connection pooling from
	// collapsing the independently configured 4..8 TCP connections into one.
	p := new(http.Protocols)
	p.SetHTTP2(true)
	transport := &http.Transport{Protocols: p, ForceAttemptHTTP2: true, HTTP2: HTTP2Settings(), MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, DisableCompression: true, ResponseHeaderTimeout: handshakeTimeout}
	var dialOnce sync.Once
	transport.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
		var c net.Conn
		dialOnce.Do(func() { c = conn })
		if c == nil {
			return nil, errors.New("hyrakenpro: physical session cannot redial")
		}
		return c, nil
	}
	owned, cancel := context.WithCancel(owner)
	stopDial := context.AfterFunc(ctx, cancel)
	defer stopDial()
	bodyR, bodyW := io.Pipe()
	req, e := http.NewRequestWithContext(owned, http.MethodPost, u.String(), bodyR)
	if e != nil {
		cancel()
		conn.Close()
		return nil, e
	}
	req.Header.Set("Content-Type", "application/grpc+hyraken")
	req.Header.Set("TE", "trailers")
	// RoundTrip returns after the server flushes headers, before either direction
	// sends business bytes. The client owner replaces this context after dialing.
	response, e := transport.RoundTrip(req)
	if e != nil {
		cancel()
		bodyR.Close()
		bodyW.Close()
		conn.Close()
		transport.CloseIdleConnections()
		return nil, e
	}
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/grpc+hyraken" {
		response.Body.Close()
		cancel()
		bodyW.Close()
		conn.Close()
		return nil, errors.New("hyrakenpro: gRPC response rejected")
	}
	g := &grpcPhysical{reader: &grpcResponseReader{response}, writer: bodyW, done: make(chan struct{})}
	g.close = func() error {
		cancel()
		_ = bodyW.Close()
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return conn.Close()
	}
	return g, nil
}

// NewServer validates one independently served Pro endpoint.
func NewServer(ctx context.Context, config ServerConfig) (*Server, error) {
	if ctx == nil {
		return nil, errors.New("hyrakenpro: nil context")
	}
	cfg, e := normalizeServerConfig(config)
	if e != nil {
		return nil, e
	}
	owned, cancel := context.WithCancel(ctx)
	s := &Server{closeDone: make(chan struct{}), cfg: cfg, ctx: owned, cancel: cancel, sessions: make(map[*session]struct{}), pending: make(map[physicalConn]struct{}), accept: make(chan *Stream, maxStreams)}
	context.AfterFunc(owned, func() { _ = s.Close() })
	return s, nil
}

// Serve owns TLS 1.3 and negotiates raw Pro or real HTTP/2 via ALPN. It never
// resolves or dials the requested target. Close joins all accepted connections.
func (s *Server) Serve(listener net.Listener, config *tls.Config) error {
	if listener == nil || config == nil {
		return errors.New("hyrakenpro: listener and TLS configuration required")
	}
	if config.InsecureSkipVerify || config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS13 {
		return errors.New("hyrakenpro: TLS 1.3 required")
	}
	cfg := config.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	cfg.NextProtos = serverALPN(s.cfg.Transport)
	if previous := cfg.GetConfigForClient; previous != nil {
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			chosen, err := previous(hello)
			if err != nil || chosen == nil {
				return chosen, err
			}
			chosen = chosen.Clone()
			chosen.MinVersion = tls.VersionTLS13
			chosen.MaxVersion = tls.VersionTLS13
			chosen.NextProtos = serverALPN(s.cfg.Transport)
			return chosen, nil
		}
	}

	s.mu.Lock()
	if s.closed || s.listener != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.listener = listener
	s.mu.Unlock()
	for {
		raw, e := listener.Accept()
		if e != nil {
			if s.ctx.Err() != nil {
				return net.ErrClosed
			}
			return e
		}
		select {
		case inboundSlots <- struct{}{}:
		default:
			raw.Close()
			continue
		}
		s.mu.Lock()
		if s.closed || len(s.pending) >= 64 {
			s.mu.Unlock()
			raw.Close()
			<-inboundSlots
			continue
		}
		s.pending[raw] = struct{}{}
		s.pendingWG.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.pendingWG.Done()
			defer func() { <-inboundSlots }()
			defer func() { raw.Close(); s.mu.Lock(); delete(s.pending, raw); s.mu.Unlock() }()
			s.serveConn(raw, cfg)
		}()
	}
}
func (s *Server) serveConn(raw net.Conn, cfg *tls.Config) {
	if e := ApplyTCPWithCongestion(raw, s.cfg.Congestion); e != nil {
		return
	}
	// Physical prefix slicing is applied once, to the outgoing socket before TLS.
	conn := tls.Server(raw, cfg)
	ctx, cancel := context.WithTimeout(s.ctx, handshakeTimeout)
	e := conn.HandshakeContext(ctx)
	cancel()
	if e != nil {
		return
	}
	switch conn.ConnectionState().NegotiatedProtocol {
	case rawALPN:
		_ = s.servePhysical(conn, TransportTCP, raw.RemoteAddr().String(), nil)
	case "h2":
		// HTTP/2 SETTINGS, PING and cover traffic do not authenticate a peer.
		// Bound its admission lease independently of HTTP/2 activity, then disarm
		// the timer only after the first complete inner mutual authentication.
		var authentication atomic.Uint32 // 0 pending, 1 authenticated, 2 expired
		timer := time.AfterFunc(handshakeTimeout, func() {
			if authentication.CompareAndSwap(0, 2) {
				_ = raw.Close()
			}
		})
		defer timer.Stop()
		authenticated := func() bool {
			if authentication.CompareAndSwap(0, 1) {
				timer.Stop()
				return true
			}
			return authentication.Load() == 1
		}
		h2ctx := context.WithValue(s.ctx, firstAuthenticationKey{}, authenticated)
		// Keep the synchronous per-connection handoff after TLS/ALPN: returning
		// releases the authentication timer and admission lease. Public Serve
		// needs a separate listener/lifecycle adapter to preserve that ownership.
		// Go 1.27's wrapper reads all settings from BaseConfig.HTTP2.
		h2 := new(http2.Server) //nolint:staticcheck // SA1019: synchronous handoff has no public net/http equivalent.
		base := &http.Server{Handler: s, HTTP2: HTTP2Settings(), MaxHeaderBytes: 16 << 10, ReadHeaderTimeout: handshakeTimeout}
		h2.ServeConn(conn, &http2.ServeConnOpts{Context: h2ctx, BaseConfig: base, Handler: s})
	default:
		// HTTP/1.1 is exclusively the existing finance cover handler.
		single := &oneConnListener{conn: conn, done: make(chan struct{})}
		server := &http.Server{Handler: http.HandlerFunc(s.fallback), ReadHeaderTimeout: handshakeTimeout, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
		stop := context.AfterFunc(s.ctx, func() { server.Close() })
		_ = server.Serve(single)
		stop()
	}
}
func (s *Server) fallback(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Fallback != nil {
		s.cfg.Fallback.ServeHTTP(w, r)
	} else {
		http.NotFound(w, r)
	}
}

// ServeHTTP accepts only bidirectional gRPC on the configured path.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Transport == TransportTCP || r.URL.Path != s.cfg.Path {
		s.fallback(w, r)
		return
	}
	if r.ProtoMajor != 2 || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/grpc+hyraken" || r.Header.Get("TE") != "trailers" {
		http.Error(w, "gRPC required", http.StatusUnsupportedMediaType)
		return
	}
	if r.Header.Get("Early-Data") != "" {
		http.Error(w, "early data unavailable", http.StatusTooEarly)
		return
	}
	w.Header().Set("Content-Type", "application/grpc+hyraken")
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	w.WriteHeader(http.StatusOK)
	controller := http.NewResponseController(w)
	if e := controller.Flush(); e != nil {
		return
	}
	g := &grpcPhysical{reader: r.Body, writer: w, flush: controller.Flush, done: make(chan struct{})}
	g.close = func() error { _ = controller.SetWriteDeadline(time.Now().Add(time.Second)); return r.Body.Close() }
	authenticated, _ := r.Context().Value(firstAuthenticationKey{}).(func() bool)
	err := s.servePhysical(g, TransportGRPC, r.RemoteAddr, authenticated)
	_ = g.Close()
	if err != nil {
		w.Header().Set("Grpc-Status", "16")
	} else {
		w.Header().Set("Grpc-Status", "0")
	}
}
func (s *Server) servePhysical(pc physicalConn, carrier, source string, authenticated func() bool) error {
	if e := acquirePhysical(); e != nil {
		pc.Close()
		return e
	}
	leased := true
	defer func() {
		if leased {
			releasePhysical()
		}
	}()
	stop := context.AfterFunc(s.ctx, func() { pc.Close() })
	defer stop()
	if e := pc.SetDeadline(time.Now().Add(handshakeTimeout)); e != nil {
		pc.Close()
		return e
	}
	keys, e := serverHandshake(pc, []byte(s.cfg.Seed), carrier, s.cfg.Path, s.cfg.Suite)
	if e != nil {
		pc.Close()
		return e
	}
	if authenticated != nil && !authenticated() {
		pc.Close()
		return errors.New("hyrakenpro: first authentication deadline exceeded")
	}
	if e = pc.SetDeadline(time.Time{}); e != nil {
		pc.Close()
		return e
	}
	sess, e := newSession(s.ctx, pc, keys, false, source, s.accept, s.cfg.Profile, s.cfg.Hydra, carrier, releasePhysical, sessionOptions{xudpEnabled: s.cfg.PacketEncoding == "xudp"})
	if e != nil {
		pc.Close()
		return e
	}
	leased = false
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		sess.Close()
		return net.ErrClosed
	}
	s.sessions[sess] = struct{}{}
	s.mu.Unlock()
	<-sess.ctx.Done()
	_ = sess.Close()
	s.mu.Lock()
	delete(s.sessions, sess)
	s.mu.Unlock()
	return nil
}

type oneConnListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
	used bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return &notifyConn{Conn: l.conn, finish: func() { l.once.Do(func() { close(l.done) }) }}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneConnListener) Close() error   { l.once.Do(func() { close(l.done) }); return l.conn.Close() }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyConn struct {
	net.Conn
	finish func()
}

func (c *notifyConn) Close() error {
	e := c.Conn.Close()
	c.finish()
	return e
}

// grpcResponseReader validates mandatory trailers before reporting clean EOF.
type grpcResponseReader struct{ response *http.Response }

func (r *grpcResponseReader) Read(p []byte) (int, error) {
	n, e := r.response.Body.Read(p)
	if e == io.EOF && r.response.Trailer.Get("Grpc-Status") != "0" {
		e = fmt.Errorf("hyrakenpro: gRPC status %q", r.response.Trailer.Get("Grpc-Status"))
	}
	return n, e
}
func (r *grpcResponseReader) Close() error { return r.response.Body.Close() }
