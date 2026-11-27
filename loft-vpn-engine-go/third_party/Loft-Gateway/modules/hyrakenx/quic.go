package hyrakenx

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"loft.local/hydra"
)

const MaxDatagramPayload = 1024

// Shared by every listener and dial in this process. Per-listener admission
// alone multiplies QUIC/TLS state when several configured ports are active.
// Initial/maximum receive credit remains a separate payload commitment; these
// limits do not describe RSS, kernel queues or a whole-host memory guarantee.
var physicalConnections = make(chan struct{}, 128)

func reservePhysicalConnection(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case physicalConnections <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-physicalConnections }) }, nil
	default:
		return nil, errors.New("hyrakenx: process physical connection budget exhausted")
	}
}

func quicOptions() *quic.Config {
	return &quic.Config{HandshakeIdleTimeout: 8 * time.Second, MaxIdleTimeout: 45 * time.Second, KeepAlivePeriod: 10 * time.Second,
		InitialPacketSize: 1200, DisablePathMTUDiscovery: true, MaxIncomingStreams: 128, MaxIncomingUniStreams: -1, EnableDatagrams: true, Allow0RTT: false,
		InitialStreamReceiveWindow: 2 << 20, MaxStreamReceiveWindow: 6 << 20,
		InitialConnectionReceiveWindow: 3 << 20, MaxConnectionReceiveWindow: 8 << 20}
}

func serverTLSConfig(source *tls.Config) (*tls.Config, error) {
	if source == nil || len(source.Certificates) == 0 && source.GetCertificate == nil && source.GetConfigForClient == nil || source.ClientCAs == nil || source.ClientAuth != tls.RequireAndVerifyClientCert {
		return nil, errors.New("hyrakenx: server certificate and verified client CA required")
	}
	c := source.Clone()
	c.MinVersion, c.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	c.NextProtos = []string{controlALPN}
	c.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	c.SessionTicketsDisabled = true
	if previous := c.GetConfigForClient; previous != nil {
		c.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			next, err := previous(hello)
			if err != nil || next == nil {
				return next, err
			}
			next = next.Clone()
			if next.ClientCAs == nil {
				next.ClientCAs = c.ClientCAs
			}
			next.ClientAuth = tls.RequireAndVerifyClientCert
			next.MinVersion, next.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
			next.NextProtos = []string{controlALPN}
			next.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
			next.SessionTicketsDisabled = true
			return next, nil
		}
	}
	return c, nil
}

func clientTLSConfig(source *tls.Config) (*tls.Config, error) {
	if source == nil || len(source.Certificates) == 0 || source.ServerName == "" || source.InsecureSkipVerify {
		return nil, errors.New("hyrakenx: client certificate and verified server name required")
	}
	c := source.Clone()
	c.MinVersion, c.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	c.NextProtos = []string{controlALPN}
	c.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	c.ClientSessionCache = nil
	return c, nil
}

// Listener owns a direct UDP QUIC socket and its immutable deployment secret.
type Listener struct {
	inner     *quic.Listener
	transport *quic.Transport
	socket    net.PacketConn
	seed      []byte
}

// Listen requires mTLS and a high-entropy deployment secret. It opens no TCP
// socket and does not permit early application data.
func Listen(address string, config *tls.Config, secret []byte) (*Listener, error) {
	if len(secret) < 32 || len(secret) > 256 {
		return nil, errors.New("hyrakenx: deployment secret must contain 32..256 bytes")
	}
	c, err := serverTLSConfig(config)
	if err != nil {
		return nil, err
	}
	socket, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, fmt.Errorf("hyrakenx: bind UDP: %w", err)
	}
	configureOwnedUDPSocket(socket)
	gate, err := NewGateConn(socket, secret, Server)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	// Retry validates the return address before QUIC allocates handshake state.
	// The outer gate keeps both Retry and all other responses invisible to
	// clients without the deployment secret.
	// Retry proves address ownership, not identity or a resource budget. Reserve
	// before QUIC constructs connection/TLS state, and hold the slot through the
	// whole connection lifetime. No untrusted per-source index is created.
	connections := make(chan struct{}, 64)
	transport := &quic.Transport{Conn: gate, VerifySourceAddress: func(net.Addr) bool { return true },
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			select {
			case connections <- struct{}{}:
				release, err := reservePhysicalConnection(ctx)
				if err != nil {
					<-connections
					return nil, err
				}
				context.AfterFunc(ctx, func() { release(); <-connections })
				return ctx, nil
			default:
				return nil, errors.New("hyrakenx: physical connection budget exhausted")
			}
		}}
	listener, err := transport.Listen(c, quicOptions())
	if err != nil {
		_ = transport.Close()
		_ = socket.Close()
		return nil, fmt.Errorf("hyrakenx: listen QUIC: %w", err)
	}
	return &Listener{inner: listener, transport: transport, socket: socket, seed: append([]byte(nil), secret...)}, nil
}

func (l *Listener) Addr() net.Addr { return l.inner.Addr() }
func (l *Listener) Close() error {
	err := l.inner.Close()
	return errors.Join(err, l.transport.Close(), l.socket.Close())
}

type peerAuthenticationError struct{ error }

func (e *peerAuthenticationError) Unwrap() error { return e.error }

// IsPeerAuthenticationError separates one failed peer from a failed listener.
// QUIC connection errors can also wrap net.ErrClosed, so that sentinel alone
// cannot decide whether a permanent accept worker should exit.
func IsPeerAuthenticationError(err error) bool {
	var peerError *peerAuthenticationError
	return errors.As(err, &peerError)
}

// Accept returns only after mTLS and the application suite have both been
// authenticated. The caller owns the returned Peer and must close it.
func (l *Listener) Accept(ctx context.Context) (_ *Peer, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("hyrakenx: accept QUIC: %w", err)
	}
	conn, err := l.inner.Accept(ctx)
	if err != nil {
		return nil, fmt.Errorf("hyrakenx: accept QUIC: %w", err)
	}
	defer func() {
		if err != nil {
			err = &peerAuthenticationError{err}
		}
	}()
	controlCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stream, err := conn.AcceptStream(controlCtx)
	if err != nil {
		_ = conn.CloseWithError(1, "control stream")
		return nil, fmt.Errorf("hyrakenx: accept control stream: %w", err)
	}
	defer stream.Close()
	// Control negotiation is one-shot. Abandon unread trailing control data
	// so it cannot retain receive credit after the authenticated peer is handed off.
	defer stream.CancelRead(0)
	releaseDeadline := bindOpeningContext(stream, controlCtx)
	session, suite, err := NegotiateServer(stream, conn.ConnectionState().TLS, l.seed)
	releaseDeadline()
	if err == nil {
		err = controlCtx.Err()
	}
	if err != nil {
		_ = conn.CloseWithError(1, "control authentication")
		return nil, err
	}
	return &Peer{conn: conn, session: session, suite: suite}, nil
}

// Dial creates one direct UDP connection. The TLS client config must verify
// the server certificate and present a valid client certificate.
func Dial(ctx context.Context, address string, config *tls.Config, secret []byte, suites []Suite) (*Peer, error) {
	return DialWithPacketListener(ctx, address, config, secret, suites, nil)
}

// DialWithPacketListener is the mobile ownership hook. The listener must reserve
// its physical slot and protect/bind the actual socket before returning it.
// The existing TLS, seed, gate, suite and reliable-stream wire paths are retained.
func DialWithPacketListener(ctx context.Context, address string, config *tls.Config, secret []byte, suites []Suite, listen func(context.Context, string, string) (net.PacketConn, error)) (*Peer, error) {
	if len(secret) < 32 || len(secret) > 256 {
		return nil, errors.New("hyrakenx: deployment secret must contain 32..256 bytes")
	}
	c, err := clientTLSConfig(config)
	if err != nil {
		return nil, err
	}
	// DNS, socket creation, TLS and control negotiation consume one opening
	// budget. quic-go detaches the successful connection from this short ctx;
	// the physical slot thereafter belongs to conn.Context(), not the caller.
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	release, err := reservePhysicalConnection(ctx)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	remote, err := resolveUDPEndpoint(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("hyrakenx: resolve UDP endpoint: %w", err)
	}
	if remote.IP == nil || remote.IP.IsUnspecified() || remote.IP.IsMulticast() {
		return nil, errors.New("hyrakenx: direct UDP endpoint must be a unicast IP")
	}
	network, local := "udp4", "0.0.0.0:0"
	if remote.IP.To4() == nil {
		network, local = "udp6", "[::]:0"
	}
	var socket net.PacketConn
	if listen == nil {
		socket, err = net.ListenPacket(network, local)
	} else {
		socket, err = listen(ctx, network, local)
	}
	if err != nil {
		return nil, fmt.Errorf("hyrakenx: create UDP socket: %w", err)
	}
	configureOwnedUDPSocket(socket)
	gate, err := NewGateConn(socket, secret, Client)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	conn, err := quic.Dial(ctx, gate, remote, c, quicOptions())
	if err != nil {
		_ = socket.Close()
		return nil, fmt.Errorf("hyrakenx: dial UDP: %w", err)
	}
	context.AfterFunc(conn.Context(), release)
	transferred = true
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "control stream")
		_ = socket.Close()
		return nil, fmt.Errorf("hyrakenx: open control stream: %w", err)
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	releaseDeadline := bindOpeningContext(stream, ctx)
	session, suite, err := NegotiateClient(stream, conn.ConnectionState().TLS, secret, suites)
	releaseDeadline()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = conn.CloseWithError(1, "control authentication")
		_ = socket.Close()
		return nil, err
	}
	return &Peer{conn: conn, socket: socket, session: session, suite: suite}, nil
}

// Preserve the public dialer's hostname/service-port compatibility while
// keeping managed/native IP-only routing and all resolver work within ctx.
func resolveUDPEndpoint(ctx context.Context, address string) (*net.UDPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := net.DefaultResolver.LookupPort(ctx, "udp", service)
	if err != nil {
		return nil, err
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return &net.UDPAddr{IP: addr.AsSlice(), Port: port, Zone: addr.Zone()}, nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("hyrakenx: UDP endpoint has no address")
	}
	selected := addresses[0]
	for _, address := range addresses {
		if address.IP.To4() != nil {
			selected = address
			break
		}
	}
	return &net.UDPAddr{IP: selected.IP, Port: port, Zone: selected.Zone}, nil
}

type controlStream interface{ SetDeadline(time.Time) error }

// bindOpeningContext covers synchronous I/O after QUIC's context-aware stream
// allocation returns. Join an already-running cancellation callback before
// clearing the deadline, so it cannot poison the returned business stream.
// Cancellation still owns the candidate until callers release this binding,
// check their opening context, and hand the candidate to its new owner.
func bindOpeningContext(stream controlStream, ctx context.Context) func() {
	deadline := time.Now().Add(5 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	_ = stream.SetDeadline(deadline)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = stream.SetDeadline(time.Now())
		close(done)
	})
	return func() {
		if !stop() {
			<-done
		}
		_ = stream.SetDeadline(time.Time{})
	}
}

// Peer carries one authenticated session over UDP only. QUIC owns congestion,
// loss recovery and physical flow control; the record layer owns nonce/replay.
type Peer struct {
	conn          *quic.Conn
	socket        net.PacketConn // Client-owned only; server peers share Listener.socket.
	session       *Session
	suite         Suite
	closeOnce     sync.Once
	closeErr      error
	hydraMu       sync.Mutex
	hydraConfig   hydra.Config
	hydraScope    string
	hydraObserver func(int, int)
	hydraStarted  bool
}

// SetHydraObserver installs a nonblocking local metrics consumer before streams.
// Only fully accepted shaped DATA records invoke it; it changes no wire bytes.
func (p *Peer) SetHydraObserver(observer func(records, paddingBytes int)) error {
	p.hydraMu.Lock()
	defer p.hydraMu.Unlock()
	if p.hydraStarted {
		return errors.New("hyrakenx: Hydra observer frozen after streams begin")
	}
	p.hydraObserver = observer
	return nil
}

// SetHydra installs the local sender policy before any logical stream begins.
// The policy is copied and frozen at first OpenStream or AcceptStream, including
// failed attempts, so concurrent stream creation always sees one immutable policy.
// Native QUIC datagrams sent through Send are not shaped.
func (p *Peer) SetHydra(config hydra.Config) error {
	return p.SetHydraScoped(config, "")
}

// SetHydraScoped publishes and freezes the policy and local scope together.
// Scope affects sender scheduling only, never the session or receiver.
func (p *Peer) SetHydraScoped(config hydra.Config, scope string) error {
	if err := ValidateHydraScope(scope); err != nil {
		return err
	}
	normalized, err := hydra.Normalize(config)
	if err != nil {
		return err
	}
	p.hydraMu.Lock()
	defer p.hydraMu.Unlock()
	if p.hydraStarted {
		return errors.New("hyrakenx: Hydra policy frozen after streams begin")
	}
	p.hydraConfig, p.hydraScope = normalized, scope
	return nil
}

func (p *Peer) streamHydraConfig() hydra.Config {
	config, _, _ := p.streamHydraPolicy()
	return config
}

func (p *Peer) streamHydraPolicy() (hydra.Config, string, func(int, int)) {
	p.hydraMu.Lock()
	defer p.hydraMu.Unlock()
	p.hydraStarted = true
	return p.hydraConfig, p.hydraScope, p.hydraObserver
}

func newStreamShaper(config hydra.Config, session *Session) (*hydra.Shaper, error) {
	return newStreamShaperScoped(config, session, "")
}

func newStreamShaperScoped(config hydra.Config, session *Session, scope string) (*hydra.Shaper, error) {
	if !config.Enabled {
		return nil, nil
	}
	// stream() already binds transcriptHash to the stream ID. Direction separates
	// the two senders without changing any encryption key or nonce derivation.
	seed := streamHydraSeed(session, scope)
	defer clear(seed[:])
	// The local adaptive algorithm preserves v1 authenticated framing. Include
	// the outer length, protected header, suite tag and encrypted payload length
	// when selecting optional framed-length targets; QUIC still owns packetization.
	return hydra.NewDynamicV2(config, "hyrakenx", seed, hydra.Limits{
		MaxPayload: MaxDatagramPayload, MaxPadding: MaxDatagramPayload / 4,
		PaddingBurst: 512, PaddingPerSecond: 512,
	}, hydra.TrafficOptions{Framing: hydra.Framing{Envelope: 2 + HeaderSize + session.suite.TagSize(), PayloadPrefix: 2, MinimumPlaintext: 16}})
}

func (p *Peer) Suite() Suite { return p.suite }
func (p *Peer) Close() error {
	p.closeOnce.Do(func() {
		p.closeErr = p.conn.CloseWithError(0, "")
		if p.socket != nil {
			p.closeErr = errors.Join(p.closeErr, p.socket.Close())
		}
	})
	return p.closeErr
}
func (p *Peer) Done() <-chan struct{} { return p.conn.Context().Done() }

// SetCongestionControl installs one controller on this physical UDP sender.
// QUIC remains the sole owner of ACK, loss detection, recovery and pacing.
func (p *Peer) SetCongestionControl(controller congestion.CongestionControl) {
	p.conn.SetCongestionControl(controller)
}

func (p *Peer) InitialPacketSize() congestion.ByteCount { return p.conn.InitialPacketSize() }

func (p *Peer) Send(payload []byte) error {
	if len(payload) > MaxDatagramPayload {
		return errors.New("hyrakenx: QUIC datagram payload exceeds 1024 bytes")
	}
	packet, err := p.session.Seal(payload)
	if err != nil {
		return err
	}
	if err := p.conn.SendDatagram(packet); err != nil {
		return fmt.Errorf("hyrakenx: send datagram: %w", err)
	}
	return nil
}

func (p *Peer) Receive(ctx context.Context) ([]byte, error) {
	packet, err := p.conn.ReceiveDatagram(ctx)
	if err != nil {
		return nil, fmt.Errorf("hyrakenx: receive datagram: %w", err)
	}
	return p.session.Open(packet)
}

func streamHydraSeed(session *Session, scope string) (seed [32]byte) {
	mac := hmac.New(sha256.New, session.master[:])
	if scope == "" {
		_, _ = mac.Write([]byte("hyrakenx/hydra/sender/v1"))
	} else {
		_, _ = mac.Write([]byte("hyrakenx/hydra/sender/scoped/v2\x00"))
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(scope)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(scope))
	}
	_, _ = mac.Write(session.transcriptHash[:])
	_, _ = mac.Write([]byte{byte(session.role)})
	mac.Sum(seed[:0])
	return seed
}
