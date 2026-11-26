package hyrakenpro

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const handshakeTimeout = 10 * time.Second

type physicalConn interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

// Client owns authenticated physical sessions to one endpoint.
type Client struct {
	closeDone     chan struct{}
	cfg           ClientConfig
	url           *url.URL
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	dialGate      chan struct{}
	pool          []*session
	closed        bool
	lastExpand    time.Time
	roundRobin    uint64
	reaperStarted bool
	reaperWG      sync.WaitGroup
}

// Server owns TLS/ALPN and accepts authenticated Pro streams without target I/O.
type Server struct {
	closeDone chan struct{}
	cfg       ServerConfig
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	sessions  map[*session]struct{}
	pending   map[physicalConn]struct{}
	pendingWG sync.WaitGroup
	accept    chan *Stream
	closed    bool
	listener  net.Listener
}

// NewClient validates the endpoint without dialing it.
func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
	if ctx == nil {
		return nil, errors.New("hyrakenpro: nil context")
	}
	cfg, u, err := normalizeClientConfig(config)
	if err != nil {
		return nil, err
	}
	owned, cancel := context.WithCancel(ctx)
	cfg.owner = owned
	c := &Client{closeDone: make(chan struct{}), cfg: cfg, url: u, ctx: owned, cancel: cancel, dialGate: make(chan struct{}, 1)}
	context.AfterFunc(owned, func() { _ = c.Close() })
	return c, nil
}

// WarmUp authenticates one ordinary physical session without opening business
// traffic. Mobile startup uses this receipt before starting its TUN reader.
// The same dial gate, TLS/ALPN, seed handshake and pool owner apply as DialContext.
func (c *Client) WarmUp(ctx context.Context) error {
	if ctx == nil {
		return errors.New("hyrakenpro: nil context")
	}
	select {
	case c.dialGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return net.ErrClosed
	}
	defer func() { <-c.dialGate }()
	_, _, err := c.sessionFor(ctx, false)
	return err
}

// DialContext opens a TCP byte stream or a UDP packet stream to target.
func (c *Client) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("hyrakenpro: nil context")
	}
	if network != "tcp" && network != "udp" && network != "xudp" {
		return nil, errors.New("hyrakenpro: unsupported network")
	}
	if network == "xudp" && (c.cfg.PacketEncoding != "xudp" || target != XUDPTarget) {
		return nil, errors.New("hyrakenpro: XUDP not enabled or invalid association target")
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case c.dialGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	}
	defer func() { <-c.dialGate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, reused, err := c.sessionFor(ctx, network == "xudp")
	if err != nil {
		return nil, err
	}
	stream, err := s.open(ctx, network, target)
	if err != nil && reused && c.url != nil && !s.active() && errors.Is(err, net.ErrClosed) && ctx.Err() == nil && c.ctx.Err() == nil {
		// Pooled physical session went stale between selection and frameOpen
		// (e.g., idle NAT drop or peer recycle). Evict it and try once more.
		s.abort()
		s, _, err = c.sessionFor(ctx, network == "xudp")
		if err != nil {
			return nil, err
		}
		stream, err = s.open(ctx, network, target)
	}
	if err != nil {
		// Return a nil interface instead of boxing a nil *Stream into net.Conn.
		return nil, err
	}
	return stream, nil
}

func validateTarget(target string) error {
	if len(target) == 0 || len(target) > maxTarget {
		return errors.New("hyrakenpro: invalid target")
	}
	for _, b := range []byte(target) {
		if b < 0x20 || b == 0x7f {
			return errors.New("hyrakenpro: invalid target")
		}
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return errors.New("hyrakenpro: target must be host:port")
	}
	if strings.ContainsAny(host, " /\\") {
		return errors.New("hyrakenpro: invalid target host")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("hyrakenpro: invalid target port")
	}
	return nil
}

func (c *Client) sessionFor(ctx context.Context, packetKinds ...bool) (*session, bool, error) {
	packetOnly := len(packetKinds) > 0 && packetKinds[0]
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false, net.ErrClosed
	}
	active := 0
	totalStreams := 0
	var selected *session
	selectedLoad := maxStreams + 1
	retained := make([]*session, 0, len(c.pool))
	for _, sess := range c.pool {
		if sess.active() {
			retained = append(retained, sess)
		}
	}
	c.pool = retained
	for i := 0; i < len(c.pool); i++ {
		sess := c.pool[(i+int(c.roundRobin%uint64(max(1, len(c.pool)))))%len(c.pool)]
		active++
		load := sess.streamCount()
		totalStreams += load
		if sess.packetOnly == packetOnly && load < selectedLoad && load < maxStreams {
			selected, selectedLoad = sess, load
		}
	}
	c.roundRobin++
	minSessions := c.cfg.Connections
	desired := minSessions
	if c.cfg.ElasticMux {
		if totalStreams >= 4 {
			desired = max(desired, 2)
		}
		if totalStreams >= 12 {
			desired = max(desired, 4)
		}
		if totalStreams >= 24 {
			desired = max(desired, 8)
		}
	}
	needNew := active < minSessions || (c.cfg.ElasticMux && active < desired && (c.lastExpand.IsZero() || time.Since(c.lastExpand) >= 2*time.Second)) || selected == nil
	if !needNew {
		c.mu.Unlock()
		return selected, true, nil
	}
	if active >= maxSessions {
		// A missing packet kind may replace an idle session, within the same budget.
		var idle *session
		if selected == nil {
			for i, sess := range c.pool {
				if sess.streamCount() == 0 {
					idle = sess
					c.pool = append(c.pool[:i], c.pool[i+1:]...)
					active--
					break
				}
			}
		}
		c.mu.Unlock()
		if idle == nil {
			return nil, false, errors.New("hyrakenpro: session capacity exhausted")
		}
		_ = idle.Close()
		s, err := c.createSession(ctx, packetOnly)
		return s, false, err
	}
	count := 1
	if active < minSessions {
		count = minSessions - active
	} else if c.cfg.ElasticMux && active < desired && (c.lastExpand.IsZero() || time.Since(c.lastExpand) >= 2*time.Second) {
		count = desired - active
	}
	if packetOnly {
		count = 1
	}
	count = min(count, maxSessions-active)
	c.mu.Unlock()
	var first *session
	if count == 1 {
		// Hot/packet/replacement construction retains its existing one-attempt path.
		var err error
		first, err = c.createSession(ctx, packetOnly)
		if err != nil {
			return nil, false, err
		}
	} else {
		// dialGate still owns the whole bounded construction. Each worker uses the
		// existing physical lease/cancellation/pool append path, and all join here.
		var results [maxSessions]struct {
			session *session
			err     error
		}
		var workers sync.WaitGroup
		workers.Add(count)
		for i := range count {
			go func() { defer workers.Done(); results[i].session, results[i].err = c.createSession(ctx, packetOnly) }()
		}
		workers.Wait()
		canceled := ctx.Err()
		if c.ctx.Err() != nil {
			canceled = net.ErrClosed
		}
		if canceled != nil {
			// A completed handshake belongs to c.ctx, so explicitly remove only this
			// canceled batch's new sessions. Existing pool streams retain their owner.
			c.mu.Lock()
			retained := c.pool[:0]
			for _, pooled := range c.pool {
				created := false
				for _, result := range results[:count] {
					if result.session == pooled {
						created = true
						break
					}
				}
				if !created {
					retained = append(retained, pooled)
				}
			}
			clear(c.pool[len(retained):])
			c.pool = retained
			c.mu.Unlock()
			for _, result := range results[:count] {
				if result.session != nil {
					result.session.Close()
				}
			}
			return nil, false, canceled
		}
		var firstErr error
		for _, result := range results[:count] {
			if first == nil && result.session != nil && result.session.active() {
				first = result.session
			}
			if firstErr == nil && result.err != nil {
				firstErr = result.err
			}
		}
		if first == nil {
			if firstErr == nil {
				firstErr = net.ErrClosed
			}
			return nil, false, firstErr
		}
		// Preserve partial-success behavior and its existing elastic expansion clock.
		if firstErr != nil {
			return first, false, nil
		}
	}
	if c.cfg.ElasticMux && active >= minSessions {
		c.mu.Lock()
		c.lastExpand = time.Now()
		c.mu.Unlock()
	}
	return first, false, nil
}

func (c *Client) createSession(ctx context.Context, packetKinds ...bool) (*session, error) {
	packetOnly := len(packetKinds) > 0 && packetKinds[0]
	physicalConfig := c.cfg
	if packetOnly {
		physicalConfig.Profile = nil
		physicalConfig.Hydra = nil
	}
	if err := acquirePhysical(); err != nil {
		return nil, err
	}
	leased := true
	defer func() {
		if leased {
			releasePhysical()
		}
	}()
	dialCtx, cancelDial := context.WithCancel(ctx)
	stopOwnerDial := context.AfterFunc(c.ctx, cancelDial)
	defer func() { stopOwnerDial(); cancelDial() }()
	pc, carrier, err := dialPhysical(dialCtx, physicalConfig, c.url)
	if err != nil {
		return nil, err
	}
	stopCall := context.AfterFunc(ctx, func() { _ = pc.Close() })
	stopOwner := context.AfterFunc(c.ctx, func() { _ = pc.Close() })
	if err := pc.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		stopCall()
		stopOwner()
		pc.Close()
		return nil, err
	}
	keys, err := clientHandshake(pc, []byte(c.cfg.Seed), carrier, c.url.Path, c.cfg.Suite)
	stopCall()
	stopOwner()
	if err != nil {
		pc.Close()
		return nil, err
	}
	if err := pc.SetDeadline(time.Time{}); err != nil {
		pc.Close()
		return nil, err
	}
	s, err := newSession(c.ctx, pc, keys, true, "", nil, physicalConfig.Profile, physicalConfig.Hydra, carrier, releasePhysical, sessionOptions{xudpEnabled: c.cfg.PacketEncoding == "xudp", packetOnly: packetOnly, hydraObserver: physicalConfig.HydraObserver})
	if err != nil {
		pc.Close()
		return nil, err
	}
	leased = false
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		s.Close()
		return nil, net.ErrClosed
	}
	c.pool = append(c.pool, s)
	if c.cfg.ElasticMux && !c.reaperStarted {
		c.reaperStarted = true
		c.reaperWG.Add(1)
		go c.reapLoop()
	}
	c.mu.Unlock()
	return s, nil
}

func (c *Client) reapLoop() {
	defer c.reaperWG.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-ticker.C:
			c.reapIdle(now)
		}
	}
}

func (c *Client) reapIdle(now time.Time) {
	select {
	case c.dialGate <- struct{}{}:
	case <-c.ctx.Done():
		return
	}
	c.mu.Lock()
	keep := c.pool[:0]
	var stale []*session
	for _, s := range c.pool {
		if len(c.pool)-len(stale) > c.cfg.Connections && s.idleFor(now) >= 30*time.Second {
			stale = append(stale, s)
		} else {
			keep = append(keep, s)
		}
	}
	c.pool = keep
	c.mu.Unlock()
	<-c.dialGate
	for _, s := range stale {
		_ = s.Close()
	}
}

// Close stops all physical sessions and waits for their workers.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		done := c.closeDone
		c.mu.Unlock()
		<-done
		return nil
	}
	c.closed = true
	defer close(c.closeDone)
	c.cancel()
	c.mu.Unlock()
	c.dialGate <- struct{}{}
	c.mu.Lock()
	pool := append([]*session(nil), c.pool...)
	c.mu.Unlock()
	<-c.dialGate
	for _, s := range pool {
		_ = s.Close()
	}
	c.reaperWG.Wait()
	return nil
}

// Accept waits for an authenticated TCP or UDP stream.
func (s *Server) Accept(ctx context.Context) (*Stream, error) {
	if ctx == nil {
		return nil, errors.New("hyrakenpro: nil context")
	}
	for {
		if s.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		select {
		case stream := <-s.accept:
			if s.ctx.Err() != nil {
				return nil, net.ErrClosed
			}
			select {
			case <-stream.done:
				continue
			default:
			}
			if !stream.session.active() {
				continue
			}
			return stream, nil
		case <-s.ctx.Done():
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Close closes upgraded connections, then joins their workers.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return nil
	}
	s.closed = true
	defer close(s.closeDone)
	s.cancel()
	sessions := make([]*session, 0, len(s.sessions))
	for session := range s.sessions {
		sessions = append(sessions, session)
	}
	pending := make([]physicalConn, 0, len(s.pending))
	for pc := range s.pending {
		pending = append(pending, pc)
	}
	listener := s.listener
	s.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	for _, pc := range pending {
		_ = pc.Close()
	}
	s.pendingWG.Wait()
	for _, session := range sessions {
		_ = session.Close()
	}
	return nil
}
