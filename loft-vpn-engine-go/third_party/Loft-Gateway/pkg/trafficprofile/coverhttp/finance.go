package coverhttp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

type financeObserverKey struct{}
type inboundObserverKey struct{}

// WithObserver installs the owner's nonblocking decoy-authentication observer.
// The callback receives only the literal physical peer, never forwarded identity.
// Owner work must be bounded; immediate enqueue is preferred. It must not spawn
// unbounded goroutines, authenticate a transport connection or grant access to
// any real resource.
func WithObserver(ctx context.Context, observer func(netip.AddrPort)) context.Context {
	return context.WithValue(ctx, financeObserverKey{}, observer)
}

// WithInboundObserver carries an owner reporter across inbound construction.
// Transport libraries remain independent of the gateway's event bus and policy.
func WithInboundObserver(ctx context.Context, observer func(string, netip.AddrPort)) context.Context {
	return context.WithValue(ctx, inboundObserverKey{}, observer)
}

// InboundObserver binds a configured inbound tag without storing per-peer state.
func InboundObserver(ctx context.Context, tag string) func(netip.AddrPort) {
	observer, _ := ctx.Value(inboundObserverKey{}).(func(string, netip.AddrPort))
	if observer == nil {
		return nil
	}
	return func(peer netip.AddrPort) { observer(tag, peer) }
}

var financeCredential = sha256.Sum256([]byte("finance\x00finance123"))

// ServeFinance serves a deliberately nonfunctional API for an invented company.
// Its public Basic credentials are unrelated to all tunnel, record and gateway
// credentials. Success creates no session, reads no body and stores no data.
// The return value describes decoy authentication only, never tunnel admission.
func ServeFinance(w http.ResponseWriter, r *http.Request) (authenticated bool) {
	status, body, allow := http.StatusNotFound, "{\"error\":\"not_found\"}\n", ""
	switch {
	case r.Method == http.MethodHead:
		// Preserve legacy probes on every path, including replay-safe early
		// HEAD on transports whose own policy permits it. The upstream hybrid
		// TLS envelope guard still rejects early HEAD before reaching here.
		// This branch never validates Basic credentials or reports an observer.
		status, body = http.StatusNoContent, ""
	case len(r.Header.Values("Early-Data")) != 0:
		status, body = http.StatusTooEarly, "{\"error\":\"too_early\"}\n"
	case r.TLS != nil && !r.TLS.HandshakeComplete:
		status, body = http.StatusTooEarly, "{\"error\":\"too_early\"}\n"
	default:
		// Dispatch uses only fixed public routes and methods. Configured
		// tunnel paths, rejection reasons, hosts and queries are irrelevant.
		switch r.URL.Path {
		case "/api/v1/status", "/api/v1/ledger":
			allow = "GET, HEAD, OPTIONS"
		case "/api/v1/invoices":
			allow = "GET, HEAD, POST, OPTIONS"
		}
		if allow != "" {
			switch {
			case r.Method == http.MethodOptions:
				status, body = http.StatusNoContent, ""
			case r.Method != http.MethodGet && !(r.URL.Path == "/api/v1/invoices" && r.Method == http.MethodPost):
				status, body = http.StatusMethodNotAllowed, "{\"error\":\"method_not_allowed\"}\n"
			case r.URL.Path == "/api/v1/status":
				status, body = http.StatusOK, "{\"status\":\"ok\",\"company\":\"Aster Vale Technologies\",\"service\":\"finance\"}\n"
			default:
				status, body = http.StatusUnauthorized, "{\"error\":\"unauthorized\"}\n"
				if len(r.Header.Values("Authorization")) != 0 {
					status, body = http.StatusForbidden, "{\"error\":\"forbidden\"}\n"
					if financeAuthorization(r) {
						authenticated = true
						status, body = http.StatusOK, "{\"status\":\"ok\",\"company\":\"Aster Vale Technologies\",\"invoices\":[]}\n"
						if r.URL.Path == "/api/v1/ledger" {
							body = "{\"status\":\"ok\",\"company\":\"Aster Vale Technologies\",\"entries\":[]}\n"
						} else if r.Method == http.MethodPost {
							status, body = http.StatusCreated, "{\"status\":\"accepted\",\"company\":\"Aster Vale Technologies\"}\n"
						}
					}
				}
			}
		}
	}
	if authenticated {
		// Publish before body Close or response I/O can block. The owner
		// captures policy authority now and revalidates it when consuming
		// the queued event, so a concurrent Release can revoke late work.
		if observer, _ := r.Context().Value(financeObserverKey{}).(func(netip.AddrPort)); observer != nil {
			if peer, err := netip.ParseAddrPort(r.RemoteAddr); err == nil && peer.Port() != 0 && peer.Addr().Zone() == "" && !peer.Addr().Unmap().IsUnspecified() && !peer.Addr().Unmap().IsMulticast() {
				observer(netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()))
			}
		}
	}
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(2 * time.Second))
	defer controller.SetWriteDeadline(time.Time{})
	if r.ProtoMajor == 1 {
		r.Close = true
		w.Header().Set("Connection", "close")
		// net/http Body.Close can drain a small remaining body. Expire
		// reads first so an untrusted slow sender cannot hold this call.
		_ = controller.SetReadDeadline(time.Now())
	}
	if r.Body != nil {
		_ = r.Body.Close()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="finance", charset="UTF-8"`)
	}
	if status == http.StatusMethodNotAllowed || (status == http.StatusNoContent && r.Method == http.MethodOptions) {
		w.Header().Set("Allow", allow)
	}
	if status != http.StatusNoContent {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}
	w.WriteHeader(status)
	if body != "" {
		_, _ = w.Write([]byte(body))
	}
	_ = controller.Flush()
	return authenticated
}

func financeAuthorization(r *http.Request) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 512 {
		return false
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	// Fixed-length digests keep both username and password comparison
	// constant-time; the public credential namespace never uses a real key.
	candidate := sha256.Sum256([]byte(username + "\x00" + password))
	return subtle.ConstantTimeCompare(candidate[:], financeCredential[:]) == 1
}
