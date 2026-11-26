// Package coverhttp supplies bounded HTTP cover for rejected gateway probes.
// It conceals application errors; it does not conceal a listening TCP/QUIC port,
// TLS identity, packet sizes, or the HTTP implementation's wire fingerprint.
package coverhttp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var sessionKey = func() [32]byte {
	var key [32]byte
	rand.Read(key[:])
	return key
}()

var pages = [...]string{
	"<!doctype html><html><head><title>Not Found</title></head><body><h1>Not Found</h1><p>The requested resource is unavailable.</p></body></html>\n",
	"<!doctype html><html><head><title>Not Found</title></head><body><h1>Not Found</h1><p>This resource could not be found.</p></body></html>\n",
}

// Serve uses a process-lifetime, authority-scoped choice from two small pages.
// This borrows scoped stability from Brave farbling, not browser impersonation.
// The key is unrelated to protocol credentials; attacker-selected hosts allocate
// no stored entries. Paths, auth failures and body contents never enter replies.
// HEAD=204 preserves existing Hyraken clients on every path, avoiding a path oracle.
func Serve(w http.ResponseWriter, r *http.Request) {
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(2 * time.Second))
	defer controller.SetWriteDeadline(time.Time{})
	if r.ProtoMajor == 1 {
		// Do not drain a slow untrusted body or retain a probe's HTTP/1 socket.
		r.Close = true
		w.Header().Set("Connection", "close")
		_ = controller.SetReadDeadline(time.Now())
	}
	if r.Body != nil {
		_ = r.Body.Close()
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusNoContent)
	} else {
		mac := hmac.New(sha256.New, sessionKey[:])
		mac.Write([]byte(strings.ToLower(r.Host)))
		body := pages[mac.Sum(nil)[0]&1]
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(body))
	}
	// Make a bounded attempt to deliver the decoy before retiring a probe socket.
	_ = controller.Flush()
}
