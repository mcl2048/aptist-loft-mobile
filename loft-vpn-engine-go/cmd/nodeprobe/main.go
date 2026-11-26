// Command nodeprobe performs explicitly requested, modest desktop protocol tests.
// Node files are private runtime input; credentials and endpoints are never logged.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/dns/dnsmessage"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/transport"
)

type receipt struct {
	Alias                    string `json:"alias"`
	Protocol                 string `json:"protocol"`
	Authenticated            bool   `json:"authenticated"`
	TCPHTTPS                 bool   `json:"tcp_https"`
	DNSTCP                   bool   `json:"dns_tcp"`
	DNSUDP                   bool   `json:"dns_udp"`
	DNSDoH                   bool   `json:"dns_doh"`
	LiteralIPHTTPS           bool   `json:"literal_ip_https"`
	LiteralIPHTTPSBytes      int    `json:"literal_ip_https_bytes,omitempty"`
	LiteralIPHTTPSSHA256     string `json:"literal_ip_https_sha256,omitempty"`
	LiteralIPHTTPSError      string `json:"literal_ip_https_error,omitempty"`
	HostDiagnosticResolution bool   `json:"host_diagnostic_resolution"`
	DNSTCPError              string `json:"dns_tcp_error,omitempty"`
	DNSUDPError              string `json:"dns_udp_error,omitempty"`
	DNSDoHError              string `json:"dns_doh_error,omitempty"`
	Error                    string `json:"error,omitempty"`
	PhysicalPeak             int    `json:"physical_peak"`
	PhysicalAfterClose       int    `json:"physical_after_close"`
	ProtectedHostSockets     uint64 `json:"owned_host_socket_receipts"`
	ResolverAfterClose       int    `json:"resolver_after_close"`
	ElapsedMS                int64  `json:"elapsed_ms"`
}

func main() {
	nodes := flag.String("nodes", "", "private node-file path (not bundled into the APK)")
	mode := flag.String("mode", "protocol", "protocol or separately authorized literal-https diagnostic")
	flag.Parse()
	if *mode != "protocol" && *mode != "literal-https" {
		fmt.Fprintln(os.Stderr, "nodeprobe: unsupported probe mode")
		os.Exit(2)
	}
	if *nodes == "" {
		fmt.Fprintln(os.Stderr, "nodeprobe: --nodes is required")
		os.Exit(2)
	}
	file, err := os.Open(*nodes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nodeprobe: private input unavailable")
		os.Exit(2)
	}
	defer func() { _ = file.Close() }() // Read-only probe input; no pending file write.
	contents, err := io.ReadAll(io.LimitReader(file, 1048577))
	if err != nil {
		fmt.Fprintln(os.Stderr, "nodeprobe: private input read failed")
		os.Exit(2)
	}
	if len(contents) > 1048576 {
		fmt.Fprintln(os.Stderr, "nodeprobe: private input exceeds byte limit")
		os.Exit(2)
	}
	defer clear(contents)
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Buffer(make([]byte, 4096), 524288)
	var results []receipt
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(raw, "hyrakenx://") && !strings.HasPrefix(raw, "hyraken-pro://") && !strings.HasPrefix(raw, "socks5://") && !strings.HasPrefix(raw, "socks://") {
			continue
		}
		if len(results) >= 3 {
			fmt.Fprintln(os.Stderr, "nodeprobe: input node limit")
			os.Exit(2)
		}
		cfg, err := nodeconfig.Parse(raw)
		if err != nil {
			results = append(results, receipt{Alias: "node-invalid", Error: "node_validation_failed"})
			continue
		}
		alias := "node-x"
		switch cfg.Protocol {
		case "hyraken-pro":
			alias = "node-pro"
		case "socks5":
			alias = "node-socks"
		}
		results = append(results, probeMode(alias, cfg, *mode))
		clear(cfg.Seed)
	}
	if scanner.Err() != nil {
		fmt.Fprintln(os.Stderr, "nodeprobe: private input read failed")
		os.Exit(2)
	}
	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "nodeprobe: no matching nodes in private input")
		os.Exit(2)
	}
	scope := "desktop_protocol_probe"
	if *mode == "literal-https" {
		scope = "desktop_literal_ip_https_diagnostic"
	}
	output := struct {
		Scope              string    `json:"scope"`
		AndroidProtectUsed bool      `json:"android_protect_used"`
		TUNUsed            bool      `json:"tun_used"`
		Results            []receipt `json:"results"`
	}{Scope: scope, Results: results}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		os.Exit(2)
	}
	for _, result := range results {
		succeeded := result.TCPHTTPS && result.DNSTCP
		if *mode == "literal-https" {
			succeeded = result.LiteralIPHTTPS
		}
		if !result.Authenticated || !succeeded || result.PhysicalAfterClose != 0 || result.ResolverAfterClose != 0 {
			os.Exit(1)
		}
	}
}

func probeMode(alias string, cfg *nodeconfig.Config, mode string) (result receipt) {
	started := time.Now()
	result.Alias = alias
	result.Protocol = cfg.Protocol
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	policy := transport.NewDesktopPolicy()
	client, err := transport.NewClient(ctx, cfg, policy)
	if err != nil {
		result.Error = "adapter_construction_failed"
		return
	}
	defer func() {
		_ = client.Close()
		stats := client.Stats()
		result.PhysicalPeak = stats.PhysicalPeak
		result.PhysicalAfterClose = stats.PhysicalOpen
		result.ProtectedHostSockets = stats.ProtectedSockets
		result.ResolverAfterClose, _, _ = policy.ResolverStats()
		result.ElapsedMS = time.Since(started).Milliseconds()
	}()
	opening, stop := context.WithTimeout(ctx, 12*time.Second)
	err = client.Ready(opening)
	stop()
	if err != nil {
		result.Error = "node_authentication_failed"
		return
	}
	result.Authenticated = true
	if mode == "literal-https" {
		// This host-only lookup is an explicit diagnostic authorized separately
		// from tunneled VPN DNS. It never supplies the synthetic DNS service.
		result.HostDiagnosticResolution = true
		addresses, err := policy.Resolve(ctx, "example.com")
		if err != nil || len(addresses) == 0 || !addresses[0].Is4() {
			result.Error = "literal_host_resolution_failed"
			result.LiteralIPHTTPSError = diagnostic(stage("literal_host_resolution", err))
			return
		}
		transfer, err := verifiedHTTPS(ctx, client, net.JoinHostPort(addresses[0].String(), "443"), "example.com", nil)
		if err != nil {
			result.Error = "literal_https_failed"
			result.LiteralIPHTTPSError = diagnostic(err)
			return
		}
		result.LiteralIPHTTPS = true
		result.LiteralIPHTTPSBytes = transfer.Bytes
		result.LiteralIPHTTPSSHA256 = transfer.SHA256
		return
	}
	if err := https(ctx, client); err != nil {
		result.Error = "tcp_https_failed"
	} else {
		result.TCPHTTPS = true
	}
	if err := dns(ctx, client, false); err != nil {
		result.Error = "dns_tcp_failed"
		result.DNSTCPError = diagnostic(err)
	} else {
		result.DNSTCP = true
	}
	if err := dns(ctx, client, true); err == nil {
		result.DNSUDP = true
	} else {
		result.DNSUDPError = diagnostic(err)
	}
	// Explicit diagnostic authorized by the user; never a resolver fallback.
	if err := doh(ctx, client); err == nil {
		result.DNSDoH = true
	} else {
		result.DNSDoHError = diagnostic(err)
	}
	return
}

func https(ctx context.Context, client *transport.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, err := client.DialTCP(ctx, "example.com:443")
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() // Session cleanup verifies physical release; an aborted stream may report cancellation.
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	if _, err := io.WriteString(tlsConn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	buffer := make([]byte, 1280)
	n, err := tlsConn.Read(buffer)
	if err != nil {
		return err
	}
	if n < 12 || !strings.HasPrefix(string(buffer[:n]), "HTTP/1.") {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func dns(ctx context.Context, client *transport.Client, udp bool) error {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	id := binary.BigEndian.Uint16(random[:])
	name, err := dnsmessage.NewName("example.com.")
	if err != nil {
		return err
	}
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		return err
	}
	var response []byte
	if udp {
		packet, err := client.DialPacket(ctx, "1.1.1.1:53")
		if err != nil {
			return stage("udp_open", err)
		}
		defer func() { _ = packet.Close() }() // Datagram cancellation can return the mature stream cancel-close error.
		_ = packet.SetDeadline(time.Now().Add(6 * time.Second))
		if _, err := packet.WriteTo(query, M.ParseSocksaddr("1.1.1.1:53")); err != nil {
			return stage("udp_write", err)
		}
		buffer := make([]byte, 65507)
		n, _, err := packet.ReadFrom(buffer)
		if err != nil {
			return stage("udp_read", err)
		}
		response = buffer[:n]
	} else {
		conn, err := client.DialTCP(ctx, "1.1.1.1:53")
		if err != nil {
			return stage("tcp_open", err)
		}
		defer func() { _ = conn.Close() }() // Client teardown owns final protocol/physical release.
		_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
		wire := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(wire[:2], uint16(len(query)))
		copy(wire[2:], query)
		if _, err := conn.Write(wire); err != nil {
			return stage("tcp_write", err)
		}
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return stage("tcp_read_length", err)
		}
		response = make([]byte, int(binary.BigEndian.Uint16(length[:])))
		if _, err := io.ReadFull(conn, response); err != nil {
			return stage("tcp_read_body", err)
		}
	}
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return stage("dns_decode", err)
	}
	if message.ID != id || !message.Response {
		return stage("dns_identity", io.ErrUnexpectedEOF)
	}
	if message.RCode != dnsmessage.RCodeSuccess {
		return stage(fmt.Sprintf("dns_rcode_%d", message.RCode), io.ErrUnexpectedEOF)
	}
	if len(message.Answers) == 0 {
		return stage("dns_no_answer", io.ErrUnexpectedEOF)
	}
	return nil
}

type stageError struct {
	name  string
	cause error
}

func (e *stageError) Error() string      { return e.name }
func (e *stageError) Unwrap() error      { return e.cause }
func stage(name string, err error) error { return &stageError{name, err} }
func diagnostic(err error) string {
	if err == nil {
		return ""
	}
	name := "operation"
	var value *stageError
	if errors.As(err, &value) {
		name = value.name
		err = value.cause
	}
	if errors.Is(err, io.EOF) {
		return name + ":eof"
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return name + ":unexpected_eof"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return name + ":timeout"
	}
	return name + ":rejected"
}

func doh(ctx context.Context, client *transport.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return stage("doh_entropy", err)
	}
	id := binary.BigEndian.Uint16(random[:])
	name, err := dnsmessage.NewName("example.com.")
	if err != nil {
		return stage("doh_query", err)
	}
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		return stage("doh_query", err)
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{ServerName: "cloudflare-dns.com", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return client.DialTCP(ctx, "cloudflare-dns.com:443")
	}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudflare-dns.com/dns-query", bytes.NewReader(query))
	if err != nil {
		return stage("doh_request", err)
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := httpClient.Do(request)
	if err != nil {
		return stage("doh_https", err)
	}
	defer func() { _ = response.Body.Close() }() // The capped read below owns response validation.
	if response.StatusCode != http.StatusOK {
		return stage(fmt.Sprintf("doh_status_%d", response.StatusCode), io.ErrUnexpectedEOF)
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "application/dns-message") {
		return stage("doh_content_type", io.ErrUnexpectedEOF)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return stage("doh_body", err)
	}
	if len(body) > 65535 {
		return stage("doh_body_limit", io.ErrUnexpectedEOF)
	}
	var message dnsmessage.Message
	if err := message.Unpack(body); err != nil {
		return stage("doh_decode", err)
	}
	if message.ID != id || !message.Response || message.RCode != dnsmessage.RCodeSuccess || len(message.Answers) == 0 {
		return stage("doh_answer", io.ErrUnexpectedEOF)
	}
	return nil
}
