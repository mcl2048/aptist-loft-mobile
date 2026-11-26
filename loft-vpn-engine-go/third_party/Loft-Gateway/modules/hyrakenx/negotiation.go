package hyrakenx

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	controlALPN = "hyrakenx/1"
	helloSize   = 52
	replySize   = 51
)

func verifiedState(state tls.ConnectionState) error {
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != controlALPN || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return errors.New("hyrakenx: verified mutual TLS 1.3 with Hyraken X ALPN required")
	}
	return nil
}

func controlMAC(seed []byte, label string, records ...[]byte) [32]byte {
	mac := hmac.New(sha256.New, seed)
	_, _ = mac.Write([]byte(label))
	for _, record := range records {
		_, _ = mac.Write(record)
	}
	var tag [32]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func writeFull(w io.Writer, packet []byte) error {
	for len(packet) != 0 {
		n, err := w.Write(packet)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(packet) {
			return io.ErrShortWrite
		}
		packet = packet[n:]
	}
	return nil
}

func suiteMask(suites []Suite) (byte, error) {
	var mask byte
	for _, suite := range suites {
		switch suite {
		case SuiteRoccaS:
			if roccaSAssemblyAvailable() {
				mask |= 1 << 0
			}
		case SuiteChaCha20Poly1305:
			mask |= 1 << 1
		case SuiteAES256GCM:
			if aesGCMConstantTimeAvailable() {
				mask |= 1 << 2
			}
		default:
			return 0, errors.New("hyrakenx: unsupported offered suite")
		}
	}
	if mask == 0 {
		return 0, errors.New("hyrakenx: no locally supported suite")
	}
	return mask, nil
}

func chooseSuite(mask byte) (Suite, error) {
	if mask&1 != 0 && roccaSAssemblyAvailable() {
		return SuiteRoccaS, nil
	}
	if mask&2 != 0 {
		return SuiteChaCha20Poly1305, nil
	}
	if mask&4 != 0 && aesGCMConstantTimeAvailable() {
		return SuiteAES256GCM, nil
	}
	return 0, errors.New("hyrakenx: no common authenticated suite")
}

func exporterSession(state tls.ConnectionState, hello, reply []byte, suite Suite, role Role, id uint32) (*Session, error) {
	exporter, err := state.ExportKeyingMaterial("EXPORTER-HyrakenX-UDP-v1", nil, 32)
	if err != nil {
		return nil, fmt.Errorf("hyrakenx: TLS exporter: %w", err)
	}
	defer clear(exporter)
	transcript := make([]byte, 0, len(hello)+len(reply))
	transcript = append(transcript, hello...)
	transcript = append(transcript, reply...)
	return NewSession(exporter, transcript, suite, role, id)
}

// NegotiateClient uses a completed, verified mTLS connection. The caller owns
// its deadline and must close the TLS connection with the UDP attachment.
func NegotiateClient(conn io.ReadWriter, state tls.ConnectionState, seed []byte, suites []Suite) (*Session, Suite, error) {
	if err := verifiedState(state); err != nil {
		return nil, 0, err
	}
	if len(seed) < 32 || len(seed) > 256 {
		return nil, 0, errors.New("hyrakenx: deployment secret must contain 32..256 bytes")
	}
	mask, err := suiteMask(suites)
	if err != nil {
		return nil, 0, err
	}
	var hello [helloSize]byte
	hello[0], hello[1] = version, mask
	if _, err = rand.Read(hello[2:18]); err != nil {
		return nil, 0, fmt.Errorf("hyrakenx: client random: %w", err)
	}
	tag := controlMAC(seed, "hyrakenx/1/client", hello[:20])
	copy(hello[20:], tag[:])
	if err = writeFull(conn, hello[:]); err != nil {
		return nil, 0, fmt.Errorf("hyrakenx: write offer: %w", err)
	}
	var reply [replySize]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil {
		return nil, 0, fmt.Errorf("hyrakenx: read selection: %w", err)
	}
	suite := Suite(reply[1])
	if reply[0] != version || suite < SuiteRoccaS || suite > SuiteAES256GCM || reply[2] == 0 || reply[2]&^mask != 0 || reply[2] != 1<<(suite-1) || binary.LittleEndian.Uint32(reply[3:7]) == 0 {
		return nil, 0, errors.New("hyrakenx: invalid suite selection")
	}
	want := controlMAC(seed, "hyrakenx/1/server", hello[:], reply[:19])
	if subtle.ConstantTimeCompare(reply[19:], want[:]) != 1 {
		return nil, 0, errors.New("hyrakenx: server selection authentication failed")
	}
	session, err := exporterSession(state, hello[:], reply[:], suite, Client, binary.LittleEndian.Uint32(reply[3:7]))
	return session, suite, err
}

// NegotiateServer selects Rocca-S on supported hardware and otherwise accepts
// ChaCha20-Poly1305 or AES-GCM only when explicitly offered by the client.
func NegotiateServer(conn io.ReadWriter, state tls.ConnectionState, seed []byte) (*Session, Suite, error) {
	if err := verifiedState(state); err != nil {
		return nil, 0, err
	}
	if len(seed) < 32 || len(seed) > 256 {
		return nil, 0, errors.New("hyrakenx: deployment secret must contain 32..256 bytes")
	}
	var hello [helloSize]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil {
		return nil, 0, fmt.Errorf("hyrakenx: read offer: %w", err)
	}
	want := controlMAC(seed, "hyrakenx/1/client", hello[:20])
	if hello[0] != version || hello[1] == 0 || hello[1]&^byte(7) != 0 || subtle.ConstantTimeCompare(hello[20:], want[:]) != 1 {
		return nil, 0, errors.New("hyrakenx: client offer authentication failed")
	}
	suite, err := chooseSuite(hello[1])
	if err != nil {
		return nil, 0, err
	}
	var reply [replySize]byte
	reply[0], reply[1], reply[2] = version, byte(suite), 1<<(suite-1)
	if _, err := rand.Read(reply[3:19]); err != nil {
		return nil, 0, fmt.Errorf("hyrakenx: server random: %w", err)
	}
	if binary.LittleEndian.Uint32(reply[3:7]) == 0 {
		reply[3] = 1
	}
	tag := controlMAC(seed, "hyrakenx/1/server", hello[:], reply[:19])
	copy(reply[19:], tag[:])
	if err := writeFull(conn, reply[:]); err != nil {
		return nil, 0, fmt.Errorf("hyrakenx: write selection: %w", err)
	}
	session, err := exporterSession(state, hello[:], reply[:], suite, Server, binary.LittleEndian.Uint32(reply[3:7]))
	return session, suite, err
}
