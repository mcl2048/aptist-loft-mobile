package hyrakenpro

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/cpu"
	"io"
	"log"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	clientHelloSize  = 3 + 32 + 32 + 1184 + 32
	serverHelloSize  = 2 + 32 + 32 + 1088 + 32
	handshakeVersion = 1
)

type recordKeys struct {
	send, recv             [32]byte
	sendPrefix, recvPrefix [8]byte
	suite                  byte
}

func domainMAC(seed []byte, label, carrier, path string, parts ...[]byte) [32]byte {
	h := hmac.New(sha256.New, seed)
	writeField(h, []byte("hyraken-pro/v1/"+label))
	writeField(h, []byte(carrier))
	writeField(h, []byte(path))
	for _, p := range parts {
		writeField(h, p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeField(w io.Writer, p []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(p)))
	_, _ = w.Write(length[:])
	_, _ = w.Write(p)
}

func deriveKeys(seed, xSecret, kemSecret, hello, reply []byte, client bool) (recordKeys, error) {
	var input []byte
	input = append(input, xSecret...)
	input = append(input, kemSecret...)
	input = append(input, seed...)
	transcript := sha256.New()
	writeField(transcript, []byte("hyraken-pro/v1/keys"))
	writeField(transcript, hello)
	writeField(transcript, reply)
	var material [80]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, input, transcript.Sum(nil), []byte("hyraken-pro/v1/record-suite/"+string([]byte{reply[1]}))), material[:]); err != nil {
		return recordKeys{}, err
	}
	k := recordKeys{suite: reply[1]}
	if client {
		copy(k.send[:], material[:32])
		copy(k.recv[:], material[32:64])
		copy(k.sendPrefix[:], material[64:72])
		copy(k.recvPrefix[:], material[72:80])
	} else {
		copy(k.recv[:], material[:32])
		copy(k.send[:], material[32:64])
		copy(k.recvPrefix[:], material[64:72])
		copy(k.sendPrefix[:], material[72:80])
	}
	return k, nil
}

func clientHandshake(conn io.ReadWriter, seed []byte, carrier, path, suite string) (recordKeys, error) {
	xPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return recordKeys{}, err
	}
	kPrivate, err := mlkem.GenerateKey768()
	if err != nil {
		return recordKeys{}, err
	}
	hello := make([]byte, clientHelloSize)
	hello[0] = handshakeVersion
	hello[1], hello[2] = suiteOffer(suite)
	if _, err := rand.Read(hello[3:35]); err != nil {
		return recordKeys{}, err
	}
	copy(hello[35:67], xPrivate.PublicKey().Bytes())
	copy(hello[67:1251], kPrivate.EncapsulationKey().Bytes())
	mac := domainMAC(seed, "client-hello", carrier, path, hello[:1251])
	copy(hello[1251:], mac[:])
	if err := writeFull(conn, hello); err != nil {
		return recordKeys{}, err
	}
	reply := make([]byte, serverHelloSize)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return recordKeys{}, err
	}
	if reply[0] != handshakeVersion {
		return recordKeys{}, errors.New("hyrakenpro: unsupported handshake version")
	}
	expected := domainMAC(seed, "server-hello", carrier, path, hello, reply[:1154])
	if !hmac.Equal(reply[1154:], expected[:]) {
		return recordKeys{}, errors.New("hyrakenpro: server authentication failed")
	}
	if reply[1] < 1 || reply[1] > 4 || hello[1]&(1<<reply[1]) == 0 {
		return recordKeys{}, errors.New("hyrakenpro: suite negotiation rejected")
	}
	peer, err := ecdh.X25519().NewPublicKey(reply[34:66])
	if err != nil {
		return recordKeys{}, fmt.Errorf("hyrakenpro: server X25519: %w", err)
	}
	xSecret, err := xPrivate.ECDH(peer)
	if err != nil {
		return recordKeys{}, fmt.Errorf("hyrakenpro: server X25519: %w", err)
	}
	kSecret, err := kPrivate.Decapsulate(reply[66:1154])
	if err != nil {
		return recordKeys{}, fmt.Errorf("hyrakenpro: server ML-KEM: %w", err)
	}
	keys, err := deriveKeys(seed, xSecret, kSecret, hello, reply, true)
	if err != nil {
		return recordKeys{}, err
	}
	finish := domainMAC(keys.send[:], "client-finish", carrier, path, hello, reply)
	if err := writeFull(conn, finish[:]); err != nil {
		return recordKeys{}, err
	}
	var confirmation [32]byte
	if _, err := io.ReadFull(conn, confirmation[:]); err != nil {
		return recordKeys{}, err
	}
	expected = domainMAC(keys.recv[:], "server-finish", carrier, path, hello, reply, finish[:])
	if !hmac.Equal(confirmation[:], expected[:]) {
		return recordKeys{}, errors.New("hyrakenpro: server finish failed")
	}
	reportSuiteFallback(suite, keys.suite)
	return keys, nil
}

func serverHandshake(conn io.ReadWriter, seed []byte, carrier, path, suite string) (recordKeys, error) {
	hello := make([]byte, clientHelloSize)
	if _, err := io.ReadFull(conn, hello); err != nil {
		return recordKeys{}, err
	}
	if hello[0] != handshakeVersion {
		return recordKeys{}, errors.New("hyrakenpro: unsupported handshake version")
	}
	expected := domainMAC(seed, "client-hello", carrier, path, hello[:1251])
	if !hmac.Equal(hello[1251:], expected[:]) {
		return recordKeys{}, errors.New("hyrakenpro: client authentication failed")
	}
	selected, err := selectSuite(suite, hello[1], hello[2])
	if err != nil {
		return recordKeys{}, err
	}
	xPeer, err := ecdh.X25519().NewPublicKey(hello[35:67])
	if err != nil {
		return recordKeys{}, fmt.Errorf("hyrakenpro: client X25519: %w", err)
	}
	kPeer, err := mlkem.NewEncapsulationKey768(hello[67:1251])
	if err != nil {
		return recordKeys{}, fmt.Errorf("hyrakenpro: client ML-KEM: %w", err)
	}
	xPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return recordKeys{}, err
	}
	xSecret, err := xPrivate.ECDH(xPeer)
	if err != nil {
		return recordKeys{}, fmt.Errorf("hyrakenpro: client X25519: %w", err)
	}
	kSecret, capsule := kPeer.Encapsulate()
	reply := make([]byte, serverHelloSize)
	reply[0] = handshakeVersion
	reply[1] = selected
	if _, err := rand.Read(reply[2:34]); err != nil {
		return recordKeys{}, err
	}
	copy(reply[34:66], xPrivate.PublicKey().Bytes())
	copy(reply[66:1154], capsule)
	mac := domainMAC(seed, "server-hello", carrier, path, hello, reply[:1154])
	copy(reply[1154:], mac[:])
	if err := writeFull(conn, reply); err != nil {
		return recordKeys{}, err
	}
	keys, err := deriveKeys(seed, xSecret, kSecret, hello, reply, false)
	if err != nil {
		return recordKeys{}, err
	}
	var finish [32]byte
	if _, err := io.ReadFull(conn, finish[:]); err != nil {
		return recordKeys{}, err
	}
	expected = domainMAC(keys.recv[:], "client-finish", carrier, path, hello, reply)
	if !hmac.Equal(finish[:], expected[:]) {
		return recordKeys{}, errors.New("hyrakenpro: client finish failed")
	}
	confirmation := domainMAC(keys.send[:], "server-finish", carrier, path, hello, reply, finish[:])
	if err := writeFull(conn, confirmation[:]); err != nil {
		return recordKeys{}, err
	}
	reportSuiteFallback(suite, keys.suite)
	return keys, nil
}

var suiteFallbackDiagnostic sync.Once

// Report only the fully authenticated intersection, without inferring peer CPU features.
func reportSuiteFallback(requested string, selected byte) {
	if requested == SuiteRoccaS && selected == 2 {
		suiteFallbackDiagnostic.Do(func() {
			log.Print("[Hyraken Pro] Rocca-S unavailable in authenticated capabilities; negotiated ChaCha20-Poly1305")
		})
	}
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func acceleratedAES() bool {
	return cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ || cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
}
func suiteOffer(suite string) (byte, byte) {
	switch suite {
	case SuiteAES256GCM:
		return 2, 1
	case SuiteChaCha20Poly1305:
		return 4, 2
	case SuiteAsconAEAD128:
		return 16, 4
	case SuiteRoccaS:
		// Both peers must offer the fallback; never select an unoffered cipher or
		// switch an established connection's key, nonce layout or algorithm.
		if roccaSAssemblyAvailable() {
			return 12, 3
		}
		return 4, 2
	default:
		allowed := byte(6)
		if roccaSAssemblyAvailable() {
			allowed |= 8
		}
		if acceleratedAES() {
			return allowed, 1
		}
		return allowed, 2
	}
}
func selectSuite(suite string, offer, preferred byte) (byte, error) {
	if offer == 0 || offer&^byte(30) != 0 || preferred < 1 || preferred > 4 || offer&(1<<preferred) == 0 {
		return 0, errors.New("hyrakenpro: invalid suite offer")
	}
	allowed, local := suiteOffer(suite)
	// Auto clients keep their established wire capabilities and preference.
	// Auto servers additionally accept explicitly requested standardized ASCON.
	if suite == SuiteAuto {
		allowed |= 16
	}
	common := allowed & offer
	if common == 0 {
		return 0, errors.New("hyrakenpro: no common authenticated suite")
	}
	if suite == SuiteAuto && preferred == 4 && common&16 != 0 {
		return 4, nil
	}
	if suite == SuiteAuto && preferred == 3 && common&8 != 0 {
		return 3, nil
	}
	if suite == SuiteAuto && preferred == 2 && common&4 != 0 {
		return 2, nil
	}
	if common&(1<<local) != 0 {
		return local, nil
	}
	for i := byte(1); i <= 4; i++ {
		if common&(1<<i) != 0 {
			return i, nil
		}
	}
	return 0, errors.New("hyrakenpro: no suite")
}
func newAEAD(suite byte, key []byte) (cipher.AEAD, error) {
	switch suite {
	case 1:
		b, e := aes.NewCipher(key)
		if e != nil {
			return nil, e
		}
		return cipher.NewGCM(b)
	case 2:
		return chacha20poly1305.New(key)
	case 3:
		return newRoccaS(key)
	case 4:
		return newAsconAEAD128(key)
	default:
		return nil, errors.New("hyrakenpro: invalid negotiated suite")
	}
}
func newCiphers(k recordKeys) (*cipherPair, error) {
	sendKey, recvKey := k.send[:], k.recv[:]
	var asconSendKey, asconRecvKey [16]byte
	defer clear(asconSendKey[:])
	defer clear(asconRecvKey[:])
	if k.suite == 4 {
		// Keep ASCON's128-bit AEAD key dedicated to encryption (SP800-232 R1).
		// The80-byte suite-bound schedule and full32-byte finish keys stay intact.
		info := []byte("hyraken-pro/v1/ascon-aead128/record-key")
		if _, err := io.ReadFull(hkdf.Expand(sha256.New, sendKey, info), asconSendKey[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(hkdf.Expand(sha256.New, recvKey, info), asconRecvKey[:]); err != nil {
			return nil, err
		}
		sendKey, recvKey = asconSendKey[:], asconRecvKey[:]
	}
	send, e := newAEAD(k.suite, sendKey)
	if e != nil {
		return nil, e
	}
	recv, e := newAEAD(k.suite, recvKey)
	if e != nil {
		return nil, e
	}
	return &cipherPair{send: send, recv: recv, sendPrefix: k.sendPrefix, recvPrefix: k.recvPrefix}, nil
}
