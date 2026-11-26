// Package hyrakenx implements the independent Hyraken X UDP data record.
// A caller supplies key material only after a verified TLS 1.3 handshake.
package hyrakenx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	HeaderSize = 13
	MaxPayload = 1400
	// RekeyPacketLimit is the legacy ceiling; AES-GCM uses a lower suite limit.
	RekeyPacketLimit = 1 << 32
	replayWindowSize = 2048
	version          = 1
	packetTypeData   = 1
)

var (
	ErrReplay         = errors.New("hyrakenx: replayed or stale packet")
	ErrRekeyRequired  = errors.New("hyrakenx: packet limit reached; establish a new TLS session")
	ErrAuthentication = errors.New("hyrakenx: packet authentication failed")
)

// Suite is authenticated by the TLS control-plane transcript and KDF context.
type Suite uint8

const (
	SuiteRoccaS           Suite = 1
	SuiteChaCha20Poly1305 Suite = 2
	SuiteAES256GCM        Suite = 3
)

func (s Suite) String() string {
	switch s {
	case SuiteRoccaS:
		return "rocca-s"
	case SuiteChaCha20Poly1305:
		return "chacha20-poly1305"
	case SuiteAES256GCM:
		return "aes-256-gcm"
	default:
		return "unknown"
	}
}

func (s Suite) TagSize() int {
	if s == SuiteRoccaS {
		return 32
	}
	return 16
}

// Maximum GCM input is 1402B plaintext + 13B AAD + the 16B length block,
// fewer than 128 AES blocks after padding. RFC 9001 Appendix B.1.1 gives
// q <= 2^35/l for a single-key distinguishing target of approximately 2^-57.
// Each direction and each stream owns a distinct key and its own budget.
func (s Suite) packetLimit() uint64 {
	if s == SuiteAES256GCM {
		return 1 << 28
	}
	return RekeyPacketLimit
}

// RFC 9001 section 6.6 gives conservative failed-authentication limits for
// GCM and ChaCha. Here they bound each independent receive key, not a QUIC
// connection across key updates. Rocca-S's value is an engineering lifetime
// ceiling only; it does not assert a normative Rocca-S cryptographic bound.
func (s Suite) failedOpenLimit() uint64 {
	switch s {
	case SuiteAES256GCM:
		return 1 << 52
	case SuiteChaCha20Poly1305:
		return 1 << 36
	default:
		return RekeyPacketLimit
	}
}

// Role determines the independent sending and receiving key domains.
type Role uint8

const (
	Client Role = 0
	Server Role = 1
)

type packetKey struct {
	aead      cipher.AEAD
	hp        cipher.Block
	hpKey     [32]byte
	hpMAC     hash.Hash
	hpSum     [sha256.Size]byte
	salt      [4]byte
	direction Role
}

// Session owns one TLS attachment and one session ID. Rekey creates a new Session.
type Session struct {
	mu             sync.Mutex
	tx             packetKey
	rx             packetKey
	id             uint32
	sendCounter    uint64
	rxFailedOpens  uint64 // Actual failed AEAD opens for this receive key only.
	replay         replayWindow
	master         [32]byte
	transcriptHash [32]byte
	suite          Suite
	role           Role
}

// NewSession derives independent direction keys from the completed TLS
// exporter and authenticated control transcript. An exporter from 0-RTT is
// forbidden: only the application traffic connection state may supply it.
func NewSession(exporter, transcript []byte, suite Suite, role Role, sessionID uint32) (*Session, error) {
	if len(exporter) != 32 || len(transcript) == 0 || len(transcript) > 4096 || sessionID == 0 || role > Server {
		return nil, errors.New("hyrakenx: invalid authenticated session context")
	}
	if suite != SuiteRoccaS && suite != SuiteChaCha20Poly1305 && suite != SuiteAES256GCM {
		return nil, errors.New("hyrakenx: unsupported negotiated suite")
	}
	if suite == SuiteRoccaS && !roccaSAssemblyAvailable() {
		return nil, errors.New("hyrakenx: Rocca-S requires amd64 AES-NI assembly")
	}
	if suite == SuiteAES256GCM && !aesGCMConstantTimeAvailable() {
		return nil, errors.New("hyrakenx: AES-GCM requires AES and GHASH hardware")
	}
	hash := sha256.Sum256(transcript)
	context := fmt.Sprintf("hyrakenx/v1/%d/%x/%08x", suite, hash, sessionID)
	clientKey, err := derivePacketKey(exporter, context, suite, Client)
	if err != nil {
		return nil, err
	}
	serverKey, err := derivePacketKey(exporter, context, suite, Server)
	if err != nil {
		return nil, err
	}
	s := &Session{id: sessionID, transcriptHash: hash, suite: suite, role: role}
	copy(s.master[:], exporter)
	if role == Client {
		s.tx, s.rx = clientKey, serverKey
	} else {
		s.tx, s.rx = serverKey, clientKey
	}
	return s, nil
}

func (s *Session) stream(id uint64) (*Session, error) {
	var context [40]byte
	copy(context[:32], s.transcriptHash[:])
	binary.LittleEndian.PutUint64(context[32:], id)
	return NewSession(s.master[:], context[:], s.suite, s.role, s.id)
}

func derivePacketKey(exporter []byte, context string, suite Suite, direction Role) (packetKey, error) {
	var k packetKey
	k.direction = direction
	label := fmt.Sprintf("%s/%d", context, direction)
	material, err := hkdf.Key(sha256.New, exporter, nil, label, 68)
	if err != nil {
		return k, fmt.Errorf("hyrakenx: derive packet key: %w", err)
	}
	defer clear(material)
	copy(k.salt[:], material[64:68])
	k.salt[0] = k.salt[0]&0x7f | byte(direction)<<7
	copy(k.hpKey[:], material[32:64])
	if suite == SuiteChaCha20Poly1305 {
		// The resulting key belongs to exactly one Session direction. All
		// header-mask mutations run under that Session's existing mutex.
		k.hpMAC = hmac.New(sha256.New, k.hpKey[:])
		k.hpMAC.Reset()
	} else {
		k.hp, err = aes.NewCipher(k.hpKey[:])
		if err != nil {
			return k, fmt.Errorf("hyrakenx: header protection: %w", err)
		}
	}
	switch suite {
	case SuiteRoccaS:
		k.aead, err = newRoccaS(material[:32])
	case SuiteChaCha20Poly1305:
		k.aead, err = chacha20poly1305.New(material[:32])
	case SuiteAES256GCM:
		var block cipher.Block
		block, err = aes.NewCipher(material[:32])
		if err == nil {
			k.aead, err = cipher.NewGCM(block)
		}
	}
	if err != nil {
		return k, fmt.Errorf("hyrakenx: create packet AEAD: %w", err)
	}
	return k, nil
}

// Seal emits a 13-byte clear header with protected flags and a protected
// full 64-bit counter. The ciphertext samples at least 16 bytes.
func (s *Session) Seal(payload []byte) ([]byte, error) {
	return s.SealPadded(payload, 0)
}

// SealPadded adds authenticated padding after the payload using the existing v1
// length field. Padding excludes the two length bytes and the mandatory minimum
// plaintext size. Zero padding preserves Seal's exact wire contract.
func (s *Session) SealPadded(payload []byte, padding int) ([]byte, error) {
	if padding < 0 || padding > MaxPayload || len(payload) > MaxPayload-padding {
		return nil, errors.New("hyrakenx: payload exceeds packet budget")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendCounter >= s.suite.packetLimit() {
		return nil, ErrRekeyRequired
	}
	n := max(16, len(payload)+padding+2)
	packet := make([]byte, 0, HeaderSize+n+s.tx.aead.Overhead())
	var workspace packetSealWorkspace
	return s.sealAppendLocked(packet, payload, padding, &workspace)
}

// packetSealWorkspace is zero-initialized and exclusively owned by its caller.
// streamConn.Write holds writeMu for its entire lifetime; no plaintext or AD
// workspace is shared with RX or retained by the returned ciphertext.
type packetSealWorkspace struct {
	plain  [MaxPayload + 2]byte
	header [HeaderSize]byte
	nonce  [16]byte
}

func (w *packetSealWorkspace) clear() {
	clear(w.plain[:])
	clear(w.header[:])
	clear(w.nonce[:])
}

// sealAppend appends only into existing caller capacity. The stream writer uses
// its existing batch; public SealPadded separately allocates an owned packet.
func (s *Session) sealAppend(dst, payload []byte, padding int, workspace *packetSealWorkspace) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sealAppendLocked(dst, payload, padding, workspace)
}

// Caller owns s.mu and workspace. Reject budget/capacity before output or nonce
// consumption, and keep complete header AD disjoint from Seal's destination.
func (s *Session) sealAppendLocked(dst, payload []byte, padding int, workspace *packetSealWorkspace) ([]byte, error) {
	defer workspace.clear()
	if padding < 0 || padding > MaxPayload || len(payload) > MaxPayload-padding {
		return nil, errors.New("hyrakenx: payload exceeds packet budget")
	}
	if s.sendCounter >= s.suite.packetLimit() {
		return nil, ErrRekeyRequired
	}
	n := max(16, len(payload)+padding+2)
	packetLength := HeaderSize + n + s.tx.aead.Overhead()
	if len(dst) > cap(dst)-packetLength {
		return nil, errors.New("hyrakenx: packet writer workspace exhausted")
	}
	counter := s.sendCounter
	header := workspace.header[:]
	header[0] = version<<6 | packetTypeData<<4 | byte(s.tx.direction)<<2
	binary.LittleEndian.PutUint32(header[1:5], s.id)
	binary.LittleEndian.PutUint64(header[5:13], counter)
	binary.LittleEndian.PutUint16(workspace.plain[:2], uint16(len(payload)))
	copy(workspace.plain[2:], payload)
	nonceSize := s.tx.aead.NonceSize()
	copy(workspace.nonce[:4], s.tx.salt[:])
	binary.LittleEndian.PutUint64(workspace.nonce[nonceSize-8:nonceSize], counter)
	prefix := len(dst)
	packet := dst[:prefix+HeaderSize]
	copy(packet[prefix:], header)
	packet = s.tx.aead.Seal(packet, workspace.nonce[:nonceSize], workspace.plain[:n], header)
	protectHeader(&s.tx, packet[prefix:])
	s.sendCounter++
	return packet, nil
}

// Open authenticates before advancing the replay window. Actual AEAD failures
// consume only the receive-key failure budget, never replay state. Once that
// budget is exhausted, even malformed input requires a new key domain.
func (s *Session) Open(packet []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rxFailedOpens >= s.suite.failedOpenLimit() {
		return nil, ErrRekeyRequired
	}
	if len(packet) < HeaderSize+16+s.rx.aead.Overhead() || len(packet) > HeaderSize+MaxPayload+2+s.rx.aead.Overhead() || binary.LittleEndian.Uint32(packet[1:5]) != s.id {
		return nil, ErrAuthentication
	}
	var header [HeaderSize]byte
	copy(header[:], packet[:HeaderSize])
	unprotectHeader(&s.rx, header[:], packet[HeaderSize:])
	if header[0] != version<<6|packetTypeData<<4|byte(s.rx.direction)<<2 {
		return nil, ErrAuthentication
	}
	counter := binary.LittleEndian.Uint64(header[5:13])
	if counter >= s.suite.packetLimit() {
		return nil, ErrRekeyRequired
	}
	if !s.replay.acceptable(counter) {
		return nil, ErrReplay
	}
	nonce := packetNonce(s.rx, counter)
	plain, err := s.rx.aead.Open(nil, nonce[:s.rx.aead.NonceSize()], packet[HeaderSize:], header[:])
	if err != nil {
		clear(plain)
		// Keep the counter saturating even if future policies change. The
		// last permitted failed attempt returns the authentication error;
		// every subsequent Open is rejected by the budget gate above.
		if s.rxFailedOpens != ^uint64(0) {
			s.rxFailedOpens++
		}
		return nil, ErrAuthentication
	}
	if len(plain) < 16 {
		clear(plain)
		return nil, ErrAuthentication
	}
	n := int(binary.LittleEndian.Uint16(plain[:2]))
	if n > MaxPayload || n+2 > len(plain) {
		clear(plain)
		return nil, ErrAuthentication
	}
	s.replay.advance(counter)
	return plain[2 : n+2], nil
}

func packetNonce(key packetKey, counter uint64) (nonce [16]byte) {
	copy(nonce[:4], key.salt[:])
	// Bytes 4..7 are the epoch. This attachment uses epoch zero and rekeys by
	// establishing a new TLS connection and a new session ID.
	binary.LittleEndian.PutUint64(nonce[8:], counter)
	if key.aead.NonceSize() == 12 {
		binary.LittleEndian.PutUint64(nonce[4:12], counter)
	}
	return nonce
}

func headerMask(key *packetKey, sample []byte) (mask [16]byte) {
	if key.hp == nil {
		if key.hpMAC == nil {
			// Compatibility for tests constructing packetKey by hand. All
			// negotiated production keys initialize their owned workspace.
			mac := hmac.New(sha256.New, key.hpKey[:])
			_, _ = mac.Write(sample[:16])
			copy(mask[:], mac.Sum(nil))
		} else {
			key.hpMAC.Reset()
			_, _ = key.hpMAC.Write(sample[:16])
			copy(mask[:], key.hpMAC.Sum(key.hpSum[:0]))
		}
	} else {
		return aesHeaderMask(key.hp, sample)
	}
	return mask
}

// Keep the cipher.Block output escape in the AES branch. Passing headerMask's
// shared return buffer to that interface would also heap-allocate the ChaCha
// result on every call, despite its allocation-free HMAC workspace.
func aesHeaderMask(block cipher.Block, sample []byte) (mask [16]byte) {
	block.Encrypt(mask[:], sample[:16])
	return mask
}

func protectHeader(key *packetKey, packet []byte) {
	mask := headerMask(key, packet[HeaderSize:])
	packet[0] ^= mask[0] & 0x3f
	for i := 0; i < 8; i++ {
		packet[5+i] ^= mask[1+i]
	}
}

func unprotectHeader(key *packetKey, header, body []byte) {
	mask := headerMask(key, body)
	header[0] ^= mask[0] & 0x3f
	for i := 0; i < 8; i++ {
		header[5+i] ^= mask[1+i]
	}
}

type replayWindow struct {
	top  uint64
	bits [replayWindowSize / 64]uint64
	seen bool
}

func (w *replayWindow) acceptable(counter uint64) bool {
	if !w.seen || counter > w.top {
		return true
	}
	delta := w.top - counter
	return delta < replayWindowSize && w.bits[delta/64]&(uint64(1)<<(delta%64)) == 0
}

func (w *replayWindow) advance(counter uint64) {
	if !w.seen {
		w.top, w.bits[0], w.seen = counter, 1, true
		return
	}
	if counter > w.top {
		shift := counter - w.top
		if shift >= replayWindowSize {
			clear(w.bits[:])
		} else {
			words, bits := int(shift/64), uint(shift%64)
			for i := len(w.bits) - 1; i >= 0; i-- {
				var value uint64
				if i >= words {
					value = w.bits[i-words] << bits
					if bits != 0 && i > words {
						value |= w.bits[i-words-1] >> (64 - bits)
					}
				}
				w.bits[i] = value
			}
		}
		w.top = counter
	}
	delta := w.top - counter
	w.bits[delta/64] |= uint64(1) << (delta % 64)
}
