package hyrakenpro

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	asconKeySize   = 16
	asconNonceSize = 16
	asconTagSize   = 16
	asconRate      = 16
)

var errAsconAuth = errors.New("hyrakenpro: Ascon-AEAD128 authentication failed")

// asconAEAD128 implements the byte-oriented Ascon-AEAD128 construction in
// NIST SP 800-232. All state operations are fixed-width Boolean/arithmetic
// operations; no secret-indexed tables or data-dependent branches are used.
type asconAEAD128 struct {
	key [asconKeySize]byte
}

var _ cipher.AEAD = (*asconAEAD128)(nil)

func newAsconAEAD128(key []byte) (cipher.AEAD, error) {
	if len(key) != asconKeySize {
		return nil, errors.New("hyrakenpro: invalid Ascon-AEAD128 key size")
	}
	a := new(asconAEAD128)
	copy(a.key[:], key)
	return a, nil
}

func (*asconAEAD128) NonceSize() int { return asconNonceSize }
func (*asconAEAD128) Overhead() int  { return asconTagSize }

func (a *asconAEAD128) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != asconNonceSize {
		panic("hyrakenpro: invalid Ascon-AEAD128 nonce size")
	}
	ret, out := aeadAppend(dst, len(plaintext)+asconTagSize)
	if aeadInexactOverlap(out, plaintext) || aeadAnyOverlap(out, additionalData) {
		panic("hyrakenpro: invalid Ascon-AEAD128 buffer overlap")
	}
	s, k0, k1 := a.initialize(nonce)
	asconAbsorbAD(&s, additionalData)
	s[4] ^= 0x8000000000000000
	ct := out[:len(plaintext)]
	asconEncrypt(&s, ct, plaintext)
	s[2] ^= k0
	s[3] ^= k1
	asconPermute(&s, 12)
	binary.LittleEndian.PutUint64(out[len(plaintext):], s[3]^k0)
	binary.LittleEndian.PutUint64(out[len(plaintext)+8:], s[4]^k1)
	clear(s[:])
	return ret
}

func (a *asconAEAD128) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != asconNonceSize {
		panic("hyrakenpro: invalid Ascon-AEAD128 nonce size")
	}
	if len(ciphertext) < asconTagSize {
		return nil, errAsconAuth
	}
	plainLen := len(ciphertext) - asconTagSize
	ret, out := aeadAppend(dst, plainLen)
	if aeadInexactOverlap(out, ciphertext) || aeadAnyOverlap(out, additionalData) {
		panic("hyrakenpro: invalid Ascon-AEAD128 buffer overlap")
	}
	s, k0, k1 := a.initialize(nonce)
	asconAbsorbAD(&s, additionalData)
	s[4] ^= 0x8000000000000000
	asconDecrypt(&s, out, ciphertext[:plainLen])
	s[2] ^= k0
	s[3] ^= k1
	asconPermute(&s, 12)
	var tag [asconTagSize]byte
	binary.LittleEndian.PutUint64(tag[:8], s[3]^k0)
	binary.LittleEndian.PutUint64(tag[8:], s[4]^k1)
	clear(s[:])
	if subtle.ConstantTimeCompare(tag[:], ciphertext[plainLen:]) != 1 {
		clear(out)
		return nil, errAsconAuth
	}
	return ret, nil
}

func (a *asconAEAD128) initialize(nonce []byte) (state [5]uint64, k0, k1 uint64) {
	k0 = binary.LittleEndian.Uint64(a.key[:8])
	k1 = binary.LittleEndian.Uint64(a.key[8:])
	state[0] = 0x00001000808c0001 // SP 800-232 IV for Ascon-AEAD128.
	state[1], state[2] = k0, k1
	state[3] = binary.LittleEndian.Uint64(nonce[:8])
	state[4] = binary.LittleEndian.Uint64(nonce[8:])
	asconPermute(&state, 12)
	state[3] ^= k0
	state[4] ^= k1
	return state, k0, k1
}

func asconAbsorbAD(state *[5]uint64, ad []byte) {
	if len(ad) == 0 {
		return
	}
	for len(ad) >= asconRate {
		state[0] ^= binary.LittleEndian.Uint64(ad[:8])
		state[1] ^= binary.LittleEndian.Uint64(ad[8:16])
		asconPermute(state, 8)
		ad = ad[asconRate:]
	}
	var last [asconRate]byte
	copy(last[:], ad)
	last[len(ad)] = 1
	state[0] ^= binary.LittleEndian.Uint64(last[:8])
	state[1] ^= binary.LittleEndian.Uint64(last[8:])
	clear(last[:])
	asconPermute(state, 8)
}

func asconEncrypt(state *[5]uint64, dst, src []byte) {
	for len(src) >= asconRate {
		state[0] ^= binary.LittleEndian.Uint64(src[:8])
		state[1] ^= binary.LittleEndian.Uint64(src[8:16])
		binary.LittleEndian.PutUint64(dst[:8], state[0])
		binary.LittleEndian.PutUint64(dst[8:16], state[1])
		asconPermute(state, 8)
		src, dst = src[asconRate:], dst[asconRate:]
	}
	var last [asconRate]byte
	copy(last[:], src)
	last[len(src)] = 1
	state[0] ^= binary.LittleEndian.Uint64(last[:8])
	state[1] ^= binary.LittleEndian.Uint64(last[8:])
	var stream [asconRate]byte
	binary.LittleEndian.PutUint64(stream[:8], state[0])
	binary.LittleEndian.PutUint64(stream[8:], state[1])
	copy(dst, stream[:len(src)])
	clear(last[:])
	clear(stream[:])
}

func asconDecrypt(state *[5]uint64, dst, src []byte) {
	for len(src) >= asconRate {
		c0, c1 := binary.LittleEndian.Uint64(src[:8]), binary.LittleEndian.Uint64(src[8:16])
		binary.LittleEndian.PutUint64(dst[:8], state[0]^c0)
		binary.LittleEndian.PutUint64(dst[8:16], state[1]^c1)
		state[0], state[1] = c0, c1
		asconPermute(state, 8)
		src, dst = src[asconRate:], dst[asconRate:]
	}
	var stream, last [asconRate]byte
	binary.LittleEndian.PutUint64(stream[:8], state[0])
	binary.LittleEndian.PutUint64(stream[8:], state[1])
	for i := range src {
		last[i] = src[i] ^ stream[i]
		dst[i] = last[i]
	}
	last[len(src)] = 1
	state[0] ^= binary.LittleEndian.Uint64(last[:8])
	state[1] ^= binary.LittleEndian.Uint64(last[8:])
	clear(stream[:])
	clear(last[:])
}

func asconPermute(s *[5]uint64, rounds int) {
	constants := [...]uint8{0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b}
	// Keep the state in local words across rounds. This changes neither the
	// SP 800-232 permutation nor its fixed-time operations, and avoids storing
	// and reloading five array words after every round on the packet hot path.
	x0, x1, x2, x3, x4 := s[0], s[1], s[2], s[3], s[4]
	for _, rc := range constants[12-rounds:] {
		x2 ^= uint64(rc)
		x0 ^= x4
		x4 ^= x3
		x2 ^= x1
		t0 := x4 ^ (^x0 & x1)
		t1 := x0 ^ (^x1 & x2)
		t2 := x1 ^ (^x2 & x3)
		t3 := x2 ^ (^x3 & x4)
		t4 := x3 ^ (^x4 & x0)
		x0, x1, x2, x3, x4 = t1, t2, t3, t4, t0
		x1 ^= x0
		x3 ^= x2
		x0 ^= x4
		x2 = ^x2
		x0 ^= bits.RotateLeft64(x0, -19) ^ bits.RotateLeft64(x0, -28)
		x1 ^= bits.RotateLeft64(x1, -61) ^ bits.RotateLeft64(x1, -39)
		x2 ^= bits.RotateLeft64(x2, -1) ^ bits.RotateLeft64(x2, -6)
		x3 ^= bits.RotateLeft64(x3, -10) ^ bits.RotateLeft64(x3, -17)
		x4 ^= bits.RotateLeft64(x4, -7) ^ bits.RotateLeft64(x4, -41)
	}
	s[0], s[1], s[2], s[3], s[4] = x0, x1, x2, x3, x4
}
