package hyrakenx

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	roccaSKeySize   = 32
	roccaSNonceSize = 16
	roccaSTagSize   = 32
	roccaSRate      = 32
	roccaSAbsorb    = 0
	roccaSEncrypt   = 1
	roccaSDecrypt   = 2
	roccaSRepeat    = 3
)

var errRoccaSAuth = errors.New("hyrakenx: Rocca-S authentication failed")

type roccaSBlock [2]uint64
type roccaSState [7]roccaSBlock

// roccaSAEAD implements draft-nakano-rocca-s-06 with a fixed 16-byte nonce
// and the full 32-byte tag. The AES single rounds run only in gated AES-NI
// assembly: crypto/aes.Block.Encrypt is a different operation. The design
// and the KDDI reference implementation are credited in THIRD_PARTY_NOTICES.
// This local implementation has not received an independent crypto audit.
type roccaSAEAD struct{ key [roccaSKeySize]byte }

var _ cipher.AEAD = (*roccaSAEAD)(nil)

func newRoccaS(key []byte) (cipher.AEAD, error) {
	if len(key) != roccaSKeySize {
		return nil, errors.New("hyrakenx: invalid Rocca-S key size")
	}
	if !roccaSAssemblyAvailable() {
		return nil, errors.New("hyrakenx: Rocca-S requires an amd64 AES-NI assembly build")
	}
	a := new(roccaSAEAD)
	copy(a.key[:], key)
	return a, nil
}

func (*roccaSAEAD) NonceSize() int { return roccaSNonceSize }
func (*roccaSAEAD) Overhead() int  { return roccaSTagSize }

func (a *roccaSAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != roccaSNonceSize {
		panic("hyrakenx: invalid Rocca-S nonce size")
	}
	if uint64(len(additionalData)) > uint64(1)<<61 {
		panic("hyrakenx: Rocca-S associated data exceeds limit")
	}
	if len(plaintext) > int(^uint(0)>>1)-roccaSTagSize {
		panic("hyrakenx: Rocca-S plaintext exceeds limit")
	}
	ret, out := aeadAppend(dst, len(plaintext)+roccaSTagSize)
	if aeadInexactOverlap(out, plaintext) || aeadAnyOverlap(out, additionalData) {
		panic("hyrakenx: invalid Rocca-S buffer overlap")
	}
	s := a.initialize(nonce)
	roccaSAbsorbAD(&s, additionalData)
	roccaSCrypt(&s, out[:len(plaintext)], plaintext, roccaSEncrypt)
	tag := roccaSFinish(&s, len(additionalData), len(plaintext))
	copy(out[len(plaintext):], tag[:])
	clear(tag[:])
	clear(s[:])
	return ret
}

func (a *roccaSAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != roccaSNonceSize {
		panic("hyrakenx: invalid Rocca-S nonce size")
	}
	if len(ciphertext) < roccaSTagSize || uint64(len(additionalData)) > uint64(1)<<61 {
		return nil, errRoccaSAuth
	}
	n := len(ciphertext) - roccaSTagSize
	ret, out := aeadAppend(dst, n)
	// Include the entire tag in overlap validation, even for a short plaintext.
	if aeadInexactOverlap(out, ciphertext) || aeadAnyOverlap(out, additionalData) {
		panic("hyrakenx: invalid Rocca-S buffer overlap")
	}
	s := a.initialize(nonce)
	roccaSAbsorbAD(&s, additionalData)
	roccaSCrypt(&s, out, ciphertext[:n], roccaSDecrypt)
	tag := roccaSFinish(&s, len(additionalData), n)
	valid := subtle.ConstantTimeCompare(tag[:], ciphertext[n:])
	clear(tag[:])
	clear(s[:])
	if valid != 1 {
		clear(out)
		return nil, errRoccaSAuth
	}
	return ret, nil
}

func (a *roccaSAEAD) initialize(nonce []byte) roccaSState {
	k0 := roccaSLoad(a.key[:16])
	k1 := roccaSLoad(a.key[16:])
	n := roccaSLoad(nonce)
	// The constants are little-endian words of the specification's byte strings.
	z := [4]uint64{0x7137449123ef65cd, 0x428a2f98d728ae22, 0xe9b5dba58189dbbc, 0xb5c0fbcfec4d3b2f}
	s := roccaSState{k1, n, {z[0], z[1]}, k0, {z[2], z[3]}, {n[0] ^ k1[0], n[1] ^ k1[1]}, {}}
	var input [roccaSRate]byte
	for i, x := range z {
		binary.LittleEndian.PutUint64(input[i*8:], x)
	}
	roccaSBlocks(&s, nil, &input[0], 16, roccaSRepeat)
	for i := range s {
		key := k0
		if i == 2 || i >= 5 {
			key = k1
		}
		s[i][0] ^= key[0]
		s[i][1] ^= key[1]
	}
	clear(input[:])
	return s
}

func roccaSLoad(p []byte) roccaSBlock {
	return roccaSBlock{binary.LittleEndian.Uint64(p[:8]), binary.LittleEndian.Uint64(p[8:16])}
}

func roccaSAbsorbAD(s *roccaSState, ad []byte) {
	blocks := len(ad) / roccaSRate
	if blocks > 0 {
		roccaSBlocks(s, nil, &ad[0], blocks, roccaSAbsorb)
		ad = ad[blocks*roccaSRate:]
	}
	if len(ad) > 0 {
		var last [roccaSRate]byte
		copy(last[:], ad)
		roccaSBlocks(s, nil, &last[0], 1, roccaSAbsorb)
		clear(last[:])
	}
}

func roccaSCrypt(s *roccaSState, dst, src []byte, mode int) {
	blocks := len(src) / roccaSRate
	if blocks > 0 {
		roccaSBlocks(s, &dst[0], &src[0], blocks, mode)
		dst, src = dst[blocks*roccaSRate:], src[blocks*roccaSRate:]
	}
	if len(src) == 0 {
		return
	}
	var last, output [roccaSRate]byte
	copy(last[:], src)
	if mode == roccaSDecrypt {
		// A padded ciphertext does not decrypt to a zero-padded message. Obtain
		// the keystream from a state copy, then absorb ONLY the padded plaintext.
		tmp := *s
		roccaSBlocks(&tmp, &output[0], &last[0], 1, roccaSDecrypt)
		copy(dst, output[:len(src)])
		clear(output[len(src):])
		roccaSBlocks(s, nil, &output[0], 1, roccaSAbsorb)
		clear(tmp[:])
	} else {
		roccaSBlocks(s, &output[0], &last[0], 1, roccaSEncrypt)
		copy(dst, output[:len(src)])
	}
	clear(last[:])
	clear(output[:])
}

func roccaSFinish(s *roccaSState, adLen, msgLen int) (tag [roccaSTagSize]byte) {
	var lengths [roccaSRate]byte
	// Both lengths are encoded as 128-bit little-endian BIT counts.
	binary.LittleEndian.PutUint64(lengths[:8], uint64(adLen)<<3)
	binary.LittleEndian.PutUint64(lengths[8:16], uint64(adLen)>>61)
	binary.LittleEndian.PutUint64(lengths[16:24], uint64(msgLen)<<3)
	binary.LittleEndian.PutUint64(lengths[24:], uint64(msgLen)>>61)
	roccaSBlocks(s, nil, &lengths[0], 16, roccaSRepeat)
	for word := 0; word < 2; word++ {
		binary.LittleEndian.PutUint64(tag[word*8:], s[0][word]^s[1][word]^s[2][word]^s[3][word])
		binary.LittleEndian.PutUint64(tag[16+word*8:], s[4][word]^s[5][word]^s[6][word])
	}
	clear(lengths[:])
	return tag
}
