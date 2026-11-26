package hyrakenx

import "unsafe"

// Shared cipher.AEAD buffer semantics: exact in-place is allowed; shifted
// overlap and output/AD overlap are rejected before plaintext is written.
func aeadAppend(dst []byte, n int) (ret, out []byte) {
	if n < 0 || len(dst) > int(^uint(0)>>1)-n {
		panic("hyrakenx: AEAD message too large")
	}
	base := len(dst)
	if n <= cap(dst)-len(dst) {
		ret = dst[:base+n]
	} else {
		ret = make([]byte, base+n)
		copy(ret, dst)
	}
	return ret, ret[base:]
}

func aeadInexactOverlap(out, in []byte) bool {
	return aeadAnyOverlap(out, in) && (len(out) == 0 || len(in) == 0 || unsafe.SliceData(out) != unsafe.SliceData(in))
}

func aeadAnyOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 {
		return false
	}
	x0, y0 := uintptr(unsafe.Pointer(unsafe.SliceData(x))), uintptr(unsafe.Pointer(unsafe.SliceData(y)))
	return x0 < y0+uintptr(len(y)) && y0 < x0+uintptr(len(x))
}
