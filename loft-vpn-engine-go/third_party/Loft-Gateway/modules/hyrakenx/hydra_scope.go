package hyrakenx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidateHydraScope bounds explicit local sender scope without changing labels.
func ValidateHydraScope(scope string) error {
	if len(scope) > 256 || !utf8.ValidString(scope) || strings.IndexFunc(scope, unicode.IsControl) >= 0 {
		return errors.New("hyrakenx: Hydra scope must contain at most 256 UTF-8 bytes without control characters")
	}
	return nil
}

// HydraScopeForTag retains every byte of legacy native tags in an opaque digest.
func HydraScopeForTag(tag string) string {
	digest := sha256.Sum256([]byte("hyrakenx/hydra/native-tag/v1\x00" + tag))
	return hex.EncodeToString(digest[:])
}
