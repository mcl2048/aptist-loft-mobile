//go:build !amd64 || !gc || purego

package hyrakenx

func aesGCMConstantTimeAvailable() bool { return false }
