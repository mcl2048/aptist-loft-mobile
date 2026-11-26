//go:build amd64 && gc && !purego

package hyrakenx

import "golang.org/x/sys/cpu"

func aesGCMConstantTimeAvailable() bool { return cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ }
