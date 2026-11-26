//go:build amd64 && gc && !purego

package hyrakenpro

import "golang.org/x/sys/cpu"

func roccaSAssemblyAvailable() bool { return cpu.X86.HasAES }

// mode selects AD absorption, encryption, decryption, or repeated absorption.
// Only public lengths/mode control branches. dst may be nil for absorption;
// src may be nil only when blocks is zero. All pointers stay on the Go stack.
//
//go:noescape
func roccaSBlocks(state *roccaSState, dst, src *byte, blocks, mode int)
