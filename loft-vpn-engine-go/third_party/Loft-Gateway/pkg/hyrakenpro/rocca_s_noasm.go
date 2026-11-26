//go:build !amd64 || !gc || purego

package hyrakenpro

func roccaSAssemblyAvailable() bool { return false }

// No table-based software AES fallback. The factory and Normalize reject this
// configuration before any packet, listener, or worker can use the primitive.
func roccaSBlocks(*roccaSState, *byte, *byte, int, int) {
	panic("hyrakenpro: Rocca-S assembly unavailable")
}
