//go:build !amd64 || !gc || purego

package hyrakenx

func roccaSAssemblyAvailable() bool { return false }

// No table-based software AES fallback. The factory and Normalize reject this
// configuration before any packet, listener, or worker can use the primitive.
func roccaSBlocks(*roccaSState, *byte, *byte, int, int) {
	panic("hyrakenx: Rocca-S assembly unavailable")
}
