//go:build android

package engine

import "runtime"

// Go is loaded lazily by the private Android VPN service. Set its scheduler
// budget in that process before any public engine constructor performs work.
// Host consumers keep their own scheduler configuration.
func init() { runtime.GOMAXPROCS(2) }
