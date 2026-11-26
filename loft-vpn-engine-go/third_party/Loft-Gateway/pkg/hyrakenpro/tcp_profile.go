package hyrakenpro

// TCPProfile records the policy applied to Pro's physical TLS 1.3 sockets.
// These are local socket parameters, never a wire field or a measured capacity.
// Kernel congestion recovery, MSS and receive/send autotuning retain ownership.
type TCPProfile struct {
	Name            string `json:"name"`
	Congestion      string `json:"congestion"`
	BrutalRate      uint64 `json:"brutal_rate_bytes_per_second"`
	UserTimeoutMS   int    `json:"user_timeout_ms"`
	NotsentLowat    int    `json:"notsent_lowat_bytes"`
	KeepIdleSeconds int    `json:"keep_idle_seconds"`
	KeepIntervalSec int    `json:"keep_interval_seconds"`
	KeepCount       int    `json:"keep_count"`
}

// DefaultTCPProfile is shared by the Naive owner and the actual GhostX child.
// Brutal requires an explicit rate: its 384 decimal Mbps setting is a bounded
// nominal target per physical socket. If the module is absent, verified kernel
// BBR is preferred, then verified CUBIC, without a guessed SO_MAX_PACING_RATE
// ceiling. Policy v3 describes this local order, not the kernel BBR version.
// Existing connected Brutal route quotas are preserved. No global sysctl or
// qdisc is modified.
func DefaultTCPProfile() TCPProfile {
	return TCPProfile{Name: "hyraken-pro-beast-v3", Congestion: "beast", BrutalRate: 48_000_000,
		UserTimeoutMS: 45000, NotsentLowat: 256 << 10, KeepIdleSeconds: 30, KeepIntervalSec: 10, KeepCount: 3}
}
