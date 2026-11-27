# Locked Hyraken QUIC recovery patch

Complete source of github.com/sagernet/quic-go v0.61.0-sing-box-mod.7, copied from the verified Go module cache. UPSTREAM-SHA256SUMS retains the original inventory. No imports or public APIs are renamed. packet_packer.go receives the ACK-only recovery fix; ack_only_recovery_test.go proves ACK-only packets remain non-ack-eliciting and deferred PING intent survives.

GhostX uses this isolated local module through its go.mod replace. Business retains its separate private fork. The patch suppresses synthetic ACK-of-ACK PING while congestion/pacing permits only ACK, preventing repeated renewal of PTO without old STREAM progress. The counter saturates; a later ordinary packet still carries the PING. No congestion window, loss percentage, record deadline or memory budget is increased.

server.go also releases Initial/queued 0-RTT packets and cancels admission on CID generation or registration failure. An unregistered connection closes only its own TLS/qlog resources, without waiting for an unstarted run loop or retiring another connection's IDs. Retry and refusal release discarded early-data queues. server_admission_failure_test.go covers the construction failures; Report/TKN-1105-03/quic-validation retains isolated baseline-versus-patched ownership and behavior checks. Business carries the corresponding fix in its independent private fork.

LOFT-SOURCE-SHA256SUMS covers the complete deliverable; build.sh checks it before building the embedded core. UPSTREAM-SHA256SUMS retains the original source identity, while LOFT-SOURCE-SHA256SUMS describes the complete local derivative, including the documented recovery and socket adapters. MIT license retained in LICENSE.

## Authenticated message wrappers (TKN-1127-01)

An explicitly enabled `MessagePacketConn` can carry Linux ECN metadata through
the wrapper's own `ReadMsgUDP` / `WriteMsgUDP` methods. The adapter does not obtain
a file descriptor and never enables GSO. The wrapper must apply its complete
authentication or transformation to every datagram; the socket owner configures
receive options and retains the MTU / DF policy. Missing capability, unsupported
platforms and `QUIC_GO_DISABLE_ECN=true` retain the original path.

Receive metadata uses a fixed 128-byte workspace with one reader. Invalid lengths,
truncation and malformed control messages discard only that packet and release
its buffer. Concurrent writes use private bounded OOB storage and preserve the
caller's packet-info bytes. QUIC still validates ECN and owns ACK, loss, recovery
and pacing. This extends a local wrapper contract; it does not change QUIC wire
framing or guarantee an ECN-capable network.

When QUIC requests neither ECN nor packet-info metadata, sending uses that same
wrapper's `WriteTo` method. This preserves authentication and avoids a redundant
OOB workspace on old-peer and ECN-bleached paths. Marked packets and nonempty
packet-info continue through the bounded message path.
