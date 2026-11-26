# Locked Hyraken QUIC recovery patch

Complete source of github.com/sagernet/quic-go v0.61.0-sing-box-mod.7, copied from the verified Go module cache. UPSTREAM-SHA256SUMS retains the original inventory. No imports or public APIs are renamed. packet_packer.go receives the ACK-only recovery fix; ack_only_recovery_test.go proves ACK-only packets remain non-ack-eliciting and deferred PING intent survives.

GhostX uses this isolated local module through its go.mod replace. Business retains its separate private fork. The patch suppresses synthetic ACK-of-ACK PING while congestion/pacing permits only ACK, preventing repeated renewal of PTO without old STREAM progress. The counter saturates; a later ordinary packet still carries the PING. No congestion window, loss percentage, record deadline or memory budget is increased.

server.go also releases Initial/queued 0-RTT packets and cancels admission on CID generation or registration failure. An unregistered connection closes only its own TLS/qlog resources, without waiting for an unstarted run loop or retiring another connection's IDs. Retry and refusal release discarded early-data queues. server_admission_failure_test.go covers the construction failures; Report/TKN-1105-03/quic-validation retains isolated baseline-versus-patched ownership and behavior checks. Business carries the corresponding fix in its independent private fork.

LOFT-SOURCE-SHA256SUMS covers the complete deliverable; build.sh checks it before building the embedded core. Upstream production files other than packet_packer.go and server.go remain byte-identical to UPSTREAM-SHA256SUMS. MIT license retained in LICENSE.
