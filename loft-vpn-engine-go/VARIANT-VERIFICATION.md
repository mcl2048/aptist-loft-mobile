# Cancellation fan-in variants · 2026-11-25

The known TCP lifecycle bug released a flow's reserved bytes after joining one of two copy workers when cancellation won the first select. The resource invariant is that the lease and handler completion remain owned until both actual I/O calls have returned. A controlled real pipe/Pro stream test held one I/O return and reproduced early lease release.

The same structure existed in the UDP relay: two workers sent to a buffered result channel, the first select could consume no result on ctx.Done, and the cleanup then consumed one result. The datagram path had no extra join protecting that branch. Both variants were reachable through ordinary policy cancellation or Stop. Severity is medium, confidence high: this was premature resource-accounting completion, with Go-managed buffers and actual sockets closed rather than a demonstrated memory corruption.

| Search | Match and triage |
| --- | --- |
| Known `case <-flow.ctx.Done()` / following result receive | Calibrated the TCP branch against the observed held-I/O failure. |
| `results := make(chan error, 2)` across owned production Go | TCP and UDP relay fan-in were the two relevant paths. |
| General context-Done selects across engine/internal/cmd | Control Drain and loss-monitor selects had no two-copy result channel; widening produced unrelated paths and stopped. |

Before the patch, the UDP shape was:

```go
select {
case <-results:
case <-flow.ctx.Done():
}
_ = conn.Close()
_ = remote.Close()
<-results
```

The fix counts whether the first select actually consumed a result, closes both directions on failure/cancellation, and receives all remaining worker completions before deferred finish returns the lease. TCP retains its graceful half-close window for late reverse bytes. Result errors trigger cancellation/close and are handled explicitly. The pending-flow timer was also checked: claim now requires a successful timer Stop before becoming a live handler, which prevents expiry cleanup racing a claimed owner. Connection pointers and map identity are captured under the owner mutex.

The original controlled TCP red/green evidence is in ignored `.verification/vpn-red-copy-join.log` and `vpn-green-copy-join.log`. Final full with_gvisor race tests passed; actual IPv4 Pro/X/SOCKS packet paths, UDP boundaries/fragmentation, SYN admission64 and deadline/late-join cases are included. Native Android/device proof remains separate.

A behavioral CI guard avoids a source-text match that would reject safe refactors:

```bash
go test -race -tags=with_gvisor -p=2 ./internal/vpn \
  -run 'TestCanceledTCPHandlerJoinsBothCopyOwnersBeforeReleasingBytes|TestAbortDeadlineRetainsOwnedCompletionUntilRealReaderJoins|TestDrainCallerDeadlineRetainsOwnedCleanupUntilRealReaderJoins|TestActualSYNFloodAdmissionAndAbortJoinPendingTCPHandshakes' \
  -count=1
```
