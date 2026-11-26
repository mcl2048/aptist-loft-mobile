//go:build with_gvisor

package vpn

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	"net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
)

type heldCloseTUN struct {
	*memoryTUN
	entered chan struct{}
	release chan struct{}
}

// The SOCKS wire reader owns a third 64 KiB allocation in addition to the two
// mobile relay buffers. Admission must reserve it before a live read can begin.
func TestSocksUDPAdmissionAccountsForItsAdditionalWireBuffer(t *testing.T) {
	address := testsupport.SocksServer(t, "synthetic-user", "synthetic-password")
	policy := &inertPolicy{}
	device := &memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}
	options := tun.Options{Name: "controlled-packet-link", Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}, MTU: 1280, DNSMode: tun.DNSModeDisabled, EXP_DisableDNSHijack: true}
	cfg := &nodeconfig.Config{Protocol: "socks5", Address: address, Username: "synthetic-user", Password: "synthetic-password"}
	created, err := startWithTun(context.Background(), device, options, cfg, policy, testWirePolicy(t, "1.1.1.1:53"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = created.stop() }() // Fallback cleanup; the test checks the stop receipt explicitly.
	accepted := 0
	for i := 0; i < 43; i++ {
		source := netip.AddrPortFrom(netip.MustParseAddr("198.18.0.1"), uint16(31000+i))
		destination := netip.MustParseAddrPort("192.0.2.1:7")
		if created.JudgeFlow(17, source, destination, nil).Action == tun.ActionAccept {
			accepted++
		}
	}
	if accepted != 39 {
		t.Fatalf("SOCKS UDP buffers exceeded the dynamic budget including guards: admitted %d instead of 39", accepted)
	}
	if created.budget.Used()+networkprivacy.DNSAllocatorBytes > 8388608 {
		t.Fatal("fixed quarantine and dynamic bytes exceeded the existing total ceiling")
	}
	if err := created.stop(); err != nil || created.budget.Used() != 0 {
		t.Fatal("SOCKS pending admission stop did not release its byte owners")
	}
}

func TestStopPublicationRevokesPrivacyBeforeOwnedTUNJoin(t *testing.T) {
	device := &heldCloseTUN{memoryTUN: &memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}, entered: make(chan struct{}), release: make(chan struct{})}
	r := runningRuntime(t, device)
	defer func() { _ = r.Close() }()
	stopping := make(chan map[string]any, 1)
	r.SetListener(func(raw string) {
		var frame map[string]any
		if json.Unmarshal([]byte(raw), &frame) == nil && frame["runtime_state"] == "stopping" {
			select {
			case stopping <- frame:
			default:
			}
		}
	})
	done := make(chan error, 1)
	go func() { done <- r.Stop() }()
	select {
	case <-device.entered:
	case <-time.After(time.Second):
		close(device.release)
		t.Fatal("Stop did not reach actual owned TUN close")
	}
	var frame map[string]any
	select {
	case frame = <-stopping:
	case <-time.After(time.Second):
		close(device.release)
		t.Fatal("captured Stop did not publish its pending receipt")
	}
	close(device.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if frame["enforcement_active"] != false || frame["dns_protection_enforced"] != false || frame["webrtc_protection_enforced"] != false || frame["ipv6_drop_active"] != false || frame["resources_released"] != false {
		t.Fatal("Stop published cached active privacy before priority cancellation/join")
	}
}

// The real pipe read has completed cancellation, but its calling I/O owner is
// still returning through the platform boundary. Both close callers are held
// so the handler first observes context cancellation before either copy result.
type heldReadCompletion struct {
	net.Conn
	readStarted  chan struct{}
	readExited   chan struct{}
	readRelease  chan struct{}
	closeCalls   chan struct{}
	closeRelease chan struct{}
	closeOnce    sync.Once
}

func (c *heldReadCompletion) Read(payload []byte) (int, error) {
	close(c.readStarted)
	n, err := c.Conn.Read(payload)
	close(c.readExited)
	<-c.readRelease
	return n, err
}

func (c *heldReadCompletion) Close() error {
	c.closeOnce.Do(func() { _ = c.Conn.Close() })
	select {
	case c.closeCalls <- struct{}{}:
	default:
	}
	<-c.closeRelease
	return nil
}

// Canceling a live handler must join both real byte-copy owners before returning
// the flow's byte lease. Consuming only one result after ctx.Done is insufficient.
func TestCanceledTCPHandlerJoinsBothCopyOwnersBeforeReleasingBytes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer testsupport.Close(t, conn)
			_, _ = io.Copy(io.Discard, conn)
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	destination := M.ParseSocksaddr(net.JoinHostPort("192.0.2.1", port))
	source := M.ParseSocksaddr("198.18.0.1:30001")
	created, _ := packetRig(t, "1.1.1.1:53")
	left, right := net.Pipe()
	defer testsupport.Close(t, right)
	conn := &heldReadCompletion{Conn: left, readStarted: make(chan struct{}), readExited: make(chan struct{}), readRelease: make(chan struct{}), closeCalls: make(chan struct{}, 8), closeRelease: make(chan struct{})}
	if verdict := created.JudgeFlow(6, source.AddrPort(), destination.AddrPort(), nil); verdict.Action != tun.ActionAccept {
		t.Fatal("real flow was not admitted")
	}
	finished := make(chan struct{})
	go func() { created.NewConnectionEx(context.Background(), conn, source, destination, nil); close(finished) }()
	select {
	case <-conn.readStarted:
	case <-time.After(time.Second):
		close(conn.closeRelease)
		close(conn.readRelease)
		t.Fatal("authenticated TCP handler did not start its real pipe reader")
	}
	created.mu.Lock()
	flow := created.flows[flowKey{6, source.AddrPort(), destination.AddrPort()}]
	created.mu.Unlock()
	flow.cancel()
	for i := 0; i < 2; i++ {
		select {
		case <-conn.closeCalls:
		case <-time.After(time.Second):
			close(conn.closeRelease)
			close(conn.readRelease)
			t.Fatal("handler and cancellation owner did not close the real connection")
		}
	}
	<-conn.readExited
	close(conn.closeRelease)
	returnedEarly := false
	select {
	case <-finished:
		returnedEarly = true
	case <-time.After(30 * time.Millisecond):
	}
	ownedBytes := created.budget.Used()
	close(conn.readRelease)
	if !returnedEarly {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("handler did not join after the held read owner returned")
		}
	}
	if returnedEarly || ownedBytes == 0 {
		t.Fatal("canceled TCP handler released its lease before both copy owners joined")
	}
	if err := created.stop(); err != nil || created.budget.Used() != 0 {
		t.Fatal("joined TCP cancellation retained owned bytes")
	}
}

// A delayed real I/O completion remains an owner after caller cancellation.
// Abort must bound the caller, retain the completion job, and let Stop join it.
func TestAbortDeadlineRetainsOwnedCompletionUntilRealReaderJoins(t *testing.T) {
	callerDeadlineRetainsOwner(t, "abort")
}

func TestDrainCallerDeadlineRetainsOwnedCleanupUntilRealReaderJoins(t *testing.T) {
	callerDeadlineRetainsOwner(t, "drain")
}

func callerDeadlineRetainsOwner(t *testing.T, operation string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer testsupport.Close(t, conn)
			_, _ = io.Copy(io.Discard, conn)
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	source := M.ParseSocksaddr("198.18.0.1:30003")
	destination := M.ParseSocksaddr(net.JoinHostPort("192.0.2.1", port))
	created, _ := packetRig(t, "1.1.1.1:53")
	r := configuredTestRuntime(t, &inertPolicy{}, "1.1.1.1:53")
	r.session, r.state, r.generation = created, "running", 1
	defer func() { _ = r.Close() }() // The test asserts both timeout and final release.
	left, right := net.Pipe()
	defer testsupport.Close(t, right)
	conn := &heldReadCompletion{Conn: left, readStarted: make(chan struct{}), readExited: make(chan struct{}), readRelease: make(chan struct{}), closeCalls: make(chan struct{}, 8), closeRelease: make(chan struct{})}
	if created.JudgeFlow(6, source.AddrPort(), destination.AddrPort(), nil).Action != tun.ActionAccept {
		t.Fatal("real byte-copy owner was not admitted")
	}
	finished := make(chan struct{})
	go func() { created.NewConnectionEx(context.Background(), conn, source, destination, nil); close(finished) }()
	select {
	case <-conn.readStarted:
	case <-time.After(time.Second):
		close(conn.closeRelease)
		close(conn.readRelease)
		t.Fatal("real authenticated handler did not start its reader")
	}
	aborted := make(chan error, 1)
	go func() {
		if operation == "drain" {
			aborted <- r.Drain(1)
		} else {
			aborted <- r.Abort()
		}
	}()
	select {
	case <-conn.closeCalls:
	case <-time.After(time.Second):
		close(conn.closeRelease)
		close(conn.readRelease)
		t.Fatal("Abort failed to cancel the real connection")
	}
	var abortErr error
	exceeded := false
	select {
	case abortErr = <-aborted:
	case <-time.After(6 * time.Second):
		exceeded = true
	}
	proof := r.Snapshot()
	close(conn.closeRelease)
	close(conn.readRelease)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("canceled copy owner did not join after its platform return")
	}
	if exceeded {
		select {
		case abortErr = <-aborted:
		case <-time.After(time.Second):
			t.Fatal("Abort did not complete after releasing its real I/O owner")
		}
	}
	if err := r.Stop(); err != nil || !r.Snapshot().ResourcesReleased {
		t.Fatal("Stop did not join and release the owned abort completion")
	}
	if exceeded || errorCode(abortErr) != "loft.vpn."+operation+"_timeout" {
		t.Fatal("lifecycle caller lacked an explicit bounded timeout")
	}
	if !proof.TunOwned || proof.ResourcesReleased || proof.ActiveFlows != 1 || proof.QueuedBytes == 0 {
		t.Fatal("timed-out Abort fabricated release of the retained I/O owner")
	}
}

// Expiry may already have fired while its cleanup callback waits for the owner
// mutex. Claim must reject that deadline, rather than race cleanup and release
// a live handler's byte lease beneath it.
func TestExpiredPendingTCPDeadlineCannotBeClaimed(t *testing.T) {
	created, _ := packetRig(t, "1.1.1.1:53")
	source := netip.MustParseAddrPort("198.18.0.1:30002")
	destination := netip.MustParseAddrPort("192.0.2.1:7")
	key := flowKey{6, source, destination}
	if verdict := created.JudgeFlow(6, source, destination, nil); verdict.Action != tun.ActionAccept {
		t.Fatal("pending flow was not admitted")
	}
	created.mu.Lock()
	flow := created.flows[key]
	flow.timer.Stop()
	// A consumed real timer has the same expired Stop result as a timer callback
	// already dispatched but waiting for the mutex, with no timing-dependent race.
	flow.timer = time.NewTimer(0)
	created.mu.Unlock()
	<-flow.timer.C
	claimed := created.claim(key)
	created.finish(flow)
	if claimed != nil {
		t.Fatal("expired pending deadline was admitted into a live handler")
	}
	if created.budget.Used() != 0 {
		t.Fatal("expired pending owner retained its byte lease")
	}
}

type failedCloseTUN struct{ *memoryTUN }

func (t *failedCloseTUN) Close() error {
	_ = t.memoryTUN.Close()
	return io.ErrUnexpectedEOF
}

type rejectingPolicy struct{ inertPolicy }

func (p *rejectingPolicy) Protect(int) error { return io.ErrClosedPipe }

// Startup failure also owns its actual TUN cleanup. A rejected platform socket
// plus a failed native close must not disappear merely because Start errored.
func TestFailedReadyRetainsUnconfirmedTUNCleanupOwner(t *testing.T) {
	policy := &rejectingPolicy{}
	r := configuredTestRuntime(t, policy, "1.1.1.1:53")
	defer func() { _ = r.Close() }() // Fallback cleanup; lifecycle success or failure is asserted explicitly.
	device := &failedCloseTUN{&memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}}
	create := func(ctx context.Context, cfg *nodeconfig.Config, address netip.Prefix, mtu int, networkPolicy networkprivacy.Policy, lost func(string)) (*session, error) {
		options := tun.Options{Name: "controlled-packet-link", Inet4Address: []netip.Prefix{address}, MTU: uint32(mtu), DNSMode: tun.DNSModeDisabled, EXP_DisableDNSHijack: true}
		return startWithTun(ctx, device, options, cfg, policy, networkPolicy, lost)
	}
	if err := r.start("socks5://127.0.0.1:1080", "198.18.0.1/30", 1280, create); err == nil || errorCode(err) != "loft.vpn.tun_close_failed" {
		t.Fatal("failed startup did not retain its unconfirmed native cleanup error")
	}
	if snapshot := r.Snapshot(); snapshot.State != "failed" || snapshot.ResourcesReleased || !snapshot.TunOwned || snapshot.TransportReady || snapshot.OwnershipPending {
		t.Fatal("joined startup failure fabricated TUN release or hid its owner")
	}
}

// The authenticated peer can die between session creation and installation.
// Its captured loss must fence Start itself; waiting for a later running-state
// callback would briefly install a dead generation as Connected.
func TestRealPeerLossBeforeStartInstallationCannotPublishRunning(t *testing.T) {
	_, raw, shutdown := routedNodeMaterial(t)
	r := configuredTestRuntime(t, &inertPolicy{}, "1.1.1.1:53")
	defer func() { _ = r.Close() }() // Fallback cleanup; lifecycle success or failure is asserted explicitly.
	device := &memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}
	lossSeen := make(chan struct{}, 1)
	create := func(ctx context.Context, cfg *nodeconfig.Config, address netip.Prefix, mtu int, networkPolicy networkprivacy.Policy, lost func(string)) (*session, error) {
		options := tun.Options{Name: "controlled-packet-link", Inet4Address: []netip.Prefix{address}, MTU: uint32(mtu), DNSMode: tun.DNSModeDisabled, EXP_DisableDNSHijack: true}
		created, err := startWithTun(ctx, device, options, cfg, r.policy, networkPolicy, func(code string) { lost(code); lossSeen <- struct{}{} })
		if err != nil {
			return created, err
		}
		shutdown()
		select {
		case <-lossSeen:
		case <-time.After(time.Second):
			t.Fatal("real peer shutdown did not deliver its captured loss")
		}
		return created, nil
	}
	if err := r.start(raw, "198.18.0.1/30", 1280, create); err == nil {
		t.Fatal("peer lost before installation was accepted as a running Start")
	}
	if snapshot := r.Snapshot(); snapshot.State != "failed" || snapshot.TransportReady || !snapshot.ResourcesReleased || snapshot.ErrorCode != "loft.vpn.protocol_connection_lost" {
		t.Fatal("startup loss was discarded or falsely published as running")
	}
}

// Native close errors must be returned and retained as unconfirmed ownership;
// a Close invocation or zero flow/socket counters are not release evidence.
func TestNativeCloseFailureCannotFabricateReleasedStop(t *testing.T) {
	device := &failedCloseTUN{&memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}}
	r := runningRuntime(t, device)
	if err := r.Stop(); err == nil || errorCode(err) != "loft.vpn.tun_close_failed" {
		t.Fatal("native close failure was ignored or exposed an unsafe error")
	}
	if snapshot := r.Snapshot(); snapshot.ResourcesReleased || !snapshot.TunOwned || snapshot.TransportReady || snapshot.State != "failed" {
		t.Fatal("native close error fabricated successful TUN/resource release")
	}
}

type heldStartResolver struct {
	inertPolicy
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (p *heldStartResolver) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	p.once.Do(func() { close(p.entered); <-p.release })
	return p.inertPolicy.Resolve(ctx, host)
}

// This factory exercises real Ready/authentication/TUN construction while only
// substituting the Android kernel descriptor boundary with a host packet link.
func TestPendingStartStopAndCloseKeepOwnershipUnconfirmedUntilReadyJoins(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		name := "Stop"
		if terminal {
			name = "Close"
		}
		t.Run(name, func(t *testing.T) {
			_, raw, _ := routedNodeMaterial(t)
			raw = strings.Replace(raw, "127.0.0.1:", "node.invalid:", 1)
			policy := &heldStartResolver{entered: make(chan struct{}), release: make(chan struct{})}
			r := configuredTestRuntime(t, policy, "1.1.1.1:53")
			defer func() { _ = r.Close() }() // Fallback cleanup; lifecycle success or failure is asserted explicitly.
			device := &memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}
			var capturedLoss func(string)
			create := func(ctx context.Context, cfg *nodeconfig.Config, address netip.Prefix, mtu int, networkPolicy networkprivacy.Policy, lost func(string)) (*session, error) {
				capturedLoss = lost
				options := tun.Options{Name: "controlled-packet-link", Inet4Address: []netip.Prefix{address}, MTU: uint32(mtu), DNSMode: tun.DNSModeDisabled, EXP_DisableDNSHijack: true}
				return startWithTun(ctx, device, options, cfg, policy, networkPolicy, lost)
			}
			startDone := make(chan error, 1)
			go func() { startDone <- r.start(raw, "198.18.0.1/30", 1280, create) }()
			select {
			case <-policy.entered:
			case <-time.After(time.Second):
				close(policy.release)
				t.Fatal("actual Ready did not reach the held platform resolver")
			}
			var pending map[string]any
			if err := json.Unmarshal([]byte(r.SnapshotJSON()), &pending); err != nil {
				close(policy.release)
				t.Fatal(err)
			}
			closeDone := make(chan error, 1)
			go func() {
				if terminal {
					closeDone <- r.Close()
				} else {
					closeDone <- r.Stop()
				}
			}()
			returnedEarly := false
			select {
			case err := <-closeDone:
				if err != nil {
					t.Errorf("unexpected early close failure: %v", err)
				}
				returnedEarly = true
			case <-time.After(30 * time.Millisecond):
			}
			stillOwned := !r.Snapshot().ResourcesReleased
			close(policy.release)
			select {
			case err := <-startDone:
				if err == nil {
					t.Fatal("canceled in-flight Start reported Connected")
				}
			case <-time.After(time.Second):
				t.Fatal("canceled Ready construction did not join")
			}
			if !returnedEarly {
				select {
				case err := <-closeDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("shutdown did not finish after Ready joined")
				}
			}
			if pending["ownership_pending"] != true || pending["resources_released"] != false {
				t.Fatal("pending construction exposed zero counters as confirmed resource facts")
			}
			if returnedEarly || !stillOwned {
				t.Fatal("shutdown fabricated release before in-flight Ready/TUN construction joined")
			}
			select {
			case <-device.done:
			default:
				t.Fatal("canceled startup retained its owned host TUN")
			}
			if snapshot := r.Snapshot(); !snapshot.ResourcesReleased || snapshot.TransportReady || snapshot.Generation != 1 {
				t.Fatal("joined canceled Start reported stale readiness or ownership")
			}
			if terminal {
				if err := r.start(raw, "198.18.0.1/30", 1280, create); err == nil {
					t.Fatal("terminal Close reopened a native construction")
				}
				return
			}
			fresh := &memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}
			createFresh := func(ctx context.Context, cfg *nodeconfig.Config, address netip.Prefix, mtu int, networkPolicy networkprivacy.Policy, lost func(string)) (*session, error) {
				options := tun.Options{Name: "controlled-packet-link", Inet4Address: []netip.Prefix{address}, MTU: uint32(mtu), DNSMode: tun.DNSModeDisabled, EXP_DisableDNSHijack: true}
				return startWithTun(ctx, fresh, options, cfg, policy, networkPolicy, lost)
			}
			if err := r.start(raw, "198.18.0.1/30", 1280, createFresh); err != nil {
				t.Fatal(err)
			}
			capturedLoss("loft.vpn.protocol_connection_lost")
			if snapshot := r.Snapshot(); snapshot.Generation != 2 || snapshot.State != "running" || !snapshot.TransportReady {
				t.Fatal("old startup loss callback was relabeled into the new generation")
			}
		})
	}
}

func (t *heldCloseTUN) Close() error {
	close(t.entered)
	<-t.release
	return t.memoryTUN.Close()
}

func runningRuntime(t *testing.T, device tun.Tun) *Runtime {
	t.Helper()
	r := configuredTestRuntime(t, &inertPolicy{}, "1.1.1.1:53")
	options := tun.Options{Name: "controlled-packet-link", Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}, MTU: 1280, DNSMode: tun.DNSModeDisabled, EXP_DisableDNSHijack: true}
	created, err := startWithTun(context.Background(), device, options, routedNode(t), r.policy, testWirePolicy(t, "1.1.1.1:53"), func(code string) { r.lost(1, code) })
	if err != nil {
		t.Fatal(err)
	}
	// The host exercises the same real session factory and runtime lifecycle;
	// Android's verified descriptor duplication is a separate boundary test.
	r.mu.Lock()
	r.session, r.state, r.generation = created, "running", 1
	r.mu.Unlock()
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// Many concurrent callers may wait for one close, but each call must not create
// another resource-completion goroutine blocked on the same actual TUN owner.
func TestConcurrentStopsShareOneOwnedCompletionWorker(t *testing.T) {
	device := &heldCloseTUN{memoryTUN: &memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}, entered: make(chan struct{}), release: make(chan struct{})}
	r := runningRuntime(t, device)
	before := runtime.NumGoroutine()
	const callers = 64
	gate := make(chan struct{})
	results := make(chan error, callers)
	var started sync.WaitGroup
	started.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			<-gate
			started.Done()
			results <- r.Stop()
		}()
	}
	close(gate)
	started.Wait()
	select {
	case <-device.entered:
	case <-time.After(time.Second):
		close(device.release)
		t.Fatal("real TUN owner did not reach close")
	}
	time.Sleep(40 * time.Millisecond)
	peak := runtime.NumGoroutine() - before
	stillOwned := r.Snapshot().TunOwned && !r.Snapshot().ResourcesReleased
	close(device.release)
	for i := 0; i < callers; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent stop waiter did not join completion")
		}
	}
	if !stillOwned {
		t.Fatal("blocked actual TUN close fabricated a release receipt")
	}
	if peak > callers+8 {
		t.Fatalf("concurrent Stop multiplied completion workers: added %d for %d callers", peak, callers)
	}
	if snapshot := r.Snapshot(); !snapshot.ResourcesReleased || snapshot.State != "stopped" {
		t.Fatal("joined stop did not publish released stopped state")
	}
}

// A deadline only bounds the caller. Actual completion must remain owned and
// reconcile later, without a second Stop call or a fabricated release receipt.
func TestStopTimeoutKeepsOwnershipAndReconcilesLateCompletion(t *testing.T) {
	device := &heldCloseTUN{memoryTUN: &memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}, entered: make(chan struct{}), release: make(chan struct{})}
	r := runningRuntime(t, device)
	result := make(chan error, 1)
	go func() { result <- r.Stop() }()
	select {
	case <-device.entered:
	case <-time.After(time.Second):
		close(device.release)
		t.Fatal("real TUN close did not begin")
	}
	select {
	case err := <-result:
		if err == nil || errorCode(err) != "loft.vpn.stop_timeout" {
			close(device.release)
			t.Fatal("blocked close failed to return the explicit bounded timeout")
		}
	case <-time.After(6 * time.Second):
		close(device.release)
		t.Fatal("stop call exceeded its bounded deadline")
	}
	snapshot := r.Snapshot()
	close(device.release)
	if !snapshot.TunOwned || snapshot.ResourcesReleased || snapshot.State != "stopping" {
		t.Fatal("timeout fabricated actual ownership release")
	}
	deadline := time.Now().Add(time.Second)
	for {
		snapshot = r.Snapshot()
		if snapshot.State == "stopped" && snapshot.ResourcesReleased {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late actual completion did not reconcile the timed-out stop")
		}
		time.Sleep(time.Millisecond)
	}
}
