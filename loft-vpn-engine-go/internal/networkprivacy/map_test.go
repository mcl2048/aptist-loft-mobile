package networkprivacy_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	privacy "net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
	"net.aptist.loft/loft-vpn-engine-go/internal/vpn"
)

func TestStableDomainTTLUpdatesDoNotConsumeAddressPool(t *testing.T) {
	if os.Getenv("LOFT_PRIVACY_TTL_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStableDomainTTLUpdatesDoNotConsumeAddressPool$")
		command.Env = append(os.Environ(), "LOFT_PRIVACY_TTL_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("stable working set lost mappings or exhausted addresses: %s", output)
		}
		return
	}
	policy := testPolicy(t, map[string]any{"dns_ttl_seconds": 1})
	budget := vpn.NewBudget(262144)
	mapping := privacy.NewMap(policy, budget)
	defer mapping.Close()
	addresses := make(map[string]netip.Addr, 256)
	start := time.Now()
	for i := 0; i < 70000; i++ {
		name := fmt.Sprintf("name-%d.invalid", i%256)
		address, err := mapping.Resolve(name, start.Add(time.Duration(i/256)*2*time.Second))
		if err != nil {
			t.Fatalf("TTL renewal consumed pool at lookup %d: %v", i, err)
		}
		if prior, ok := addresses[name]; ok && prior != address {
			t.Fatalf("stable name changed address at renewal %d", i)
		}
		addresses[name] = address
	}
	if entries, bytes := mapping.Usage(); entries != 256 || bytes != 262144 {
		t.Fatal("stable cache exceeded its finite entry/byte budget")
	}
}

func TestPoolExhaustionRecoversPassivelyAfterTTLAndFinalLease(t *testing.T) {
	if os.Getenv("LOFT_PRIVACY_POOL_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPoolExhaustionRecoversPassivelyAfterTTLAndFinalLease$")
		command.Env = append(os.Environ(), "LOFT_PRIVACY_POOL_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("bounded pool failed TTL/lease quarantine or recovery: %s", output)
		}
		return
	}
	policy := testPolicy(t, map[string]any{"dns_map_max_entries": 1, "dns_map_max_bytes": 1024, "dns_ttl_seconds": 1})
	budget := vpn.NewBudget(2048)
	now := time.Now()
	first := privacy.NewMap(policy, budget)
	address, err := first.Resolve("renewed.invalid", now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := first.Borrow(address, now)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := first.Resolve("renewed.invalid", now.Add(750*time.Millisecond)); err != nil || again != address {
		t.Fatal("renewal changed a live alias")
	}
	first.Close()
	fillOthers := func(at time.Time, phase string) {
		t.Helper()
		for i := 0; i < 65533; i++ {
			mapping := privacy.NewMap(policy, budget)
			ip, err := mapping.Resolve(fmt.Sprintf("%s-%d.invalid", phase, i), at)
			if err != nil || ip == address {
				t.Fatalf("pool redirected a TTL/live alias in phase %s at %d: %v", phase, i, err)
			}
			mapping.Close()
		}
	}
	assertFull := func(at time.Time) {
		t.Helper()
		mapping := privacy.NewMap(policy, budget)
		if _, err := mapping.Resolve("overload.invalid", at); err == nil || err.Error() != "loft.vpn.dns_address_exhausted" {
			t.Fatal("full pool did not return a typed temporary overload")
		}
		mapping.Close()
		if budget.Used() > 1024 {
			t.Fatal("rejected pool allocation retained dynamic bytes")
		}
	}
	fillOthers(now, "initial")
	assertFull(now.Add(500 * time.Millisecond))
	fillOthers(now.Add(1500*time.Millisecond), "expired")
	lease.Close()
	assertFull(now.Add(1500 * time.Millisecond))
	recovered := privacy.NewMap(policy, budget)
	ip, err := recovered.Resolve("current.invalid", now.Add(1800*time.Millisecond))
	if err != nil || ip != address {
		t.Fatal("expiry did not passively recover the refreshed slot")
	}
	lease, err = recovered.Borrow(ip, now.Add(1800*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	recovered.Close()
	fillOthers(now.Add(3*time.Second), "held-past-ttl")
	assertFull(now.Add(3 * time.Second))
	lease.Close()
	final := privacy.NewMap(policy, budget)
	ip, err = final.Resolve("final.invalid", now.Add(3*time.Second))
	if err != nil || ip != address {
		t.Fatal("final lease did not passively recover its expired slot")
	}
	final.Close()
	if budget.Used() != 0 {
		t.Fatal("completed maps/leases retained dynamic resources")
	}
}

func TestMapPinsLiveAndAdvertisedTTLWithoutReassigningAddresses(t *testing.T) {
	policy := testPolicy(t, map[string]any{"dns_map_max_entries": 1, "dns_map_max_bytes": 1024, "dns_ttl_seconds": 1})
	budget := vpn.NewBudget(8192)
	mapping := privacy.NewMap(policy, budget)
	now := time.Now()
	ip, err := mapping.Resolve("first.invalid", now)
	if err != nil || !privacy.FakePrefix().Contains(ip) || ip == netip.MustParseAddr("198.18.0.2") {
		t.Fatal("mapping did not allocate from separate pool")
	}
	lease, err := mapping.Borrow(ip, now)
	if err != nil || lease.Host() != "first.invalid" {
		t.Fatal("mapping lease lost domain")
	}
	if _, err := mapping.Resolve("other.invalid", now.Add(2*time.Second)); err == nil {
		t.Fatal("active mapping was evicted after TTL")
	}
	lease.Close()
	other, err := mapping.Resolve("other.invalid", now.Add(2*time.Second))
	if err != nil || other == ip {
		t.Fatal("retired synthetic address was reassigned")
	}
	if _, err := mapping.Borrow(ip, now.Add(2*time.Second)); err == nil {
		t.Fatal("retired mapping was reused")
	}
	mapping.Close()
	if budget.Used() != 0 {
		t.Fatal("closed mapping retained byte charge")
	}
}

func TestMapRetirementKeepsBorrowedBytesOwnedUntilFinalClose(t *testing.T) {
	policy := testPolicy(t, map[string]any{"dns_map_max_entries": 1, "dns_map_max_bytes": 1024})
	budget := vpn.NewBudget(1024)
	mapping := privacy.NewMap(policy, budget)
	now := time.Now()
	ip, err := mapping.Resolve("live.invalid", now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := mapping.Borrow(ip, now)
	if err != nil {
		t.Fatal(err)
	}
	mapping.Close()
	if budget.Used() != 1024 {
		t.Fatal("retirement disposed an active mapping owner")
	}
	if _, err := mapping.Borrow(ip, now); err == nil {
		t.Fatal("closed policy admitted an old mapping")
	}
	lease.Close()
	lease.Close()
	if budget.Used() != 0 {
		t.Fatal("mapping final lease failed to release exactly once")
	}
}

func TestMapAdmissionRejectsBeforeAllocationWhenSharedBytesAreExhausted(t *testing.T) {
	policy := testPolicy(t, nil)
	budget := vpn.NewBudget(1023)
	mapping := privacy.NewMap(policy, budget)
	if _, err := mapping.Resolve("denied.invalid", time.Now()); err == nil || budget.Used() != 0 {
		t.Fatal("map exceeded shared byte admission")
	}
	entries, bytes := mapping.Usage()
	if entries != 0 || bytes != 0 {
		t.Fatal("rejected allocation created mapping state")
	}
	mapping.Close()
}

func TestLateCapturedRenewalCannotShortenFinalAdvertisementDeadline(t *testing.T) {
	policy := testPolicy(t, map[string]any{"dns_map_max_entries": 1, "dns_map_max_bytes": 1024, "dns_ttl_seconds": 1})
	budget := vpn.NewBudget(1024)
	mapping := privacy.NewMap(policy, budget)
	defer mapping.Close()
	now := time.Now()
	address, err := mapping.Resolve("first.invalid", now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := mapping.Borrow(address, now)
	if err != nil {
		t.Fatal(err)
	}
	lease.HoldAdvertisementUntil(now.Add(500 * time.Millisecond))
	lease.Close()
	if _, err := mapping.Resolve("first.invalid", now.Add(100*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := mapping.Resolve("other.invalid", now.Add(1200*time.Millisecond)); err == nil {
		t.Fatal("late captured renewal shortened a still-valid final-write TTL")
	}
}

func TestAtomicResolveLeasePinsOriginalDomainBeforeConcurrentPressure(t *testing.T) {
	policy := testPolicy(t, map[string]any{"dns_map_max_entries": 1, "dns_map_max_bytes": 1024, "dns_ttl_seconds": 1})
	budget := vpn.NewBudget(1024)
	mapping := privacy.NewMap(policy, budget)
	defer mapping.Close()
	now := time.Now()
	lease, err := mapping.ResolveLease("first.invalid", now)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if lease.Host() != "first.invalid" || !privacy.FakePrefix().Contains(lease.Address()) {
		t.Fatal("atomic resolver leased another domain or an invalid pool address")
	}
	if _, err := mapping.Resolve("other.invalid", now.Add(2*time.Second)); err == nil {
		t.Fatal("pressure reassigned the address before the original resolve/lease completed")
	}
}

func TestConcurrentRetirementAndAdvertisementKeepEveryBorrowOwned(t *testing.T) {
	policy := testPolicy(t, map[string]any{"dns_map_max_entries": 1, "dns_map_max_bytes": 1024})
	budget := vpn.NewBudget(1024)
	mapping := privacy.NewMap(policy, budget)
	now := time.Now()
	address, err := mapping.Resolve("shared.invalid", now)
	if err != nil {
		t.Fatal(err)
	}
	var entered, joined sync.WaitGroup
	entered.Add(8)
	joined.Add(8)
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer joined.Done()
			lease, err := mapping.Borrow(address, now)
			if err != nil {
				entered.Done()
				t.Error(err)
				return
			}
			defer lease.Close()
			entered.Done()
			<-start
			for j := 0; j < 1000; j++ {
				lease.HoldAdvertisementUntil(now.Add(time.Duration(j) * time.Millisecond))
				if lease.Host() != "shared.invalid" {
					t.Error("retirement disposed another live borrow")
					return
				}
				if _, err := mapping.Borrow(address, now); err == nil {
					t.Error("retirement allowed a new borrow")
					return
				}
			}
		}()
	}
	entered.Wait()
	mapping.Close()
	if budget.Used() != 1024 {
		t.Fatal("map released borrowed bytes before concurrent owners joined")
	}
	close(start)
	joined.Wait()
	if budget.Used() != 0 {
		t.Fatal("final concurrent borrow retained dynamic bytes")
	}
}
