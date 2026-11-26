package networkprivacy_test

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	privacy "net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
	"net.aptist.loft/loft-vpn-engine-go/internal/vpn"
)

type readyProxy struct {
	ready atomic.Bool
	done  chan struct{}
}

func (p *readyProxy) PrivacyReady() bool           { return p.ready.Load() }
func (p *readyProxy) PrivacyDone() <-chan struct{} { return p.done }

func activeEnforcer(t *testing.T, changes map[string]any) (*privacy.Enforcer, *readyProxy, *vpn.ByteBudget) {
	t.Helper()
	proxy := &readyProxy{done: make(chan struct{})}
	proxy.ready.Store(true)
	budget := vpn.NewBudget(8388608)
	enforcer, err := privacy.New(testPolicy(t, changes), budget, proxy)
	if err != nil {
		t.Fatal(err)
	}
	if err := enforcer.Activate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(enforcer.Revoke)
	return enforcer, proxy, budget
}

func dnsQuestion(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	domain, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 73, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: domain, Type: typ, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestSyntheticDNSAllocatesRoutesWithoutClaimingRealAnswers(t *testing.T) {
	e, _, budget := activeEnforcer(t, nil)
	query := dnsQuestion(t, "does-not-exist.invalid.", dnsmessage.TypeA)
	answer, err := e.AnswerDNS(context.Background(), query, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer answer.Close()
	var message dnsmessage.Message
	if err := message.Unpack(answer.Packet); err != nil {
		t.Fatal(err)
	}
	if !answer.Synthetic || message.ID != 73 || !message.Response || message.RCode != dnsmessage.RCodeSuccess || len(message.Answers) != 1 || message.Answers[0].Header.TTL != 60 {
		t.Fatal("synthetic routing reply changed its DNS contract")
	}
	ip := netip.AddrFrom4(message.Answers[0].Body.(*dnsmessage.AResource).A)
	flow, err := e.NewFlow("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(443)), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if flow.Target() != "does-not-exist.invalid:443" {
		t.Fatal("synthetic address was sent as a literal business destination")
	}
	flow.Close()
	e.ConfirmDNS(answer)
	facts := e.Snapshot()
	if facts.DNSSyntheticCount != 1 || facts.DNSValidatedWireCount != 0 || facts.BusinessResolverCalls != 0 {
		t.Fatal("synthetic allocation fabricated a real resolver result or physical lookup")
	}
	answer.Close()
	e.Revoke()
	if budget.Used() != 0 {
		t.Fatal("DNS retirement retained owned buffers or maps")
	}
}

func TestPendingSyntheticReplyPinsItsMappingThroughFinalIO(t *testing.T) {
	e, _, _ := activeEnforcer(t, map[string]any{"dns_map_max_entries": 1, "dns_map_max_bytes": 1024, "dns_ttl_seconds": 1})
	now := time.Now()
	first, err := e.AnswerDNS(context.Background(), dnsQuestion(t, "first.invalid.", dnsmessage.TypeA), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := e.AnswerDNS(context.Background(), dnsQuestion(t, "other.invalid.", dnsmessage.TypeA), now.Add(2*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var message dnsmessage.Message
	if message.Unpack(second.Packet) != nil || second.Synthetic || message.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("pending DNS response lost its original mapping before the write owner completed")
	}
}

func TestFinalDNSWriteLifetimeExtendsAdvertisedTTL(t *testing.T) {
	e, _, _ := activeEnforcer(t, map[string]any{"dns_ttl_seconds": 1})
	answer, err := e.AnswerDNS(context.Background(), dnsQuestion(t, "delayed.invalid.", dnsmessage.TypeA), time.Now().Add(-2*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	var message dnsmessage.Message
	if message.Unpack(answer.Packet) != nil {
		t.Fatal("synthetic response invalid")
	}
	address := netip.AddrFrom4(message.Answers[0].Body.(*dnsmessage.AResource).A)
	e.ConfirmDNS(answer)
	answer.Close()
	flow, err := e.NewFlow("tcp", net.JoinHostPort(address.String(), "443"), time.Now().Add(500*time.Millisecond))
	if err != nil {
		t.Fatal("mapping TTL started at preparation instead of its actual final write lifetime")
	}
	flow.Close()
}

func TestSyntheticDNSUnsupportedTypesAndDNSSECDoNotFabricateRecords(t *testing.T) {
	e, _, _ := activeEnforcer(t, nil)
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeTXT, dnsmessage.TypeMX, dnsmessage.TypePTR, dnsmessage.Type(65)} {
		answer, err := e.AnswerDNS(context.Background(), dnsQuestion(t, "ordinary.invalid.", typ), time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		var message dnsmessage.Message
		if message.Unpack(answer.Packet) != nil || message.RCode != dnsmessage.RCodeRefused || len(message.Answers) != 0 {
			t.Fatal("unsupported RR was manufactured")
		}
		answer.Close()
	}
	query := dnsQuestion(t, "edns.invalid.", dnsmessage.TypeA)
	var message dnsmessage.Message
	if message.Unpack(query) != nil {
		t.Fatal("fixture query invalid")
	}
	root, _ := dnsmessage.NewName(".")
	for _, flags := range []uint32{0, 0x8000} {
		message.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: root, Type: dnsmessage.TypeOPT, Class: 1232, TTL: flags}, Body: &dnsmessage.OPTResource{}}}
		wire, err := message.Pack()
		if err != nil {
			t.Fatal(err)
		}
		answer, err := e.AnswerDNS(context.Background(), wire, time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		var response dnsmessage.Message
		if response.Unpack(answer.Packet) != nil {
			t.Fatal("EDNS response invalid")
		}
		if flags == 0 && (response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 1) {
			t.Fatal("bounded EDNS0 without DO was rejected")
		}
		if flags != 0 && (response.RCode != dnsmessage.RCodeRefused || len(response.Answers) != 0) {
			t.Fatal("synthetic response claimed DNSSEC semantics")
		}
		answer.Close()
	}
}

func TestPrivacyProofLossAndCancelPreventNewDNSWork(t *testing.T) {
	e, proxy, budget := activeEnforcer(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if answer, err := e.AnswerDNS(ctx, dnsQuestion(t, "canceled.invalid.", dnsmessage.TypeA), time.Now(), nil); err == nil {
		answer.Close()
		t.Fatal("canceled query allocated an answer")
	}
	proxy.ready.Store(false)
	if e.Snapshot().EnforcementActive {
		t.Fatal("lost selected client retained its enforcement proof")
	}
	if answer, err := e.AnswerDNS(context.Background(), dnsQuestion(t, "lost.invalid.", dnsmessage.TypeA), time.Now(), nil); err == nil {
		answer.Close()
		t.Fatal("lost proof admitted a query")
	}
	e.Revoke()
	if budget.Used() != 0 {
		t.Fatal("canceled DNS created byte ownership")
	}
}
