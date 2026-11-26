package networkprivacy_test

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func stunRequest() []byte {
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet, 1)
	binary.BigEndian.PutUint32(packet[4:], 0x2112a442)
	return packet
}

func TestSharedBlockPolicyStopsSTUNOnArbitraryUDPPortsAndEmptyReplies(t *testing.T) {
	e, _, _ := activeEnforcer(t, map[string]any{"webrtc_policy": "block"})
	flow, err := e.NewFlow("udp", "192.0.2.1:60000", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	if err := flow.InspectUDP(stunRequest()); err == nil {
		t.Fatal("STUN escaped arbitrary-port policy")
	}
	if err := flow.InspectReply(nil); err == nil {
		t.Fatal("empty reply forgot the association's blocked RTC identity")
	}
	ordinary, err := e.NewFlow("udp", "192.0.2.1:60001", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	malformed := stunRequest()
	malformed[4] = 0
	if err := ordinary.InspectUDP(malformed); err != nil {
		t.Fatal("cookie-invalid ordinary UDP was blocked")
	}
}

func TestFragmentedTCPSTUNIsDeniedBeforeAnyProhibitedBytesLeave(t *testing.T) {
	e, _, _ := activeEnforcer(t, map[string]any{"webrtc_policy": "block"})
	flow, err := e.NewFlow("tcp", "192.0.2.1:60000", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	var output bytes.Buffer
	packet := stunRequest()
	for _, part := range [][]byte{packet[:2], packet[2:4]} {
		if _, err := flow.WriteTo(&output, part); err != nil {
			t.Fatal(err)
		}
	}
	if output.Len() != 0 {
		t.Fatal("undecided STUN prefix left the guarded flow")
	}
	if _, err := flow.WriteTo(&output, packet[4:]); err == nil || output.Len() != 0 {
		t.Fatal("recognized STUN reached the business writer")
	}
}

func TestFragmentedTCPDNSBlockRetainsQuestionUntilDecision(t *testing.T) {
	e, _, _ := activeEnforcer(t, map[string]any{"dns_leak_policy": "block"})
	flow, err := e.NewFlow("tcp", "192.0.2.1:60000", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	query := dnsQuestion(t, "ordinary.invalid.", dnsmessage.TypeA)
	wire := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(wire, uint16(len(query)))
	copy(wire[2:], query)
	var output bytes.Buffer
	denied := false
	for _, piece := range wire {
		if _, err := flow.WriteTo(&output, []byte{piece}); err != nil {
			denied = true
			break
		}
	}
	if !denied || output.Len() != 0 {
		t.Fatal("fragmented DNS query bypassed the common policy")
	}
}

func TestProxyOnlyPreservesOrdinaryTCPAndRevokesExistingFlows(t *testing.T) {
	e, _, _ := activeEnforcer(t, nil)
	flow, err := e.NewFlow("tcp", "192.0.2.1:7", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	var output bytes.Buffer
	for _, payload := range [][]byte{{5, 1, 0}, []byte("ordinary TCP")} {
		if _, err := flow.WriteTo(&output, payload); err != nil {
			t.Fatal("proxy-only policy changed ordinary byte streams")
		}
	}
	if output.Len() != 15 {
		t.Fatal("ordinary data was withheld or lost")
	}
	e.Revoke()
	before := output.Len()
	if _, err := flow.WriteTo(&output, []byte("late")); err == nil || output.Len() != before {
		t.Fatal("retired policy let bytes leave an old flow")
	}
}

func TestReplyTCPHasIndependentFragmentedSTUNAndDNSProbes(t *testing.T) {
	for _, mode := range []string{"rtc", "dns"} {
		t.Run(mode, func(t *testing.T) {
			changes := map[string]any{"webrtc_policy": "block"}
			packet := stunRequest()
			if mode == "dns" {
				changes = map[string]any{"dns_leak_policy": "block"}
				packet = dnsQuestion(t, "ordinary.invalid.", dnsmessage.TypeA)
				packet[2] |= 0x80
				wire := make([]byte, len(packet)+2)
				binary.BigEndian.PutUint16(wire, uint16(len(packet)))
				copy(wire[2:], packet)
				packet = wire
			}
			e, _, _ := activeEnforcer(t, changes)
			flow, err := e.NewFlow("tcp", "192.0.2.1:60000", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer flow.Close()
			var outgoing, replies bytes.Buffer
			if _, err := flow.WriteTo(&outgoing, []byte("GET / HTTP/1.1\r\n")); err != nil {
				t.Fatal(err)
			}
			denied := false
			for _, piece := range packet {
				if _, err := flow.WriteReplyTo(&replies, []byte{piece}); err != nil {
					denied = true
					break
				}
			}
			if !denied || replies.Len() != 0 {
				t.Fatal("opposite TCP direction reused a cleared classifier or forwarded prohibited reply prefix")
			}
		})
	}
}

func TestOrdinaryShortTCPPrefixFlushesOnActualEOF(t *testing.T) {
	e, _, _ := activeEnforcer(t, map[string]any{"dns_leak_policy": "block", "webrtc_policy": "block"})
	flow, err := e.NewFlow("tcp", "192.0.2.1:60000", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	var output bytes.Buffer
	if _, err := flow.WriteTo(&output, []byte{'z'}); err != nil {
		t.Fatal(err)
	}
	if err := flow.FinishTCP(&output, false); err != nil || output.String() != "z" {
		t.Fatal("ordinary short TCP half-close discarded admitted bytes")
	}
}
