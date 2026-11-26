package networkprivacy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type WireExchange func(context.Context, []byte) ([]byte, error)

// DNSResult owns admitted message buffers through the actual reply write.
// Synthetic identifies routing replies; ValidatedWire never describes Fake-IP.
type DNSResult struct {
	Packet                   []byte
	Synthetic, ValidatedWire bool
	owner                    *Enforcer
	flow                     *Flow
	mapping                  *MappingLease
	bytes                    int
	once                     sync.Once
	confirmed                atomic.Bool
	closed                   atomic.Bool
}

func (r *DNSResult) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.closed.Store(true)
		// Even a failed/retired writer may have accepted the packet before its
		// final receipt. Retain TTL from this last possible delivery time.
		r.mapping.HoldAdvertisementUntil(time.Now())
		clear(r.Packet)
		r.owner.budget.ReleasePacket(r.bytes)
		r.mapping.Close()
		if r.flow != nil {
			r.flow.Close()
		}
	})
}

// ConfirmDNS records a completed reply, separately from preparing an answer.
func (e *Enforcer) ConfirmDNS(answer *DNSResult) {
	if answer == nil || answer.owner != e || answer.closed.Load() || !answer.confirmed.CompareAndSwap(false, true) {
		return
	}
	answer.mapping.HoldAdvertisementUntil(time.Now())
	if !e.Current() {
		return
	}
	if answer.Synthetic {
		increment(&e.synthetic)
	}
	if answer.ValidatedWire {
		increment(&e.wire)
	}
}

func (e *Enforcer) AnswerDNS(ctx context.Context, query []byte, now time.Time, exchange WireExchange) (*DNSResult, error) {
	flow, err := e.NewDNSFlow("198.18.0.2:53", now)
	if err != nil {
		return nil, err
	}
	answer, err := flow.AnswerDNS(ctx, query, now, exchange)
	if err != nil {
		flow.Close()
		return nil, err
	}
	answer.flow = flow
	return answer, nil
}

// AnswerDNS uses the existing flow/DNS admission and only the selected owner's
// wire exchange callback. There is no physical DNS fallback or new wire verb.
func (f *Flow) AnswerDNS(ctx context.Context, query []byte, now time.Time, exchange WireExchange) (*DNSResult, error) {
	e := f.owner
	if ctx == nil || ctx.Err() != nil || !f.Current() {
		return nil, errors.New("loft.vpn.privacy_not_active")
	}
	if len(query) < 2 || len(query) > e.policy.DNSMaxQueryBytes {
		increment(&e.dnsDrops)
		return nil, errors.New("loft.vpn.dns_query_limit")
	}
	bytes := 2*len(query) + 2048
	if e.policy.DNSMode == "wire_tcp" {
		bytes += 2 * e.policy.DNSMaxResponseBytes
	} else {
		bytes += 1024
	}
	if !e.budget.ReservePacket(bytes) {
		return nil, errors.New("loft.vpn.byte_limit")
	}
	result := &DNSResult{owner: e, bytes: bytes}
	owned := true
	defer func() {
		if owned {
			clear(result.Packet)
			result.mapping.HoldAdvertisementUntil(time.Now())
			result.mapping.Close()
			e.budget.ReleasePacket(bytes)
		}
	}()
	message, parseErr := parseDNSQuery(query)
	if parseErr != nil {
		increment(&e.dnsDrops)
		result.Packet = dnsFailure(query, dnsmessage.RCodeFormatError)
	} else if e.policy.DNSLeakPolicy == "block" {
		increment(&e.dnsDrops)
		result.Packet, _ = dnsReply(message, dnsmessage.RCodeRefused, nil)
	} else if e.policy.DNSMode == "node_domain_fake_ip" {
		question := message.Questions[0]
		dnssec := false
		for _, additional := range message.Additionals {
			dnssec = dnssec || additional.Header.TTL&0x8000 != 0
		}
		name := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))
		if question.Class != dnsmessage.ClassINET || dnssec || !canonicalDomain(name) || question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA {
			increment(&e.dnsDrops)
			result.Packet, _ = dnsReply(message, dnsmessage.RCodeRefused, nil)
		} else if question.Type == dnsmessage.TypeAAAA {
			// An explicitly disabled synthetic family has no address. This is not
			// an authoritative negative AAAA lookup or a real resolver receipt.
			result.Packet, _ = dnsReply(message, dnsmessage.RCodeSuccess, nil)
			result.Synthetic = true
		} else {
			lease, err := e.mapping.ResolveLease(name, now)
			if err != nil {
				increment(&e.dnsDrops)
				result.Packet, _ = dnsReply(message, dnsmessage.RCodeServerFailure, nil)
			} else {
				result.mapping = lease
				address := lease.Address()
				record := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: uint32(e.policy.DNSTTLSeconds)}, Body: &dnsmessage.AResource{A: address.As4()}}
				result.Packet, _ = dnsReply(message, dnsmessage.RCodeSuccess, []dnsmessage.Resource{record})
				result.Synthetic = true
			}
		}
	} else {
		if exchange == nil {
			return nil, errors.New("loft.vpn.dns_wire_unavailable")
		}
		packet, err := exchange(ctx, query)
		if err != nil {
			return nil, err
		}
		if len(packet) > e.policy.DNSMaxResponseBytes || validateDNSResponse(query, packet) != nil {
			clear(packet)
			return nil, errors.New("loft.vpn.dns_invalid_response")
		}
		result.Packet = packet
		result.ValidatedWire = true
	}
	if ctx.Err() != nil || !f.Current() {
		clear(result.Packet)
		return nil, errors.New("loft.vpn.privacy_not_active")
	}
	if len(result.Packet) == 0 || len(result.Packet) > e.policy.DNSMaxResponseBytes {
		clear(result.Packet)
		return nil, errors.New("loft.vpn.dns_response_limit")
	}
	owned = false
	return result, nil
}

func dnsFailure(query []byte, code dnsmessage.RCode) []byte {
	id := uint16(0)
	if len(query) >= 2 {
		id = binary.BigEndian.Uint16(query)
	}
	packet, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: id, Response: true, RCode: code}}).Pack()
	return packet
}

func dnsReply(query dnsmessage.Message, code dnsmessage.RCode, answers []dnsmessage.Resource) ([]byte, error) {
	return (&dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true, RCode: code}, Questions: query.Questions, Answers: answers}).Pack()
}

func parseDNSQuery(packet []byte) (dnsmessage.Message, error) {
	if len(packet) < 12 || packet[2]&0xf8 != 0 || binary.BigEndian.Uint16(packet[4:6]) != 1 || binary.BigEndian.Uint16(packet[6:8]) != 0 || binary.BigEndian.Uint16(packet[8:10]) != 0 || binary.BigEndian.Uint16(packet[10:12]) > 1 {
		return dnsmessage.Message{}, io.ErrUnexpectedEOF
	}
	if validateDNSLayout(packet, true) != nil {
		return dnsmessage.Message{}, io.ErrUnexpectedEOF
	}
	var message dnsmessage.Message
	if message.Unpack(packet) != nil || len(message.Questions) != 1 {
		return dnsmessage.Message{}, io.ErrUnexpectedEOF
	}
	return message, nil
}

// validateDNSLayout bounds structure and allocation-driving fields before the
// mature dnsmessage codec decodes names/options. No declared count allocates.
func validateDNSLayout(packet []byte, query bool) error {
	if len(packet) < 12 {
		return io.ErrUnexpectedEOF
	}
	counts := [4]int{}
	for i := range counts {
		counts[i] = int(binary.BigEndian.Uint16(packet[4+2*i:]))
	}
	if counts[0] != 1 || counts[1]+counts[2]+counts[3] > 128 {
		return io.ErrUnexpectedEOF
	}
	position := 12
	var err error
	position, err = wireNameEnd(packet, position)
	if err != nil || position+4 > len(packet) {
		return io.ErrUnexpectedEOF
	}
	position += 4
	cnameCount := 0
	for section := 1; section < 4; section++ {
		for record := 0; record < counts[section]; record++ {
			nameStart := position
			position, err = wireNameEnd(packet, position)
			if err != nil || position+10 > len(packet) {
				return io.ErrUnexpectedEOF
			}
			typ := dnsmessage.Type(binary.BigEndian.Uint16(packet[position:]))
			ttl := binary.BigEndian.Uint32(packet[position+4:])
			size := int(binary.BigEndian.Uint16(packet[position+8:]))
			position += 10
			end := position + size
			if end > len(packet) {
				return io.ErrUnexpectedEOF
			}
			if query && (section != 3 || typ != dnsmessage.TypeOPT || packet[nameStart] != 0 || ttl&0xffff7fff != 0 || size > 1024) {
				return io.ErrUnexpectedEOF
			}
			switch typ {
			case dnsmessage.TypeA:
				if size != 4 {
					return io.ErrUnexpectedEOF
				}
			case dnsmessage.TypeAAAA:
				if size != 16 {
					return io.ErrUnexpectedEOF
				}
			case dnsmessage.TypeCNAME, dnsmessage.TypeNS, dnsmessage.TypePTR:
				last, err := wireNameEnd(packet, position)
				if err != nil || last != end {
					return io.ErrUnexpectedEOF
				}
				if typ == dnsmessage.TypeCNAME {
					cnameCount++
					if cnameCount > 8 {
						return io.ErrUnexpectedEOF
					}
				}
			case dnsmessage.TypeMX, dnsmessage.TypeSRV:
				offset := 2
				if typ == dnsmessage.TypeSRV {
					offset = 6
				}
				if position+offset > end {
					return io.ErrUnexpectedEOF
				}
				last, err := wireNameEnd(packet, position+offset)
				if err != nil || last != end {
					return io.ErrUnexpectedEOF
				}
			case dnsmessage.TypeTXT:
				pieces := 0
				for cursor := position; cursor < end; {
					pieces++
					if pieces > 128 || cursor+1+int(packet[cursor]) > end {
						return io.ErrUnexpectedEOF
					}
					cursor += 1 + int(packet[cursor])
				}
			case dnsmessage.TypeOPT:
				options := 0
				for cursor := position; cursor < end; {
					options++
					if options > 16 || cursor+4 > end {
						return io.ErrUnexpectedEOF
					}
					length := int(binary.BigEndian.Uint16(packet[cursor+2:]))
					cursor += 4 + length
					if cursor > end {
						return io.ErrUnexpectedEOF
					}
				}
			}
			position = end
		}
	}
	if position != len(packet) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// wireNameEnd follows at most eight compression hops with a fixed cycle set.
func wireNameEnd(packet []byte, start int) (int, error) {
	position, next, total, hops := start, -1, 0, 0
	var visited [8]int
	for position < len(packet) && total <= 255 {
		length := int(packet[position])
		position++
		if length == 0 {
			if next < 0 {
				next = position
			}
			return next, nil
		}
		if length&0xc0 == 0xc0 {
			if position >= len(packet) || hops == len(visited) {
				return 0, io.ErrUnexpectedEOF
			}
			offset := (length&0x3f)<<8 | int(packet[position])
			position++
			if next < 0 {
				next = position
			}
			for i := 0; i < hops; i++ {
				if visited[i] == offset {
					return 0, io.ErrUnexpectedEOF
				}
			}
			visited[hops] = offset
			hops++
			position = offset
			continue
		}
		if length > 63 || position+length > len(packet) {
			return 0, io.ErrUnexpectedEOF
		}
		position += length
		total += length + 1
	}
	return 0, io.ErrUnexpectedEOF
}

func validateDNSResponse(query, response []byte) error {
	if validateDNSLayout(response, false) != nil {
		return io.ErrUnexpectedEOF
	}
	var requested, answered dnsmessage.Parser
	requestHeader, err := requested.Start(query)
	if err != nil {
		return err
	}
	responseHeader, err := answered.Start(response)
	if err != nil || responseHeader.ID != requestHeader.ID || !responseHeader.Response || responseHeader.OpCode != requestHeader.OpCode {
		return io.ErrUnexpectedEOF
	}
	question, err := requested.Question()
	if err != nil {
		return err
	}
	result, err := answered.Question()
	if err != nil || result.Type != question.Type || result.Class != question.Class || !strings.EqualFold(result.Name.String(), question.Name.String()) {
		return io.ErrUnexpectedEOF
	}
	// Layout validation already walked every bounded resource/name/option without
	// collecting answer slices. The original wire bytes and TTL/rcode are retained.
	return nil
}
