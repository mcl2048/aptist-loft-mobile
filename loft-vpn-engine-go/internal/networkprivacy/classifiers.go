// Bounded classifiers adapted from Loft-Gateway 231f14813f2b45cb6f0bde984181c57cba1d02fd.
// Original source paths and SHA256 are retained in SOURCE-PIN.json.
// No registry, AI policy, session tracker or physical resolver is imported.
package networkprivacy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

func isEncryptedDNSHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, name := range []string{"dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "one.one.one.one", "dns.quad9.net", "dns.adguard-dns.com", "doh.opendns.com", "dns.nextdns.io", "doh.dns.sb"} {
		if host == name || strings.HasSuffix(host, "."+name) {
			return true
		}
	}
	return false
}

func isDNSRequestHeader(p []byte) bool {
	return len(p) >= 12 && p[2]&0x80 == 0 && isDNSQuestionHeader(p)
}

func isDNSQuestionHeader(p []byte) bool {
	if len(p) < 12 || binary.BigEndian.Uint16(p[4:6]) != 1 {
		return false
	}
	switch (p[2] >> 3) & 0xf {
	case 0, 4, 5: // QUERY, NOTIFY (RFC 1996), UPDATE (RFC 2136).
		return true
	default:
		return false
	}
}

// isDNSQuery 使用有界零分配解析识别非标准端口的明文 DNS 请求。
// 仅接受单问题 QUERY/NOTIFY/UPDATE；不递归解析压缩指针，不保存数据报。
func isDNSQuery(p []byte) bool {
	return len(p) >= 17 && isDNSRequestHeader(p) && isDNSQuestion(p)
}

// IsDNSQuery is the bounded classifier used by common TUN DNS interception.
func IsDNSQuery(packet []byte) bool { return isDNSQuery(packet) }

func isDNSQuestion(p []byte) bool {
	if len(p) < 17 || !isDNSQuestionHeader(p) {
		return false
	}
	query := p[2]&0x78 == 0
	i, total := 12, 0
	for i < len(p) && total <= 255 {
		n := int(p[i])
		i++
		total++
		if n == 0 {
			return isDNSQuestionTrailer(p[i:], query)
		}
		// 压缩问题名不递归解码，只验证指针和后续问题字段；CD/AD标志不能成为旁路。
		if n&0xc0 == 0xc0 {
			if i >= len(p) {
				return false
			}
			offset := (n&0x3f)<<8 | int(p[i])
			i++
			return offset < len(p) && isDNSQuestionTrailer(p[i:], query)
		}
		if n > 63 || i+n > len(p) {
			return false
		}
		i += n
		total += n
	}
	return false
}

// IN/CH/HS/ANY 都可以向外部解析器发出有效问题，不能仅用 IN 类识别防泄露流量。
func isDNSQuestionTrailer(p []byte, query bool) bool {
	if len(p) < 4 || binary.BigEndian.Uint16(p[:2]) == 0 {
		return false
	}
	class := binary.BigEndian.Uint16(p[2:4])
	if query {
		class &= 0x7fff // RFC 6762 QU 位仅对 QUERY 问题类有意义。
	}
	switch class {
	case 1, 3, 4, 255:
		return true
	default:
		return false
	}
}

type dnsTCPProbe struct {
	header    [2 + 12 + 255 + 4]byte
	length    int
	done      bool
	detected  bool
	responses bool
}

func (p *dnsTCPProbe) feed(data []byte) {
	if p.done || len(data) == 0 {
		return
	}
	p.length += copy(p.header[p.length:], data)
	if p.length < 2 {
		return
	}
	messageLen := int(binary.BigEndian.Uint16(p.header[:2]))
	if messageLen < 17 {
		p.done = true
		return
	}
	if p.length >= 14 {
		q := p.header[2:p.length]
		if !isDNSRequestHeader(q) && (!p.responses || !isDNSQuestionHeader(q)) {
			p.done = true
			return
		}
	}
	question := p.header[2:min(p.length, messageLen+2)]
	p.detected = isDNSQuery(question) || p.responses && isDNSQuestion(question)
	p.done = p.detected || p.length == len(p.header) || p.length >= messageLen+2
}

func isWebRTCServicePort(port int) bool {
	switch port {
	case 3478, 5349, 19302: // RFC 8489/8656 默认端口 + Google 公共 STUN 的常用兼容端口。
		return true
	default:
		return false
	}
}

func isWebRTCServiceHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || net.ParseIP(strings.Trim(host, "[]")) != nil {
		return false
	}
	// TURN 服务常见 global.turn.vendor.example 形态，因此检查每个 DNS label，
	// 但只接受精确 stun/turn/turns 或数字后缀，避免 stunning.example 等普通域名误报。
	for _, label := range strings.Split(host, ".") {
		for _, prefix := range []string{"stun", "turn", "turns"} {
			if label == prefix {
				return true
			}
			if strings.HasPrefix(label, prefix) && isNumericOrHyphenSuffix(label[len(prefix):]) {
				return true
			}
		}
	}
	return false
}

func isNumericOrHyphenSuffix(s string) bool {
	if s == "" {
		return false
	}
	hasDigit := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			hasDigit = true
			continue
		}
		if r != '-' {
			return false
		}
	}
	return hasDigit
}

func classifyWebRTCDatagram(payload []byte, endpointHint, stunSeen bool) (kind, detail string) {
	if method, ok := parseSTUNMessage(payload); ok {
		return "stun", stunMethodName(method)
	}
	// DTLS 也承载企业 VPN/IoT；只有同一五元组已出现 STUN，或目标明确为 STUN/TURN 端点时，
	// 才把 ClientHello 归入 WebRTC，避免粗暴封杀所有合法 DTLS 应用。
	if (endpointHint || stunSeen) && looksLikeDTLSClientHello(payload) {
		return "dtls", "client-hello"
	}
	if (endpointHint || stunSeen) && looksLikeTURNChannelData(payload) {
		return "turn", "channel-data"
	}
	return "", ""
}

// parseSTUNMessage 按 RFC 8489 执行有界解析：固定 Cookie、4 字节对齐长度和每个属性边界
// 必须全部成立，避免仅凭 0x2112A442 四字节误杀普通 UDP。
func parseSTUNMessage(payload []byte) (uint16, bool) {
	if len(payload) < 20 || payload[0]&0xc0 != 0 ||
		payload[4] != 0x21 || payload[5] != 0x12 || payload[6] != 0xa4 || payload[7] != 0x42 {
		return 0, false
	}
	messageLen := int(payload[2])<<8 | int(payload[3])
	if messageLen%4 != 0 || messageLen > len(payload)-20 || 20+messageLen != len(payload) {
		return 0, false
	}

	for offset, end := 20, 20+messageLen; offset < end; {
		if end-offset < 4 {
			return 0, false
		}
		attributeLen := int(payload[offset+2])<<8 | int(payload[offset+3])
		paddedLen := (attributeLen + 3) &^ 3
		if attributeLen < 0 || paddedLen < attributeLen || offset+4+paddedLen > end {
			return 0, false
		}
		offset += 4 + paddedLen
	}

	messageType := uint16(payload[0])<<8 | uint16(payload[1])
	method := (messageType & 0x000f) | ((messageType & 0x00e0) >> 1) | ((messageType & 0x3e00) >> 2)
	return method, true
}

func stunMethodName(method uint16) string {
	switch method {
	case 0x001:
		return "binding"
	case 0x003:
		return "allocate"
	case 0x004:
		return "refresh"
	case 0x006:
		return "send"
	case 0x007:
		return "data"
	case 0x008:
		return "create-permission"
	case 0x009:
		return "channel-bind"
	case 0x00a:
		return "connect"
	case 0x00b:
		return "connection-bind"
	case 0x00c:
		return "connection-attempt"
	default:
		return fmt.Sprintf("method-0x%03x", method)
	}
}

// webRTCStreamProbe 仅保留 STUN 流式首部所需的 8 字节，不缓存业务正文。
// RFC 8489 在 TCP/TLS 上仍使用相同的 Message Type、Length 与 Magic Cookie；明文 TCP
// 即使被拆成多个 Read，也会在服务端收到完整请求前完成识别。TLS 加密后的随机端口内容
// 无法在未终止 TLS 的数据面解析，该边界必须由出口策略和部署文档继续约束。
type webRTCStreamProbe struct {
	header  [8]byte
	length  uint8
	decided bool
}

// feed 追加只读流片段；最多复制 8 字节到连接内固定数组，不分配堆内存。
// detected=true 表示已经确认明文 STUN 首部，done=true 表示无需再探测后续字节。
func (p *webRTCStreamProbe) feed(chunk []byte) (method uint16, detected, done bool) {
	if p == nil || p.decided {
		return 0, false, true
	}
	for _, b := range chunk {
		if p.length >= uint8(len(p.header)) {
			break
		}
		p.header[p.length] = b
		p.length++

		// STUN Message Type 的最高两位必须为 0。尽早结束普通 HTTP/二进制流探测。
		if p.length == 1 && p.header[0]&0xc0 != 0 {
			p.decided = true
			return 0, false, true
		}
		// STUN Message Length 必须按 4 字节对齐。
		if p.length == 4 {
			messageLen := int(p.header[2])<<8 | int(p.header[3])
			if messageLen%4 != 0 {
				p.decided = true
				return 0, false, true
			}
		}
	}

	if p.length < uint8(len(p.header)) {
		return 0, false, false
	}
	p.decided = true
	if p.header[0]&0xc0 != 0 ||
		p.header[4] != 0x21 || p.header[5] != 0x12 || p.header[6] != 0xa4 || p.header[7] != 0x42 {
		return 0, false, true
	}
	messageType := uint16(p.header[0])<<8 | uint16(p.header[1])
	method = (messageType & 0x000f) | ((messageType & 0x00e0) >> 1) | ((messageType & 0x3e00) >> 2)
	return method, true, true
}

func looksLikeTURNChannelData(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	channel := uint16(payload[0])<<8 | uint16(payload[1])
	if channel < 0x4000 || channel > 0x7fff {
		return false
	}
	dataLen := int(payload[2])<<8 | int(payload[3])
	if dataLen <= 0 || dataLen > len(payload)-4 {
		return false
	}
	// UDP ChannelData 通常无填充；TCP/TLS 承载允许补齐到 4 字节边界。
	total := 4 + dataLen
	padded := 4 + ((dataLen + 3) &^ 3)
	return len(payload) == total || len(payload) == padded
}

// looksLikeDTLSClientHello 只匹配 epoch=0 且握手片段边界完整的 DTLS ClientHello。
// 相比“任何 0xfe 版本记录都拦截”，该约束显著降低对普通 UDP 的误判。
func looksLikeDTLSClientHello(payload []byte) bool {
	if len(payload) < 25 || payload[0] != 22 || payload[1] != 0xfe {
		return false
	}
	if payload[2] != 0xff && payload[2] != 0xfd && payload[2] != 0xfc {
		return false
	}
	if payload[3] != 0 || payload[4] != 0 { // 首次 ClientHello 必须位于 epoch 0。
		return false
	}
	recordLen := int(payload[11])<<8 | int(payload[12])
	if recordLen < 12 || 13+recordLen > len(payload) {
		return false
	}
	handshake := payload[13 : 13+recordLen]
	if handshake[0] != 1 { // ClientHello
		return false
	}
	messageLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	fragmentOffset := int(handshake[6])<<16 | int(handshake[7])<<8 | int(handshake[8])
	fragmentLen := int(handshake[9])<<16 | int(handshake[10])<<8 | int(handshake[11])
	return messageLen > 0 && fragmentOffset == 0 && fragmentLen > 0 && fragmentLen <= messageLen && 12+fragmentLen <= len(handshake)
}
