// 文件路径：pkg/trafficprofile/timing.go
package trafficprofile

import (
	"errors"
	"strings"
	"time"
)

// Timing 使用预设流量节奏与在线包长观察，未加载训练模型，不宣称复制某应用流量。
// 延迟每次至多 2ms、令牌容量 4ms、补充速率 10ms/s；填充容量 512B、速率 512B/s。
// 额外等待另限初始 4 次、每秒 32 次，避免耗尽延迟预算后产生大量纳秒级 timer。
// 调用方只能在真实业务写入后采样；不生成空闲流量、不直接控制 TCP/QUIC 拥塞窗口。
type Timing struct {
	Enabled    bool   `json:"enabled"`
	Imprint    string `json:"imprint,omitempty"`
	MaxDelayUS int    `json:"max_delay_us,omitempty"`
	Padding    bool   `json:"padding,omitempty"`
}

// Profile 是受管进程之间的版本化只读配置；不扩展 Hyraken 的线上认证协议。
type Profile struct {
	Version    int         `json:"version"`
	Identity   *Identity   `json:"identity,omitempty"`
	Timing     *Timing     `json:"timing,omitempty"`
	TCPSlicing *TCPSlicing `json:"tcp_slicing,omitempty"`
}

// NormalizeImprint 兼容历史视频档名称；未知枚举交由控制面/核心显式拒绝。
func NormalizeImprint(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return "auto", true
	case "gaming":
		return "gaming", true
	case "wechat_voice":
		return "wechat_voice", true
	case "streaming", "video_streaming":
		return "streaming", true
	case "web_browsing":
		return "web_browsing", true
	default:
		return "", false
	}
}

// Normalize 复制包括内部指针在内的完整配置；未知版本/枚举报错，防跨进程静默失效。
func Normalize(p *Profile) (*Profile, error) {
	if p == nil {
		return nil, nil
	}
	if p.Version != 1 {
		return nil, errors.New("traffic profile: unsupported version")
	}
	out := *p
	if p.TCPSlicing != nil {
		slicing := normalizeTCPSlicing(*p.TCPSlicing)
		out.TCPSlicing = &slicing
	}
	if p.Identity != nil {
		identity := *p.Identity
		if err := identity.Validate(); err != nil {
			return nil, err
		}
		out.Identity = &identity
	}
	if p.Timing != nil {
		timing := *p.Timing
		var valid bool
		timing.Imprint, valid = NormalizeImprint(timing.Imprint)
		if !valid || timing.MaxDelayUS < 0 || timing.MaxDelayUS > 2000 {
			return nil, errors.New("traffic profile: invalid timing limits")
		}
		out.Timing = &timing
	}
	return &out, nil
}

// Decision 只描述一次业务发送后的计划开销；Padding 为填充载荷字节数（不含记录头）。
type Decision struct {
	Delay   time.Duration
	Padding int
}

// Sampler 固定大小、零后台任务。不能按值跨协程复制；Hyraken 用 Stream.mu，
// Chameleon 用 rngMu 串行调用 Next。伪随机数仅供调度，绝不用于密钥/nonce。
type Sampler struct {
	config      Timing
	state       uint64
	last        time.Time
	delayTokens time.Duration
	pauseTokens time.Duration // 每次等待消耗 1/32 秒；容量对应最多 4 次突发等待。
	padTokens   time.Duration // 以“1 字节对应 1/512 秒”记账，保留不足一字节的余量。
	remaining   int
	average     int
}

// NewSampler 构造连接独占状态。调用方传入随机调度种子，并负责持锁、取消和期限。
func NewSampler(config Timing, seed uint64) Sampler {
	config.Imprint, _ = NormalizeImprint(config.Imprint)
	config.MaxDelayUS = min(max(config.MaxDelayUS, 0), 2000)
	return Sampler{config: config, state: seed, delayTokens: 4 * time.Millisecond, pauseTokens: time.Second / 8, padTokens: time.Second}
}

func (s *Sampler) random() uint64 {
	s.state += 0x9e3779b97f4a7c15
	z := s.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// Next 模拟小突发后短暂停顿。bulk/发送积压立即抑制额外等待和填充；没有全局时段
// 切换，也不会把多条连接同步到同一个固定节拍。返回值由调用方用可取消定时器执行。
func (s *Sampler) Next(now time.Time, size int, backlogged bool) Decision {
	if !s.config.Enabled || size <= 0 {
		return Decision{}
	}
	if !s.last.IsZero() {
		elapsed := min(max(now.Sub(s.last), 0), time.Second)
		s.delayTokens = min(4*time.Millisecond, s.delayTokens+elapsed/100)
		s.pauseTokens = min(time.Second/8, s.pauseTokens+elapsed)
		s.padTokens = min(time.Second, s.padTokens+elapsed)
	}
	s.last = now
	s.average = (7*s.average + min(size, 1<<20)) / 8
	if backlogged || size >= 8192 || s.average >= 4096 {
		return Decision{}
	}
	if s.remaining > 0 {
		s.remaining--
		return Decision{}
	}
	mode := s.config.Imprint
	if mode == "auto" || mode == "" {
		switch {
		case s.average >= 1024:
			mode = "streaming"
		case s.average < 192:
			mode = "gaming"
		default:
			mode = "web_browsing"
		}
	}
	burst, spread, capUS := 2, 5, 2000
	switch mode {
	case "gaming":
		burst, spread, capUS = 4, 9, 250
	case "wechat_voice":
		burst, spread, capUS = 3, 6, 500
	case "streaming":
		burst, spread, capUS = 8, 9, 250
	}
	s.remaining = burst + int(s.random()%uint64(spread))
	capUS = min(capUS, s.config.MaxDelayUS)
	out := Decision{}
	if capUS > 0 {
		// 右偏短延迟分布；不是逐包均匀加噪，长延迟也受总令牌上限约束。
		x := s.random()%1024 + 1
		wanted := time.Duration(1+uint64(capUS-1)*x*x/(1024*1024)) * time.Microsecond
		// 不把不足的余额拆成微小等待；操作系统调度成本与请求的纳秒数不成比例。
		if wanted <= s.delayTokens && s.pauseTokens >= time.Second/32 {
			out.Delay = wanted
			s.delayTokens -= wanted
			s.pauseTokens -= time.Second / 32
		}
	}
	if s.config.Padding && size < 1024 {
		n := 64 + int(s.random()%192)
		cost := time.Duration(n) * time.Second / 512
		if cost <= s.padTokens {
			out.Padding = n
			s.padTokens -= cost
		}
	}
	return out
}
