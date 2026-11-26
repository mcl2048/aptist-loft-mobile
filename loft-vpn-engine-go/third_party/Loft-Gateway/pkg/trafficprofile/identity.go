// 文件路径：pkg/trafficprofile/identity.go
// 本地小模块只依赖标准库；网关与受管 GhostX 共用同一实现，不相互导入业务模块。
package trafficprofile

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
)

// Identity 只携带不可逆分桶材料与枚举，不接受任意 HTTP 首部或原始 fingerprint_seed。
// 画像在配置准备期复制，发布后只读；无需 Context、后台任务或网络锁。
type Identity struct {
	Material string `json:"material"`
	Browser  string `json:"browser"`
	Locale   string `json:"locale"`
	CPU      string `json:"cpu"`
}

// HTTPIdentity 的 UA、Client Hints 和 TLS 家族成组选择。
// 版本对应两套已锁定 uTLS 的实际 Auto 模板（Chrome 133 / Firefox 120 / Safari 16），
// 不是对“当前最新版浏览器”或完整浏览器 HTTP/2/QUIC 指纹的承诺。
type HTTPIdentity struct {
	Browser, Locale, TLSFingerprint   string
	UserAgent, Accept, AcceptLanguage string
	SecCHUA, SecCHUAPlatform, DNT     string
	UpgradeInsecure                   bool
}

var browsers = [...]string{"chrome-windows", "chrome-macos", "chrome-linux", "firefox-windows", "firefox-linux", "safari-macos"}
var locales = [...]string{"en-us", "en-gb", "zh-cn", "zh-hk", "ja-jp", "de-de", "fr-fr", "es-es"}
var languages = [...]string{"en-US,en;q=0.9", "en-GB,en;q=0.9", "zh-CN,zh;q=0.9,en;q=0.8", "zh-HK,zh;q=0.9,en-US;q=0.8", "ja-JP,ja;q=0.9,en-US;q=0.7", "de-DE,de;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8", "es-ES,es;q=0.9,en;q=0.8"}

func validChoice(value string, choices []string) bool {
	if value == "" || value == "auto" {
		return true
	}
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

// Validate 拒绝无限材料、未知枚举和控制字符，避免配置退化成任意首部注入接口。
func (i Identity) Validate() error {
	if len(i.Material) == 0 || len(i.Material) > 128 || !validChoice(i.Browser, browsers[:]) || !validChoice(i.Locale, locales[:]) ||
		!validChoice(i.CPU, []string{"generic-x86_64", "generic-arm64", "low-power-vcpu", "datacenter-vcpu"}) {
		return errors.New("traffic profile: invalid identity")
	}
	for _, ch := range i.Material {
		if ch < 33 || ch > 126 {
			return errors.New("traffic profile: invalid identity material")
		}
	}
	return nil
}

// SelectIdentity 只用 Pipeline 材料分桶，不用 inbound tag/墙上时钟选浏览器，避免同条
// Pipeline 的缓存、Hyraken 与 Xray 各自随机成不同身份。不同连接仍可有不同的时序采样。
func SelectIdentity(i Identity) HTTPIdentity {
	sum := sha256.Sum256([]byte(i.Material))
	n := binary.BigEndian.Uint64(sum[:8])
	browser := strings.ToLower(strings.TrimSpace(i.Browser))
	if browser == "" || browser == "auto" {
		browser = browsers[n%uint64(len(browsers))]
		switch i.CPU {
		case "generic-arm64", "low-power-vcpu":
			browser = []string{"safari-macos", "chrome-macos"}[n%2]
		case "datacenter-vcpu":
			browser = []string{"chrome-linux", "firefox-linux"}[n%2]
		}
	}
	locale := strings.ToLower(strings.TrimSpace(i.Locale))
	if locale == "" || locale == "auto" {
		locale = locales[(n>>32)%uint64(len(locales))]
	}
	out := HTTPIdentity{Browser: browser, Locale: locale, TLSFingerprint: "chrome", UpgradeInsecure: true,
		Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", AcceptLanguage: languages[0]}
	for idx, name := range locales {
		if locale == name {
			out.AcceptLanguage = languages[idx]
			break
		}
	}
	platform, os := `"Windows"`, "Windows NT 10.0; Win64; x64"
	if strings.HasSuffix(browser, "macos") {
		platform, os = `"macOS"`, "Macintosh; Intel Mac OS X 10_15_7"
	}
	if strings.HasSuffix(browser, "linux") {
		platform, os = `"Linux"`, "X11; Linux x86_64"
	}
	switch {
	case strings.HasPrefix(browser, "firefox-"):
		out.TLSFingerprint = "firefox"
		out.UserAgent = "Mozilla/5.0 (" + os + "; rv:120.0) Gecko/20100101 Firefox/120.0"
	case browser == "safari-macos":
		out.TLSFingerprint = "safari"
		out.UserAgent = "Mozilla/5.0 (" + os + ") AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
		out.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		// Safari 缩减语言列表以降低指纹熵；不附加用户未选择的英语偏好。
		// 依据 MDN Accept-Language 的单语言行为，保留已选地区语言本身。
		out.AcceptLanguage, _, _ = strings.Cut(out.AcceptLanguage, ",")
	default:
		out.UserAgent = "Mozilla/5.0 (" + os + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
		out.SecCHUA = `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`
		out.SecCHUAPlatform = platform
	}
	return out
}
