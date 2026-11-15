// Package dnsprobe 选出一个“引导 DNS”：sing-box 解析节点域名、直连域名和 DoH 服务器都靠它。
//
// 背景：有的网关拦截所有发往公网的 UDP 53（只有路由器自己能答），有的用户把系统 DNS
// 手工写死成同样不通的地址。只用一个写死的 UDP 223.5.5.5:53 时 sbtun 在这些网络里完全不能用。
// 这里按优先级探测几种国内公共 DNS（UDP / DoH / DoT，全部用 IP，不需要先解析任何域名）
// 和系统配置的 DNS，选能答的、优先级最高的一个。
package dnsprobe

import (
	"fmt"
	"net/netip"
	"strings"
)

// 服务器类型，取值和 sing-box 的 DNS server type 一致。
const (
	TypeUDP   = "udp"
	TypeHTTPS = "https"
	TypeTLS   = "tls"
)

// Server 是一个只用 IP 就能访问的 DNS 服务器。
type Server struct {
	Type       string `json:"type"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Path       string `json:"path,omitempty"`        // 只用于 https
	ServerName string `json:"server_name,omitempty"` // https / tls 的证书名
	// System 表示来自系统网络设置（而不是内置的公共 DNS）。
	System bool `json:"system,omitempty"`
}

// Addr 返回服务器 IP；Address 不是合法 IP 时返回无效地址。
func (s Server) Addr() netip.Addr {
	addr, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(s.Address), "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap().WithZone("")
}

// Validate 检查服务器能否原样写进 sing-box 配置：类型认识、地址是 IP、端口合法，
// 加密类型必须带证书名，DoH 必须带路径。
func (s Server) Validate() error {
	switch s.Type {
	case TypeUDP, TypeHTTPS, TypeTLS:
	default:
		return fmt.Errorf("不支持的 DNS 类型: %q", s.Type)
	}
	if !s.Addr().IsValid() {
		return fmt.Errorf("DNS 地址不是 IP: %q", s.Address)
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("DNS 端口无效: %d", s.Port)
	}
	if s.Type != TypeUDP && strings.TrimSpace(s.ServerName) == "" {
		return fmt.Errorf("%s DNS 缺少证书名", s.Type)
	}
	if s.Type == TypeHTTPS && !strings.HasPrefix(s.Path, "/") {
		return fmt.Errorf("DoH 路径无效: %q", s.Path)
	}
	return nil
}

// String 给日志和界面看。
func (s Server) String() string {
	host := s.Addr().String()
	if s.Addr().Is6() {
		host = "[" + host + "]"
	}
	switch s.Type {
	case TypeHTTPS:
		return fmt.Sprintf("DoH https://%s:%d%s (%s)", host, s.Port, s.Path, s.ServerName)
	case TypeTLS:
		return fmt.Sprintf("DoT %s:%d (%s)", host, s.Port, s.ServerName)
	default:
		label := "UDP"
		if s.System {
			label = "系统 DNS UDP"
		}
		return fmt.Sprintf("%s %s:%d", label, host, s.Port)
	}
}

// UDP 生成一个普通 DNS 服务器。
func UDP(ip string) Server { return Server{Type: TypeUDP, Address: ip, Port: 53} }

// DoH 生成一个用 IP 访问的 DoH 服务器。
func DoH(ip, serverName string) Server {
	return Server{Type: TypeHTTPS, Address: ip, Port: 443, Path: "/dns-query", ServerName: serverName}
}

// DoT 生成一个用 IP 访问的 DoT 服务器。
func DoT(ip, serverName string) Server {
	return Server{Type: TypeTLS, Address: ip, Port: 853, ServerName: serverName}
}

// BuiltinCandidates 是内置候选，按优先级排列：UDP 最快，DoH 走 TCP 443，
// 在拦截 UDP 53 的网络里通常仍然能用。
func BuiltinCandidates() []Server {
	return []Server{
		UDP("223.5.5.5"),
		UDP("119.29.29.29"),
		DoH("223.5.5.5", "dns.alidns.com"),
		DoH("1.12.12.12", "doh.pub"),
		DoT("223.5.5.5", "dns.alidns.com"),
	}
}

// Fallback 是什么都探测不到、也没有保存过结果时的选择：TCP 443 比 UDP 53 更容易通。
func Fallback() Server { return DoH("223.5.5.5", "dns.alidns.com") }

// excludedPrefixes 是不能当作“系统 DNS”的地址：sbtun 自己的 TUN 网段（sing-box 在 x.x.0.2 上应答，
// 上次异常退出后 macOS 的系统 DNS 可能还指着它），以及其他代理客户端常用的 fake-ip 网段。
var excludedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for second := 18; second <= 31; second++ {
		out = append(out, netip.MustParsePrefix(fmt.Sprintf("172.%d.0.0/30", second)))
	}
	return append(out,
		netip.MustParsePrefix("fdfe:dcba:9876::/48"),
		netip.MustParsePrefix("198.18.0.0/15"),
	)
}()

// usableSystemDNS 报告系统 DNS 地址能不能拿来当候选：排除回环（127.0.0.53 之类的本机转发器
// 在 TUN 运行时会被劫持，而且 sing-box 自己也可能在本机监听）、链路本地、未指定地址和 TUN 网段。
func usableSystemDNS(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	for _, prefix := range excludedPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// Candidates 返回全部候选：内置的在前，系统 DNS 在后（去重、过滤掉不可用的地址）。
func Candidates() []Server {
	return withSystem(BuiltinCandidates(), systemDNSServers())
}

func withSystem(builtin []Server, system []netip.Addr) []Server {
	out := append([]Server(nil), builtin...)
	seen := make(map[netip.Addr]bool)
	for _, s := range builtin {
		if s.Type == TypeUDP {
			seen[s.Addr()] = true
		}
	}
	for _, addr := range system {
		addr = addr.Unmap().WithZone("")
		if !usableSystemDNS(addr) || seen[addr] {
			continue
		}
		seen[addr] = true
		server := UDP(addr.String())
		server.System = true
		out = append(out, server)
	}
	return out
}
