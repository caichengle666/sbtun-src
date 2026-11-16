package singbox

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/caichengle666/sbtun/core/tun"
)

const tunIPv6Address = "fdfe:dcba:9876::1/126"

// HasUsableIPv6 reports whether an active non-loopback interface has a usable
// IPv6 address. The sbtun TUN address is excluded so reloads cannot self-detect.
func HasUsableIPv6() bool {
	tunPrefix := &net.IPNet{
		IP:   net.ParseIP("fdfe:dcba:9876::"),
		Mask: net.CIDRMask(48, 128),
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() && !tunPrefix.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// HasIPv6Stack 报告本机 IPv6 协议栈是否在用：任一非回环网卡（sbtun 自己的 TUN 除外）上有任何 IPv6 地址，
// 包括链路本地地址。系统彻底关掉 IPv6 时返回 false，这时给 TUN 加 IPv6 地址会失败，也不存在 IPv6 绕过的问题。
func HasIPv6Stack() bool {
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err == nil && strings.TrimSpace(string(data)) == "1" {
			return false
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Name == tun.InterfaceName {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip != nil && ip.To4() == nil && ip.To16() != nil && !ip.IsLoopback() {
				return true
			}
		}
	}
	return false
}

// 探测函数做成变量，测试时替换。
var (
	hostHasUsableIPv6 = HasUsableIPv6
	hostHasIPv6Stack  = HasIPv6Stack
)

// ipv6Plan 决定 IPv6 怎么处理。
//   - active：用户开了 IPv6 且本机确实有可用的公网 IPv6，IPv6 流量照常经 TUN 代理。
//   - tunIPv6：TUN 是否加 IPv6 地址。只要本机 IPv6 协议栈在用就加（即使 active 为 false），
//     这样 auto_route 才会把 IPv6 默认路由也指向 TUN；否则关掉 IPv6 时 IPv6 流量和发往 IPv6 DNS 的查询
//     会直接走物理网卡，暴露真实地址。active 为 false 时由路由规则把 IPv6 目标拒绝、DNS 只回 A 记录。
type ipv6Plan struct {
	active  bool
	tunIPv6 bool
}

func planIPv6(enabled bool) ipv6Plan {
	active := enabled && hostHasUsableIPv6()
	return ipv6Plan{active: active, tunIPv6: active || hostHasIPv6Stack()}
}

// dnsStrategy 是 DNS 和 resolve 动作用的地址族策略：IPv6 不可用时只要 A 记录，AAAA 一律回空。
func (p ipv6Plan) dnsStrategy() string {
	if p.active {
		return "prefer_ipv4"
	}
	return "ipv4_only"
}

func tunAddresses(plan ipv6Plan) []string {
	addresses := []string{tunIPv4Address(localIPv4s())}
	if plan.tunIPv6 {
		addresses = append(addresses, tunIPv6Address)
	}
	return addresses
}

// tunIPv4Address 默认用 172.18.0.1/30。Windows / Linux 上这个地址可能已被别的网卡占着
// （v2rayN 等同样基于 sing-box 的客户端默认也用它，或上次异常退出残留的网卡），
// sing-box 会报 “set ipv4 address: The object already exists” 直接退出；这时顺延到
// 172.19.0.1、172.20.0.1……第一个空闲的 /30。macOS 的路由修正依赖固定地址，不换。
func tunIPv4Address(used []net.IP) string {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		return "172.18.0.1/30"
	}
	for second := 18; second <= 31; second++ {
		_, block, _ := net.ParseCIDR(fmt.Sprintf("172.%d.0.0/30", second))
		free := true
		for _, ip := range used {
			if block.Contains(ip) {
				free = false
				break
			}
		}
		if free {
			return fmt.Sprintf("172.%d.0.1/30", second)
		}
	}
	return "172.18.0.1/30"
}

// localIPv4s 列出本机网卡（包括未连接的）上的 IPv4 地址，跳过 sbtun 自己的 TUN 网卡，
// 否则运行中重载配置会因为看到自己的地址而换地址、导致无谓重启。
func localIPv4s() []net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ips []net.IP
	for _, iface := range interfaces {
		if iface.Name == tun.InterfaceName {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if value, ok := address.(*net.IPNet); ok && value.IP.To4() != nil {
				ips = append(ips, value.IP)
			}
		}
	}
	return ips
}
