package singbox

import "github.com/caichengle666/sbtun/core/dnsprobe"

// healthDNSConfig 是测速 / 临时代理用的 DNS：和运行配置一样用探测选出的引导 DNS（只用 IP）。
// 以前桌面上用 "local"（系统 DNS），但系统 DNS 可能本身就坏了（被手工写死成不通的地址，
// 或上次异常退出后 macOS 还指着 TUN 地址），启动前测速就必然失败；安卓上 "local" 会去问 [::1]:53。
func healthDNSConfig(bootstrap dnsprobe.Server) map[string]any {
	return map[string]any{
		"servers": []map[string]any{bootstrapDNSServer(bootstrap)},
		"final":   localDNSTag,
	}
}
