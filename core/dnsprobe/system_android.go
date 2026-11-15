//go:build android

package dnsprobe

import "net/netip"

// 安卓没有 /etc/resolv.conf，sbtun 进程也拿不到系统 DNS（需要 Java 层的 LinkProperties），
// 只用内置候选。
func systemDNSServers() []netip.Addr { return nil }
