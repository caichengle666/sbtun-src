//go:build windows

package dnsprobe

import (
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/caichengle666/sbtun/core/tun"
)

// systemDNSServers 用 GetAdaptersAddresses 取所有已连接网卡上配置的 DNS 服务器。失败时当没有。
func systemDNSServers() []netip.Addr {
	size := uint32(15 * 1024)
	var buf []byte
	for attempt := 0; attempt < 3; attempt++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_UNICAST|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || size == 0 {
			return nil
		}
		buf = nil
	}
	if buf == nil {
		return nil
	}
	var out []netip.Addr
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp || aa.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		// sbtun 自己的 TUN 网卡的 DNS 指向 sing-box 本身。
		if strings.EqualFold(windows.UTF16PtrToString(aa.FriendlyName), tun.InterfaceName) {
			continue
		}
		for dns := aa.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil {
				continue
			}
			if addr, ok := netip.AddrFromSlice(ip); ok {
				out = append(out, addr.Unmap())
			}
		}
	}
	return out
}
