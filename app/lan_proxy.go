package app

import (
	"net"
	"runtime"
	"sort"
	"strings"

	"github.com/caichengle666/sbtun/core/tun"
)

// GetLANAddresses 返回局域网设备连接本机代理时可以填的 IPv4 地址（不含 TUN 网卡）。
func (a *App) GetLANAddresses() []string {
	seen := map[string]bool{}
	var result []string
	add := func(ip net.IP) {
		if ip = ip.To4(); ip != nil && ip.IsPrivate() && !seen[ip.String()] {
			seen[ip.String()] = true
			result = append(result, ip.String())
		}
	}
	ifaces, err := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || iface.Name == tun.InterfaceName || virtualInterface(iface.Name) {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			// TUN 地址是 /30，即使网卡没被上面的条件排除也不列出来。
			if n, ok := addr.(*net.IPNet); ok {
				if ones, _ := n.Mask.Size(); ones < 30 {
					add(n.IP)
				}
			}
		}
	}
	if runtime.GOOS == "android" && (err != nil || len(result) == 0) {
		// 新版安卓不让普通应用枚举网卡；sbtun 自己不走 VPN，向外“连”一次 UDP（不发包）就能拿到 Wi-Fi 地址。
		if conn, err := net.Dial("udp4", "223.5.5.5:53"); err == nil {
			add(conn.LocalAddr().(*net.UDPAddr).IP)
			conn.Close()
		}
	}
	sort.Strings(result)
	return result
}

// virtualInterface 排除局域网设备连不到的网卡：Docker/虚拟机网桥、手机的移动数据网卡。
func virtualInterface(name string) bool {
	for _, prefix := range []string{"docker", "br-", "veth", "virbr", "vmnet", "rmnet", "ccmni", "dummy"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
