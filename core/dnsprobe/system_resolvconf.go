//go:build !windows && !android

package dnsprobe

import (
	"bufio"
	"bytes"
	"net/netip"
	"os"
	"strings"
)

// systemDNSServers 尽力读取 /etc/resolv.conf 里的 nameserver（Linux、macOS）。读不到就当没有。
func systemDNSServers() []netip.Addr {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseResolvConf(data)
}

func parseResolvConf(data []byte) []netip.Addr {
	var out []netip.Addr
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if addr, err := netip.ParseAddr(fields[1]); err == nil {
			out = append(out, addr.WithZone(""))
		}
	}
	return out
}
