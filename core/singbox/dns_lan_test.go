package singbox

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/caichengle666/sbtun/config"
	"github.com/caichengle666/sbtun/core/dnsprobe"
)

func TestBootstrapDNSServerShapes(t *testing.T) {
	cases := []struct {
		in   dnsprobe.Server
		want map[string]any
	}{
		{dnsprobe.UDP("223.5.5.5"), map[string]any{"type": "udp", "tag": "dns-local", "server": "223.5.5.5", "server_port": 53}},
		{dnsprobe.DoH("1.12.12.12", "doh.pub"), map[string]any{"type": "https", "tag": "dns-local", "server": "1.12.12.12", "server_port": 443, "path": "/dns-query",
			"tls": map[string]any{"enabled": true, "server_name": "doh.pub"}}},
		{dnsprobe.DoT("223.5.5.5", "dns.alidns.com"), map[string]any{"type": "tls", "tag": "dns-local", "server": "223.5.5.5", "server_port": 853,
			"tls": map[string]any{"enabled": true, "server_name": "dns.alidns.com"}}},
		// 零值和不合法的值都退回 DoH 223.5.5.5。
		{dnsprobe.Server{}, map[string]any{"type": "https", "tag": "dns-local", "server": "223.5.5.5", "server_port": 443, "path": "/dns-query",
			"tls": map[string]any{"enabled": true, "server_name": "dns.alidns.com"}}},
		{dnsprobe.Server{Type: "udp", Address: "dns.example", Port: 53}, map[string]any{"type": "https", "tag": "dns-local", "server": "223.5.5.5", "server_port": 443, "path": "/dns-query",
			"tls": map[string]any{"enabled": true, "server_name": "dns.alidns.com"}}},
	}
	for _, tc := range cases {
		got, _ := json.Marshal(bootstrapDNSServer(tc.in))
		want, _ := json.Marshal(tc.want)
		if string(got) != string(want) {
			t.Fatalf("%v:\n got %s\nwant %s", tc.in, got, want)
		}
	}
}

func decodeRuntime(t *testing.T, data []byte) RuntimeConfig {
	t.Helper()
	var rc RuntimeConfig
	if err := json.Unmarshal(data, &rc); err != nil {
		t.Fatal(err)
	}
	return rc
}

func buildWith(t *testing.T, cfg config.Config, boot dnsprobe.Server) []byte {
	t.Helper()
	data, err := BuildConfigWithAuth(cfg, t.TempDir(), LocalAuth{ClashSecret: "s"}, nil, BuildOptions{BootstrapDNS: boot})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var allModes = []config.RoutingMode{config.RoutingSmart, config.RoutingGlobal, config.RoutingDirect}

// 引导 DNS 不能有单点：dns-local 由探测结果生成，全部用 IP；不再有从未被引用的 dns-local-standby；
// dns-remote 不依赖 dns-local；DNS 规则不再用弃用的 ip_is_private。
func TestDNSHasNoSinglePointOfFailure(t *testing.T) {
	for _, mode := range allModes {
		for _, dnsMode := range []config.DNSMode{config.DNSAuto, config.DNSSystem, config.DNSCustom} {
			cfg := testConfig(mode)
			cfg.DNSMode = dnsMode
			cfg.Nodes = append(cfg.Nodes, config.Node{ID: "n2", Protocol: "socks", Server: "node.example.com", Port: 1080})
			data := buildWith(t, cfg, dnsprobe.DoH("1.12.12.12", "doh.pub"))
			text := string(data)
			if strings.Contains(text, "dns-local-standby") || strings.Contains(text, "ip_is_private\": true,\n          \"server") {
				t.Fatalf("%s/%s: dead or deprecated DNS config:\n%s", mode, dnsMode, text)
			}
			rc := decodeRuntime(t, data)
			for _, r := range rc.DNS["rules"].([]any) {
				if _, ok := r.(map[string]any)["ip_is_private"]; ok {
					t.Fatalf("%s/%s: DNS rule uses deprecated ip_is_private: %v", mode, dnsMode, r)
				}
			}
			for _, s := range rc.DNS["servers"].([]any) {
				server := s.(map[string]any)
				if _, ok := server["domain_resolver"]; ok {
					t.Fatalf("%s/%s: DNS server needs a resolver: %v", mode, dnsMode, server)
				}
				if _, err := netip.ParseAddr(server["server"].(string)); err != nil {
					t.Fatalf("%s/%s: DNS server is not an IP: %v", mode, dnsMode, server)
				}
			}
			local := rc.DNS["servers"].([]any)[0].(map[string]any)
			if local["tag"] != "dns-local" || local["type"] != "https" || local["server"] != "1.12.12.12" {
				t.Fatalf("%s/%s: dns-local must follow bootstrap: %v", mode, dnsMode, local)
			}
		}
	}
}

func findRule(rules []any, pred func(map[string]any) bool) int {
	for i, r := range rules {
		if pred(r.(map[string]any)) {
			return i
		}
	}
	return -1
}

func isResolve(r map[string]any) bool { return r["action"] == "resolve" }

// 全局 resolve 不能统一指定 dns-local：resolve 之后交给节点的是 IP，国内 DNS 给被墙域名的是污染地址。
// 按 DNS 规则选服务器，直连规则的域名由 DNS 规则送到 dns-local（见 TestDirectRuleDomainsResolveLocally）。
func TestRouteResolveFollowsDNSRules(t *testing.T) {
	for _, mode := range allModes {
		rc := decodeRuntime(t, buildWith(t, testConfig(mode), dnsprobe.Server{}))
		rules := rc.Route["rules"].([]any)
		i := findRule(rules, isResolve)
		if i < 0 {
			t.Fatalf("%s: no resolve rule", mode)
		}
		if _, ok := rules[i].(map[string]any)["server"]; ok {
			t.Fatalf("%s: resolve rule must not pin a server: %v", mode, rules[i])
		}
		if rc.Route["default_domain_resolver"] != "dns-local" {
			t.Fatalf("%s: default_domain_resolver=%v", mode, rc.Route["default_domain_resolver"])
		}
	}
}

// 当前节点挂了时，写了直连规则的域名必须还能解析：它们的 DNS 走 dns-local，不经节点。
// TUN 里应用自己发的 DNS（hijack-dns）和 route 里的 resolve 都按这条规则走。
func TestDirectRuleDomainsResolveLocally(t *testing.T) {
	for _, mode := range []config.RoutingMode{config.RoutingSmart, config.RoutingGlobal} {
		for _, dnsMode := range []config.DNSMode{config.DNSAuto, config.DNSCustom} {
			cfg := testConfig(mode)
			cfg.DNSMode = dnsMode
			cfg.CustomRules = []config.Rule{
				{MatchType: "domain_suffix", Value: "Baidu.com", Action: "direct"},
				{MatchType: "domain", Value: "intranet.example.com", Action: "direct"},
				{MatchType: "domain_keyword", Value: "taobao", Action: "direct"},
				{MatchType: "domain_suffix", Value: "baidu.com", Action: "direct"}, // 重复
				{MatchType: "domain_suffix", Value: "google.com", Action: "proxy"},
				{MatchType: "domain_suffix", Value: "ads.example", Action: "block"},
				{MatchType: "ip_cidr", Value: "10.0.0.0/8", Action: "direct"},
				{MatchType: "domain_suffix", Value: "hk.example", Action: "node:abc"},
			}
			rc := decodeRuntime(t, buildWith(t, cfg, dnsprobe.Server{}))
			if rc.DNS["final"] != "dns-remote" {
				t.Fatalf("%s/%s final=%v", mode, dnsMode, rc.DNS["final"])
			}
			var direct map[string]any
			for _, r := range rc.DNS["rules"].([]any) {
				rule := r.(map[string]any)
				if rule["domain_suffix"] != nil || rule["domain_keyword"] != nil {
					direct = rule
				}
			}
			if direct == nil || direct["server"] != "dns-local" {
				t.Fatalf("%s/%s: no direct-domain DNS rule: %v", mode, dnsMode, rc.DNS["rules"])
			}
			if got := strings.Join(toStrings(direct["domain_suffix"]), ","); got != "baidu.com" {
				t.Fatalf("domain_suffix=%v", got)
			}
			if got := strings.Join(toStrings(direct["domain"]), ","); got != "intranet.example.com" {
				t.Fatalf("domain=%v", got)
			}
			if got := strings.Join(toStrings(direct["domain_keyword"]), ","); got != "taobao" {
				t.Fatalf("domain_keyword=%v", got)
			}
		}
	}
	// 直连模式 / 系统 DNS：final 已经是 dns-local，不加多余的规则。
	cfg := testConfig(config.RoutingDirect)
	cfg.CustomRules = []config.Rule{{MatchType: "domain_suffix", Value: "baidu.com", Action: "direct"}}
	rc := decodeRuntime(t, buildWith(t, cfg, dnsprobe.Server{}))
	if rc.DNS["final"] != "dns-local" || len(rc.DNS["rules"].([]any)) != 0 {
		t.Fatalf("direct mode dns=%v", rc.DNS)
	}
}

func withInterfaceAddrs(t *testing.T, addrs ...string) {
	t.Helper()
	old := localInterfaceAddrs
	t.Cleanup(func() { localInterfaceAddrs = old })
	localInterfaceAddrs = func() []netip.Addr {
		var out []netip.Addr
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
}

func TestLANProxyHardeningRules(t *testing.T) {
	withInterfaceAddrs(t, "192.168.3.10", "127.0.0.1", "172.18.0.1", "172.19.0.1", "172.20.1.5", "fe80::1", "2408:8000::10", "fdfe:dcba:9876::1", "192.168.3.10")
	for _, mode := range allModes {
		cfg := testConfig(mode)
		cfg.LANProxy = &config.LANProxy{Enabled: true}
		rc := decodeRuntime(t, buildWith(t, cfg, dnsprobe.Server{}))
		rules := rc.Route["rules"].([]any)

		// B2：第一条就拒绝来源不是私有网段的 lan-in 连接。
		first := rules[0].(map[string]any)
		if first["type"] != "logical" || first["mode"] != "and" || first["action"] != "reject" {
			t.Fatalf("%s: first rule=%v", mode, first)
		}
		sub := first["rules"].([]any)
		if inb := sub[0].(map[string]any)["inbound"].([]any); len(inb) != 1 || inb[0] != "lan-in" {
			t.Fatalf("%s: logical rule must be scoped to lan-in: %v", mode, sub)
		}
		src := sub[1].(map[string]any)
		if src["invert"] != true || !slices.Contains(toStrings(src["source_ip_cidr"]), "192.168.0.0/16") {
			t.Fatalf("%s: source rule=%v", mode, src)
		}

		resolve := findRule(rules, isResolve)
		localhost := findRule(rules, func(r map[string]any) bool { return slices.Contains(toStrings(r["domain"]), "localhost") })
		if localhost < 0 || localhost > resolve || rules[localhost].(map[string]any)["action"] != "reject" ||
			!slices.Contains(toStrings(rules[localhost].(map[string]any)["domain_suffix"]), ".localhost") {
			t.Fatalf("%s: localhost rule must be a reject before resolve: localhost=%d resolve=%d", mode, localhost, resolve)
		}
		// B1：resolve 之后紧跟着按 IP 拒绝发往本机的连接，在“内网直连”和所有分流规则之前。
		deny := rules[resolve+1].(map[string]any)
		if deny["action"] != "reject" || toStrings(deny["inbound"])[0] != "lan-in" {
			t.Fatalf("%s: rule after resolve=%v", mode, deny)
		}
		cidrs := toStrings(deny["ip_cidr"])
		for _, want := range []string{"127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10", "0.0.0.0/8", "192.168.3.10/32", "172.20.1.5/32", "2408:8000::10/128"} {
			if !slices.Contains(cidrs, want) {
				t.Fatalf("%s: denied destinations %v missing %s", mode, cidrs, want)
			}
		}
		for _, unwanted := range []string{"172.18.0.1/32", "172.19.0.1/32", "fdfe:dcba:9876::1/128", "127.0.0.1/32", "fe80::1/128"} {
			if slices.Contains(cidrs, unwanted) {
				t.Fatalf("%s: denied destinations %v must not contain %s", mode, cidrs, unwanted)
			}
		}
		if strings.Count(strings.Join(cidrs, ","), "192.168.3.10/32") != 1 {
			t.Fatalf("duplicates: %v", cidrs)
		}
		private := findRule(rules, func(r map[string]any) bool { return r["ip_is_private"] == true })
		if private >= 0 && private < resolve+1 {
			t.Fatalf("%s: private direct rule before LAN deny", mode)
		}
	}
}

// 局域网代理关闭时不加任何 lan-in 规则，tun-in 的规则顺序不变。
func TestNoLANRulesWhenLANProxyOff(t *testing.T) {
	data := buildWith(t, testConfig(config.RoutingSmart), dnsprobe.Server{})
	if strings.Contains(string(data), "lan-in") || strings.Contains(string(data), "logical") {
		t.Fatalf("unexpected LAN rules:\n%s", data)
	}
	rules := decodeRuntime(t, data).Route["rules"].([]any)
	if rules[0].(map[string]any)["action"] != "sniff" {
		t.Fatalf("first rule=%v", rules[0])
	}
}

// 本机网卡地址变化前后（TUN 起没起来）生成的配置必须一致，否则运行中每次保存都会无谓重启。
func TestLANDenyListStableAcrossTUN(t *testing.T) {
	cfg := testConfig(config.RoutingSmart)
	cfg.LANProxy = &config.LANProxy{Enabled: true}
	withInterfaceAddrs(t, "192.168.3.10")
	before := buildWith(t, cfg, dnsprobe.Server{})
	withInterfaceAddrs(t, "192.168.3.10", "172.18.0.1", "fdfe:dcba:9876::1")
	after := buildWith(t, cfg, dnsprobe.Server{})
	if string(before) != string(after) {
		t.Fatal("TUN addresses changed the generated config")
	}
}

func toStrings(v any) []string {
	var out []string
	switch values := v.(type) {
	case []any:
		for _, x := range values {
			out = append(out, x.(string))
		}
	case []string:
		out = values
	}
	return out
}

// 用真实 sing-box 校验三种模式 × 三种引导 DNS × 局域网代理开关，并确认没有弃用警告。
func TestHardenedConfigsPassSingBoxCheckWithoutDeprecation(t *testing.T) {
	binary := singBoxTestBinary(t)
	withInterfaceAddrs(t, "192.168.3.10", "2408:8000::10")
	boots := []dnsprobe.Server{dnsprobe.UDP("223.5.5.5"), dnsprobe.DoH("223.5.5.5", "dns.alidns.com"), dnsprobe.DoT("223.5.5.5", "dns.alidns.com")}
	for _, mode := range allModes {
		for _, boot := range boots {
			for _, lan := range []bool{false, true} {
				cfg := testConfig(mode)
				cfg.Nodes = append(cfg.Nodes, config.Node{ID: "n2", Protocol: "socks", Server: "node.example.com", Port: 1080})
				cfg.CustomRules = []config.Rule{
					{MatchType: "domain_suffix", Value: "baidu.com", Action: "direct"},
					{MatchType: "domain_keyword", Value: "taobao", Action: "direct"},
					{MatchType: "domain", Value: "www.qq.com", Action: "direct"},
				}
				if lan {
					cfg.LANProxy = &config.LANProxy{Enabled: true, Port: 17990}
				}
				data := buildWith(t, cfg, boot)
				path := filepath.Join(t.TempDir(), "c.json")
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				output, err := exec.Command(binary, "check", "-c", path).CombinedOutput()
				if err != nil {
					t.Fatalf("%s/%v/lan=%v: sing-box check failed: %v\n%s", mode, boot, lan, err, output)
				}
				if strings.Contains(strings.ToLower(string(output)), "deprecated") || strings.Contains(string(output), "WARN") {
					t.Fatalf("%s/%v/lan=%v: sing-box warns:\n%s", mode, boot, lan, output)
				}
			}
		}
		boot := dnsprobe.DoH("1.12.12.12", "doh.pub")
		data, err := BuildHealthConfig(config.Node{ID: "h", Protocol: "socks", Server: "node.example.com", Port: 1080}, 18080, "u", "p", boot)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "h.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil || len(output) > 0 && strings.Contains(string(output), "WARN") {
			t.Fatalf("health config check: %v\n%s", err, output)
		}
	}
}
