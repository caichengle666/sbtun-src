package singbox

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/caichengle666/sbtun/config"
)

// stubIPv6 固定 IPv6 探测结果：usable = 本机有可用公网 IPv6，stack = 本机 IPv6 协议栈在用。
func stubIPv6(t *testing.T, usable, stack bool) {
	t.Helper()
	oldUsable, oldStack := hostHasUsableIPv6, hostHasIPv6Stack
	hostHasUsableIPv6 = func() bool { return usable }
	hostHasIPv6Stack = func() bool { return stack }
	t.Cleanup(func() { hostHasUsableIPv6, hostHasIPv6Stack = oldUsable, oldStack })
}

type ipv6View struct {
	tunV6        bool
	rejectV6     bool
	rejectBefore int // reject 规则在规则列表里的位置，-1 表示没有
	hijackAt     int
	dnsStrategy  string
	resolveStrat string
}

func inspectIPv6(t *testing.T, data []byte) ipv6View {
	t.Helper()
	var rc RuntimeConfig
	if err := json.Unmarshal(data, &rc); err != nil {
		t.Fatal(err)
	}
	v := ipv6View{rejectBefore: -1, hijackAt: -1}
	for _, a := range rc.Inbounds[0]["address"].([]any) {
		if a == tunIPv6Address {
			v.tunV6 = true
		}
	}
	for i, r := range rc.Route["rules"].([]any) {
		rule := r.(map[string]any)
		if rule["action"] == "hijack-dns" && v.hijackAt < 0 {
			v.hijackAt = i
		}
		if rule["ip_version"] == float64(6) && rule["action"] == "reject" {
			v.rejectV6, v.rejectBefore = true, i
		}
		if rule["action"] == "resolve" {
			v.resolveStrat, _ = rule["strategy"].(string)
		}
	}
	v.dnsStrategy, _ = rc.DNS["strategy"].(string)
	return v
}

func TestIPv6AlwaysCapturedByTUN(t *testing.T) {
	cases := []struct {
		name          string
		enabled       bool
		usable, stack bool
		wantTunV6     bool
		wantReject    bool
		wantStrategy  string
	}{
		// 用户开了 IPv6 且可用：照常代理 IPv6。
		{"enabled+usable", true, true, true, true, false, "prefer_ipv4"},
		// 用户关了 IPv6，本机却有 IPv6：TUN 仍接管 IPv6，拒绝 IPv6 目标，DNS 只回 A。
		{"disabled+usable", false, true, true, true, true, "ipv4_only"},
		// 开了但没检测到可用 IPv6（只有链路本地）：同上。
		{"enabled+unusable", true, false, true, true, true, "ipv4_only"},
		// 系统彻底没有 IPv6：不加 IPv6 地址（加了会启动失败），规则照样拒绝、DNS 只回 A。
		{"no-stack", false, false, false, false, true, "ipv4_only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubIPv6(t, tc.usable, tc.stack)
			for _, mode := range []config.RoutingMode{config.RoutingSmart, config.RoutingGlobal, config.RoutingDirect} {
				cfg := testConfig(mode)
				cfg.IPv6Enabled = tc.enabled
				cfg.LANProxy = &config.LANProxy{Enabled: true, Port: 17890}
				data, err := BuildConfig(cfg, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				v := inspectIPv6(t, data)
				if v.tunV6 != tc.wantTunV6 || v.rejectV6 != tc.wantReject || v.dnsStrategy != tc.wantStrategy || v.resolveStrat != tc.wantStrategy {
					t.Fatalf("%s: got %+v", mode, v)
				}
				if v.rejectV6 && v.rejectBefore < v.hijackAt {
					t.Fatalf("%s: IPv6 reject must come after hijack-dns so DNS over IPv6 is still answered: %+v", mode, v)
				}
				if binary := os.Getenv("SING_BOX_BINARY"); binary != "" {
					path := filepath.Join(t.TempDir(), "c.json")
					if err := os.WriteFile(path, data, 0o600); err != nil {
						t.Fatal(err)
					}
					if out, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil {
						t.Fatalf("%s: sing-box check: %v\n%s\n%s", mode, err, out, data)
					}
				}
			}
		})
	}
}
