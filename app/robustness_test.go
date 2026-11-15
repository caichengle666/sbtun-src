package app

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caichengle666/sbtun/config"
	"github.com/caichengle666/sbtun/core"
	"github.com/caichengle666/sbtun/core/dnsprobe"
)

// 节点挂了时 TUN 劫持的系统解析每次都卡满超时：失败要负缓存，不能每次 Reload 都重查。
func TestNodeResolverNegativeCache(t *testing.T) {
	now := time.Now()
	var calls atomic.Int32
	r := &nodeResolver{
		now: func() time.Time { return now },
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			calls.Add(1)
			return nil, errors.New("timeout")
		},
	}
	nodes := []config.Node{{Server: "dead.example.com"}}
	if got := r.resolve(nodes); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	now = now.Add(10 * time.Second)
	r.resolve(nodes)
	if calls.Load() != 1 {
		t.Fatalf("failed lookup retried inside negative TTL: calls=%d", calls.Load())
	}
	now = now.Add(nodeResolveNegativeTTL)
	r.resolve(nodes)
	if calls.Load() != 2 {
		t.Fatalf("negative entry never expired: calls=%d", calls.Load())
	}
}

// 失败后旧答案继续用，负缓存期间也不丢。
func TestNodeResolverNegativeCacheKeepsOldAnswer(t *testing.T) {
	now := time.Now()
	fail := false
	r := &nodeResolver{
		now: func() time.Time { return now },
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			if fail {
				return nil, errors.New("down")
			}
			return []netip.Addr{netip.MustParseAddr("198.51.100.4")}, nil
		},
	}
	nodes := []config.Node{{Server: "n.example.com"}}
	r.resolve(nodes)
	fail = true
	now = now.Add(nodeResolveCacheTTL + time.Second)
	if got := r.resolve(nodes); len(got["n.example.com"]) != 1 {
		t.Fatalf("old answer lost: %v", got)
	}
	now = now.Add(time.Second)
	if got := r.resolve(nodes); len(got["n.example.com"]) != 1 {
		t.Fatalf("old answer lost during negative TTL: %v", got)
	}
}

// 系统解析失败（系统 DNS 被写死成不通的地址）时用引导 DNS 兜底。
func TestNodeResolverFallsBackToBootstrapDNS(t *testing.T) {
	var fallbackCalls atomic.Int32
	r := &nodeResolver{
		lookup: func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("system dns broken") },
		fallback: func(_ context.Context, host string) ([]netip.Addr, error) {
			fallbackCalls.Add(1)
			return []netip.Addr{netip.MustParseAddr("203.0.113.8")}, nil
		},
	}
	got := r.resolve([]config.Node{{Server: "node.example.com"}})
	if len(got["node.example.com"]) != 1 || got["node.example.com"][0].String() != "203.0.113.8" || fallbackCalls.Load() != 1 {
		t.Fatalf("got %v calls=%d", got, fallbackCalls.Load())
	}
}

// 引导 DNS 兜底只在没有 TUN 运行时用：运行中直接发出的查询会被 TUN 劫持。
func TestRuntimeResolverFallbackOnlyWhenNotRunning(t *testing.T) {
	r := NewRuntimeCoordinator(t.TempDir(), "sing-box")
	if !r.mayProbeDNS() {
		t.Fatal("stopped runtime must allow probing")
	}
	r.State.Set(core.StateRunning, "")
	if r.mayProbeDNS() {
		t.Fatal("running runtime must not probe")
	}
	if _, err := r.resolver.fallback(context.Background(), "node.example.com"); err == nil {
		t.Fatal("fallback must refuse while running")
	}
	r.State.Set(core.StateStarting, "")
	if r.mayProbeDNS() {
		t.Fatal("starting runtime must not probe")
	}
	r.State.Set(core.StateError, "boom")
	if !r.mayProbeDNS() {
		t.Fatal("error state without a process must allow probing")
	}
}

// Start/Reload 在锁外解析节点域名：解析卡住时不能挡住拿 r.mu 的崩溃处理和界面操作。
func TestResolveHappensOutsideCoordinatorLock(t *testing.T) {
	r := NewRuntimeCoordinator(t.TempDir(), "/nonexistent/sing-box")
	r.DNS.SetProbe(func(context.Context) (dnsprobe.Server, error) { return dnsprobe.UDP("223.5.5.5"), nil })
	inLookup := make(chan struct{})
	release := make(chan struct{})
	r.resolver.lookup = func(context.Context, string) ([]netip.Addr, error) {
		close(inLookup)
		<-release
		return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
	}
	cfg := config.Default()
	cfg.Nodes = []config.Node{{ID: "a", Name: "a", Protocol: "socks", Server: "node.example.com", Port: 1080}}
	cfg.CurrentNodeID = "a"
	done := make(chan error, 1)
	go func() { done <- r.Start(context.Background(), cfg) }()
	<-inLookup
	locked := r.mu.TryLock()
	if locked {
		r.mu.Unlock()
	}
	close(release)
	<-done // 启动本身会因为没有 sing-box 失败，这里不关心
	if !locked {
		t.Fatal("r.mu is held while resolving node domains")
	}
}

// 生成的运行配置用保存的引导 DNS；GUI 和 CLI（另一个 RuntimeCoordinator）读同一个文件，结果一致。
func TestRuntimeConfigUsesSavedBootstrapDNS(t *testing.T) {
	dir := t.TempDir()
	r := NewRuntimeCoordinator(dir, "sing-box")
	r.DNS.SetProbe(func(context.Context) (dnsprobe.Server, error) {
		return dnsprobe.DoH("1.12.12.12", "doh.pub"), nil
	})
	if _, err := r.DNS.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Nodes = []config.Node{{ID: "a", Name: "a", Protocol: "socks", Server: "203.0.113.5", Port: 1080}}
	cfg.CurrentNodeID = "a"
	gui, err := r.buildConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewRuntimeCoordinator(dir, "sing-box").buildConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(gui) != string(cli) {
		t.Fatal("GUI and CLI generated different configs")
	}
	if !strings.Contains(string(gui), `"server": "1.12.12.12"`) || !strings.Contains(string(gui), `"server_name": "doh.pub"`) {
		t.Fatalf("bootstrap DNS not used:\n%s", gui)
	}
}

type firewallCall struct {
	binary string
	port   uint16
}

func recordFirewall(r *RuntimeCoordinator) *[]firewallCall {
	var mu sync.Mutex
	calls := &[]firewallCall{}
	r.firewall = func(binary string, port uint16) error {
		mu.Lock()
		defer mu.Unlock()
		*calls = append(*calls, firewallCall{binary, port})
		return nil
	}
	return calls
}

// 防火墙规则：端口变化时重建；停止时删除；状态未知（刚启动、可能有上次留下的）时无条件同步一次。
func TestLANFirewallLifecycle(t *testing.T) {
	r := NewRuntimeCoordinator(t.TempDir(), "sing-box")
	calls := recordFirewall(r)
	r.tunCleanup = func() error { return nil }

	// 刚启动、什么都没开过：Stop（例如退出时）也要删一遍可能残留的规则。
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || (*calls)[0].port != 0 {
		t.Fatalf("calls=%v", *calls)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("known-clean state must not call netsh again: %v", *calls)
	}

	_ = r.syncLANFirewallLocked(&config.LANProxy{Enabled: true, Port: 7890})
	_ = r.syncLANFirewallLocked(&config.LANProxy{Enabled: true, Port: 7890})
	_ = r.syncLANFirewallLocked(&config.LANProxy{Enabled: true, Port: 7891})
	if got := *calls; len(got) != 3 || got[1].port != 7890 || got[2].port != 7891 || got[2].binary != "sing-box" {
		t.Fatalf("calls=%v", got)
	}

	// 运行中停止：删除。
	r.State.Set(core.StateRunning, "")
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := *calls; len(got) != 4 || got[3].port != 0 {
		t.Fatalf("Stop must remove the rule: %v", got)
	}

	// 启动失败（fail）也删除。
	_ = r.syncLANFirewallLocked(&config.LANProxy{Enabled: true, Port: 7890})
	_ = r.fail(ErrSingBoxStartFailed, errors.New("boom"))
	if got := *calls; got[len(got)-1].port != 0 {
		t.Fatalf("fail must remove the rule: %v", got)
	}
}

// 设置失败时记为未知，下次一定重试。
func TestLANFirewallRetriesAfterError(t *testing.T) {
	r := NewRuntimeCoordinator(t.TempDir(), "sing-box")
	n := 0
	r.firewall = func(string, uint16) error {
		n++
		if n == 1 {
			return errors.New("netsh failed")
		}
		return nil
	}
	if err := r.syncLANFirewallLocked(&config.LANProxy{Enabled: true}); err == nil {
		t.Fatal("error must be reported")
	}
	_ = r.syncLANFirewallLocked(&config.LANProxy{Enabled: true})
	_ = r.syncLANFirewallLocked(&config.LANProxy{Enabled: true})
	if n != 2 {
		t.Fatalf("calls=%d", n)
	}
}

func TestLANFirewallCommands(t *testing.T) {
	del := lanFirewallCommands(`C:\sbtun\sing-box.exe`, 0)
	if len(del) != 1 || strings.Join(del[0], " ") != `netsh advfirewall firewall delete rule name=sbtun LAN proxy` {
		t.Fatalf("delete=%v", del)
	}
	cmds := lanFirewallCommands(`C:\sbtun\sing-box.exe`, 7890)
	if len(cmds) != 3 {
		t.Fatalf("cmds=%v", cmds)
	}
	for i, protocol := range []string{"TCP", "UDP"} {
		line := strings.Join(cmds[i+1], " ")
		for _, want := range []string{"add rule", "name=sbtun LAN proxy", "dir=in", "action=allow", `program=C:\sbtun\sing-box.exe`,
			"protocol=" + protocol, "localport=7890", "remoteip=localsubnet", "profile=private,domain"} {
			if !strings.Contains(line, want) {
				t.Fatalf("%q missing %q", line, want)
			}
		}
		if strings.Contains(line, "profile=any") {
			t.Fatal(line)
		}
	}
}

// sing-box 崩溃后清理 TUN 失败（如 macOS 系统 DNS 没还原）必须写进状态消息。
func TestWatchSingBoxExitReportsCleanupError(t *testing.T) {
	r := NewRuntimeCoordinator(t.TempDir(), "sing-box")
	r.tunCleanup = func() error { return errors.New("恢复系统 DNS 失败: Wi-Fi") }
	r.State.Set(core.StateRunning, "")
	r.SingBox.InjectExit(os.ErrProcessDone)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if state, message := r.State.Get(); state == core.StateError {
			if !strings.Contains(message, "清理失败") || !strings.Contains(message, "恢复系统 DNS 失败") {
				t.Fatalf("message=%q", message)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("state not updated")
}
