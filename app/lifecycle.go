package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caichengle666/sbtun/config"
	"github.com/caichengle666/sbtun/core"
	"github.com/caichengle666/sbtun/core/capture"
	"github.com/caichengle666/sbtun/core/dnsprobe"
	"github.com/caichengle666/sbtun/core/singbox"
	"github.com/caichengle666/sbtun/core/tun"
)

const (
	ErrConfigInvalid      = "CONFIG_INVALID"
	ErrSingBoxStartFailed = "SINGBOX_START_FAILED"
	ErrSingBoxReload      = "SINGBOX_RELOAD_FAILED"
	ErrTunNotReady        = "TUN_NOT_READY"
	ErrSingBoxExited      = "SINGBOX_EXITED"
	ErrCaptureStartFailed = "CAPTURE_START_FAILED"
)

type RuntimeCoordinator struct {
	mu      sync.Mutex
	State   *core.StateStore
	SingBox *singbox.Manager
	TUN     *tun.Manager
	Capture *capture.Manager
	WorkDir string
	Binary  string
	// ResourceDir 放规则文件的目录，默认是 sing-box 所在目录（安卓上内核目录只读，单独指定）。
	ResourceDir     string
	ReadyCheck      func(context.Context) error
	activeConfig    config.Config
	activeConfigSet bool
	activeData      []byte // 正在运行的 sing-box 配置内容，用来判断重载是否真有必要
	// activeResolved 是生成 activeData 时节点域名的解析结果。判断配置是否变化时沿用它，
	// DNS 轮换或缓存过期换了 IP 不会被当成配置变化而重启、断开所有连接。
	activeResolved map[string][]netip.Addr
	// LocalAuth protects the clash API and capture proxy ports.
	LocalAuth singbox.LocalAuth
	resolver  nodeResolver
	// DNS 保存探测选出的引导 DNS（runtime-data/dns-bootstrap.json），生成运行配置和测速配置都用它。
	DNS *dnsprobe.Store
	// firewall 增删 Windows 防火墙的局域网代理放行规则（port 为 0 表示删除）；测试时替换。
	firewall func(binary string, port uint16) error
	// firewallPort 是本进程最后一次设置的放行端口，0 表示已删除；firewallKnown 为 false 表示
	// 还不知道系统里有没有（可能是上次异常退出留下的），下一次同步时无条件删一遍再按需添加。
	firewallPort  uint16
	firewallKnown bool
	// tunCleanup 不为空时代替 TUN.Cleanup（测试用）。
	tunCleanup func() error
}

func NewRuntimeCoordinator(workDir, binary string) *RuntimeCoordinator {
	r := &RuntimeCoordinator{
		State: core.NewStateStore(), SingBox: singbox.NewManager(), TUN: tun.NewManager(),
		Capture: capture.NewManager(filepath.Join(workDir, "capture"), "127.0.0.1:9081", "127.0.0.1:9082"),
		WorkDir: workDir, Binary: binary,
	}
	if auth, err := loadOrCreateLocalAuth(workDir); err == nil {
		r.LocalAuth = auth
	} else if auth, genErr := newLocalAuth(); genErr == nil {
		// Still protect the ports for this process even if the shared file
		// cannot be written; the CLI then cannot reach this instance's API.
		fmt.Fprintf(os.Stderr, "本地认证信息无法保存，仅本进程有效: %v\n", err)
		r.LocalAuth = auth
	}
	r.DNS = dnsprobe.NewStore(workDir)
	r.firewall = setLANProxyFirewall
	// 节点域名系统解析失败时（比如系统 DNS 被写死成不通的地址），直接问引导 DNS。
	// 只在流量没被 TUN 接管时这么做：运行中发出的包会被 TUN 劫持，答案不可信，也可能又绕回坏掉的节点。
	r.resolver.fallback = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if !r.mayProbeDNS() {
			return nil, errors.New("TUN 运行中，不直接查询引导 DNS")
		}
		return dnsprobe.Lookup(ctx, r.DNS.Current(), host)
	}
	setClashAPISecret(r.LocalAuth.ClashSecret)
	r.Capture.SetAuth(&capture.ProxyAuth{Username: r.LocalAuth.ProxyUsername, Password: r.LocalAuth.ProxyPassword})
	go r.watchSingBoxExit()
	return r
}

func (r *RuntimeCoordinator) watchSingBoxExit() {
	if r.SingBox == nil || r.State == nil {
		return
	}
	for event := range r.SingBox.Exited() {
		if event.Expected {
			continue
		}
		r.mu.Lock()
		// A crash can be queued while Start/Reload holds the lock and has
		// already launched a replacement process. That stale event must not
		// mark the new process as failed or tear down its routes.
		if current := r.SingBox.Generation(); current != 0 && current != event.Generation {
			r.mu.Unlock()
			continue
		}
		state, _ := r.State.Get()
		if state == core.StateStopping || state == core.StateStopped || state == core.StateError {
			r.mu.Unlock()
			continue
		}
		if r.TUN != nil {
			r.TUN.MarkStopped()
		}
		message := ErrSingBoxExited
		if event.Err != nil {
			message += ": " + event.Err.Error()
		}
		// “exit status 1”本身看不出原因，带上 sing-box 日志里最后一条错误。
		if reason := r.SingBox.LastError(); reason != "" {
			message += "：" + reason
		}
		if r.Capture != nil {
			_ = r.Capture.Stop()
		}
		// 清理失败（比如 macOS 系统 DNS 没还原）必须让用户看到，否则断网了也不知道为什么。
		if err := r.cleanupTUN(); err != nil {
			message += "；清理失败: " + err.Error()
		}
		_ = r.syncLANFirewallLocked(nil)
		r.State.Set(core.StateError, message)
		r.mu.Unlock()
	}
}

func (r *RuntimeCoordinator) Start(ctx context.Context, cfg config.Config) error {
	// 节点域名解析可能要几秒，放在锁外做，不卡住崩溃处理和界面操作。
	resolved := r.resolver.resolve(cfg.Nodes)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.State == nil || r.SingBox == nil || r.TUN == nil {
		return errors.New("runtime 未完整初始化")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, _ := r.State.Get()
	if state == core.StateStarting || state == core.StateRunning || state == core.StateStopping {
		return fmt.Errorf("runtime already active: %s", state)
	}
	_ = r.TUN.RecoverStale()
	return r.startConfigLocked(ctx, cfg, resolved)
}

// RecoverStale 在没有代理运行时清理上次异常退出的残留：还原 macOS 系统 DNS（之前指向 TUN 地址）、
// 删除残留的 TUN 地址，结束 pid 文件里记录的孤儿 sing-box。必须在启动前测速之前做：
// 残留的系统 DNS / 孤儿进程会让测速失败，而测速失败又会挡住启动，永远走不到这一步。
// 只在持有单实例锁的进程里调用；本进程的 sing-box 在运行（或正在启停）时什么也不做。
func (r *RuntimeCoordinator) RecoverStale() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.State == nil || r.TUN == nil {
		return nil
	}
	state, _ := r.State.Get()
	if state == core.StateStarting || state == core.StateRunning || state == core.StateStopping {
		return nil
	}
	if r.SingBox != nil && r.SingBox.Running() {
		return nil
	}
	err := r.TUN.RecoverStale()
	if r.WorkDir != "" && r.Binary != "" {
		singbox.CleanupStale(r.WorkDir, r.Binary)
	}
	return err
}

// mayProbeDNS 报告现在直接发出的 DNS 查询会不会被本进程的 TUN 劫持。安卓上 sbtun 进程不走 VPN，随时可以。
// 其他进程（如 sbtun run）的 TUN 由调用方另外判断（App.mayProbeDNS 会再查一次 Clash API）。
func (r *RuntimeCoordinator) mayProbeDNS() bool {
	if runtime.GOOS == "android" {
		return true
	}
	if r.State == nil {
		return true
	}
	state, _ := r.State.Get()
	return state == core.StateStopped || state == core.StateError && (r.SingBox == nil || !r.SingBox.Running())
}

// bootstrapDNS 返回生成配置用的引导 DNS（只读保存的结果，不探测）。
func (r *RuntimeCoordinator) bootstrapDNS() dnsprobe.Server {
	if r == nil || r.DNS == nil {
		return dnsprobe.Fallback()
	}
	return r.DNS.Current()
}

// Reload restarts sing-box without disabling the existing TUN adapter. This
// keeps rule and routing changes fast while still replacing the running config.
func (r *RuntimeCoordinator) Reload(ctx context.Context, cfg config.Config) error {
	resolved := r.resolver.resolve(cfg.Nodes) // 锁外解析，见 Start
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.State == nil || r.SingBox == nil || r.TUN == nil {
		return errors.New("runtime 未完整初始化")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, _ := r.State.Get()
	if state == core.StateStopped {
		// 已停止就只写配置，绝不自行启动（退出过程中被重载会留下孤儿进程）。
		_, err := r.syncConfigResolved(cfg, resolved)
		return err
	}
	if state != core.StateRunning && state != core.StateError {
		return fmt.Errorf("runtime cannot reload from state: %s", state)
	}
	// 先校验通过再替换 runtime.json；校验失败时旧配置原样保留，旧进程继续运行。
	built, err := r.writeValidatedConfig(ctx, cfg, resolved)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrConfigInvalid, err)
	}
	captureRestart := !r.activeConfigSet || captureConfigChanged(r.activeConfig, cfg)
	r.State.Set(core.StateStopping, "")
	if err := r.SingBox.Stop(); err != nil {
		return r.fail(ErrSingBoxReload, fmt.Errorf("停止旧 sing-box 失败: %w", err))
	}
	if captureRestart && r.Capture != nil {
		if err := r.Capture.Stop(); err != nil {
			return r.fail(ErrSingBoxReload, fmt.Errorf("停止流量分析器失败: %w", err))
		}
	}
	if err := r.TUN.CleanupRoutes(); err != nil {
		return r.fail(ErrSingBoxReload, fmt.Errorf("清理旧 TUN 路由失败: %w", err))
	}
	return r.launchLocked(ctx, cfg, built)
}

// SyncIfUnchanged 在运行中且新配置生成的 sing-box 配置与正在运行的完全一致时，只写回 runtime.json、不重启，
// 返回 true。订阅定时更新等只改了元数据（如 UpdatedAt）的场景靠它避免断开所有连接。
func (r *RuntimeCoordinator) SyncIfUnchanged(cfg config.Config) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.State == nil || !r.State.IsRunning() || !r.activeConfigSet || captureConfigChanged(r.activeConfig, cfg) ||
		!slices.Equal(singbox.NodeDomains(cfg.Nodes), singbox.NodeDomains(r.activeConfig.Nodes)) {
		return false, nil
	}
	data, err := r.buildConfig(cfg, r.activeResolved)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(data, r.activeData) && !r.onlySelectionChanged(cfg) {
		return false, nil
	}
	if err := atomicWrite(r.configPath(), data, nil); err != nil {
		return false, fmt.Errorf("写入运行配置失败: %w", err)
	}
	r.activeConfig = cfg
	r.activeData = data
	return true, nil
}

// onlySelectionChanged 判断新配置和运行中的配置是否只差当前节点：切节点只改了 selector 的默认值，
// 运行中靠 Clash API 无缝切换，不需要重启 sing-box。
func (r *RuntimeCoordinator) onlySelectionChanged(cfg config.Config) bool {
	if cfg.CurrentNodeID == r.activeConfig.CurrentNodeID {
		return false
	}
	cfg.CurrentNodeID = r.activeConfig.CurrentNodeID
	data, err := r.buildConfig(cfg, r.activeResolved)
	return err == nil && bytes.Equal(data, r.activeData)
}

func (r *RuntimeCoordinator) startConfigLocked(ctx context.Context, cfg config.Config, resolved map[string][]netip.Addr) error {
	r.State.Set(core.StateStarting, "")
	// 每次从停止状态启动都按当前配置重新决定防火墙规则（可能是上次异常退出留下的）。
	r.firewallKnown = false
	built, err := r.writeValidatedConfig(ctx, cfg, resolved)
	if err != nil {
		return r.fail(ErrConfigInvalid, err)
	}
	return r.launchLocked(ctx, cfg, built)
}

// launchLocked 用已校验并写好的配置启动 sing-box，并按需启停流量分析器。
func (r *RuntimeCoordinator) launchLocked(ctx context.Context, cfg config.Config, built builtConfig) error {
	r.State.Set(core.StateStarting, "")
	if r.Capture != nil {
		if cfg.CaptureEnabled && len(cfg.CaptureDomains) > 0 {
			if err := r.Capture.Start(ctx, cfg.CaptureDomains); err != nil {
				return r.fail(ErrCaptureStartFailed, err)
			}
		} else if err := r.Capture.Stop(); err != nil {
			return r.fail(ErrCaptureStartFailed, err)
		}
	}
	if err := r.SingBox.Start(ctx, r.Binary, r.configPath()); err != nil {
		return r.fail(ErrSingBoxStartFailed, err)
	}
	if r.ReadyCheck != nil {
		readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := r.ReadyCheck(readyCtx)
		cancel()
		if err != nil {
			stopErr := r.SingBox.Stop()
			cleanupErr := r.cleanupTUN()
			if r.Capture != nil {
				_ = r.Capture.Stop()
			}
			if stopErr != nil {
				err = fmt.Errorf("%w; 停止失败: %v", err, stopErr)
			}
			if cleanupErr != nil {
				err = fmt.Errorf("%w; 清理失败: %v", err, cleanupErr)
			}
			return r.fail(ErrTunNotReady, err)
		}
	}
	// sing-box 起来之后再放行端口：校验或启动失败时不会留下一条对着空端口的规则。
	message := ""
	if err := r.syncLANFirewallLocked(cfg.LANProxyOn()); err != nil {
		message = "局域网代理的防火墙放行规则设置失败，局域网设备可能连不上: " + err.Error()
	}
	r.TUN.MarkRunning()
	r.State.Set(core.StateRunning, message)
	r.activeConfig = cfg
	r.activeConfigSet = true
	r.activeData = built.data
	r.activeResolved = built.resolved
	return nil
}

func captureConfigChanged(before, after config.Config) bool {
	if before.CaptureEnabled != after.CaptureEnabled {
		return true
	}
	left := append([]string(nil), before.CaptureDomains...)
	right := append([]string(nil), after.CaptureDomains...)
	normalize := func(values []string) []string {
		seen := make(map[string]struct{}, len(values))
		result := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), ".")
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			result = append(result, value)
		}
		sort.Strings(result)
		return result
	}
	left = normalize(left)
	right = normalize(right)
	if len(left) != len(right) {
		return true
	}
	for i := range left {
		if left[i] != right[i] {
			return true
		}
	}
	return false
}

// builtConfig 是一份生成好的 sing-box 配置和生成时用到的节点解析结果。
type builtConfig struct {
	data     []byte
	resolved map[string][]netip.Addr
}

func (r *RuntimeCoordinator) buildConfig(cfg config.Config, resolved map[string][]netip.Addr) ([]byte, error) {
	return singbox.BuildConfigWithAuth(cfg, r.resourceDir(), r.LocalAuth, resolved, singbox.BuildOptions{BootstrapDNS: r.bootstrapDNS()})
}

func (r *RuntimeCoordinator) configPath() string { return filepath.Join(r.WorkDir, "runtime.json") }

// SyncConfig 生成并原子写入 runtime.json，不做 sing-box 校验（未运行时保存配置用）。
// 不要在持有 r.mu 时调用（会做节点域名解析）；持锁的路径用 syncConfigResolved。
func (r *RuntimeCoordinator) SyncConfig(cfg config.Config) (string, error) {
	return r.syncConfigResolved(cfg, r.resolver.resolve(cfg.Nodes))
}

func (r *RuntimeCoordinator) syncConfigResolved(cfg config.Config, resolved map[string][]netip.Addr) (string, error) {
	data, err := r.buildConfig(cfg, resolved)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(r.WorkDir, 0o755); err != nil {
		return "", fmt.Errorf("创建运行目录失败: %w", err)
	}
	if err := atomicWrite(r.configPath(), data, nil); err != nil {
		return "", fmt.Errorf("写入运行配置失败: %w", err)
	}
	return r.configPath(), nil
}

// writeValidatedConfig 把配置写到临时文件，sing-box check 通过后才替换 runtime.json；
// 任何一步失败都保留旧的 runtime.json，避免之后每次启动和内核升级校验都被坏配置卡住。
func (r *RuntimeCoordinator) writeValidatedConfig(ctx context.Context, cfg config.Config, resolved map[string][]netip.Addr) (builtConfig, error) {
	if err := config.Validate(cfg); err != nil {
		return builtConfig{}, err
	}
	built := builtConfig{resolved: resolved}
	var err error
	if built.data, err = r.buildConfig(cfg, built.resolved); err != nil {
		return builtConfig{}, err
	}
	if err := r.prepareLANProxy(cfg); err != nil {
		return builtConfig{}, err
	}
	if err := os.MkdirAll(r.WorkDir, 0o755); err != nil {
		return builtConfig{}, fmt.Errorf("创建运行目录失败: %w", err)
	}
	err = atomicWrite(r.configPath(), built.data, func(tmp string) error {
		return singbox.ValidateConfig(ctx, r.Binary, tmp)
	})
	if err != nil {
		return builtConfig{}, err
	}
	return built, nil
}

// prepareLANProxy 在局域网代理开启或换端口时先确认端口没被别的程序占着（否则整个 sing-box 起不来）。
// 运行中端口没变时旧进程自己占着端口，不用检查。防火墙规则由 syncLANFirewallLocked 单独管理。
func (r *RuntimeCoordinator) prepareLANProxy(cfg config.Config) error {
	next := cfg.LANProxyOn()
	if next == nil {
		return nil
	}
	if r.activeConfigSet {
		if prev := r.activeConfig.LANProxyOn(); prev != nil && prev.ListenPort() == next.ListenPort() {
			return nil
		}
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", next.ListenPort()))
	if err != nil {
		return fmt.Errorf("局域网代理端口 %d 已被其他程序占用，请换一个端口", next.ListenPort())
	}
	ln.Close()
	return nil
}

// syncLANFirewallLocked 让 Windows 防火墙的放行规则和 lan（nil 表示不需要）一致：端口变了就重建，
// 不需要了就删除。状态未知（刚启动、上次异常退出）时先无条件删一遍。调用方持有 r.mu。
// 防火墙失败不阻止代理启动（最坏是局域网设备连不上），启动时会写进状态消息。
func (r *RuntimeCoordinator) syncLANFirewallLocked(lan *config.LANProxy) error {
	if r.firewall == nil {
		return nil
	}
	var want uint16
	if lan != nil {
		want = lan.ListenPort()
	}
	if r.firewallKnown && r.firewallPort == want {
		return nil
	}
	if err := r.firewall(r.Binary, want); err != nil {
		// 不确定系统里现在是什么状态，下次再同步一遍。
		r.firewallKnown = false
		return err
	}
	r.firewallPort, r.firewallKnown = want, true
	return nil
}

func (r *RuntimeCoordinator) resourceDir() string {
	if r.ResourceDir != "" {
		return r.ResourceDir
	}
	dir := filepath.Dir(r.Binary)
	if dir == "." || dir == "" {
		dir, _ = os.Getwd()
	}
	return dir
}

func (r *RuntimeCoordinator) cleanupTUN() error {
	if r.tunCleanup != nil {
		return r.tunCleanup()
	}
	if r.TUN == nil {
		return nil
	}
	return r.TUN.Cleanup()
}

func (r *RuntimeCoordinator) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.State == nil {
		return errors.New("runtime 状态未初始化")
	}
	state, _ := r.State.Get()
	if state == core.StateStopped {
		_ = r.syncLANFirewallLocked(nil)
		if r.TUN == nil {
			return nil
		}
		r.TUN.MarkStopped()
		return r.cleanupTUN()
	}
	r.State.Set(core.StateStopping, "")
	var stopErr error
	if r.SingBox != nil {
		stopErr = r.SingBox.Stop()
	}
	if r.Capture != nil {
		if err := r.Capture.Stop(); stopErr == nil {
			stopErr = err
		}
	}
	cleanupErr := r.cleanupTUN()
	if r.TUN != nil {
		r.TUN.MarkStopped()
	}
	// 停止或退出时删掉局域网代理的防火墙放行规则，不在系统里留一个开着的口子。
	_ = r.syncLANFirewallLocked(nil)
	if stopErr != nil || cleanupErr != nil {
		message := ""
		if stopErr != nil {
			message = stopErr.Error()
		}
		if cleanupErr != nil {
			if message != "" {
				message += "; "
			}
			message += "清理失败: " + cleanupErr.Error()
		}
		r.State.Set(core.StateError, message)
		if stopErr != nil {
			return stopErr
		}
		return cleanupErr
	}
	r.State.Set(core.StateStopped, "")
	r.activeConfig = config.Config{}
	r.activeConfigSet = false
	r.activeData = nil
	r.activeResolved = nil
	return nil
}

func (r *RuntimeCoordinator) fail(code string, err error) error {
	if r.Capture != nil {
		_ = r.Capture.Stop()
	}
	_ = r.syncLANFirewallLocked(nil)
	if r.TUN != nil {
		r.TUN.MarkStopped()
	}
	cleanupErr := r.cleanupTUN()
	if cleanupErr != nil {
		if err == nil {
			err = cleanupErr
		} else {
			err = fmt.Errorf("%w; 清理失败: %v", err, cleanupErr)
		}
	}
	if err == nil {
		err = errors.New("未知运行时错误")
	}
	if r.State != nil {
		r.State.Set(core.StateError, code+": "+err.Error())
	}
	return fmt.Errorf("%s: %w", code, err)
}

// atomicWrite 先写同目录临时文件；check 不为空时校验临时文件，通过后才替换 path。
func atomicWrite(path string, data []byte, check func(tmp string) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runtime-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if check != nil {
		if err := check(name); err != nil {
			return err
		}
	}
	// 含本地认证密钥，只有本人可读；sudo/pkexec 下交还调用者（内核更新校验要读它）。
	if err := config.ShareWithInvoker(name, 0o600); err != nil {
		return err
	}
	if err := config.ReplaceConfigFile(name, path); err != nil {
		return fmt.Errorf("替换运行配置失败: %w", err)
	}
	return nil
}
