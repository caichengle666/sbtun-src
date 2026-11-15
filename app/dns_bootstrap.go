package app

import (
	"context"
	"runtime"
	"time"

	"github.com/caichengle666/sbtun/core/dnsprobe"
)

// bootstrapDNS 返回保存的引导 DNS（不探测），给生成配置和临时代理用。
func (a *App) bootstrapDNS() dnsprobe.Server {
	if a == nil || a.runtime == nil {
		return dnsprobe.Fallback()
	}
	return a.runtime.bootstrapDNS()
}

// mayProbeDNS 报告现在直接发出的 DNS 探测会不会被某个 sbtun 的 TUN 劫持：本进程的代理在运行，
// 或另一个 sbtun 进程（界面 / sbtun run）的 Clash API 有响应，都不能探测。安卓上 sbtun 进程不走 VPN，随时可以。
func (a *App) mayProbeDNS(ctx context.Context) bool {
	if a == nil || a.runtime == nil || a.runtime.DNS == nil {
		return false
	}
	if runtime.GOOS == "android" {
		return true
	}
	if !a.runtime.mayProbeDNS() {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	checkCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err := currentSelectorContext(checkCtx)
	return err != nil
}

// refreshBootstrapDNS 在可以探测时按需探测（缓存 10 分钟；force 时无视缓存），否则直接用保存的结果。
func (a *App) refreshBootstrapDNS(ctx context.Context, force bool) (dnsprobe.Server, error) {
	if !a.mayProbeDNS(ctx) {
		return a.bootstrapDNS(), nil
	}
	if force {
		return a.runtime.DNS.Reprobe(ctx)
	}
	return a.runtime.DNS.Refresh(ctx)
}
