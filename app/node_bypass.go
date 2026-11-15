package app

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/caichengle666/sbtun/config"
	"github.com/caichengle666/sbtun/core/singbox"
)

const (
	// nodeResolveTimeout 是系统解析的时限；失败后再用引导 DNS 直接问（nodeFallbackTimeout）。
	nodeResolveTimeout  = 2500 * time.Millisecond
	nodeFallbackTimeout = 2 * time.Second
	nodeResolveCacheTTL = 10 * time.Minute
	// nodeResolveNegativeTTL 内不重试解析失败的域名：节点挂了时 TUN 劫持的系统解析每次都要卡满超时，
	// 不缓存失败的话每次 Reload / 切节点都要白等。
	nodeResolveNegativeTTL = 45 * time.Second
)

type nodeResolveEntry struct {
	addrs []netip.Addr
	at    time.Time // 最近一次成功的时间
	// failedAt 是最近一次失败的时间（成功后清零）。失败时保留 addrs（旧答案仍然可用）。
	failedAt time.Time
}

// nodeResolver caches node server lookups so switching nodes does not wait on
// DNS every time.
type nodeResolver struct {
	mu     sync.Mutex
	cache  map[string]nodeResolveEntry
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// fallback 在系统解析失败时直接问引导 DNS（只在流量没被 TUN 接管时可用，见 RuntimeCoordinator）；
	// 为空或返回错误就算失败。
	fallback func(ctx context.Context, host string) ([]netip.Addr, error)
	now      func() time.Time
}

func (r *nodeResolver) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// needsLookup 报告缓存里的这一项要不要重新解析：成功的答案没过期、或者刚失败过（负缓存）都不查。
func (r *nodeResolver) needsLookup(entry nodeResolveEntry, ok bool, now time.Time) bool {
	if !ok {
		return true
	}
	if !entry.failedAt.IsZero() && now.Sub(entry.failedAt) < nodeResolveNegativeTTL {
		return false
	}
	return len(entry.addrs) == 0 || now.Sub(entry.at) > nodeResolveCacheTTL
}

// resolve 返回节点域名到解析结果的映射；查不到的域名沿用上次的结果，从没查到过就没有这一项。
// 可能阻塞几秒（系统解析 + 引导 DNS），调用方不要在持有 RuntimeCoordinator.mu 时调用。
func (r *nodeResolver) resolve(nodes []config.Node) map[string][]netip.Addr {
	domains := singbox.NodeDomains(nodes)
	now := r.clock()
	r.mu.Lock()
	if r.cache == nil {
		r.cache = make(map[string]nodeResolveEntry)
	}
	var stale []string
	for _, domain := range domains {
		entry, ok := r.cache[domain]
		if r.needsLookup(entry, ok, now) {
			stale = append(stale, domain)
		}
	}
	lookup, fallback := r.lookup, r.fallback
	r.mu.Unlock()
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}

	if len(stale) > 0 {
		var wg sync.WaitGroup
		for _, domain := range stale {
			wg.Add(1)
			go func() {
				defer wg.Done()
				addrs := lookupWithTimeout(lookup, domain, nodeResolveTimeout)
				if len(addrs) == 0 && fallback != nil {
					addrs = lookupWithTimeout(fallback, domain, nodeFallbackTimeout)
				}
				r.mu.Lock()
				defer r.mu.Unlock()
				entry := r.cache[domain]
				if len(addrs) == 0 {
					// Keep the previous answer, if any, when a lookup fails.
					entry.failedAt = r.clock()
				} else {
					entry = nodeResolveEntry{addrs: addrs, at: r.clock()}
				}
				r.cache[domain] = entry
			}()
		}
		wg.Wait()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	result := make(map[string][]netip.Addr, len(domains))
	for _, domain := range domains {
		if addrs := r.cache[domain].addrs; len(addrs) > 0 {
			result[domain] = addrs
		}
	}
	return result
}

func lookupWithTimeout(lookup func(context.Context, string) ([]netip.Addr, error), host string, timeout time.Duration) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil
	}
	return addrs
}
