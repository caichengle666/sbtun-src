package dnsprobe

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// ProbeTimeout 是一次探测的总时长：所有候选并行，到点还没答的算失败。
	ProbeTimeout = 2 * time.Second
	// probeDomain 是探测用的域名，国内公共 DNS 一定能答出 A 记录。
	probeDomain = "www.baidu.com"
)

// errNotFinished 标记更高优先级的候选已经成功、没等它出结果的候选。
var errNotFinished = errors.New("未等待（已有更高优先级的结果）")

// Result 是一个候选的探测结果。
type Result struct {
	Server  Server
	Err     error
	Latency time.Duration
}

// Probe 并行探测全部候选（总时长不超过 timeout），返回能拿到有效 A 记录的、优先级最高的候选。
// 优先级更高的候选都有了结果之后立即返回，不等慢的。全部失败时返回错误。
func Probe(ctx context.Context, candidates []Server, timeout time.Duration) (Server, []Result, error) {
	return defaultClient.Probe(ctx, candidates, timeout)
}

func (c *Client) Probe(ctx context.Context, candidates []Server, timeout time.Duration) (Server, []Result, error) {
	if len(candidates) == 0 {
		return Server{}, nil, errors.New("没有可探测的 DNS")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = ProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type done struct {
		index int
		res   Result
	}
	ch := make(chan done, len(candidates))
	for i, server := range candidates {
		go func() {
			started := time.Now()
			addrs, err := c.Query(ctx, server, probeDomain, dnsmessage.TypeA)
			if err == nil && len(addrs) == 0 {
				err = errors.New("应答里没有 A 记录")
			}
			ch <- done{i, Result{Server: server, Err: err, Latency: time.Since(started)}}
		}()
	}
	results := make([]Result, len(candidates))
	for i, server := range candidates {
		results[i] = Result{Server: server, Err: errNotFinished}
	}
	finished := make([]bool, len(candidates))
	for range candidates {
		d := <-ch
		results[d.index] = d.res
		finished[d.index] = true
		// 从高到低看：遇到还没结果的就继续等；遇到成功的就是答案。
		for i := range candidates {
			if !finished[i] {
				break
			}
			if results[i].Err == nil {
				cancel()
				return candidates[i], results, nil
			}
		}
	}
	return Server{}, results, fmt.Errorf("所有 DNS 都不可用: %s", summarize(results))
}

func summarize(results []Result) string {
	parts := make([]string, 0, len(results))
	for _, r := range results {
		if r.Err != nil {
			parts = append(parts, fmt.Sprintf("%s: %v", r.Server, r.Err))
		}
	}
	return strings.Join(parts, "; ")
}
