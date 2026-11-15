package dnsprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/caichengle666/sbtun/config"
)

const (
	// FileName 是保存探测结果的文件，放在 runtime-data 目录：GUI 和 CLI 读同一份，生成的配置一致。
	FileName = "dns-bootstrap.json"
	// CacheTTL 内不重复探测。
	CacheTTL = 10 * time.Minute
	// systemCacheTTL 是选中系统 DNS（通常是路由器）时的缓存时长：它只在当前网络里有效，
	// 笔记本换了网络后要尽快重新探测。
	systemCacheTTL = time.Minute
	// failureBackoff 是一次全部失败之后不再重试的时间，避免批量测速时每个节点都白等 2 秒。
	failureBackoff = 30 * time.Second
)

// saved 是 dns-bootstrap.json 的内容。
type saved struct {
	Server   Server    `json:"server"`
	ProbedAt time.Time `json:"probed_at"`
}

// Store 保存当前选中的引导 DNS。Current 只读不探测；Refresh 在需要时探测并保存。
// 可以并发使用；同一时间最多一个探测在跑，其他调用者等它的结果。
type Store struct {
	path string

	// 下面三个字段测试时替换。
	probe func(ctx context.Context) (Server, error)
	now   func() time.Time
	ttl   time.Duration

	probeMu     sync.Mutex // 串行化探测
	mu          sync.Mutex // 保护下面两个字段
	lastFailure time.Time
	probes      uint64 // 已完成的探测次数，用来判断等锁期间别人是否刚探测过
}

// NewStore 创建一个把结果保存在 dir/dns-bootstrap.json 的 Store。
func NewStore(dir string) *Store {
	return &Store{path: filepath.Join(dir, FileName)}
}

// SetProbe 替换探测函数（默认并行探测 Candidates()），供测试和特殊环境使用。
func (s *Store) SetProbe(probe func(ctx context.Context) (Server, error)) {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	s.probe = probe
}

// Path 返回保存文件的位置。
func (s *Store) Path() string { return s.path }

func (s *Store) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Store) cacheTTL() time.Duration {
	if s.ttl > 0 {
		return s.ttl
	}
	return CacheTTL
}

func (s *Store) load() (saved, bool) {
	if s == nil || s.path == "" {
		return saved{}, false
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return saved{}, false
	}
	var v saved
	if json.Unmarshal(data, &v) != nil || v.Server.Validate() != nil {
		return saved{}, false
	}
	return v, true
}

// Current 返回保存的选择；没有保存过或文件损坏时返回 Fallback。不做任何网络操作。
func (s *Store) Current() Server {
	if v, ok := s.load(); ok {
		return v.Server
	}
	return Fallback()
}

// Refresh 在缓存过期时探测一次并保存结果，返回当前应该用的引导 DNS 和探测错误（成功或用缓存时为 nil）。
// 只能在流量没有被 TUN 接管时调用，否则探测包会被 sing-box 劫持，结果不可信。
// 全部候选都失败时沿用上次保存的结果，没有就用 Fallback；失败后短时间内不重复探测。
func (s *Store) Refresh(ctx context.Context) (Server, error) {
	return s.refresh(ctx, false)
}

// Reprobe 和 Refresh 一样，但不管缓存是否过期都重新探测（失败退避仍然有效）。
// 用于缓存的选择看起来不能用了（例如启动前测速失败）的时候。
func (s *Store) Reprobe(ctx context.Context) (Server, error) {
	return s.refresh(ctx, true)
}

func (s *Store) refresh(ctx context.Context, force bool) (Server, error) {
	if s == nil {
		return Fallback(), nil
	}
	if v, ok := s.load(); ok && !force && s.fresh(v) {
		return v.Server, nil
	}
	s.mu.Lock()
	seen := s.probes
	s.mu.Unlock()
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	// 等锁期间别人可能刚探测完，直接用它的结果。
	v, ok := s.load()
	s.mu.Lock()
	probedMeanwhile := s.probes != seen
	s.mu.Unlock()
	if ok && s.fresh(v) && (!force || probedMeanwhile) {
		return v.Server, nil
	}
	current := Fallback()
	if ok {
		current = v.Server
	}
	s.mu.Lock()
	backoff := !s.lastFailure.IsZero() && s.clock().Sub(s.lastFailure) < failureBackoff
	s.mu.Unlock()
	if backoff {
		return current, nil
	}
	probe := s.probe
	if probe == nil {
		probe = func(ctx context.Context) (Server, error) {
			server, _, err := Probe(ctx, Candidates(), ProbeTimeout)
			return server, err
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	server, err := probe(ctx)
	if err == nil {
		err = server.Validate()
	}
	s.mu.Lock()
	s.probes++
	if err != nil {
		s.lastFailure = s.clock()
	} else {
		s.lastFailure = time.Time{}
	}
	s.mu.Unlock()
	if err != nil {
		return current, err
	}
	if saveErr := s.save(saved{Server: server, ProbedAt: s.clock()}); saveErr != nil {
		// 存不下也照样用这次的结果；下次进程再探测。
		return server, fmt.Errorf("保存引导 DNS 失败: %w", saveErr)
	}
	return server, nil
}

func (s *Store) fresh(v saved) bool {
	ttl := s.cacheTTL()
	if v.Server.System && ttl > systemCacheTTL {
		ttl = systemCacheTTL
	}
	age := s.clock().Sub(v.ProbedAt)
	return age >= 0 && age < ttl
}

// save 原子写入：先写同目录临时文件再改名，进程中途被杀也不会留下半个文件。
func (s *Store) save(v saved) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".dns-bootstrap-*.json")
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
	// sudo/pkexec 下交还给调用者，之后不提权的 CLI 命令也能读到同一份结果。
	if err := config.ShareWithInvoker(name, 0o600); err != nil {
		return err
	}
	return config.ReplaceConfigFile(name, s.path)
}
