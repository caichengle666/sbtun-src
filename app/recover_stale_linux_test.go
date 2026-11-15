//go:build linux

package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caichengle666/sbtun/config"
	"github.com/caichengle666/sbtun/core"
	"github.com/caichengle666/sbtun/core/dnsprobe"
)

// fakeSingBox 把 sleep 复制成 dir/sing-box：既能当“孤儿 sing-box”（sleep 60），
// 当真内核用时（run -c ...）又会立即失败，用来模拟测速失败。
func fakeSingBox(t *testing.T, dir string) string {
	t.Helper()
	src, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("没有 sleep")
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(binary, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return binary
}

func startOrphan(t *testing.T, binary, workDir string) (*exec.Cmd, chan struct{}) {
	t.Helper()
	orphan := exec.Command(binary, "60")
	if err := orphan.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = orphan.Process.Kill() })
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "sing-box.pid"), []byte(strconv.Itoa(orphan.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = orphan.Wait(); close(exited) }()
	return orphan, exited
}

func waitExited(exited chan struct{}, d time.Duration) bool {
	select {
	case <-exited:
		return true
	case <-time.After(d):
		return false
	}
}

// 本进程代理运行时 RecoverStale 不能动 pid 文件里的进程（那可能就是自己的 sing-box）。
func TestRecoverStaleRespectsRunningState(t *testing.T) {
	dir := t.TempDir()
	binary := fakeSingBox(t, dir)
	workDir := filepath.Join(dir, "runtime-data")
	_, exited := startOrphan(t, binary, workDir)
	r := NewRuntimeCoordinator(workDir, binary)
	for _, state := range []core.RuntimeState{core.StateStarting, core.StateRunning, core.StateStopping} {
		r.State.Set(state, "")
		if err := r.RecoverStale(); err != nil {
			t.Fatal(err)
		}
	}
	if waitExited(exited, 300*time.Millisecond) {
		t.Fatal("RecoverStale killed sing-box while the runtime was active")
	}
	r.State.Set(core.StateStopped, "")
	if err := r.RecoverStale(); err != nil {
		t.Fatal(err)
	}
	if !waitExited(exited, 5*time.Second) {
		t.Fatal("orphan sing-box not cleaned up")
	}
}

// 启动前测速失败也必须已经清理过残留：以前恢复排在测速之后，测速一失败就永远恢复不了。
func TestStartRecoversStaleBeforeHealthCheck(t *testing.T) {
	dir := t.TempDir()
	binary := fakeSingBox(t, dir)
	workDir := filepath.Join(dir, "runtime-data")
	_, exited := startOrphan(t, binary, workDir)

	oldAPI := clashAPIBaseURL
	clashAPIBaseURL = "http://127.0.0.1:1" // 没有其他实例
	t.Cleanup(func() { clashAPIBaseURL = oldAPI })

	a := New()
	a.ctx = context.Background()
	a.workDir = workDir
	a.binary = binary
	a.manager = config.NewManager(filepath.Join(workDir, "config.json"))
	a.initRuntime("")
	probes := 0
	a.runtime.DNS.SetProbe(func(context.Context) (dnsprobe.Server, error) {
		probes++
		return dnsprobe.UDP("119.29.29.29"), nil
	})
	cfg := config.Default()
	cfg.Nodes = []config.Node{{ID: "a", Name: "a", Protocol: "socks", Server: "127.0.0.1", Port: 1}}
	cfg.CurrentNodeID = "a"

	err := a.startWithConfigLocked(cfg)
	if err == nil || !strings.Contains(err.Error(), "节点不可用") {
		t.Fatalf("expected health check failure, got %v", err)
	}
	if !waitExited(exited, 5*time.Second) {
		t.Fatal("stale sing-box was not cleaned up before the health check")
	}
	// 测速前探测过引导 DNS；测速失败后又强制重探一次（结果没变，不重复测速）。
	if probes != 2 {
		t.Fatalf("probes=%d", probes)
	}
	if got := a.bootstrapDNS(); got != dnsprobe.UDP("119.29.29.29") {
		t.Fatalf("bootstrap=%v", got)
	}
}
