//go:build !windows

package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caichengle666/sbtun/config"
	"github.com/caichengle666/sbtun/core"
)

// 假内核：check 总是通过；run 每次启动记一行。运行目录下有 crash-always 时 0.1 秒后异常退出；
// 有 crash-once 时删掉它并异常退出（只崩一次）；否则一直运行，收到 SIGTERM 正常退出。
const fakeCrashingSingBox = `#!/bin/sh
dir="$(dirname "$0")"
if [ "$1" = check ]; then exit 0; fi
echo run >> "$dir/runs"
if [ -f "$dir/crash-always" ]; then sleep 0.1; echo "FATAL[0000] boom" >&2; exit 1; fi
if [ -f "$dir/crash-once" ]; then rm -f "$dir/crash-once"; sleep 0.1; exit 1; fi
trap 'exit 0' TERM
while :; do sleep 0.05; done
`

func newCrashTestRuntime(t *testing.T, delay time.Duration, marker string) (*RuntimeCoordinator, string) {
	t.Helper()
	r, dir := newReloadTestRuntime(t)
	if err := os.WriteFile(r.Binary, []byte(fakeCrashingSingBox), 0o755); err != nil {
		t.Fatal(err)
	}
	if marker != "" {
		if err := os.WriteFile(filepath.Join(dir, marker), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r.restartBaseDelay = delay
	go r.watchSingBoxExit()
	return r, dir
}

func waitState(t *testing.T, r *RuntimeCoordinator, timeout time.Duration, ok func(core.RuntimeState, string) bool) (core.RuntimeState, string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		state, message := r.State.Get()
		if ok(state, message) {
			return state, message
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待状态超时: state=%s message=%q", state, message)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// 只崩一次：退避后自动重启，回到运行状态并在状态里说明。
func TestAutoRestartRecoversAfterCrash(t *testing.T) {
	r, dir := newCrashTestRuntime(t, 20*time.Millisecond, "crash-once")
	if err := r.Start(context.Background(), reloadTestConfig("good", 1080)); err != nil {
		t.Fatal(err)
	}
	_, message := waitState(t, r, 3*time.Second, func(s core.RuntimeState, m string) bool {
		return s == core.StateRunning && strings.Contains(m, "已自动重启")
	})
	if !strings.Contains(message, ErrSingBoxExited) {
		t.Fatalf("状态应带上退出原因: %q", message)
	}
	if n := countRuns(t, dir, 2); n != 2 {
		t.Fatalf("sing-box 启动次数=%d want 2", n)
	}
	if !r.SingBox.Running() {
		t.Fatal("自动重启后 sing-box 应在运行")
	}
	if status := r.AutoRestartStatus(); status.Count != 1 || status.GaveUp {
		t.Fatalf("status=%+v", status)
	}
}

// 一直崩：1 分钟内最多重启 3 次，之后停止重启并在状态（含 CLI 读的文件）里报告原因。
func TestAutoRestartStopsAfterLimit(t *testing.T) {
	r, dir := newCrashTestRuntime(t, 10*time.Millisecond, "crash-always")
	if err := r.Start(context.Background(), reloadTestConfig("good", 1080)); err != nil {
		t.Fatal(err)
	}
	_, message := waitState(t, r, 5*time.Second, func(s core.RuntimeState, m string) bool {
		return s == core.StateError && strings.Contains(m, ErrSingBoxRestartLimit)
	})
	if !strings.Contains(message, "已停止自动重启") || !strings.Contains(message, "boom") {
		t.Fatalf("放弃重启的原因不完整: %q", message)
	}
	time.Sleep(300 * time.Millisecond)
	if n := countRuns(t, dir, 4); n != 4 {
		t.Fatalf("sing-box 启动次数=%d want 4（1 次启动 + 3 次重启）", n)
	}
	status := r.AutoRestartStatus()
	if !status.GaveUp || status.Count != autoRestartMax {
		t.Fatalf("status=%+v", status)
	}
	report, ok := loadExitReport(r.WorkDir)
	if !ok || report.Reason != status.Reason {
		t.Fatalf("CLI 状态文件 report=%+v ok=%v", report, ok)
	}
	// 用户再次启动时清空计数和状态文件。
	_ = os.Remove(filepath.Join(dir, "crash-always"))
	if err := r.Start(context.Background(), reloadTestConfig("good", 1080)); err != nil {
		t.Fatal(err)
	}
	if status := r.AutoRestartStatus(); status.Count != 0 || status.GaveUp {
		t.Fatalf("重新启动后应清空自动重启状态: %+v", status)
	}
	if _, ok := loadExitReport(r.WorkDir); ok {
		t.Fatal("重新启动后应删除状态文件")
	}
}

// 用户主动停止（运行中、或正在等待重启）后都不再重启。
func TestAutoRestartNotAfterUserStop(t *testing.T) {
	r, dir := newCrashTestRuntime(t, 20*time.Millisecond, "")
	if err := r.Start(context.Background(), reloadTestConfig("good", 1080)); err != nil {
		t.Fatal(err)
	}
	countRuns(t, dir, 1) // 等假内核真正跑起来
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if state, _ := r.State.Get(); state != core.StateStopped || r.SingBox.Running() {
		t.Fatalf("用户停止后被重启: state=%s running=%v", state, r.SingBox.Running())
	}
	if n := countRuns(t, dir, 1); n != 1 {
		t.Fatalf("runs=%d want 1", n)
	}

	// 崩溃后在退避等待中用户停止：安排好的重启必须作废。
	r.mu.Lock()
	r.restartBaseDelay = 400 * time.Millisecond
	r.mu.Unlock()
	if err := os.WriteFile(filepath.Join(dir, "crash-once"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), reloadTestConfig("good", 1080)); err != nil {
		t.Fatal(err)
	}
	waitState(t, r, 3*time.Second, func(s core.RuntimeState, m string) bool {
		return s == core.StateError && strings.Contains(m, "后自动重启")
	})
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(800 * time.Millisecond)
	if state, _ := r.State.Get(); state != core.StateStopped || r.SingBox.Running() {
		t.Fatalf("等待重启时用户停止后仍被重启: state=%s running=%v", state, r.SingBox.Running())
	}
	if n := countRuns(t, dir, 2); n != 2 {
		t.Fatalf("runs=%d want 2", n)
	}
}

// 应用退出（ctx 取消）：运行中退出按预期退出处理，等待中的重启也作废。
func TestAutoRestartNotAfterAppExit(t *testing.T) {
	r, dir := newCrashTestRuntime(t, 400*time.Millisecond, "crash-once")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx, reloadTestConfig("good", 1080)); err != nil {
		t.Fatal(err)
	}
	waitState(t, r, 3*time.Second, func(s core.RuntimeState, m string) bool {
		return s == core.StateError && strings.Contains(m, "后自动重启")
	})
	cancel()
	time.Sleep(800 * time.Millisecond)
	if r.SingBox.Running() {
		t.Fatal("应用退出后仍被重启")
	}
	if n := countRuns(t, dir, 1); n != 1 {
		t.Fatalf("runs=%d want 1", n)
	}

	// 运行中 ctx 取消导致的退出是预期退出，不触发重启。
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if err := r.Start(ctx2, reloadTestConfig("good", 1080)); err != nil {
		t.Fatal(err)
	}
	countRuns(t, dir, 2)
	cancel2()
	time.Sleep(time.Second)
	if r.SingBox.Running() {
		t.Fatal("ctx 取消后被重启")
	}
	if n := countRuns(t, dir, 2); n != 2 {
		t.Fatalf("runs=%d want 2", n)
	}
	if status := r.AutoRestartStatus(); status.Count != 0 {
		t.Fatalf("预期退出不应计入自动重启: %+v", status)
	}
}

// 次数按 1 分钟滑动窗口计算，退避每次翻倍。
func TestAutoRestartWindowAndBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // 结束等待中的重启 goroutine
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r, _ := newReloadTestRuntime(t)
	r.runCtx, r.activeConfigSet = ctx, true
	r.restartBaseDelay = time.Hour
	r.now = func() time.Time { return now }
	schedule := func() string {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.State.Set(core.StateError, "crash")
		r.scheduleRestartLocked("crash")
		_, message := r.State.Get()
		return message
	}
	for i, want := range []string{"1h0m0s 后自动重启（1 分钟内第 1/3 次）", "2h0m0s 后自动重启（1 分钟内第 2/3 次）"} {
		if got := schedule(); !strings.Contains(got, want) {
			t.Fatalf("第 %d 次: %q want %q", i+1, got, want)
		}
		now = now.Add(20 * time.Second)
	}
	now = now.Add(30 * time.Second) // 第一次已滑出窗口
	if got := schedule(); !strings.Contains(got, "第 2/3 次") {
		t.Fatalf("窗口外的重启不应计数: %q", got)
	}
	if got := schedule(); !strings.Contains(got, "第 3/3 次") {
		t.Fatalf("%q", got)
	}
	if got := schedule(); !strings.Contains(got, ErrSingBoxRestartLimit) {
		t.Fatalf("超过次数应停止重启: %q", got)
	}
}

// 另一个进程（sbtun run）放弃自动重启后，CLI status 进程的 GetStatus 能读到原因。
func TestGetStatusReportsAutoRestartGiveUpFromFile(t *testing.T) {
	writer, _ := newReloadTestRuntime(t)
	writer.saveExitReport(AutoRestartStatus{Count: 3, GaveUp: true, Reason: ErrSingBoxRestartLimit + ": test", At: time.Now()})

	a := New()
	a.manager = config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	a.runtime = &RuntimeCoordinator{State: core.NewStateStore(), WorkDir: writer.WorkDir}
	status := a.GetStatus()
	if status.AutoRestart == nil || !status.AutoRestart.GaveUp || !strings.Contains(status.Message, ErrSingBoxRestartLimit) {
		t.Fatalf("status=%+v", status)
	}
}
