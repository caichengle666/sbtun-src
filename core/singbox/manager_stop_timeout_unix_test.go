//go:build !windows

package singbox

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func shortStopTimeouts(t *testing.T) {
	t.Helper()
	graceful, killWait := gracefulStopTimeout, killWaitTimeout
	gracefulStopTimeout, killWaitTimeout = 200*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { gracefulStopTimeout, killWaitTimeout = graceful, killWait })
}

// 优雅停止超时、强杀后进程仍不退出（这里让 Kill 失效来模拟）：Stop 要有上限地返回错误，
// 并清空 cmd 等状态，下次 Start 不能以为旧进程还在运行。
func TestStopTimeoutClearsStateAfterForcedKill(t *testing.T) {
	shortStopTimeouts(t)
	binary, configPath := writeScript(t, `trap '' TERM
touch "$(dirname "$0")/ready"
while :; do sleep 0.05; done
`)
	dir := filepath.Dir(binary)
	m := NewManager()
	var kills atomic.Int32
	var stuck []*exec.Cmd
	m.kill = func(cmd *exec.Cmd) error {
		kills.Add(1)
		stuck = append(stuck, cmd)
		return nil // 假装发出了 SIGKILL，但进程没有退出
	}
	t.Cleanup(func() {
		for _, cmd := range stuck {
			_ = cmd.Process.Kill()
		}
	})
	if err := m.Start(context.Background(), binary, configPath); err != nil {
		t.Fatal(err)
	}
	if !waitFile(filepath.Join(dir, "ready"), 2*time.Second) {
		t.Fatal("假内核未就绪")
	}
	started := time.Now()
	err := m.Stop()
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "仍未退出") {
		t.Fatalf("Stop err=%v", err)
	}
	if kills.Load() != 1 {
		t.Fatalf("优雅停止超时后应强杀一次, kills=%d", kills.Load())
	}
	if elapsed > gracefulStopTimeout+killWaitTimeout+time.Second {
		t.Fatalf("Stop 等待没有上限: %v", elapsed)
	}
	m.mu.Lock()
	cmd, done, logFile := m.cmd, m.done, m.logFile
	m.mu.Unlock()
	if cmd != nil || done != nil || logFile != nil {
		t.Fatalf("超时后状态未清空: cmd=%v done=%v log=%v", cmd, done, logFile)
	}
	if m.Running() || m.Generation() != 0 {
		t.Fatalf("超时后仍报告运行中: running=%v generation=%d", m.Running(), m.Generation())
	}

	// 下次 Start 应正常启动新进程，而不是报“已经在运行”。
	m.kill = nil
	if err := m.Start(context.Background(), binary, configPath); err != nil {
		t.Fatalf("清空状态后 Start 失败: %v", err)
	}
	m.mu.Lock()
	if m.cmd != nil {
		stuck = append(stuck, m.cmd)
	}
	m.mu.Unlock()
	// 被放弃的旧进程现在才退出：不能被当成新进程的异常退出，也不能清掉新进程的状态。
	_ = stuck[0].Process.Kill()
	time.Sleep(200 * time.Millisecond)
	if !m.Running() {
		t.Fatal("旧进程退出清掉了新进程的状态")
	}
	select {
	case event := <-m.Exited():
		if !event.Expected {
			t.Fatalf("被放弃的旧进程退出不应算异常退出: %+v", event)
		}
	default:
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop new process: %v", err)
	}
}
