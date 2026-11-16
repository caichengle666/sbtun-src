package singbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// ExitEvent 描述 sing-box 进程退出。
type ExitEvent struct {
	Err      error
	Expected bool
	// Generation identifies which Start produced the process. A coordinator
	// uses it to ignore an exit that belongs to a process already replaced.
	Generation uint64
}

// Manager 负责 sing-box 进程生命周期，不负责业务配置逻辑。
type Manager struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	pidPath  string
	logPath  string
	logFile  *os.File
	exited   chan ExitEvent
	done     chan struct{}
	stopping bool
	starting bool
	// generation counts successful Starts; current is the generation of the
	// running process, or 0 when none is running.
	generation uint64
	current    uint64
	// kill 强制结束进程，为空时用 cmd.Process.Kill（测试注入）。
	kill func(*exec.Cmd) error
}

var (
	// gracefulStopTimeout is how long sing-box gets to remove its routes, rules
	// and DNS settings after a stop signal before it is killed.
	gracefulStopTimeout = 3 * time.Second
	// killWaitTimeout 是强杀之后等待进程真正退出的上限；超过就放弃跟踪这个进程。
	killWaitTimeout = 5 * time.Second
)

func NewManager() *Manager { return &Manager{exited: make(chan ExitEvent, 1)} }

func (m *Manager) Start(ctx context.Context, binary, configPath string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.starting || (m.cmd != nil && m.cmd.Process != nil) {
		return fmt.Errorf("sing-box 已经在运行或正在启动")
	}
	m.starting = true
	pidPath := filepath.Join(filepath.Dir(configPath), pidFileName)
	cleanupStalePID(pidPath, binary)
	cmd := exec.CommandContext(ctx, binary, "run", "-c", configPath)
	// ctx 取消（如 CLI 收到 Ctrl+C / SIGTERM）时先请求优雅退出让内核撤掉路由，
	// WaitDelay 后仍未退出才强杀；这次退出按预期退出处理。
	cmd.Cancel = func() error {
		m.markStopping(cmd)
		if err := requestGracefulStop(cmd); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = gracefulStopTimeout
	m.stopping = false
	configureProcess(cmd)
	cmd.Dir = filepath.Dir(binary)
	if runtime.GOOS == "android" {
		// APK 里的内核目录只读，cache.db 要写在数据目录。
		cmd.Dir = filepath.Dir(configPath)
	}
	logFile := filepath.Join(filepath.Dir(configPath), "sing-box.log")
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		m.starting = false
		return fmt.Errorf("打开 sing-box 日志失败: %w", err)
	}
	cmd.Stdout = f
	cmd.Stderr = f
	m.logFile = f
	m.logPath = logFile

	if err := startProcess(cmd); err != nil {
		_ = f.Close()
		m.logFile = nil
		m.starting = false
		return fmt.Errorf("启动 sing-box 失败: %w", err)
	}

	m.cmd = cmd
	m.pidPath = pidPath
	m.done = make(chan struct{})
	m.starting = false
	m.generation++
	m.current = m.generation
	_ = writePIDFile(pidPath, cmd.Process.Pid) // 写失败只影响下次残留清理，不阻止启动
	go m.wait(cmd, m.generation)
	return nil
}

// markStopping 把 cmd 的这次退出标记为预期退出。
func (m *Manager) markStopping(cmd *exec.Cmd) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == cmd {
		m.stopping = true
	}
}

func (m *Manager) wait(cmd *exec.Cmd, generation uint64) {
	err := cmd.Wait()
	m.mu.Lock()
	if m.pidPath != "" {
		removePIDFile(m.pidPath, cmd.Process.Pid)
	}
	ownsProcess := m.cmd == cmd
	// 不再归本 Manager 跟踪的进程（Stop 超时后已放弃）退出时不算异常退出，
	// 也不能动新进程的日志文件和 stopping 标记。
	expected := m.stopping || !ownsProcess
	done := m.done
	if ownsProcess {
		m.cmd = nil
		m.done = nil
		m.current = 0
		if m.logFile != nil {
			_ = m.logFile.Close()
			m.logFile = nil
		}
		m.stopping = false
	} else {
		done = nil // 已在放弃跟踪时关闭
	}
	m.mu.Unlock()
	select {
	case m.exited <- ExitEvent{Err: err, Expected: expected, Generation: generation}:
	default:
	}
	if done != nil {
		close(done)
	}
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	if m.starting {
		m.mu.Unlock()
		return fmt.Errorf("sing-box 正在启动，暂时无法停止")
	}
	cmd := m.cmd
	done := m.done
	m.stopping = cmd != nil
	if cmd == nil || cmd.Process == nil {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	if done == nil {
		return killProcess(m, cmd)
	}
	// Ask sing-box to exit on its own first so it can undo auto_route,
	// strict_route rules and DNS changes; kill it only if it does not finish.
	if err := requestGracefulStop(cmd); err == nil {
		timer := time.NewTimer(gracefulStopTimeout)
		select {
		case <-done:
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	killErr := killProcess(m, cmd)
	timer := time.NewTimer(killWaitTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
	}
	// 强杀后仍等不到退出（进程卡在内核态、Kill 失败等）：放弃跟踪，清空状态，
	// 否则下次 Start 会一直以为它还在运行。pid 文件保留，下次 Start 的残留清理会再试着结束它。
	m.abandon(cmd)
	if killErr != nil {
		return fmt.Errorf("强制结束 sing-box 失败: %w", killErr)
	}
	return fmt.Errorf("sing-box 强制结束后 %s 内仍未退出，已放弃等待", killWaitTimeout)
}

// abandon 不再跟踪 cmd：清空运行状态并通知等待者。cmd 之后真正退出时 wait 只按预期退出上报。
func (m *Manager) abandon(cmd *exec.Cmd) {
	m.mu.Lock()
	if m.cmd != cmd {
		m.mu.Unlock()
		return
	}
	done := m.done
	m.cmd = nil
	m.done = nil
	m.current = 0
	m.stopping = false
	if m.logFile != nil {
		_ = m.logFile.Close()
		m.logFile = nil
	}
	m.mu.Unlock()
	if done != nil {
		close(done)
	}
}

func killProcess(m *Manager, cmd *exec.Cmd) error {
	kill := m.kill
	if kill == nil {
		kill = func(cmd *exec.Cmd) error { return cmd.Process.Kill() }
	}
	if err := kill(cmd); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		// Kill 失败时不能继续保留 stopping=true，否则后续异常退出会被误判为预期退出。
		m.mu.Lock()
		if m.cmd == cmd {
			m.stopping = false
		}
		m.mu.Unlock()
		return err
	}
	return nil
}

// Generation returns the generation of the running process, or 0 when no
// process is running.
func (m *Manager) Generation() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmd != nil && m.cmd.Process != nil
}

func (m *Manager) Exited() <-chan ExitEvent { return m.exited }

// InjectExit 仅用于测试：向 exited 通道注入退出事件。
func (m *Manager) InjectExit(err error) {
	m.exited <- ExitEvent{Err: err}
}

// InjectExitEvent 仅用于测试：注入一个完整的退出事件。
func (m *Manager) InjectExitEvent(event ExitEvent) {
	m.exited <- event
}

// SetGenerationForTest 仅用于测试：模拟某一代进程正在运行。
func (m *Manager) SetGenerationForTest(generation uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = generation
	if generation > m.generation {
		m.generation = generation
	}
}

// StartProcess starts cmd bound to sbtun's lifetime (Pdeathsig on Linux, a
// kill-on-close Job on Windows), so a crash never leaves sing-box behind.
func StartProcess(cmd *exec.Cmd) error { return startProcess(cmd) }
