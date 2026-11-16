package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/caichengle666/sbtun/core"
)

// ErrSingBoxRestartLimit 表示 sing-box 短时间内反复异常退出，已停止自动重启。
const ErrSingBoxRestartLimit = "SINGBOX_RESTART_LIMIT"

const (
	// autoRestartMax 是 autoRestartWindow 内最多自动重启的次数，超过就停止重启。
	autoRestartMax    = 3
	autoRestartWindow = time.Minute
	// autoRestartBaseDelay 是第一次重启前的等待，之后每次翻倍（1s、2s、4s）。
	autoRestartBaseDelay = time.Second
	// exitReportName 记录最近一次放弃自动重启的原因，另一个进程里的 CLI status 读它。
	exitReportName = "sing-box-exit.json"
)

// AutoRestartStatus 描述 sing-box 异常退出后的自动重启情况，GUI 和 CLI 状态里展示。
type AutoRestartStatus struct {
	// Count 是最近一分钟内已经安排的自动重启次数。
	Count int `json:"count"`
	// GaveUp 为 true 表示次数用完、已停止自动重启，需要用户手动启动。
	GaveUp bool `json:"gave_up"`
	// Reason 是最近一次异常退出（或放弃重启）的原因。
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at,omitempty"`
}

// AutoRestartStatus 返回当前的自动重启状态；从未异常退出过时为零值。
// 不拿 r.mu：启动等就绪时 r.mu 会被持有十秒，界面轮询状态不能被卡住。
func (r *RuntimeCoordinator) AutoRestartStatus() AutoRestartStatus {
	r.restartMu.Lock()
	defer r.restartMu.Unlock()
	return r.restartStatus
}

// setRestartStatusLocked 更新自动重启状态。调用方持有 r.mu。
func (r *RuntimeCoordinator) setRestartStatusLocked(status AutoRestartStatus) {
	r.restartMu.Lock()
	r.restartStatus = status
	r.restartMu.Unlock()
}

// cancelAutoRestartLocked 让已经安排、还没执行的自动重启作废。用户主动启动、停止、重载时调用，
// 之后的启停由用户的操作决定。reset 为 true 时同时清空重启计数和状态（用户重新启动）。
func (r *RuntimeCoordinator) cancelAutoRestartLocked(reset bool) {
	r.restartToken++
	if reset {
		r.restartTimes = nil
		r.setRestartStatusLocked(AutoRestartStatus{})
		r.removeExitReport()
	}
}

// scheduleRestartLocked 在 sing-box 异常退出（或自动重启失败）后决定是否再重启：一分钟内不超过
// autoRestartMax 次，每次之间退避；次数用完就停止重启并把原因写进状态。调用方持有 r.mu，
// 且已经把状态设为 StateError。
func (r *RuntimeCoordinator) scheduleRestartLocked(reason string) {
	ctx := r.runCtx
	if !r.activeConfigSet || ctx == nil || ctx.Err() != nil || r.SingBox == nil {
		return
	}
	now := r.restartClock()
	kept := r.restartTimes[:0]
	for _, at := range r.restartTimes {
		if now.Sub(at) < autoRestartWindow {
			kept = append(kept, at)
		}
	}
	r.restartTimes = kept
	if len(kept) >= autoRestartMax {
		message := fmt.Sprintf("%s: sing-box 1 分钟内已自动重启 %d 次仍然退出，已停止自动重启，请检查后手动启动。最后一次退出原因: %s",
			ErrSingBoxRestartLimit, autoRestartMax, reason)
		status := AutoRestartStatus{Count: len(kept), GaveUp: true, Reason: message, At: now}
		r.setRestartStatusLocked(status)
		r.State.Set(core.StateError, message)
		r.saveExitReport(status)
		return
	}
	base := r.restartBaseDelay
	if base <= 0 {
		base = autoRestartBaseDelay
	}
	delay := base << len(kept)
	r.restartTimes = append(r.restartTimes, now)
	attempt := len(r.restartTimes)
	r.setRestartStatusLocked(AutoRestartStatus{Count: attempt, Reason: reason, At: now})
	r.State.Set(core.StateError, fmt.Sprintf("%s；%s 后自动重启（1 分钟内第 %d/%d 次）", reason, delay, attempt, autoRestartMax))
	token := r.restartToken
	go r.restartAfter(ctx, token, delay, attempt, reason)
}

func (r *RuntimeCoordinator) restartClock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// restartAfter 等待 delay 后用当前生效的配置（runtime.json 就是它）重新拉起 sing-box。
// 期间用户停止、启动、重载或应用退出（ctx 取消）都会让这次重启作废。
func (r *RuntimeCoordinator) restartAfter(ctx context.Context, token uint64, delay time.Duration, attempt int, reason string) {
	timer := time.NewTimer(delay)
	select {
	case <-ctx.Done():
		timer.Stop()
		return
	case <-timer.C:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.restartToken != token || ctx.Err() != nil || !r.activeConfigSet {
		return
	}
	if state, _ := r.State.Get(); state != core.StateError || r.SingBox.Running() {
		return
	}
	r.firewallKnown = false
	cfg := r.activeConfig
	built := builtConfig{data: r.activeData, resolved: r.activeResolved}
	if err := r.launchLocked(ctx, cfg, built); err != nil {
		// 启动失败也算一次重启，按同样的次数限制继续。
		_, message := r.State.Get()
		r.scheduleRestartLocked(message)
		return
	}
	_, message := r.State.Get()
	note := fmt.Sprintf("sing-box 异常退出后已自动重启（1 分钟内第 %d 次），退出原因: %s", attempt, reason)
	if message != "" {
		note = message + "；" + note
	}
	r.State.Set(core.StateRunning, note)
}

func (r *RuntimeCoordinator) exitReportPath() string {
	if r.WorkDir == "" {
		return ""
	}
	return filepath.Join(r.WorkDir, exitReportName)
}

// saveExitReport 把放弃自动重启的原因写进运行目录，CLI 的 status 在别的进程里也能看到。
func (r *RuntimeCoordinator) saveExitReport(status AutoRestartStatus) {
	path := r.exitReportPath()
	if path == "" {
		return
	}
	data, err := json.Marshal(status)
	if err != nil {
		return
	}
	if err := os.MkdirAll(r.WorkDir, 0o755); err != nil {
		return
	}
	_ = atomicWrite(path, data, nil)
}

func (r *RuntimeCoordinator) removeExitReport() {
	if path := r.exitReportPath(); path != "" {
		_ = os.Remove(path)
	}
}

// loadExitReport 读取运行目录里记录的放弃自动重启原因（可能由另一个 sbtun 进程写入）。
func loadExitReport(workDir string) (AutoRestartStatus, bool) {
	if workDir == "" {
		return AutoRestartStatus{}, false
	}
	data, err := os.ReadFile(filepath.Join(workDir, exitReportName))
	if err != nil {
		return AutoRestartStatus{}, false
	}
	var status AutoRestartStatus
	if json.Unmarshal(data, &status) != nil || !status.GaveUp {
		return AutoRestartStatus{}, false
	}
	return status, true
}
