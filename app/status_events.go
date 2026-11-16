package app

import "github.com/caichengle666/sbtun/core"

// watchStatusChanges 让运行状态（启动中/运行中/停止/出错）一变化就推送事件给界面，
// 不用等前端下一次 2 秒轮询，状态显示不再最多滞后 2 秒。只在 GUI 下调用。
func (a *App) watchStatusChanges() {
	if a.runtime == nil || a.runtime.State == nil {
		return
	}
	a.runtime.State.OnChange(func(core.RuntimeState, string) { a.emitStatusChanged() })
}
