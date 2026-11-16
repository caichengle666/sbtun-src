//go:build !android

package app

import "github.com/wailsapp/wails/v2/pkg/runtime"

func (a *App) emitDownloadProgress(kind string, done, total int64) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "download-progress", kind, done, total)
	}
}

// emitStatusChanged 通知界面运行状态变了，界面马上重新拉取状态。异步发出，不占用调用方持有的锁。
func (a *App) emitStatusChanged() {
	if a.ctx != nil {
		go runtime.EventsEmit(a.ctx, "status-changed")
	}
}

func (a *App) HideToTray() {
	if a.ctx != nil {
		runtime.WindowHide(a.ctx)
	}
}

func (a *App) ShowWindow() {
	if a.ctx != nil {
		runtime.WindowShow(a.ctx)
		runtime.WindowUnminimise(a.ctx)
	}
}

func (a *App) MinimizeToTray() {
	a.HideToTray()
}

func (a *App) CloseToTray() {
	a.HideToTray()
}

func (a *App) QuitApp() {
	// Let Wails invoke OnShutdown so the proxy and TUN state are cleaned up.
	if a.ctx != nil {
		runtime.Quit(a.ctx)
	}
}
