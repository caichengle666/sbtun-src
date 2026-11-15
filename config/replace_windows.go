//go:build windows

package config

import (
	"os"
	"time"
)

// replaceConfigFile 用改名覆盖目标文件。Go 的 os.Rename 在 Windows 上调用
// MoveFileEx(MOVEFILE_REPLACE_EXISTING)，可以直接覆盖已有文件，而且是一步完成：
// 以前先 os.Remove(target) 再改名，改名一旦失败（杀毒软件、索引服务、编辑器短暂占用文件），
// 新旧配置就都没了，下次启动会悄悄换成默认配置。
// 被短暂占用时（共享冲突、拒绝访问）带退避重试几次；失败时旧文件原样保留。
func replaceConfigFile(tempPath, targetPath string) error {
	return renameWithRetry(os.Rename, tempPath, targetPath, replaceAttempts, replaceFirstDelay, time.Sleep)
}
