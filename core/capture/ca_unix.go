//go:build !windows

package capture

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// currentEUID 便于测试模拟以 root 运行。
var currentEUID = os.Geteuid

func createExclusive(path string, _ bool) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
}

func replaceFile(from, to string) error { return os.Rename(from, to) }

func linkCount(_ string, info fs.FileInfo) (uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("无法读取文件链接数")
	}
	return uint64(stat.Nlink), nil
}

// checkPrivateOwner 以 root 运行时要求私钥属于 root，并且不能被其他用户读写。
func checkPrivateOwner(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("无法读取文件属主")
	}
	if currentEUID() == 0 && stat.Uid != 0 {
		return fmt.Errorf("不属于 root（uid=%d）", stat.Uid)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("权限过宽（%o）", info.Mode().Perm())
	}
	return nil
}
