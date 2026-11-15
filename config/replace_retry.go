package config

import (
	"errors"
	"os"
	"time"
)

const (
	// replaceAttempts 次尝试，间隔从 replaceFirstDelay 开始翻倍（10+20+40+80+160 ms，总共不到 0.5 秒）。
	replaceAttempts   = 6
	replaceFirstDelay = 10 * time.Millisecond
)

// renameWithRetry 把 from 改名为 to（覆盖），失败时按指数退避重试。源文件已经不存在时不再重试。
// 任何一次失败都不会删除 to：要么换成新文件，要么旧文件原样保留。
func renameWithRetry(rename func(from, to string) error, from, to string, attempts int, delay time.Duration, sleep func(time.Duration)) error {
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for i := 0; i < attempts; i++ {
		if err = rename(from, to); err == nil {
			return nil
		}
		if _, statErr := os.Stat(from); errors.Is(statErr, os.ErrNotExist) {
			return err
		}
		if i < attempts-1 {
			sleep(delay)
			delay *= 2
		}
	}
	return err
}
