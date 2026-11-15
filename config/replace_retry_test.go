package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 改名短暂失败（Windows 上被杀毒软件等占用）时重试，期间旧文件一直在。
func TestRenameWithRetryKeepsTargetUntilSuccess(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "new.tmp"), filepath.Join(dir, "config.json")
	if err := os.WriteFile(from, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	failures := 3
	var delays []time.Duration
	rename := func(a, b string) error {
		if data, err := os.ReadFile(to); err != nil || string(data) != "old" {
			t.Fatalf("target must stay intact before the replace succeeds: %q %v", data, err)
		}
		if failures > 0 {
			failures--
			return &os.LinkError{Op: "rename", Old: a, New: b, Err: errors.New("sharing violation")}
		}
		return os.Rename(a, b)
	}
	if err := renameWithRetry(rename, from, to, 6, 10*time.Millisecond, func(d time.Duration) { delays = append(delays, d) }); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(to); string(data) != "new" {
		t.Fatalf("target=%q", data)
	}
	if len(delays) != 3 || delays[0] != 10*time.Millisecond || delays[2] != 40*time.Millisecond {
		t.Fatalf("delays=%v", delays)
	}
}

// 一直失败：返回错误，旧文件原样保留（以前先删旧文件再改名，这时新旧都没了）。
func TestRenameWithRetryGivesUpWithoutLosingTarget(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "new.tmp"), filepath.Join(dir, "config.json")
	_ = os.WriteFile(from, []byte("new"), 0o600)
	_ = os.WriteFile(to, []byte("old"), 0o600)
	calls := 0
	err := renameWithRetry(func(string, string) error { calls++; return errors.New("access denied") }, from, to, 4, time.Millisecond, func(time.Duration) {})
	if err == nil || calls != 4 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	if data, _ := os.ReadFile(to); string(data) != "old" {
		t.Fatalf("old config lost: %q", data)
	}
}

// 源文件不存在时不白白重试。
func TestRenameWithRetryStopsWhenSourceMissing(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	err := renameWithRetry(func(a, b string) error { calls++; return os.Rename(a, b) }, filepath.Join(dir, "missing"), filepath.Join(dir, "x"), 6, time.Millisecond, func(time.Duration) {})
	if err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

// 实际替换路径：覆盖已有文件、不留临时文件（Windows 上走 MoveFileEx 覆盖）。
func TestReplaceConfigFileOverwrites(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "new.tmp"), filepath.Join(dir, "config.json")
	_ = os.WriteFile(from, []byte("new"), 0o600)
	_ = os.WriteFile(to, []byte("old"), 0o600)
	if err := ReplaceConfigFile(from, to); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(to); string(data) != "new" {
		t.Fatalf("target=%q", data)
	}
	if _, err := os.Stat(from); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
}
