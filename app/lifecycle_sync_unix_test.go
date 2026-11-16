//go:build !windows

package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 未运行时保存配置：sing-box check 失败时 runtime.json 保持旧内容并返回错误，通过后才替换。
func TestSyncConfigKeepsRuntimeConfigWhenCheckFails(t *testing.T) {
	r, _ := newReloadTestRuntime(t)
	if _, err := r.SyncConfig(reloadTestConfig("good", 1080)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(r.configPath())
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.SyncConfig(reloadTestConfig("bad", 1080))
	if err == nil || !strings.Contains(err.Error(), ErrConfigInvalid) || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("SyncConfig err=%v", err)
	}
	after, _ := os.ReadFile(r.configPath())
	if !bytes.Equal(before, after) {
		t.Fatal("check 失败后 runtime.json 被覆盖")
	}
	if matches, _ := filepath.Glob(filepath.Join(r.WorkDir, ".runtime-*")); len(matches) != 0 {
		t.Fatalf("临时文件未清理: %v", matches)
	}
	if _, err := r.SyncConfig(reloadTestConfig("better", 1081)); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(r.configPath()); !bytes.Contains(data, []byte("node-better")) {
		t.Fatal("check 通过后应替换 runtime.json")
	}
}

// 还没有内核时无法 check，仍要能保存配置（启动时会再校验）。
func TestSyncConfigWithoutBinaryStillWrites(t *testing.T) {
	r, _ := newReloadTestRuntime(t)
	r.Binary = filepath.Join(t.TempDir(), "missing-sing-box")
	if _, err := r.SyncConfig(reloadTestConfig("bad", 1080)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.configPath()); err != nil {
		t.Fatal(err)
	}
}
