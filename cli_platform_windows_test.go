//go:build windows && cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 带空格、单引号和空字符串的参数提权后要原样传给子进程。
func TestElevatedArgumentsQuotesEachArgument(t *testing.T) {
	got := elevatedArguments([]string{"edit", "1", "My Node", "it's", ""})
	want := `'edit 1 "My Node" it''s ""'`
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestTrimFinalPathPrefix(t *testing.T) {
	cases := map[string]string{
		`\\?\C:\Program Files\sbtun\sbtun-cli.exe`: `C:\Program Files\sbtun\sbtun-cli.exe`,
		`\\?\UNC\server\share\sbtun-cli.exe`:       `\\server\share\sbtun-cli.exe`,
		`C:\sbtun\sbtun-cli.exe`:                   `C:\sbtun\sbtun-cli.exe`,
	}
	for in, want := range cases {
		if got := trimFinalPathPrefix(in); got != want {
			t.Fatalf("trimFinalPathPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// 普通文件解析成真实路径；指向它的符号链接要被拒绝（没有创建符号链接的权限时跳过这一半）。
func TestResolveElevationTargetRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sbtun-cli.exe")
	if err := os.WriteFile(target, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveElevationTarget(target)
	if err != nil {
		t.Fatalf("普通文件应能解析: %v", err)
	}
	if !strings.EqualFold(filepath.Base(got), "sbtun-cli.exe") || strings.HasPrefix(got, `\\?\`) {
		t.Fatalf("解析结果异常: %s", got)
	}
	link := filepath.Join(dir, "link.exe")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}
	if _, err := resolveElevationTarget(link); err == nil {
		t.Fatal("符号链接应被拒绝")
	}
}
