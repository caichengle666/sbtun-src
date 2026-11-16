//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestShareWithInvokerSetsModeAndOwner(t *testing.T) {
	t.Setenv("SUDO_UID", strconv.Itoa(os.Getuid()))
	t.Setenv("SUDO_GID", strconv.Itoa(os.Getgid()))
	path := filepath.Join(t.TempDir(), "sets.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ShareWithInvoker(path, 0o644); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o644 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Getuid() {
		t.Fatalf("mode=%v", info.Mode())
	}
}

// root 下把旧版本留下的 root 文件交还调用者，私钥除外。非 root 环境跳过。
func TestShareTreeWithInvokerSkipsPrivateKeys(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root")
	}
	t.Setenv("SUDO_UID", "12345")
	t.Setenv("SUDO_GID", "12345")
	dir := t.TempDir()
	for _, name := range []string{"config.json", "ca.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ShareTreeWithInvoker(dir)
	uid := func(name string) uint32 {
		info, _ := os.Stat(filepath.Join(dir, name))
		return info.Sys().(*syscall.Stat_t).Uid
	}
	if uid("config.json") != 12345 || uid("ca.key") != 0 {
		t.Fatalf("config=%d key=%d", uid("config.json"), uid("ca.key"))
	}
}

// 模拟 sudo 下以 root 运行（isPrivileged=true，当前用户当作 root），检查不跟随符号链接、不碰硬链接、不碰别人的文件。
func asFakeRoot(t *testing.T) {
	t.Helper()
	oldPriv, oldTrusted := isPrivileged, trustedUID
	isPrivileged = func() bool { return true }
	trustedUID = os.Getuid()
	t.Cleanup(func() { isPrivileged, trustedUID = oldPriv, oldTrusted })
}

func TestPrivilegedChmodDoesNotFollowFinalSymlink(t *testing.T) {
	asFakeRoot(t)
	t.Setenv("SUDO_UID", strconv.Itoa(os.Getuid()))
	t.Setenv("SUDO_GID", strconv.Itoa(os.Getgid()))
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "sets.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := ShareWithInvoker(link, 0o644); err == nil {
		t.Fatal("ShareWithInvoker followed a symlink")
	}
	if info, _ := os.Stat(victim); info.Mode().Perm() != 0o600 {
		t.Fatalf("symlink target was chmodded: %v", info.Mode())
	}
	if err := applyOwnership(link, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("applyOwnership followed a symlink")
	}
}

func TestPrivilegedChownRefusesUserSymlinkInPath(t *testing.T) {
	asFakeRoot(t)
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	// 链接属主是“root”（trustedUID = 当前用户）：允许，像 macOS 的 /var → /private/var。
	if err := ShareWithInvoker(filepath.Join(dir, "link", "f"), 0o640); err != nil {
		t.Fatalf("trusted symlink in path refused: %v", err)
	}
	// 链接属主是普通用户：拒绝。
	trustedUID = os.Getuid() + 1
	t.Setenv("SUDO_UID", strconv.Itoa(os.Getuid()))
	if err := ShareWithInvoker(filepath.Join(dir, "link", "f"), 0o600); err == nil {
		t.Fatal("user-owned symlink in the middle of the path was followed")
	}
	if info, _ := os.Stat(filepath.Join(real, "f")); info.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed through user symlink: %v", info.Mode())
	}
}

func TestPrivilegedChownRefusesHardLinksAndForeignOwners(t *testing.T) {
	asFakeRoot(t)
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "config.json.lock")
	if err := os.Link(victim, hard); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	if err := ShareWithInvoker(hard, 0o644); err == nil {
		t.Fatal("hard-linked file was modified")
	}
	if info, _ := os.Stat(victim); info.Mode().Perm() != 0o600 {
		t.Fatalf("hard link target chmodded: %v", info.Mode())
	}

	// 属主既不是 root 也不是调用者的文件不碰：当前用户既不当 root 也不当调用者。
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	trustedUID = os.Getuid() + 1
	if err := setMetadata(plain, os.Getuid()+2, -1, 0o644, true); err == nil {
		t.Fatal("file owned by another user was modified")
	}
	if info, _ := os.Stat(plain); info.Mode().Perm() != 0o600 {
		t.Fatalf("foreign file chmodded: %v", info.Mode())
	}
}

func TestLockRefusesSymlinkedLockFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	path := filepath.Join(dir, "config.json")
	if err := os.Symlink(target, path+".lock"); err != nil {
		t.Fatal(err)
	}
	if err := withConfigLock(path, func() error { return nil }); err == nil {
		t.Fatal("lock followed a symlink")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("lock created the symlink target: %v", err)
	}
}

func TestShareTreeSkipsSymlinks(t *testing.T) {
	asFakeRoot(t)
	t.Setenv("SUDO_UID", strconv.Itoa(os.Getuid()))
	t.Setenv("SUDO_GID", strconv.Itoa(os.Getgid()))
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(victim, filepath.Join(dir, "evil")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "evildir")); err != nil {
		t.Fatal(err)
	}
	ShareTreeWithInvoker(dir) // 不能 panic，也不能跟进链接（这里属主相同，只能靠不跟随保证）
	if info, _ := os.Stat(victim); info.Mode().Perm() != 0o600 {
		t.Fatalf("victim changed: %v", info.Mode())
	}
}
