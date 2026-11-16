//go:build !windows

package capture

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"
)

func TestCARegeneratedWhenRootDoesNotOwnKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("测试以 root 运行，私钥本来就属于 root")
	}
	m := newCAManager(t)
	first := mustEnsureCA(t, m)
	if _, err := loadCA(m.certPath(), m.keyPath(), time.Now()); err != nil {
		t.Fatalf("普通用户下应能加载自己的私钥: %v", err)
	}
	original := currentEUID
	currentEUID = func() int { return 0 }
	defer func() { currentEUID = original }()
	if _, err := loadCA(m.certPath(), m.keyPath(), time.Now()); !errors.Is(err, errCARegenerate) {
		t.Fatalf("以 root 运行而私钥不属于 root 时应要求重新生成，得到 %v", err)
	}
	// 模拟环境下新文件仍属于当前用户，只验证确实触发了重新生成。
	m.mu.Lock()
	_, _ = m.ensureCA()
	m.mu.Unlock()
	currentEUID = original
	if bytes.Equal(first, readCertDER(t, m.certPath())) {
		t.Fatal("应重新生成 CA")
	}
}

func TestCARegeneratedWhenKeyIsWorldReadable(t *testing.T) {
	m := newCAManager(t)
	first := mustEnsureCA(t, m)
	if err := os.Chmod(m.keyPath(), 0o644); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, mustEnsureCA(t, m)) {
		t.Fatal("私钥权限过宽时应重新生成 CA")
	}
}
