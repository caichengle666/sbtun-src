package capture

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func newCAManager(t *testing.T) *Manager {
	t.Helper()
	return NewManager(filepath.Join(t.TempDir(), "capture"), "127.0.0.1:0", "")
}

func mustEnsureCA(t *testing.T, m *Manager) []byte {
	t.Helper()
	m.mu.Lock()
	cert, err := m.ensureCA()
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return cert.Certificate[0]
}

func readCertDER(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("证书文件不是 PEM")
	}
	return block.Bytes
}

func TestGeneratedCAHasOneYearValidityAndMaxPathLenZero(t *testing.T) {
	m := newCAManager(t)
	der := mustEnsureCA(t, m)
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got != caValidity {
		t.Fatalf("有效期 = %v，期望 %v", got, caValidity)
	}
	if !leaf.IsCA || !leaf.BasicConstraintsValid {
		t.Fatal("证书应是 CA")
	}
	if leaf.MaxPathLen != 0 || !leaf.MaxPathLenZero {
		t.Fatalf("MaxPathLen=%d MaxPathLenZero=%t，期望 0/true", leaf.MaxPathLen, leaf.MaxPathLenZero)
	}
	if len(leaf.PermittedDNSDomains) != 0 || leaf.PermittedDNSDomainsCritical {
		t.Fatal("不应设置 NameConstraints")
	}
	if leaf.Subject.CommonName != caCommonName {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(m.keyPath())
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("私钥权限 = %o", info.Mode().Perm())
		}
	}
	// 再次加载应复用同一张证书。
	if again := mustEnsureCA(t, m); !bytes.Equal(again, der) {
		t.Fatal("有效的 CA 不应被重新生成")
	}
	if m.caNotice != "" {
		t.Fatalf("首次生成不应有提示: %s", m.caNotice)
	}
}

func TestCARegeneratedWhenKeyDoesNotMatch(t *testing.T) {
	m := newCAManager(t)
	first := mustEnsureCA(t, m)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)})
	if err := os.WriteFile(m.keyPath(), otherPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCA(m.certPath(), m.keyPath(), time.Now()); !errors.Is(err, errCARegenerate) {
		t.Fatalf("私钥不匹配应要求重新生成，得到 %v", err)
	}
	second := mustEnsureCA(t, m)
	if bytes.Equal(first, second) {
		t.Fatal("私钥不匹配时应重新生成 CA")
	}
	if _, err := loadCA(m.certPath(), m.keyPath(), time.Now()); err != nil {
		t.Fatalf("重新生成后应能加载: %v", err)
	}
	if m.caNotice == "" {
		t.Fatal("重新生成后应提示用户重新安装")
	}
}

func TestCARegeneratedWhenKeyIsHardLinked(t *testing.T) {
	m := newCAManager(t)
	first := mustEnsureCA(t, m)
	outside := filepath.Join(t.TempDir(), "stolen.key")
	if err := os.Link(m.keyPath(), outside); err != nil {
		t.Skipf("不支持硬链接: %v", err)
	}
	if _, err := loadCA(m.certPath(), m.keyPath(), time.Now()); !errors.Is(err, errCARegenerate) {
		t.Fatalf("硬链接的私钥应要求重新生成，得到 %v", err)
	}
	second := mustEnsureCA(t, m)
	if bytes.Equal(first, second) {
		t.Fatal("私钥存在硬链接时应重新生成 CA")
	}
	// 新私钥不能写进硬链接的另一端。
	stolen, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(m.keyPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(stolen, current) {
		t.Fatal("新私钥被写入了硬链接指向的文件")
	}
}

func TestCARegeneratedWhenKeyIsSymlink(t *testing.T) {
	m := newCAManager(t)
	first := mustEnsureCA(t, m)
	target := filepath.Join(t.TempDir(), "attacker.key")
	data, err := os.ReadFile(m.keyPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.keyPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, m.keyPath()); err != nil {
		t.Skipf("不支持符号链接: %v", err)
	}
	if _, err := loadCA(m.certPath(), m.keyPath(), time.Now()); !errors.Is(err, errCARegenerate) {
		t.Fatalf("符号链接的私钥应要求重新生成，得到 %v", err)
	}
	second := mustEnsureCA(t, m)
	if bytes.Equal(first, second) {
		t.Fatal("私钥是符号链接时应重新生成 CA")
	}
	info, err := os.Lstat(m.keyPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("重新生成后私钥仍是符号链接")
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, data) {
		t.Fatal("新私钥被写进了符号链接指向的文件")
	}
}

func TestCARegeneratedWhenCertificateIsSymlink(t *testing.T) {
	m := newCAManager(t)
	first := mustEnsureCA(t, m)
	target := filepath.Join(t.TempDir(), "attacker.crt")
	data, err := os.ReadFile(m.certPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.certPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, m.certPath()); err != nil {
		t.Skipf("不支持符号链接: %v", err)
	}
	if bytes.Equal(first, mustEnsureCA(t, m)) {
		t.Fatal("证书是符号链接时应重新生成 CA")
	}
}

// writeLegacyCA 生成旧版规格（10 年、无 MaxPathLenZero）的 CA 文件。
func writeLegacyCA(t *testing.T, m *Manager, notBefore, notAfter time.Time, maxPathLenZero bool) {
	t.Helper()
	if err := os.MkdirAll(m.workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: caCommonName, Organization: []string{"sbtun"}},
		NotBefore:    notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: maxPathLenZero,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.certPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.keyPath(), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCARegeneratedForLegacyOrExpiringCertificates(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name                string
		notBefore, notAfter time.Time
		maxPathLenZero      bool
	}{
		{"十年有效期", now.Add(-time.Hour), now.AddDate(10, 0, 0), true},
		{"没有 MaxPathLenZero", now.Add(-time.Hour), now.Add(300 * 24 * time.Hour), false},
		{"少于 30 天过期", now.Add(-340 * 24 * time.Hour), now.Add(20 * 24 * time.Hour), true},
		{"已过期", now.Add(-400 * 24 * time.Hour), now.Add(-time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newCAManager(t)
			writeLegacyCA(t, m, tc.notBefore, tc.notAfter, tc.maxPathLenZero)
			old := readCertDER(t, m.certPath())
			if _, err := loadCA(m.certPath(), m.keyPath(), now); !errors.Is(err, errCARegenerate) {
				t.Fatalf("应要求重新生成，得到 %v", err)
			}
			if bytes.Equal(old, mustEnsureCA(t, m)) {
				t.Fatal("应重新生成 CA")
			}
		})
	}
	// 对照：符合规格且离过期还远的证书不应被替换。
	m := newCAManager(t)
	writeLegacyCA(t, m, now.Add(-time.Hour), now.Add(200*24*time.Hour), true)
	old := readCertDER(t, m.certPath())
	if !bytes.Equal(old, mustEnsureCA(t, m)) {
		t.Fatal("符合规格的 CA 不应被重新生成")
	}
}

func TestStatusReportsCertificateStillTrustedAfterStop(t *testing.T) {
	m := newCAManager(t)
	mustEnsureCA(t, m)
	if err := os.WriteFile(m.installMarkerPath("system"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := m.Status(false)
	if !status.CertificateInstalled || !status.CertificateStillTrusted || status.CertificateNotice == "" {
		t.Fatalf("停止后应提示证书仍被信任: %+v", status)
	}
	if err := os.Remove(m.installMarkerPath("system")); err != nil {
		t.Fatal(err)
	}
	if status := m.Status(false); status.CertificateStillTrusted || status.CertificateNotice != "" {
		t.Fatalf("未安装证书时不应提示: %+v", status)
	}
}

func TestRemoveLocalCADeletesKeyAndCertificate(t *testing.T) {
	m := newCAManager(t)
	mustEnsureCA(t, m)
	if err := m.removeLocalCA(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{m.keyPath(), m.certPath()} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s 应已删除: %v", path, err)
		}
	}
}
