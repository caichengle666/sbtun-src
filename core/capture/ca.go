package capture

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	// caCommonName 也是卸载时在各平台信任库里查找证书用的名称。
	caCommonName = "sbtun Local Capture CA"
	// caValidity 是新生成的分析 CA 的有效期。根证书一旦被信任，私钥泄露就能
	// 冒充任意网站，所以有效期控制在 1 年，到期前自动换新。
	caValidity = 365 * 24 * time.Hour
	// caRenewBefore 内即将过期的 CA 会被重新生成。
	caRenewBefore = 30 * 24 * time.Hour
	// caMaxValiditySlack 容忍生成时的 NotBefore 回拨等小误差。
	caMaxValiditySlack = 2 * 24 * time.Hour
)

// errCARegenerate 表示磁盘上的 CA 不可再用，需要重新生成。
var errCARegenerate = errors.New("分析 CA 需要重新生成")

// timeNow 便于测试替换当前时间。
var timeNow = time.Now

// caFingerprint 返回证书 DER 的 SHA-256 指纹（十六进制）。
func caFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ensureCA 返回可用的分析 CA；磁盘上的 CA 缺失、被篡改、和私钥不匹配、
// 是旧版或快过期时重新生成。regenerated 表示本次替换了已有的 CA 文件。
// 调用方需持有 m.mu。
func (m *Manager) ensureCA() (tls.Certificate, error) {
	if err := os.MkdirAll(m.workDir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("创建分析证书目录失败: %w", err)
	}
	cert, loadErr := loadCA(m.certPath(), m.keyPath(), timeNow())
	if loadErr == nil {
		return cert, nil
	}
	existed := fileExists(m.certPath()) || fileExists(m.keyPath())
	cert, err := generateCA(m.certPath(), m.keyPath(), timeNow())
	if err != nil {
		return tls.Certificate{}, err
	}
	if existed {
		m.caNotice = "分析证书已重新生成（" + loadErr.Error() + "），如之前安装过旧证书，请重新安装"
	}
	return cert, nil
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// generateCA 生成新的 CA 并原子地替换证书和私钥文件。
func generateCA(certPath, keyPath string, now time.Time) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	notBefore := now.Add(-time.Hour)
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: caCommonName, Organization: []string{"sbtun"}},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(caValidity),
		IsCA:         true, BasicConstraintsValid: true,
		// 只允许直接签发网站证书，不允许再派生中间 CA。
		// 不加 NameConstraints：抓包规则支持 * 和关键词，需要为任意域名签发。
		MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	// 先写私钥再写证书：任何一步失败，下次加载都会因不匹配而重新生成。
	if err := writeFileReplace(keyPath, keyPEM, true); err != nil {
		return tls.Certificate{}, fmt.Errorf("写入分析 CA 私钥失败: %w", err)
	}
	if err := writeFileReplace(certPath, certPEM, false); err != nil {
		return tls.Certificate{}, fmt.Errorf("写入分析 CA 证书失败: %w", err)
	}
	return parseCA(certPEM, keyPEM, now)
}

// writeFileReplace 把 data 写进同目录的新临时文件（O_EXCL，不跟随已有文件），
// 再 rename 覆盖 path。rename 替换的是目录项本身，path 是符号链接或硬链接时
// 不会写到链接指向的文件里。
func writeFileReplace(path string, data []byte, private bool) error {
	dir := filepath.Dir(path)
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(suffix[:]))
	f, err := createExclusive(tmp, private)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(tmp)
		return writeErr
	}
	if err := replaceFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// loadCA 读取并校验磁盘上的 CA。返回错误时调用方应重新生成。
func loadCA(certPath, keyPath string, now time.Time) (tls.Certificate, error) {
	if err := checkCAFile(keyPath, true); err != nil {
		return tls.Certificate{}, err
	}
	if err := checkCAFile(certPath, false); err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	return parseCA(certPEM, keyPEM, now)
}

// checkCAFile 拒绝符号链接、非普通文件和硬链接；私钥还要求属主可信、权限私有。
func checkCAFile(path string, private bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s 是符号链接: %w", filepath.Base(path), errCARegenerate)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s 不是普通文件: %w", filepath.Base(path), errCARegenerate)
	}
	links, err := linkCount(path, info)
	if err != nil {
		return err
	}
	if links > 1 {
		return fmt.Errorf("%s 存在硬链接: %w", filepath.Base(path), errCARegenerate)
	}
	if private {
		if err := checkPrivateOwner(info); err != nil {
			return fmt.Errorf("%s %v: %w", filepath.Base(path), err, errCARegenerate)
		}
	}
	return nil
}

// parseCA 解析 PEM，校验私钥和证书匹配、证书自签名有效，以及是否符合当前的 CA 规格。
func parseCA(certPEM, keyPEM []byte, now time.Time) (tls.Certificate, error) {
	// tls.X509KeyPair 会校验私钥与证书公钥是否匹配。
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("证书与私钥不匹配或格式无效: %v: %w", err, errCARegenerate)
	}
	if len(cert.Certificate) != 1 {
		return tls.Certificate{}, fmt.Errorf("证书文件应只包含一张证书: %w", errCARegenerate)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("解析证书失败: %v: %w", err, errCARegenerate)
	}
	if err := validateCALeaf(leaf, now); err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf = leaf
	return cert, nil
}

func validateCALeaf(leaf *x509.Certificate, now time.Time) error {
	switch {
	case leaf.Subject.CommonName != caCommonName:
		return fmt.Errorf("证书名称不符: %w", errCARegenerate)
	case !bytes.Equal(leaf.RawIssuer, leaf.RawSubject) || leaf.CheckSignatureFrom(leaf) != nil:
		return fmt.Errorf("证书不是有效的自签名 CA: %w", errCARegenerate)
	case !leaf.IsCA || !leaf.BasicConstraintsValid:
		return fmt.Errorf("证书不是 CA: %w", errCARegenerate)
	case leaf.MaxPathLen != 0 || !leaf.MaxPathLenZero:
		return fmt.Errorf("旧版证书未限制路径长度: %w", errCARegenerate)
	case leaf.NotAfter.Sub(leaf.NotBefore) > caValidity+caMaxValiditySlack:
		return fmt.Errorf("旧版证书有效期过长: %w", errCARegenerate)
	case now.Before(leaf.NotBefore):
		return fmt.Errorf("证书尚未生效: %w", errCARegenerate)
	case leaf.NotAfter.Sub(now) < caRenewBefore:
		return fmt.Errorf("证书即将过期: %w", errCARegenerate)
	}
	return nil
}

// isCaptureCA 判断 DER 证书是否是 sbtun 生成的分析 CA（按 CN 匹配，用于卸载）。
func isCaptureCA(der []byte) bool {
	cert, err := x509.ParseCertificate(der)
	return err == nil && cert.Subject.CommonName == caCommonName
}

// removeLocalCA 删除本地的私钥和证书文件（不跟随符号链接）。
func (m *Manager) removeLocalCA() error {
	var firstErr error
	for _, path := range []string{m.keyPath(), m.certPath()} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
