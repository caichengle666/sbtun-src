//go:build darwin

package capture

import (
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const systemKeychain = "/Library/Keychains/System.keychain"

func userCertificateSupported() bool { return false }

// installCertificate 把内存里的 CA 写到新建的 0700 临时目录，再交给 security 导入，
// 不从可能被替换的工作目录路径读取。
func installCertificate(der []byte, level string) error {
	if level == "user" {
		return fmt.Errorf("macOS 只支持安装到系统钥匙串")
	}
	dir, err := os.MkdirTemp("", "sbtun-ca-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "sbtun-capture-ca.pem")
	file, err := createExclusive(path, false)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return writeErr
	}
	// 先按名称清掉旧证书，避免旧 CA 一直留在信任列表里。
	_ = deleteKeychainCertificates()
	return runSecurity("add-trusted-cert", "-d", "-r", "trustRoot", "-k", systemKeychain, path)
}

// uninstallCertificate 按 CN 从系统钥匙串删除所有分析 CA（连同信任设置）。
func uninstallCertificate(level string) error {
	if level == "user" {
		return fmt.Errorf("macOS 只支持从系统钥匙串卸载")
	}
	return deleteKeychainCertificates()
}

// deleteKeychainCertificates 循环删除同名证书，直到找不到为止。
func deleteKeychainCertificates() error {
	for i := 0; i < 64; i++ {
		if runSecurity("find-certificate", "-c", caCommonName, systemKeychain) != nil {
			return nil
		}
		if err := runSecurity("delete-certificate", "-t", "-c", caCommonName, systemKeychain); err != nil {
			return err
		}
	}
	return fmt.Errorf("系统钥匙串中的 %s 证书过多，未能全部删除", caCommonName)
}

func runSecurity(args ...string) error {
	if out, err := exec.Command("security", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("security %s 失败: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}
