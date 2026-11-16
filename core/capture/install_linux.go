//go:build linux

package capture

import (
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const systemCertificateDir = "/usr/local/share/ca-certificates"

var systemCertificatePath = filepath.Join(systemCertificateDir, "sbtun-capture-ca.crt")

func userCertificateSupported() bool { return false }

// installCertificate 把内存里的 CA（DER）以 PEM 写入系统证书目录，不从工作目录重新读取。
func installCertificate(der []byte, level string) error {
	if level == "user" {
		return fmt.Errorf("Linux 暂不支持自动安装用户级证书，请安装系统级证书或手动导入")
	}
	if err := removeCaptureCAFiles(systemCertificateDir); err != nil {
		return fmt.Errorf("清除旧的系统证书失败，请使用管理员权限运行: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeFileReplace(systemCertificatePath, data, false); err != nil {
		return fmt.Errorf("写入系统证书失败，请使用管理员权限运行: %w", err)
	}
	if err := os.Chmod(systemCertificatePath, 0o644); err != nil {
		return err
	}
	return runUpdateCertificates()
}

// uninstallCertificate 删除系统证书目录里所有 CN 为分析 CA 的证书。
func uninstallCertificate(level string) error {
	if level == "user" {
		return fmt.Errorf("Linux 暂不支持自动卸载用户级证书")
	}
	if err := removeCaptureCAFiles(systemCertificateDir); err != nil {
		return err
	}
	return runUpdateCertificates()
}

// removeCaptureCAFiles 删除 dir 下（不递归）CN 为分析 CA 的 PEM 证书，以及固定文件名的证书。
func removeCaptureCAFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() && entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		match := path == systemCertificatePath
		if !match && entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".crt") {
			match = pemHasCaptureCA(path)
		}
		if match {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func pemHasCaptureCA(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return false
		}
		if block.Type == "CERTIFICATE" && isCaptureCA(block.Bytes) {
			return true
		}
	}
}

func runUpdateCertificates() error {
	cmd := exec.Command("update-ca-certificates")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("更新系统证书失败: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
