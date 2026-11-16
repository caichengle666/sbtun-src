//go:build windows

package capture

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func userCertificateSupported() bool { return true }

const certEncoding = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING

func openRootStore(level string) (windows.Handle, error) {
	location := uint32(windows.CERT_SYSTEM_STORE_LOCAL_MACHINE)
	if level == "user" {
		location = windows.CERT_SYSTEM_STORE_CURRENT_USER
	}
	name, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		return 0, err
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, location, uintptr(unsafe.Pointer(name)))
	if err != nil {
		if level == "user" {
			return 0, fmt.Errorf("打开当前用户根证书存储失败: %w", err)
		}
		return 0, fmt.Errorf("打开系统根证书存储失败，请使用管理员权限运行: %w", err)
	}
	return store, nil
}

// installCertificate 直接把内存里的 CA（DER）加入根证书存储，不经过磁盘文件。
func installCertificate(der []byte, level string) error {
	if len(der) == 0 {
		return errors.New("分析 CA 证书为空")
	}
	store, err := openRootStore(level)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	// 先按名称删除旧的分析 CA，避免旧证书一直被信任。
	if err := deleteCaptureCAs(store); err != nil {
		return err
	}
	ctx, err := windows.CertCreateCertificateContext(certEncoding, &der[0], uint32(len(der)))
	if err != nil {
		return fmt.Errorf("解析分析 CA 证书失败: %w", err)
	}
	defer windows.CertFreeCertificateContext(ctx)
	if err := windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil); err != nil {
		return fmt.Errorf("安装分析 CA 证书失败: %w", err)
	}
	return nil
}

// uninstallCertificate 按 CN 从对应级别的根证书存储删除所有分析 CA。
func uninstallCertificate(level string) error {
	store, err := openRootStore(level)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	return deleteCaptureCAs(store)
}

func deleteCaptureCAs(store windows.Handle) error {
	// 先收集再删除：枚举过程中删除会让枚举上下文失效。
	var matches []*windows.CertContext
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil || ctx == nil {
			break
		}
		if ctx.EncodedCert != nil && ctx.Length > 0 && isCaptureCA(unsafe.Slice(ctx.EncodedCert, ctx.Length)) {
			matches = append(matches, windows.CertDuplicateCertificateContext(ctx))
		}
		prev = ctx
	}
	var firstErr error
	for _, ctx := range matches {
		// CertDeleteCertificateFromStore 总会释放传入的上下文。
		if err := windows.CertDeleteCertificateFromStore(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("删除分析 CA 证书失败: %w", err)
		}
	}
	return firstErr
}
