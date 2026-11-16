//go:build windows

package capture

import (
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// privateKeySecurityDescriptor 返回只允许当前用户完全控制、且不继承父目录 ACL 的安全描述符。
func privateKeySecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
}

func createExclusive(path string, private bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var sa *windows.SecurityAttributes
	if private {
		sd, err := privateKeySecurityDescriptor()
		if err != nil {
			return nil, err
		}
		sa = &windows.SecurityAttributes{SecurityDescriptor: sd}
		sa.Length = uint32(unsafe.Sizeof(*sa))
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.WRITE_DAC, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	if private {
		// 再显式设置一次，确保 DACL 受保护、不从父目录继承。
		if err := setPrivateDACL(handle); err != nil {
			windows.CloseHandle(handle)
			_ = os.Remove(path)
			return nil, err
		}
	}
	return os.NewFile(uintptr(handle), path), nil
}

func setPrivateDACL(handle windows.Handle) error {
	sd, err := privateKeySecurityDescriptor()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func replaceFile(from, to string) error { return os.Rename(from, to) }

func linkCount(path string, _ fs.FileInfo) (uint64, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, err
	}
	return uint64(info.NumberOfLinks), nil
}

// Windows 下没有 root；私钥的访问控制由创建时设置的 DACL 保证。
func checkPrivateOwner(fs.FileInfo) error { return nil }
