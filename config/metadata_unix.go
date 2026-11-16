//go:build !windows

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// 以 root（sudo/pkexec，macOS 上 CLI 就是这样跑的）改属主和权限时，路径里的东西可能是调用者
// （普通用户）事先放好的：符号链接、指向系统文件的硬链接。root 跟着它们 chown/chmod 就等于把
// /etc/sudoers 这类文件交给普通用户，属于本地提权。所以 root 下的改动都满足：
//   - 逐级用 openat 打开路径，最后一级用 O_NOFOLLOW，绝不跟随最后一级的符号链接；中间各级只跟随属主是 root 的
//     符号链接（macOS 的 /var、/tmp、/etc 这类系统链接），用户自己建的链接一律拒绝；
//   - 只处理普通文件和目录，普通文件的硬链接数必须是 1；
//   - 文件当前属主只能是 root 或调用者本人，别人的文件不碰；
//   - chown/chmod 都对打开的 fd 做（Fchown/Fchmod），检查和修改之间路径被换掉也改不到别处。
// 非 root 进程改不了别人的文件，没有提权问题，沿用原来的行为。

var (
	// isPrivileged 报告当前进程是否以 root 运行；测试时替换。
	isPrivileged = func() bool { return os.Geteuid() == 0 }
	// trustedUID 是可以信任的属主（root）：它建的符号链接可以跟随，它的文件可以交给调用者。测试时替换。
	trustedUID = 0
)

const maxSymlinkHops = 40

var errSymlinkRefused = errors.New("拒绝跟随符号链接")

func preserveFileMetadata(path string, info os.FileInfo) error {
	uid, gid := -1, -1
	if invokerUID, invokerGID, ok := invokerOwnership(); ok {
		uid, gid = invokerUID, invokerGID
	} else if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid = int(stat.Uid), int(stat.Gid)
	}
	return setMetadata(path, uid, gid, info.Mode().Perm(), true)
}

func applyInvokerOwnership(path string) error {
	uid, gid, ok := invokerOwnership()
	if !ok {
		return nil
	}
	return applyOwnership(path, uid, gid)
}

func invokerOwnership() (int, int, bool) {
	uidText := os.Getenv("SUDO_UID")
	if uidText == "" {
		uidText = os.Getenv("PKEXEC_UID")
	}
	uid, err := strconv.Atoi(uidText)
	if err != nil || uid < 0 {
		return 0, 0, false
	}
	gid := -1
	if gidText := os.Getenv("SUDO_GID"); gidText != "" {
		if parsed, parseErr := strconv.Atoi(gidText); parseErr == nil && parsed >= 0 {
			gid = parsed
		}
	}
	return uid, gid, true
}

func applyOwnership(path string, uid, gid int) error {
	return setMetadata(path, uid, gid, 0, false)
}

// setMetadata 把 path 的属主改成 uid/gid（-1 表示不改），setMode 时同时设权限。
func setMetadata(path string, uid, gid int, mode os.FileMode, setMode bool) error {
	if !isPrivileged() {
		return setMetadataUnprivileged(path, uid, gid, mode, setMode)
	}
	fd, err := openNoUserSymlinks(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch uint32(st.Mode) & unix.S_IFMT {
	case unix.S_IFREG:
		if uint64(st.Nlink) != 1 {
			return fmt.Errorf("%s: 文件有 %d 个硬链接，拒绝修改", path, uint64(st.Nlink))
		}
	case unix.S_IFDIR:
	default:
		return fmt.Errorf("%s: 不是普通文件或目录，拒绝修改", path)
	}
	owner := int(st.Uid)
	if owner != trustedUID && owner != uid {
		return fmt.Errorf("%s: 属主 %d 既不是 root 也不是调用者，拒绝修改", path, owner)
	}
	if setMode {
		if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
			return err
		}
	}
	changeUID, changeGID := -1, -1
	if uid >= 0 && owner != uid {
		changeUID = uid
	}
	if gid >= 0 && int(st.Gid) != gid {
		changeGID = gid
	}
	if changeUID == -1 && changeGID == -1 {
		return nil
	}
	return unix.Fchown(fd, changeUID, changeGID)
}

func setMetadataUnprivileged(path string, uid, gid int, mode os.FileMode, setMode bool) error {
	if setMode {
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	changeUID, changeGID := -1, -1
	if uid >= 0 && int(stat.Uid) != uid {
		changeUID = uid
	}
	if gid >= 0 && int(stat.Gid) != gid {
		changeGID = gid
	}
	if changeUID == -1 && changeGID == -1 {
		return nil
	}
	return os.Chown(path, changeUID, changeGID)
}

// openNoUserSymlinks 从根目录开始逐级 openat 打开 path（只读）：最后一级不跟随任何符号链接，
// 中间各级只跟随属主为 trustedUID 的符号链接。返回的 fd 指向的就是检查过的那个对象。
func openNoUserSymlinks(path string) (int, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return -1, err
	}
	dirfd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	comps := splitPath(abs)
	hops := 0
	for len(comps) > 0 {
		name := comps[0]
		comps = comps[1:]
		last := len(comps) == 0
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if !last {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(dirfd, name, flags, 0)
		if err != nil {
			var st unix.Stat_t
			if statErr := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); statErr != nil || uint32(st.Mode)&unix.S_IFMT != unix.S_IFLNK {
				unix.Close(dirfd)
				return -1, err
			}
			if last {
				unix.Close(dirfd)
				return -1, errSymlinkRefused
			}
			// 真正的 root（uid 0）建的链接总是可信，例如 macOS 的 /var → /private/var。
			if st.Uid != 0 && int(st.Uid) != trustedUID {
				unix.Close(dirfd)
				return -1, fmt.Errorf("%w：路径中的 %s 是普通用户建的符号链接", errSymlinkRefused, name)
			}
			hops++
			if hops > maxSymlinkHops {
				unix.Close(dirfd)
				return -1, unix.ELOOP
			}
			target, err := readlinkat(dirfd, name)
			if err != nil {
				unix.Close(dirfd)
				return -1, err
			}
			if filepath.IsAbs(target) {
				unix.Close(dirfd)
				if dirfd, err = unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err != nil {
					return -1, err
				}
			}
			comps = append(splitPath(target), comps...)
			continue
		}
		unix.Close(dirfd)
		if last {
			return fd, nil
		}
		dirfd = fd
	}
	// path 就是 "/"。
	return dirfd, nil
}

func splitPath(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

func readlinkat(dirfd int, name string) (string, error) {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// ShareWithInvoker sets path's mode and, under sudo/pkexec, hands it back to
// the invoking user so unprivileged CLI commands can still read it.
func ShareWithInvoker(path string, mode os.FileMode) error {
	uid, gid, ok := invokerOwnership()
	if !ok {
		uid, gid = -1, -1
	}
	return setMetadata(path, uid, gid, mode, true)
}

// ShareTreeWithInvoker hands every root-owned entry under dir back to the
// invoking user. It repairs files an older version created as root; it does
// nothing unless running as root with a known invoker. Private keys (*.key,
// the capture CA) stay root-only. Symlinks are never followed (the walk skips
// them and every change goes through openNoUserSymlinks), hard-linked files
// and files owned by anyone other than root or the invoker are left alone.
func ShareTreeWithInvoker(dir string) {
	uid, gid, ok := invokerOwnership()
	if !ok || !isPrivileged() {
		return
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink != 0 || strings.HasSuffix(d.Name(), ".key") {
			return nil
		}
		if info, err := d.Info(); err == nil {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) == trustedUID {
				if applyOwnership(path, uid, gid) != nil && d.IsDir() {
					// 目录交不出去（比如被换成了别的东西），里面的内容也不碰。
					return filepath.SkipDir
				}
			}
		}
		return nil
	})
}
