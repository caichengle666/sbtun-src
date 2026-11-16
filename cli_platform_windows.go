//go:build windows && cli

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func cliSignals() []os.Signal { return []os.Signal{os.Interrupt} }

// 提权后的进程开在新控制台窗口里，执行完就关；父进程用这个前置参数给它一个文件收集输出，结束后回显。
// 用参数不用环境变量：经 UAC 提权的进程不一定继承父进程设置的环境变量。
const elevatedLogFlag = "--sbtun-elevated-log="

// errorCancelled 是父进程约定的退出码：用户在 UAC 里点了“否”或提权失败（sbtun 自己只用 0、1、2）。
const errorCancelled = 1223

func redirectElevatedOutput() {
	if len(os.Args) < 2 || !strings.HasPrefix(os.Args[1], elevatedLogFlag) {
		return
	}
	path := strings.TrimPrefix(os.Args[1], elevatedLogFlag)
	os.Args = append(os.Args[:1], os.Args[2:]...)
	if file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0); err == nil {
		os.Stdout, os.Stderr = file, file
	}
}

// elevatedArguments 把参数拼成 Windows 命令行（Start-Process 的 -ArgumentList 数组不给元素加引号，
// 带空格的参数会被拆开、空参数会丢），再写成 PowerShell 单引号字符串。
func elevatedArguments(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = syscall.EscapeArg(arg)
	}
	return psQuote(strings.Join(quoted, " "))
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func relaunchElevated(command string, args []string) error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	if os.Getenv("SBTUN_ELEVATED") == "1" {
		return fmt.Errorf("需要管理员权限，请使用管理员身份运行")
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取 CLI 路径失败: %w", err)
	}
	// 以管理员身份启动的是这个路径上的文件：先解析成真实路径，拒绝符号链接/重解析点，
	// 免得普通权限就能改的链接被指向别的程序，借 UAC 提权运行。
	if exe, err = resolveElevationTarget(exe); err != nil {
		return err
	}
	// 前台运行和交互式编辑要在新窗口里看输出、输入，不收集。
	childArgs := os.Args[1:]
	logPath := ""
	if !interactiveCommand(command, args) {
		log, err := os.CreateTemp("", "sbtun-elevated-*.log")
		if err != nil {
			return fmt.Errorf("创建输出文件失败: %w", err)
		}
		log.Close()
		logPath = log.Name()
		childArgs = append([]string{elevatedLogFlag + logPath}, childArgs...)
	}
	script := "$env:SBTUN_ELEVATED='1'; try { $p = Start-Process -FilePath " + psQuote(exe) + " -ArgumentList " + elevatedArguments(childArgs) +
		" -Verb RunAs -Wait -PassThru -ErrorAction Stop } catch { [Console]::Error.WriteLine($_.Exception.Message); exit " +
		fmt.Sprint(errorCancelled) + " }; exit $p.ExitCode"
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		code = exitErr.ExitCode()
	} else if runErr != nil {
		os.Remove(logPath)
		return fmt.Errorf("请求管理员权限失败: %w", runErr)
	}
	wroteElevatedOutput := false
	if logPath != "" {
		output, _ := os.ReadFile(logPath)
		os.Remove(logPath)
		wroteElevatedOutput = len(output) > 0
		if code == 0 {
			os.Stdout.Write(output)
		} else {
			os.Stderr.Write(output)
		}
	}
	if code == errorCancelled {
		return fmt.Errorf("请求管理员权限失败: %s", strings.TrimSpace(stderr.String()))
	}
	if code != 0 && logPath != "" && !wroteElevatedOutput {
		// 提权进程打不开父进程在用户临时目录里建的输出文件（例如 UAC 里换了另一个管理员账户，
		// 该账户无权写当前用户的 %TEMP%），输出会随它的控制台窗口一起消失，这里至少把退出码说清楚。
		fmt.Fprintf(os.Stderr, "管理员权限下的 sbtun 退出码 %d，没有收集到它的输出（提权账户可能无权写入 %s）\n", code, logPath)
	}
	os.Exit(code)
	return nil
}

// volumeNameDOS 是 GetFinalPathNameByHandle 的 VOLUME_NAME_DOS|FILE_NAME_NORMALIZED（都是 0）：返回带盘符的规范路径。
const volumeNameDOS = 0

// resolveElevationTarget 把要提权运行的程序路径解析成真实路径：
// 程序文件本身是符号链接或其他重解析点时直接拒绝；路径中的目录联接/符号链接由
// GetFinalPathNameByHandle 展开，提权进程启动的就是解析时确认过的那个文件。
func resolveElevationTarget(exe string) (string, error) {
	path, err := filepath.Abs(exe)
	if err != nil {
		return "", fmt.Errorf("解析 CLI 路径失败: %w", err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("解析 CLI 路径失败: %w", err)
	}
	// FILE_FLAG_OPEN_REPARSE_POINT：打开链接本身而不是它指向的文件，好识别出来拒绝。
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", fmt.Errorf("打开 CLI 程序文件失败: %w", err)
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return "", fmt.Errorf("读取 CLI 程序文件信息失败: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", fmt.Errorf("拒绝提权：%s 是符号链接或重解析点，请直接运行 sbtun 安装目录里的程序", path)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return "", fmt.Errorf("拒绝提权：%s 不是程序文件", path)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), volumeNameDOS)
	if err != nil {
		return "", fmt.Errorf("解析 CLI 真实路径失败: %w", err)
	}
	if n == 0 || int(n) >= len(buf) {
		return "", errors.New("解析 CLI 真实路径失败: 路径过长")
	}
	return trimFinalPathPrefix(windows.UTF16ToString(buf[:n])), nil
}

// trimFinalPathPrefix 去掉 GetFinalPathNameByHandle 返回的 \\?\ 前缀，PowerShell 和 ShellExecute 都认普通路径。
func trimFinalPathPrefix(path string) string {
	if strings.HasPrefix(path, `\\?\UNC\`) {
		return `\\` + path[len(`\\?\UNC\`):]
	}
	return strings.TrimPrefix(path, `\\?\`)
}
