//go:build windows

package app

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func singBoxBinaryName() string { return "sing-box.exe" }

func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

func pingCommand(ctx context.Context, host string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "ping.exe", "-n", "1", "-w", "3000", host)
	configureProcess(cmd)
	return cmd
}

// setLANProxyFirewall 让局域网代理的入站放行规则和 port 一致（0 表示删除），命令见 lanFirewallCommands。
// 没有这条规则 Windows 防火墙会挡住局域网设备。sbtun 以管理员运行，可以直接改。
func setLANProxyFirewall(binary string, port uint16) error {
	if abs, err := filepath.Abs(binary); err == nil {
		binary = abs
	}
	for i, args := range lanFirewallCommands(binary, port) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		configureProcess(cmd)
		output, err := cmd.CombinedOutput()
		cancel()
		// 第一条是删除旧规则，没有旧规则时 netsh 返回失败，忽略。
		if err != nil && i > 0 {
			return fmt.Errorf("%s: %v %s", strings.Join(args[1:], " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}
