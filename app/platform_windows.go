//go:build windows

package app

import (
	"context"
	"os/exec"
	"path/filepath"
	"syscall"
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

const lanFirewallRule = "sbtun LAN proxy"

// setLANProxyFirewall 开启局域网代理时给 sing-box.exe 加入站放行规则（先删旧的，程序目录可能换过），
// 否则 Windows 防火墙会挡住局域网设备；关闭时删掉。sbtun 以管理员运行，可以直接改。
func setLANProxyFirewall(binary string, allow bool) {
	del := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+lanFirewallRule)
	configureProcess(del)
	_ = del.Run()
	if !allow {
		return
	}
	if abs, err := filepath.Abs(binary); err == nil {
		binary = abs
	}
	add := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+lanFirewallRule,
		"dir=in", "action=allow", "program="+binary, "enable=yes", "profile=any")
	configureProcess(add)
	_ = add.Run()
}
