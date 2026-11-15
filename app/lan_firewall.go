package app

import "strconv"

// lanFirewallRule 是局域网代理防火墙规则的名字；TCP 和 UDP 两条同名，一条 delete 命令就能一起删掉。
const lanFirewallRule = "sbtun LAN proxy"

// lanFirewallCommands 返回让 Windows 防火墙和局域网代理端口 port 一致的 netsh 命令：
// 先删掉旧规则（程序目录或端口可能变过，也可能是上次异常退出留下的），port 不为 0 时再加 TCP、UDP 各一条。
// 规则只放行 sing-box.exe 的这个端口、只接受本地子网来的连接、只在专用/域网络生效，
// 在咖啡店之类的公共网络里不会对外开放。
func lanFirewallCommands(binary string, port uint16) [][]string {
	commands := [][]string{{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + lanFirewallRule}}
	if port == 0 {
		return commands
	}
	for _, protocol := range []string{"TCP", "UDP"} {
		commands = append(commands, []string{
			"netsh", "advfirewall", "firewall", "add", "rule", "name=" + lanFirewallRule,
			"dir=in", "action=allow", "program=" + binary, "protocol=" + protocol,
			"localport=" + strconv.Itoa(int(port)), "remoteip=localsubnet", "profile=private,domain", "enable=yes",
		})
	}
	return commands
}
