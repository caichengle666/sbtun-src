package app

import (
	"net"
	"strings"
	"testing"

	"github.com/caichengle666/sbtun/config"
)

func TestPrepareLANProxyRejectsBusyPort(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	cfg := config.Config{LANProxy: &config.LANProxy{Enabled: true, Port: port}}
	r := &RuntimeCoordinator{}
	if err := r.prepareLANProxy(cfg); err == nil || !strings.Contains(err.Error(), "占用") {
		t.Fatalf("busy port should be rejected, got %v", err)
	}
	// 运行中且端口没变：端口是旧 sing-box 自己占着的，不能当成冲突。
	r.activeConfig, r.activeConfigSet = cfg, true
	if err := r.prepareLANProxy(cfg); err != nil {
		t.Fatal(err)
	}
}
