package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/caichengle666/sbtun/config"
	"github.com/caichengle666/sbtun/core"
)

// fakeClashAPI 模拟 sing-box 的 Clash API：secret 非空时只认 Bearer secret。
func fakeClashAPI(secret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secret != "" && r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/version":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "sing-box 1.12.0", "premium": true, "meta": true})
		case "/configs":
			_ = json.NewEncoder(w).Encode(map[string]any{"mode": "rule"})
		case "/proxies/proxy":
			_ = json.NewEncoder(w).Encode(map[string]string{"now": "node-n1"})
		default:
			http.NotFound(w, r)
		}
	})
}

func withClashAPI(t *testing.T, baseURL, secret string) {
	t.Helper()
	previousURL := clashAPIBaseURL
	previousSecret := currentClashAPISecret()
	clashAPIBaseURL = baseURL
	setClashAPISecret(secret)
	t.Cleanup(func() {
		clashAPIBaseURL = previousURL
		setClashAPISecret(previousSecret)
	})
}

// statusTestApp 返回一个内存状态为 state、没有本实例 sing-box 进程的 App（相当于 CLI 或刚打开的 GUI）。
func statusTestApp(t *testing.T, state core.RuntimeState) *App {
	t.Helper()
	dir := t.TempDir()
	manager := config.NewManager(filepath.Join(dir, "config.json"))
	cfg := config.Default()
	cfg.Nodes = []config.Node{{ID: "n1", Name: "n1", Protocol: "socks", Server: "127.0.0.1", Port: 1081}}
	if err := manager.Save(cfg); err != nil {
		t.Fatal(err)
	}
	a := New()
	a.manager = manager
	a.runtime = &RuntimeCoordinator{State: core.NewStateStore()}
	a.runtime.State.Set(state, "")
	return a
}

func TestGetStatusPortTakenReturns401(t *testing.T) {
	// 端口上是另一个 sing-box（别的 secret），本实例的 secret 得到 401。
	server := httptest.NewServer(fakeClashAPI("someone-else"))
	defer server.Close()
	withClashAPI(t, server.URL, "ours")

	for _, state := range []core.RuntimeState{core.StateStopped, core.StateRunning} {
		status := statusTestApp(t, state).GetStatus()
		if status.Running || status.State != string(core.StateStopped) || !status.PortConflict {
			t.Fatalf("from %s: status=%+v, want stopped with port conflict", state, status)
		}
		if status.Selector != "" {
			t.Fatalf("selector read from foreign API: %q", status.Selector)
		}
	}
}

func TestGetStatusCorrectSecretIsRunning(t *testing.T) {
	server := httptest.NewServer(fakeClashAPI("ours"))
	defer server.Close()
	withClashAPI(t, server.URL, "ours")

	status := statusTestApp(t, core.StateStopped).GetStatus()
	if !status.Running || status.State != string(core.StateRunning) || status.PortConflict {
		t.Fatalf("status=%+v, want running", status)
	}
	if status.Selector != "node-n1" || status.CurrentNodeID != "n1" {
		t.Fatalf("selector=%q node=%q", status.Selector, status.CurrentNodeID)
	}
}

func TestGetStatusNoResponseIsNotRunning(t *testing.T) {
	server := httptest.NewServer(fakeClashAPI("ours"))
	url := server.URL
	server.Close() // 端口上没人监听
	withClashAPI(t, url, "ours")

	status := statusTestApp(t, core.StateStopped).GetStatus()
	if status.Running || status.State != string(core.StateStopped) || status.PortConflict {
		t.Fatalf("status=%+v, want stopped without port conflict", status)
	}
}

func TestProbeClashInstanceRejectsImpostors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		want    clashProbeResult
	}{
		{"ours", fakeClashAPI("ours"), clashProbeOurs},
		{"wrong secret", fakeClashAPI("other"), clashProbeForeign},
		{"sing-box without secret", fakeClashAPI(""), clashProbeForeign},
		{"not sing-box", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"version":"v1.18.0","meta":true}`))
		}), clashProbeForeign},
		{"html page", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<html>hello</html>`))
		}), clashProbeForeign},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			withClashAPI(t, server.URL, "ours")
			if got := probeClashInstance(t.Context()); got != test.want {
				t.Fatalf("probe=%v want %v", got, test.want)
			}
		})
	}
}

func TestGetStatusEmptySecretTrustsManagedProcess(t *testing.T) {
	// 没有 secret 时端口上的 sing-box 无法确认归属，以本实例进程为准（此处没有进程）。
	server := httptest.NewServer(fakeClashAPI(""))
	defer server.Close()
	withClashAPI(t, server.URL, "")

	for _, state := range []core.RuntimeState{core.StateStopped, core.StateRunning} {
		status := statusTestApp(t, state).GetStatus()
		if status.Running || status.PortConflict {
			t.Fatalf("from %s: status=%+v, want not running", state, status)
		}
	}
}
