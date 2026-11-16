package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// clashProbeResult 描述 9090 上的 Clash API 是不是本实例的 sing-box。
type clashProbeResult int

const (
	// clashProbeNone：端口上没有响应（没人监听、超时等）。
	clashProbeNone clashProbeResult = iota
	// clashProbeOurs：响应来自 sing-box，且只认本实例的 secret。
	clashProbeOurs
	// clashProbeForeign：端口被别的程序占着：拒绝本实例的 secret、不是 sing-box，
	// 或者连错误的 secret 也放行（说明它不是用本实例的 secret 启动的）。
	clashProbeForeign
)

const clashProbeTimeout = 500 * time.Millisecond

// portConflictMessage 是端口被别的程序占用时给界面的提示。
func portConflictMessage() string {
	host := strings.TrimPrefix(strings.TrimPrefix(clashAPIBaseURL, "http://"), "https://")
	return "Clash API 端口 " + host + " 被其他程序占用，sbtun 未运行；请关闭占用该端口的程序后再启动"
}

// probeClashInstance 用本实例的 secret 请求 /version，判断端口上是不是本实例的 sing-box。
// secret 为空时无法区分实例，调用方应以本实例管理的进程是否存活为准，这里返回 clashProbeNone。
func probeClashInstance(ctx context.Context) clashProbeResult {
	secret := currentClashAPISecret()
	if secret == "" {
		return clashProbeNone
	}
	status, body, err := requestClash(ctx, "/version", secret)
	if err != nil {
		return clashProbeNone
	}
	if status != http.StatusOK || !isSingBoxVersion(body) {
		// 401/403（secret 不匹配）、404 或其它程序的页面都不是本实例。
		return clashProbeForeign
	}
	// 再用一个错误的 secret 请求需要鉴权的 /configs：本实例的 sing-box 必须拒绝它。
	// 放行说明对方没有启用本实例的 secret（比如另一个无密码的 sing-box），也不是本实例。
	wrong, err := randomToken(16)
	if err != nil {
		return clashProbeNone
	}
	if wrong == secret {
		wrong += "x"
	}
	status, _, err = requestClash(ctx, "/configs", wrong)
	if err != nil {
		return clashProbeNone
	}
	if status != http.StatusUnauthorized {
		return clashProbeForeign
	}
	return clashProbeOurs
}

func requestClash(ctx context.Context, path, secret string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, clashProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clashAPIBaseURL+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := (&http.Client{Timeout: clashProbeTimeout}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

// isSingBoxVersion 识别 sing-box Clash API 的 /version 响应，形如 {"version":"sing-box 1.x.y",...}。
func isSingBoxVersion(body []byte) bool {
	var v struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(body, &v) != nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v.Version)), "sing-box")
}
