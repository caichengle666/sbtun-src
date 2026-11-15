package dnsprobe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Client 是一个最小 DNS 客户端，支持 UDP、DoH（RFC 8484 POST）和 DoT。
// 只做 A / AAAA 查询，够探测和解析节点域名用。零值可以直接用。
type Client struct {
	// RootCAs 为空时用系统根证书（测试里换成自签证书）。
	RootCAs *x509.CertPool
	// Dialer 为空时用 net.Dialer。不走任何代理环境变量。
	Dialer *net.Dialer
}

// defaultClient 是包级函数用的客户端。
var defaultClient = &Client{}

// Lookup 用 server 查询 host 的 A 和 AAAA 记录（并行），返回全部地址；两种都失败时返回错误。
func Lookup(ctx context.Context, server Server, host string) ([]netip.Addr, error) {
	return defaultClient.Lookup(ctx, server, host)
}

func (c *Client) Lookup(ctx context.Context, server Server, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{addr}, nil
	}
	type answer struct {
		addrs []netip.Addr
		err   error
	}
	results := make([]answer, 2)
	var wg sync.WaitGroup
	for i, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, err := c.Query(ctx, server, host, qtype)
			results[i] = answer{addrs, err}
		}()
	}
	wg.Wait()
	addrs := append(results[0].addrs, results[1].addrs...)
	if len(addrs) > 0 {
		return addrs, nil
	}
	if results[0].err != nil {
		return nil, results[0].err
	}
	if results[1].err != nil {
		return nil, results[1].err
	}
	return nil, fmt.Errorf("%s 没有 %s 的地址", server, host)
}

// Query 查询一种记录类型，返回应答里的地址（CNAME 链上的 A/AAAA 都算）。
// 应答必须是对这次查询的成功响应，否则返回错误。
func (c *Client) Query(ctx context.Context, server Server, host string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	if err := server.Validate(); err != nil {
		return nil, err
	}
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return nil, fmt.Errorf("不支持的查询类型: %v", qtype)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	id := randomID()
	if server.Type == TypeHTTPS {
		id = 0 // RFC 8484 建议 DoH 用 0，方便 HTTP 缓存
	}
	query, name, err := buildQuery(id, host, qtype)
	if err != nil {
		return nil, err
	}
	var response []byte
	switch server.Type {
	case TypeUDP:
		response, err = c.exchangeUDP(ctx, server, query, id)
	case TypeHTTPS:
		response, err = c.exchangeHTTPS(ctx, server, query)
	case TypeTLS:
		response, err = c.exchangeTLS(ctx, server, query)
	}
	if err != nil {
		return nil, err
	}
	return parseResponse(response, id, name, qtype)
}

func randomID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

func buildQuery(id uint16, host string, qtype dnsmessage.Type) ([]byte, dnsmessage.Name, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, dnsmessage.Name{}, errors.New("域名为空")
	}
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, dnsmessage.Name{}, fmt.Errorf("域名无效: %w", err)
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	data, err := msg.Pack()
	return data, name, err
}

// errMismatch 表示收到的包不是这次查询的应答（UDP 上可能是迟到的旧应答或伪造包），继续等。
var errMismatch = errors.New("应答与查询不匹配")

func parseResponse(data []byte, id uint16, name dnsmessage.Name, qtype dnsmessage.Type) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	header, err := p.Start(data)
	if err != nil {
		return nil, fmt.Errorf("应答格式错误: %w", err)
	}
	if !header.Response || header.ID != id {
		return nil, errMismatch
	}
	questions, err := p.AllQuestions()
	if err != nil {
		return nil, fmt.Errorf("应答格式错误: %w", err)
	}
	if len(questions) > 0 && (!strings.EqualFold(questions[0].Name.String(), name.String()) || questions[0].Type != qtype) {
		return nil, errMismatch
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DNS 返回 %v", header.RCode)
	}
	var addrs []netip.Addr
	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("应答格式错误: %w", err)
		}
		switch {
		case h.Type == dnsmessage.TypeA && qtype == dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, fmt.Errorf("应答格式错误: %w", err)
			}
			addrs = append(addrs, netip.AddrFrom4(r.A))
		case h.Type == dnsmessage.TypeAAAA && qtype == dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, fmt.Errorf("应答格式错误: %w", err)
			}
			addrs = append(addrs, netip.AddrFrom16(r.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, fmt.Errorf("应答格式错误: %w", err)
			}
		}
	}
	return addrs, nil
}

func (c *Client) dialer() *net.Dialer {
	if c.Dialer != nil {
		return c.Dialer
	}
	return &net.Dialer{}
}

func hostPort(server Server) string {
	return net.JoinHostPort(server.Addr().String(), strconv.Itoa(server.Port))
}

func (c *Client) exchangeUDP(ctx context.Context, server Server, query []byte, id uint16) ([]byte, error) {
	conn, err := c.dialer().DialContext(ctx, "udp", hostPort(server))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		// 只收这次查询的应答，其他包（迟到的、ID 不对的）丢掉继续等。
		var p dnsmessage.Parser
		if h, err := p.Start(buf[:n]); err == nil && h.Response && h.ID == id {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func (c *Client) tlsConfig(server Server) *tls.Config {
	return &tls.Config{ServerName: server.ServerName, RootCAs: c.RootCAs, MinVersion: tls.VersionTLS12}
}

func (c *Client) exchangeHTTPS(ctx context.Context, server Server, query []byte) ([]byte, error) {
	dialer := c.dialer()
	transport := &http.Transport{
		// 不能走 HTTP_PROXY 等环境变量：探测的就是本机直连能不能用。
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, hostPort(server))
		},
		TLSClientConfig:     c.tlsConfig(server),
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	url := "https://" + server.ServerName + server.Path
	if server.Port != 443 {
		url = "https://" + net.JoinHostPort(server.ServerName, strconv.Itoa(server.Port)) + server.Path
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 返回 HTTP %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 64*1024))
}

func (c *Client) exchangeTLS(ctx context.Context, server Server, query []byte) ([]byte, error) {
	tlsDialer := &tls.Dialer{NetDialer: c.dialer(), Config: c.tlsConfig(server)}
	conn, err := tlsDialer.DialContext(ctx, "tcp", hostPort(server))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	response := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}
