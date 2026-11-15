package dnsprobe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// answer 按查询生成应答：A 查询答 1.2.3.4（带一条 CNAME），AAAA 答 2001:db8::1。
func answer(t *testing.T, query []byte, rcode dnsmessage.RCode) []byte {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		t.Errorf("bad query: %v", err)
		return nil
	}
	q, err := p.Question()
	if err != nil {
		t.Errorf("bad question: %v", err)
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RCode: rcode, RecursionAvailable: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	if rcode == dnsmessage.RCodeSuccess {
		cname := dnsmessage.MustNewName("alias.example.")
		_ = b.CNAMEResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.CNAMEResource{CNAME: cname})
		switch q.Type {
		case dnsmessage.TypeA:
			_ = b.AResource(dnsmessage.ResourceHeader{Name: cname, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}})
		case dnsmessage.TypeAAAA:
			_ = b.AAAAResource(dnsmessage.ResourceHeader{Name: cname, Class: dnsmessage.ClassINET, TTL: 60},
				dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()})
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Errorf("build answer: %v", err)
	}
	return out
}

// udpServer 起一个本地 UDP DNS。silent 时只收不答（模拟被网关拦截的 UDP 53）。
func udpServer(t *testing.T, silent bool, garbageFirst bool) Server {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if silent {
				continue
			}
			if garbageFirst {
				// 先回一个 ID 不对的应答，客户端必须忽略它继续等。
				bad := answer(t, buf[:n], dnsmessage.RCodeSuccess)
				binary.BigEndian.PutUint16(bad, binary.BigEndian.Uint16(bad)+1)
				_, _ = conn.WriteTo(bad, addr)
			}
			_, _ = conn.WriteTo(answer(t, buf[:n], dnsmessage.RCodeSuccess), addr)
		}
	}()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	return Server{Type: TypeUDP, Address: "127.0.0.1", Port: port}
}

// dohServer 起一个本地 DoH（RFC 8484 POST）。
func dohServer(t *testing.T, rcode dnsmessage.RCode) (Server, *Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if host, _, _ := net.SplitHostPort(r.Host); host != "example.com" {
			http.Error(w, "bad host "+r.Host, http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answer(t, body, rcode))
	}))
	t.Cleanup(srv.Close)
	_, portText, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	return Server{Type: TypeHTTPS, Address: "127.0.0.1", Port: port, Path: "/dns-query", ServerName: "example.com"}, &Client{RootCAs: pool}
}

// dotServer 起一个本地 DoT。
func dotServer(t *testing.T) (Server, *Client) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS() // 只为拿到测试证书
	certs := srv.TLS.Certificates
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	srv.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: certs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				resp := answer(t, query, dnsmessage.RCodeSuccess)
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				copy(out[2:], resp)
				_, _ = conn.Write(out)
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return Server{Type: TypeTLS, Address: "127.0.0.1", Port: port, ServerName: "example.com"}, &Client{RootCAs: pool}
}

func TestQueryUDP(t *testing.T) {
	server := udpServer(t, false, true)
	addrs, err := (&Client{}).Lookup(context.Background(), server, "node.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 || addrs[0].String() != "1.2.3.4" || addrs[1].String() != "2001:db8::1" {
		t.Fatalf("addrs=%v", addrs)
	}
}

func TestQueryDoHIgnoresProxyEnvironment(t *testing.T) {
	// 代理环境变量指向一个不存在的端口：DoH 必须直连，不能走它。
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	server, client := dohServer(t, dnsmessage.RCodeSuccess)
	addrs, err := client.Query(context.Background(), server, "www.baidu.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0].String() != "1.2.3.4" {
		t.Fatalf("addrs=%v", addrs)
	}
}

func TestQueryDoT(t *testing.T) {
	server, client := dotServer(t)
	addrs, err := client.Query(context.Background(), server, "www.baidu.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0].String() != "1.2.3.4" {
		t.Fatalf("addrs=%v", addrs)
	}
}

func TestQueryRejectsErrorRCode(t *testing.T) {
	server, client := dohServer(t, dnsmessage.RCodeServerFailure)
	if _, err := client.Query(context.Background(), server, "www.baidu.com", dnsmessage.TypeA); err == nil {
		t.Fatal("SERVFAIL must be an error")
	}
}

func TestQueryTimesOutOnSilentServer(t *testing.T) {
	server := udpServer(t, true, false)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := (&Client{}).Query(ctx, server, "www.baidu.com", dnsmessage.TypeA); err == nil {
		t.Fatal("silent server must fail")
	}
	if time.Since(started) > time.Second {
		t.Fatalf("timeout not honored: %v", time.Since(started))
	}
}

func TestParseResponseRejectsMismatch(t *testing.T) {
	query, name, err := buildQuery(7, "a.example", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	resp := answer(t, query, dnsmessage.RCodeSuccess)
	if _, err := parseResponse(resp, 8, name, dnsmessage.TypeA); !errors.Is(err, errMismatch) {
		t.Fatalf("wrong id err=%v", err)
	}
	other, _ := dnsmessage.NewName("b.example.")
	if _, err := parseResponse(resp, 7, other, dnsmessage.TypeA); !errors.Is(err, errMismatch) {
		t.Fatalf("wrong name err=%v", err)
	}
	if _, err := parseResponse(query, 7, name, dnsmessage.TypeA); !errors.Is(err, errMismatch) {
		t.Fatalf("a query is not a response, err=%v", err)
	}
	if _, err := parseResponse([]byte{1, 2, 3}, 7, name, dnsmessage.TypeA); err == nil {
		t.Fatal("garbage must fail")
	}
}

func TestProbePicksHighestPriorityWorkingCandidate(t *testing.T) {
	silent := udpServer(t, true, false)
	working := udpServer(t, false, false)
	doh, client := dohServer(t, dnsmessage.RCodeSuccess)

	// 被拦截的 UDP 排第一：要等它超时，然后选 DoH（第二优先）。
	got, results, err := client.Probe(context.Background(), []Server{silent, doh, working}, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got != doh {
		t.Fatalf("got %v, want DoH; results=%v", got, results)
	}
	if results[0].Err == nil {
		t.Fatal("silent server reported success")
	}

	// 第一优先能用时直接选它，不用等慢的。
	started := time.Now()
	got, _, err = client.Probe(context.Background(), []Server{working, silent}, 2*time.Second)
	if err != nil || got != working {
		t.Fatalf("got %v err=%v", got, err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("probe waited for lower priority candidates: %v", time.Since(started))
	}
}

func TestProbeAllFail(t *testing.T) {
	silent := udpServer(t, true, false)
	started := time.Now()
	_, results, err := (&Client{}).Probe(context.Background(), []Server{silent, {Type: TypeUDP, Address: "bad", Port: 53}}, 300*time.Millisecond)
	if err == nil {
		t.Fatal("expected error")
	}
	if len(results) != 2 || results[1].Err == nil {
		t.Fatalf("results=%v", results)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatalf("total timeout not honored: %v", time.Since(started))
	}
}

func TestValidate(t *testing.T) {
	for _, s := range BuiltinCandidates() {
		if err := s.Validate(); err != nil {
			t.Fatalf("%v: %v", s, err)
		}
	}
	if err := Fallback().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Server{
		{Type: "local", Address: "1.1.1.1", Port: 53},
		{Type: TypeUDP, Address: "dns.google", Port: 53},
		{Type: TypeUDP, Address: "1.1.1.1", Port: 0},
		{Type: TypeHTTPS, Address: "1.1.1.1", Port: 443, Path: "/dns-query"},
		{Type: TypeHTTPS, Address: "1.1.1.1", Port: 443, ServerName: "x"},
		{Type: TypeTLS, Address: "1.1.1.1", Port: 853},
	}
	for _, s := range bad {
		if s.Validate() == nil {
			t.Fatalf("%+v should be invalid", s)
		}
	}
}

func TestBuiltinOrder(t *testing.T) {
	want := []string{"udp 223.5.5.5", "udp 119.29.29.29", "https 223.5.5.5 dns.alidns.com", "https 1.12.12.12 doh.pub", "tls 223.5.5.5 dns.alidns.com"}
	got := BuiltinCandidates()
	for i, s := range got {
		desc := strings.TrimSpace(s.Type + " " + s.Address + " " + s.ServerName)
		if desc != want[i] {
			t.Fatalf("candidate %d = %q, want %q", i, desc, want[i])
		}
	}
	if f := Fallback(); f.Type != TypeHTTPS || f.Address != "223.5.5.5" {
		t.Fatalf("fallback=%v", f)
	}
}

func TestWithSystemFiltersAndDedups(t *testing.T) {
	system := []netip.Addr{
		netip.MustParseAddr("192.168.3.1"),
		netip.MustParseAddr("127.0.0.53"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("172.18.0.2"), // sbtun TUN
		netip.MustParseAddr("172.19.0.2"), // sbtun TUN（顺延网段）
		netip.MustParseAddr("fdfe:dcba:9876::2"),
		netip.MustParseAddr("198.18.0.2"), // fake-ip
		netip.MustParseAddr("223.5.5.5"),  // 内置已有
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("114.114.114.114"),
		netip.MustParseAddr("192.168.3.1"),
		netip.MustParseAddr("172.20.5.9"), // 公司内网 DNS，不是 TUN 网段
	}
	got := withSystem(BuiltinCandidates(), system)
	var extra []string
	for _, s := range got[len(BuiltinCandidates()):] {
		if !s.System || s.Type != TypeUDP || s.Port != 53 {
			t.Fatalf("bad system candidate %+v", s)
		}
		extra = append(extra, s.Address)
	}
	if strings.Join(extra, ",") != "192.168.3.1,114.114.114.114,172.20.5.9" {
		t.Fatalf("system candidates=%v", extra)
	}
}

func TestServerString(t *testing.T) {
	if s := DoH("223.5.5.5", "dns.alidns.com").String(); !strings.Contains(s, "https://223.5.5.5:443/dns-query") {
		t.Fatal(s)
	}
	if s := UDP("2001:db8::1").String(); !strings.Contains(s, "[2001:db8::1]:53") {
		t.Fatal(s)
	}
}

func newTestStore(t *testing.T) (*Store, *time.Time, *atomic.Int32) {
	t.Helper()
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	calls := &atomic.Int32{}
	s := NewStore(t.TempDir())
	s.now = func() time.Time { return now }
	return s, &now, calls
}

func TestStoreCurrentDefaultsToFallback(t *testing.T) {
	s, _, _ := newTestStore(t)
	if got := s.Current(); got != Fallback() {
		t.Fatalf("got %v", got)
	}
	if err := os.WriteFile(s.Path(), []byte(`{"server":{"type":"udp","address":"dns.example","port":53}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := s.Current(); got != Fallback() {
		t.Fatalf("invalid saved server must be ignored, got %v", got)
	}
	if err := os.WriteFile(s.Path(), []byte(`{broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := s.Current(); got != Fallback() {
		t.Fatalf("corrupt file must be ignored, got %v", got)
	}
}

func TestStoreRefreshCachesAndPersists(t *testing.T) {
	s, now, calls := newTestStore(t)
	udp := UDP("119.29.29.29")
	s.probe = func(context.Context) (Server, error) { calls.Add(1); return udp, nil }
	got, err := s.Refresh(context.Background())
	if err != nil || got != udp {
		t.Fatalf("got %v err=%v", got, err)
	}
	// 另一个进程（CLI）读到同一个结果。
	if other := NewStore(filepath.Dir(s.Path())).Current(); other != udp {
		t.Fatalf("other store got %v", other)
	}
	if info, err := os.Stat(s.Path()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved file mode: %v %v", info, err)
	}
	*now = now.Add(5 * time.Minute)
	if _, err := s.Refresh(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatalf("fresh cache must not reprobe, calls=%d err=%v", calls.Load(), err)
	}
	*now = now.Add(6 * time.Minute)
	if _, err := s.Refresh(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatalf("expired cache must reprobe, calls=%d err=%v", calls.Load(), err)
	}
	if _, err := s.Reprobe(context.Background()); err != nil || calls.Load() != 3 {
		t.Fatalf("Reprobe must always probe, calls=%d", calls.Load())
	}
	entries, _ := os.ReadDir(filepath.Dir(s.Path()))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestStoreFailureKeepsLastResultAndBacksOff(t *testing.T) {
	s, now, calls := newTestStore(t)
	doT := DoT("223.5.5.5", "dns.alidns.com")
	s.probe = func(context.Context) (Server, error) { calls.Add(1); return doT, nil }
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Hour)
	s.probe = func(context.Context) (Server, error) { calls.Add(1); return Server{}, errors.New("all failed") }
	got, err := s.Refresh(context.Background())
	if err == nil || got != doT {
		t.Fatalf("failure must keep last saved: got %v err=%v", got, err)
	}
	if s.Current() != doT {
		t.Fatal("failure must not overwrite the saved choice")
	}
	// 退避期间不再探测。
	*now = now.Add(10 * time.Second)
	if got, err := s.Refresh(context.Background()); err != nil || got != doT || calls.Load() != 2 {
		t.Fatalf("backoff: got %v err=%v calls=%d", got, err, calls.Load())
	}
	*now = now.Add(time.Minute)
	if _, _ = s.Refresh(context.Background()); calls.Load() != 3 {
		t.Fatalf("after backoff must probe again, calls=%d", calls.Load())
	}
}

func TestStoreFailureWithoutHistoryUsesFallback(t *testing.T) {
	s, _, _ := newTestStore(t)
	s.probe = func(context.Context) (Server, error) { return Server{}, errors.New("all failed") }
	got, err := s.Refresh(context.Background())
	if err == nil || got != Fallback() {
		t.Fatalf("got %v err=%v", got, err)
	}
	// 探测返回了不合法的服务器也按失败处理。
	s2, _, _ := newTestStore(t)
	s2.probe = func(context.Context) (Server, error) { return Server{Type: "udp", Address: "x"}, nil }
	if got, err := s2.Refresh(context.Background()); err == nil || got != Fallback() {
		t.Fatalf("got %v err=%v", got, err)
	}
}

func TestStoreSystemChoiceExpiresSooner(t *testing.T) {
	s, now, calls := newTestStore(t)
	router := UDP("192.168.3.1")
	router.System = true
	s.probe = func(context.Context) (Server, error) { calls.Add(1); return router, nil }
	_, _ = s.Refresh(context.Background())
	*now = now.Add(2 * time.Minute)
	_, _ = s.Refresh(context.Background())
	if calls.Load() != 2 {
		t.Fatalf("system DNS choice must be re-checked after a minute, calls=%d", calls.Load())
	}
}

func TestNilStore(t *testing.T) {
	var s *Store
	if s.Current() != Fallback() {
		t.Fatal("nil store Current")
	}
	if got, err := s.Refresh(context.Background()); err != nil || got != Fallback() {
		t.Fatal("nil store Refresh")
	}
}
