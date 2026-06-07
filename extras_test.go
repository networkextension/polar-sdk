package sdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Verifies each new wrapper hits the expected path + returns the
// decoded shape. One server per test keeps the call counter clean
// for cache-behavior assertions.

func TestUserGet_Cached(t *testing.T) {
	var hits int32
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(User{ID: "u_abc", Username: "kong"})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)

	for i := 0; i < 3; i++ {
		u, err := c.UserGet("u_abc")
		if err != nil || u.Username != "kong" {
			t.Fatalf("call %d: %v %+v", i, err, u)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("upstream hits: got %d want 1 (cache should absorb 2,3)", got)
	}
}

func TestTeamGet_Cached(t *testing.T) {
	var hits int32
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(Team{ID: "t_root", Slug: "root", Name: "Root"})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	for i := 0; i < 3; i++ {
		_, err := c.TeamGet("t_root")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if hits != 1 {
		t.Fatalf("team cache should absorb: got %d hits", hits)
	}
}

func TestLLMConfigGet_NotCached(t *testing.T) {
	var hits int32
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if !strings.Contains(r.URL.RawQuery, "workspace_id=t_root") {
			t.Errorf("missing workspace_id query: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(LLMConfig{ID: 42, Model: "gpt-4", APIKey: "sk-..."})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	for i := 0; i < 3; i++ {
		cfg, err := c.LLMConfigGet(42, "t_root")
		if err != nil || cfg.APIKey != "sk-..." {
			t.Fatalf("call %d: %v %+v", i, err, cfg)
		}
	}
	if hits != 3 {
		t.Fatalf("llm-config MUST NOT cache (api_key sensitive): got %d hits, want 3", hits)
	}
}

func TestAgentPresenceGet(t *testing.T) {
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AgentPresence{
			BotUserID: "u_bot1", Attached: true, HostID: "h_zen", Tool: "kimi",
			LastSeenAt: time.Now().UTC().Format(time.RFC3339),
		})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	p, err := c.AgentPresenceGet("u_bot1")
	if err != nil || !p.Attached || p.HostID != "h_zen" {
		t.Fatalf("got %+v err %v", p, err)
	}
}

func TestAgentDispatch_Posts(t *testing.T) {
	var bodySeen string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: got %s want POST", r.Method)
		}
		buf := make([]byte, 1<<10)
		n, _ := r.Body.Read(buf)
		bodySeen = string(buf[:n])
		_ = json.NewEncoder(w).Encode(AgentDispatchResponse{Queued: true})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	out, err := c.AgentDispatch(AgentDispatchRequest{
		ThreadID: 7, UserID: "u_user", ResponderUserID: "u_bot", Content: "hi",
	})
	if err != nil || !out.Queued {
		t.Fatalf("%+v %v", out, err)
	}
	if !strings.Contains(bodySeen, `"thread_id":7`) {
		t.Fatalf("body missing thread_id: %s", bodySeen)
	}
}

func TestBotUserGet_NotCached(t *testing.T) {
	var hits int32
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(BotUser{ID: 1, BotUserID: "u_bot", Name: "Helper"})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	for i := 0; i < 2; i++ {
		_, err := c.BotUserGet("u_bot")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if hits != 2 {
		t.Fatalf("bot-user MUST NOT cache (ownership can change): got %d hits, want 2", hits)
	}
}

func TestWorkspacePluginAccess_AllowsRoot(t *testing.T) {
	var capturedPath string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.RequestURI()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"workspace_id":"t_root","plugin":"expense","enabled":true}`))
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	got, err := c.WorkspacePluginAccess("t_root", "expense")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !got.Enabled {
		t.Fatalf("expected enabled=true, got %+v", got)
	}
	if !strings.Contains(capturedPath, "workspace_id=t_root") || !strings.Contains(capturedPath, "plugin=expense") {
		t.Fatalf("URL didn't carry both query params: %s", capturedPath)
	}
}

func TestWorkspacePluginAccess_DeniesNonRootWithoutGrant(t *testing.T) {
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"workspace_id":"t_alpha","plugin":"expense","enabled":false}`))
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	got, err := c.WorkspacePluginAccess("t_alpha", "expense")
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled {
		t.Fatalf("expected enabled=false, got %+v", got)
	}
}

func TestWorkspacePluginAccess_RejectsEmptyArgs(t *testing.T) {
	c := newTestClient("http://unused")
	if _, err := c.WorkspacePluginAccess("", "expense"); err == nil {
		t.Fatal("empty workspaceID should reject")
	}
	if _, err := c.WorkspacePluginAccess("t_x", ""); err == nil {
		t.Fatal("empty plugin should reject")
	}
}

func TestAgentLLMCallRecord_Posts(t *testing.T) {
	called := false
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"recorded":true}`))
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	err := c.AgentLLMCallRecord(AgentLLMCallRecord{
		WorkspaceID: "t_root", LLMConfigID: 1, ModelResolved: "gpt-4",
		PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15, StatusCode: 200,
	})
	if err != nil || !called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}

func TestVideoShotCallRecord_Posts(t *testing.T) {
	var capturedURL string
	var capturedBody string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.Path
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		capturedBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"recorded":true,"deduped":false,"id":42}`))
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	err := c.VideoShotCallRecord(VideoShotCallRecord{
		WorkspaceID: "t_root", ProjectID: 7, ShotID: 99,
		Provider: "video.seedance", Model: "doubao-seedance-1-0-pro-250528",
		Resolution: "1080p", DurationChargedSec: 10, FPS: 24, FramesTotal: 240,
		CostUSD: 0.50, CostPerFrameUSD: 0.002083,
		BillingMeta: map[string]any{"rate_usd_per_sec": 0.05},
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if capturedURL != "/internal/v1/billing/video-shots" {
		t.Fatalf("URL: got %q", capturedURL)
	}
	if !strings.Contains(capturedBody, `"shot_id":99`) {
		t.Fatalf("body missing shot_id: %s", capturedBody)
	}
	if !strings.Contains(capturedBody, `"cost_usd":0.5`) {
		t.Fatalf("body missing cost_usd: %s", capturedBody)
	}
	if !strings.Contains(capturedBody, `"provider":"video.seedance"`) {
		t.Fatalf("body missing provider: %s", capturedBody)
	}
}

func TestVideoShotCallRecord_AlwaysIncludesCostUSDEvenWhenZero(t *testing.T) {
	// Pricing miss returns cost=0; the on-wire JSON must still carry
	// the field so dock's audit can distinguish "row recorded, no
	// price" from "field omitted".
	var body string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		body = string(buf[:n])
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"recorded":true}`))
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	_ = c.VideoShotCallRecord(VideoShotCallRecord{
		WorkspaceID: "t_root", ProjectID: 1, ShotID: 2,
		Provider: "video.runway", CostUSD: 0,
	})
	if !strings.Contains(body, `"cost_usd":0`) {
		t.Fatalf("cost_usd=0 must be present in body, got: %s", body)
	}
}

func TestIssueAgentToken_Posts(t *testing.T) {
	var capturedURL, capturedBody string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.Path
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		capturedBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"tok_abc","deduped":false}`))
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	out, err := c.IssueAgentToken(AgentTokenIssueRequest{
		ID:              "tok_abc",
		UserID:          "u_owner",
		Name:            "enroll:emei",
		TokenHash:       "deadbeef",
		CoderConfigJSON: `{"pending_enrollment":true}`,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if out.ID != "tok_abc" || out.Deduped {
		t.Fatalf("response: %+v", out)
	}
	if capturedURL != "/internal/v1/agent-tokens/issue" {
		t.Fatalf("URL: got %q", capturedURL)
	}
	if !strings.Contains(capturedBody, `"id":"tok_abc"`) {
		t.Fatalf("body missing id: %s", capturedBody)
	}
	if !strings.Contains(capturedBody, `"token_hash":"deadbeef"`) {
		t.Fatalf("body missing token_hash: %s", capturedBody)
	}
	if !strings.Contains(capturedBody, `pending_enrollment`) {
		t.Fatalf("body missing coder_config_json: %s", capturedBody)
	}
}

func TestIssueAgentToken_DedupedResponse(t *testing.T) {
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"tok_abc","deduped":true}`))
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	out, err := c.IssueAgentToken(AgentTokenIssueRequest{
		ID: "tok_abc", UserID: "u_owner", TokenHash: "deadbeef",
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !out.Deduped {
		t.Fatalf("expected deduped=true, got %+v", out)
	}
}

func TestIssueAgentToken_RejectsEmptyArgs(t *testing.T) {
	c := newTestClient("http://unused")
	if _, err := c.IssueAgentToken(AgentTokenIssueRequest{UserID: "u", TokenHash: "h"}); err == nil {
		t.Fatal("empty id should reject")
	}
	if _, err := c.IssueAgentToken(AgentTokenIssueRequest{ID: "tok", TokenHash: "h"}); err == nil {
		t.Fatal("empty user_id should reject")
	}
	if _, err := c.IssueAgentToken(AgentTokenIssueRequest{ID: "tok", UserID: "u"}); err == nil {
		t.Fatal("empty token_hash should reject")
	}
}

func TestIssueHost_Posts(t *testing.T) {
	var capturedURL, capturedBody string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.Path
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		capturedBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"h_xyz","deduped":false}`))
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	out, err := c.IssueHost(HostIssueRequest{
		ID: "h_xyz", WorkspaceID: "t_root", Slug: "emei", Name: "emei",
		AgentTokenID: "tok_abc", OS: "darwin", Arch: "arm64",
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if out.ID != "h_xyz" {
		t.Fatalf("response: %+v", out)
	}
	if capturedURL != "/internal/v1/hosts/issue" {
		t.Fatalf("URL: got %q", capturedURL)
	}
	if !strings.Contains(capturedBody, `"id":"h_xyz"`) {
		t.Fatalf("body missing id: %s", capturedBody)
	}
	if !strings.Contains(capturedBody, `"workspace_id":"t_root"`) {
		t.Fatalf("body missing workspace_id: %s", capturedBody)
	}
	if !strings.Contains(capturedBody, `"agent_token_id":"tok_abc"`) {
		t.Fatalf("body missing agent_token_id: %s", capturedBody)
	}
}

func TestIssueHost_RejectsEmptyArgs(t *testing.T) {
	c := newTestClient("http://unused")
	if _, err := c.IssueHost(HostIssueRequest{WorkspaceID: "t", Slug: "s", Name: "n"}); err == nil {
		t.Fatal("empty id should reject")
	}
	if _, err := c.IssueHost(HostIssueRequest{ID: "h", Slug: "s", Name: "n"}); err == nil {
		t.Fatal("empty workspace_id should reject")
	}
	if _, err := c.IssueHost(HostIssueRequest{ID: "h", WorkspaceID: "t", Name: "n"}); err == nil {
		t.Fatal("empty slug should reject")
	}
	if _, err := c.IssueHost(HostIssueRequest{ID: "h", WorkspaceID: "t", Slug: "s"}); err == nil {
		t.Fatal("empty name should reject")
	}
}

// v4 — AgentRegister + workspace-proxy-tokens/ensure + bots/create-for-agent.

func TestAgentRegister_PostsAndDecodes(t *testing.T) {
	var capturedURL, capturedBody string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.Path
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		capturedBody = string(buf[:n])
		_ = json.NewEncoder(w).Encode(AgentRegisterResponse{
			AgentID:       "ag_abcdef0123456789abcdef0123456789",
			HostID:        "5f4dcc3b5aa765d61d8327deb882cf99",
			BotUserID:     "bot_xyz",
			AgentTokenRaw: "polar_agent_raw_sample",
			Server:        "https://zen.4950.store:2443",
		})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	out, err := c.AgentRegister(AgentRegisterRequest{
		EnrollToken:    "tok_enroll_raw",
		WorkspaceID:    "t_root",
		Name:           "emei-kimi",
		MachineUUIDRaw: "12345678-90AB-CDEF-1234-567890ABCDEF",
		HostInfo: map[string]any{
			"hw_model":        "Mac15,8",
			"cpu_brand":       "Apple processor",
			"cpu_cores":       16,
			"mem_total_bytes": int64(51539607552),
		},
		OS:   "darwin",
		Arch: "arm64",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if capturedURL != "/internal/v1/agents/register" {
		t.Fatalf("URL: got %q", capturedURL)
	}
	if out.AgentID != "ag_abcdef0123456789abcdef0123456789" {
		t.Fatalf("AgentID round-trip: %+v", out)
	}
	if out.BotUserID != "bot_xyz" {
		t.Fatalf("BotUserID round-trip: %+v", out)
	}
	if out.AgentTokenRaw != "polar_agent_raw_sample" {
		t.Fatalf("AgentTokenRaw round-trip: %+v", out)
	}
	if out.Server == "" {
		t.Fatalf("Server should echo, got empty: %+v", out)
	}
	// Body must carry the v4 fields verbatim so dock can hash + persist.
	for _, needle := range []string{
		`"name":"emei-kimi"`,
		`"machine_uuid_raw":"12345678-90AB-CDEF-1234-567890ABCDEF"`,
		`"workspace_id":"t_root"`,
		`"hw_model":"Mac15,8"`,
	} {
		if !strings.Contains(capturedBody, needle) {
			t.Errorf("body missing %q: %s", needle, capturedBody)
		}
	}
}

func TestAgentRegister_RejectsMissingFields(t *testing.T) {
	c := newTestClient("http://unused")
	if _, err := c.AgentRegister(AgentRegisterRequest{WorkspaceID: "t", MachineUUIDRaw: "u"}); err == nil {
		t.Fatal("missing name should reject")
	}
	if _, err := c.AgentRegister(AgentRegisterRequest{Name: "n", MachineUUIDRaw: "u"}); err == nil {
		t.Fatal("missing workspace_id should reject")
	}
	if _, err := c.AgentRegister(AgentRegisterRequest{Name: "n", WorkspaceID: "t"}); err == nil {
		t.Fatal("missing machine_uuid_raw should reject (v4 requires it)")
	}
}

func TestEnsureWorkspaceAgentPoolProxyToken_DefaultsName(t *testing.T) {
	var body string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		body = string(buf[:n])
		_ = json.NewEncoder(w).Encode(WorkspaceProxyTokenEnsureResponse{ID: 42, Created: false})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	out, err := c.EnsureWorkspaceAgentPoolProxyToken(WorkspaceProxyTokenEnsureRequest{
		WorkspaceID: "t_root", OwnerUserID: "u_op", // Name intentionally empty
	})
	if err != nil || out.ID != 42 {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if !strings.Contains(body, `"name":"agent-pool"`) {
		t.Fatalf("default name should be agent-pool: %s", body)
	}
}

func TestCreateBotForAgent_Posts(t *testing.T) {
	var body string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		body = string(buf[:n])
		_ = json.NewEncoder(w).Encode(BotForAgentCreateResponse{
			BotUserID: "bot_freshly_created",
			Created:   true,
		})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)
	out, err := c.CreateBotForAgent(BotForAgentCreateRequest{
		WorkspaceID: "t_root",
		OwnerUserID: "u_op",
		Name:        "bot-emei-kimi-abc12345",
		LLMConfig:   map[string]any{"proxy_token_id": int64(42)},
	})
	if err != nil || out.BotUserID == "" || !out.Created {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	for _, needle := range []string{`"name":"bot-emei-kimi-abc12345"`, `"proxy_token_id":42`} {
		if !strings.Contains(body, needle) {
			t.Errorf("body missing %q: %s", needle, body)
		}
	}
}

func TestEmptyArgsRejected(t *testing.T) {
	c := newTestClient("http://unused")
	if _, err := c.UserGet(""); err == nil {
		t.Fatal("UserGet should reject empty id")
	}
	if _, err := c.TeamGet("   "); err == nil {
		t.Fatal("TeamGet should reject blank id")
	}
	if _, err := c.LLMConfigGet(0, "t_x"); err == nil {
		t.Fatal("LLMConfigGet should reject id=0")
	}
	if _, err := c.LLMConfigGet(1, ""); err == nil {
		t.Fatal("LLMConfigGet should reject empty workspace")
	}
	if _, err := c.BotUserGet(""); err == nil {
		t.Fatal("BotUserGet should reject empty id")
	}
	if _, err := c.ChatThreadGet(0); err == nil {
		t.Fatal("ChatThreadGet should reject id=0")
	}
	if _, err := c.AgentPresenceGet(""); err == nil {
		t.Fatal("AgentPresenceGet should reject empty bot_id")
	}
}

// ── helpers ─────────────────────────────────────────────────────────

// newSignedServer wraps an httptest server that does NOT verify the
// HMAC signature (these wrappers' job is to construct + send, not to
// re-test the signing scheme that client_test.go already covers).
func TestAssetGet_HitsByNameWithQuery(t *testing.T) {
	var seenPath string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path + "?" + r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(AssetMeta{
			ID: 42, Kind: "model", Name: "qwen3/7b", Version: "v1",
			SHA256: "abc123", SizeBytes: 1024,
		})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)

	ws := "t_root"
	m, err := c.AssetGet(&ws, "model", "qwen3/7b", "v1")
	if err != nil {
		t.Fatalf("AssetGet err: %v", err)
	}
	if m.ID != 42 || m.Kind != "model" || m.SHA256 != "abc123" {
		t.Fatalf("unexpected meta: %+v", m)
	}
	want := "/internal/v1/assets/by-name?kind=model&name=qwen3%2F7b&version=v1&workspace_id=t_root"
	if seenPath != want {
		t.Fatalf("path/query mismatch:\n got %q\nwant %q", seenPath, want)
	}
}

func TestAssetGet_DefaultsVersion(t *testing.T) {
	var seenRawQuery string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenRawQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(AssetMeta{ID: 1, Version: "v1"})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)

	if _, err := c.AssetGet(nil, "package", "polar-agent/darwin-arm64", ""); err != nil {
		t.Fatalf("AssetGet: %v", err)
	}
	if !strings.Contains(seenRawQuery, "version=v1") {
		t.Fatalf("expected version=v1 default in query, got %q", seenRawQuery)
	}
	if strings.Contains(seenRawQuery, "workspace_id=") {
		t.Fatalf("expected no workspace_id for nil arg, got %q", seenRawQuery)
	}
}

func TestAssetStat_HitsBySHA256Path(t *testing.T) {
	var seenPath string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(AssetMeta{ID: 99, SHA256: strings.TrimPrefix(r.URL.Path, "/internal/v1/assets/by-sha256/")})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)

	m, err := c.AssetStat("deadbeef1234")
	if err != nil {
		t.Fatalf("AssetStat err: %v", err)
	}
	if seenPath != "/internal/v1/assets/by-sha256/deadbeef1234" {
		t.Fatalf("wrong path: %q", seenPath)
	}
	if m.SHA256 != "deadbeef1234" {
		t.Fatalf("wrong sha: %q", m.SHA256)
	}
}

func TestAssetDelete_HitsDeleteByID(t *testing.T) {
	var seenMethod, seenPath string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenMethod, seenPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	defer srv.Close()
	c := newTestClient(srv.URL)

	if err := c.AssetDelete(42); err != nil {
		t.Fatalf("AssetDelete: %v", err)
	}
	if seenMethod != http.MethodDelete {
		t.Fatalf("wrong method: %q", seenMethod)
	}
	if seenPath != "/internal/v1/assets/42" {
		t.Fatalf("wrong path: %q", seenPath)
	}
}

func TestAssetDelete_RejectsBadID(t *testing.T) {
	c := newTestClient("http://example.invalid")
	for _, id := range []int64{0, -1, -999} {
		if err := c.AssetDelete(id); err == nil {
			t.Errorf("expected error for id=%d, got nil", id)
		}
	}
}

// download-url 503 → AssetDownload falls back to the through-dock
// /blob stream (provider mode off / older dock).
func TestAssetDownload_FallsBackToBlob(t *testing.T) {
	payload := []byte("the quick brown fox over the lazy dog")
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/assets/7/download-url":
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"provider mode off"}`))
		case "/internal/v1/assets/7/blob":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(payload)
		default:
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
	})
	defer srv.Close()
	c := newTestClient(srv.URL)

	resp, err := c.AssetDownload(&AssetMeta{ID: 7, SHA256: "x"})
	if err != nil {
		t.Fatalf("AssetDownload: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != string(payload) {
		t.Fatalf("body mismatch: got %q want %q", got, payload)
	}
}

// download-url returns a signed provider URL → AssetDownload streams
// straight from there, bypassing dock's /blob path entirely.
func TestAssetDownload_DirectSignedURL(t *testing.T) {
	payload := []byte("direct-from-provider-bytes")
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/assets/9/download-url":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"url": "http://" + r.Host + "/prov/v1/blob/deadbeef?token=1:2",
			})
		case "/prov/v1/blob/deadbeef":
			w.Write(payload)
		case "/internal/v1/assets/9/blob":
			t.Errorf("should not hit through-dock blob when direct URL works")
		default:
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
	})
	defer srv.Close()
	c := newTestClient(srv.URL)

	resp, err := c.AssetDownload(&AssetMeta{ID: 9})
	if err != nil {
		t.Fatalf("AssetDownload: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != string(payload) {
		t.Fatalf("direct body mismatch: got %q want %q", got, payload)
	}
}

// AssetDownloadURLWS must forward the caller's workspace_id as a query
// param so dock can authorize a workspace-private asset. The plain
// AssetDownloadURL (ws="") must send no workspace_id.
func TestAssetDownloadURL_WorkspaceParam(t *testing.T) {
	var gotQuery string
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/assets/9/download-url" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{"url": "http://x/prov/blob?token=1:2"})
	})
	defer srv.Close()
	c := newTestClient(srv.URL)

	if _, err := c.AssetDownloadURLWS(9, "ws_abc"); err != nil {
		t.Fatalf("AssetDownloadURLWS: %v", err)
	}
	if gotQuery != "workspace_id=ws_abc" {
		t.Fatalf("ws query = %q, want workspace_id=ws_abc", gotQuery)
	}

	gotQuery = "sentinel"
	if _, err := c.AssetDownloadURL(9); err != nil {
		t.Fatalf("AssetDownloadURL: %v", err)
	}
	if gotQuery != "" {
		t.Fatalf("plain download-url should send no query, got %q", gotQuery)
	}
}

// Full signed-PUT round-trip: grant → PUT bytes direct to provider →
// finalize. Asserts the sha the SDK computes is the content key, and
// the bytes that land at the provider match the body.
func TestAssetUpload_SignedPutRoundtrip(t *testing.T) {
	body := []byte("module-binary-bytes-v0.0.3")
	wantSHA := sha256.Sum256(body)
	wantSHAHex := hex.EncodeToString(wantSHA[:])

	var grantSHA, putPath string
	var putBytes []byte
	var finalized bool
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/internal/v1/assets/upload-grant":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			grantSHA, _ = in["sha256"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"asset_id":    int64(5),
				"sha256":      grantSHA,
				"exists":      false,
				"put_url":     "http://" + r.Host + "/prov/v1/blob/" + grantSHA + "?exp=1&max=99&ct=x&sig=y",
				"provider_id": int64(1),
			})
		case strings.HasPrefix(r.URL.Path, "/prov/v1/blob/"):
			putPath = r.URL.Path
			putBytes, _ = io.ReadAll(r.Body)
			_ = json.NewEncoder(w).Encode(map[string]any{"sha256": grantSHA, "size_bytes": len(putBytes)})
		case r.URL.Path == "/internal/v1/assets/finalize":
			finalized = true
			_ = json.NewEncoder(w).Encode(AssetMeta{ID: 5, Kind: "module", Name: "buildings/darwin-arm64", SHA256: grantSHA, SizeBytes: int64(len(body))})
		default:
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
	})
	defer srv.Close()
	c := newTestClient(srv.URL)

	meta, err := c.AssetUpload(AssetUploadInput{Kind: "module", Name: "buildings/darwin-arm64"}, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("AssetUpload: %v", err)
	}
	if grantSHA != wantSHAHex {
		t.Errorf("grant sha: got %q want %q", grantSHA, wantSHAHex)
	}
	if putPath != "/prov/v1/blob/"+wantSHAHex {
		t.Errorf("put path: got %q", putPath)
	}
	if string(putBytes) != string(body) {
		t.Errorf("provider bytes mismatch: got %q", putBytes)
	}
	if !finalized {
		t.Error("finalize was not called")
	}
	if meta == nil || meta.ID != 5 || meta.SHA256 != wantSHAHex {
		t.Errorf("returned meta: %+v", meta)
	}
}

// exists=true (content dedup) → no PUT, no finalize; AssetUpload returns
// the existing metadata.
func TestAssetUpload_DedupSkipsPut(t *testing.T) {
	srv := newSignedServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/assets/upload-grant":
			_ = json.NewEncoder(w).Encode(map[string]any{"asset_id": int64(8), "exists": true})
		case "/internal/v1/assets/8":
			_ = json.NewEncoder(w).Encode(AssetMeta{ID: 8, Kind: "module", Name: "x"})
		default:
			t.Errorf("unexpected path (PUT/finalize should be skipped): %q", r.URL.Path)
		}
	})
	defer srv.Close()
	c := newTestClient(srv.URL)

	meta, err := c.AssetUpload(AssetUploadInput{Kind: "module", Name: "x"}, strings.NewReader("dup"))
	if err != nil {
		t.Fatalf("AssetUpload: %v", err)
	}
	if meta == nil || meta.ID != 8 {
		t.Errorf("expected existing meta id=8, got %+v", meta)
	}
}

func TestAssetUpload_RejectsBadInput(t *testing.T) {
	c := newTestClient("http://unused.invalid")
	if _, err := c.AssetUpload(AssetUploadInput{Name: "x"}, strings.NewReader("b")); err == nil {
		t.Error("expected error for missing kind")
	}
	if _, err := c.AssetUpload(AssetUploadInput{Kind: "k", Name: "n"}, nil); err == nil {
		t.Error("expected error for nil body")
	}
	if _, err := c.AssetUpload(AssetUploadInput{Kind: "k", Name: "n"}, strings.NewReader("")); err == nil {
		t.Error("expected error for empty body")
	}
}

func newSignedServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(h)
}

func newTestClient(base string) *Client {
	return NewClient(base, "test-plugin", DeriveHMACKey("polar_plugin_test"))
}
