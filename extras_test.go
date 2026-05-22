package sdk

import (
	"encoding/json"
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
func newSignedServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(h)
}

func newTestClient(base string) *Client {
	return NewClient(base, "test-plugin", DeriveHMACKey("polar_plugin_test"))
}
