package sdk

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAuthVerifyAgent_OK_AndCaches(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/auth/verify-agent" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if got := r.URL.Query().Get("token"); got != "polar_agent_good" {
			http.Error(w, "invalid agent token", http.StatusUnauthorized)
			return
		}
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_id":"at_1","user_id":"u_1","workspace_id":"ws_1"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tester", DeriveHMACKey("polar_plugin_test"))

	res, err := c.AuthVerifyAgent("polar_agent_good")
	if err != nil {
		t.Fatalf("AuthVerifyAgent: %v", err)
	}
	if res.TokenID != "at_1" || res.UserID != "u_1" || res.WorkspaceID != "ws_1" {
		t.Fatalf("unexpected result: %+v", res)
	}

	// Second call within the 30s window must be served from cache (no extra
	// server hit) — mirrors AuthVerify's caching contract.
	if _, err := c.AuthVerifyAgent("polar_agent_good"); err != nil {
		t.Fatalf("AuthVerifyAgent (cached): %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 upstream hit (cached), got %d", got)
	}
}

func TestAuthVerifyAgent_InvalidPropagatesAndDoesNotCache(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "invalid agent token", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tester", DeriveHMACKey("polar_plugin_test"))

	if _, err := c.AuthVerifyAgent("polar_agent_bad"); err == nil {
		t.Fatal("expected error for 401, got nil")
	}
	// A failed verify must not be cached: a second call hits the server again.
	if _, err := c.AuthVerifyAgent("polar_agent_bad"); err == nil {
		t.Fatal("expected error for 401 (2nd), got nil")
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("invalid result must not cache: expected 2 hits, got %d", got)
	}
}

func TestAuthVerifyAgent_EmptyToken(t *testing.T) {
	c := NewClient("http://127.0.0.1:0", "tester", DeriveHMACKey("polar_plugin_test"))
	if _, err := c.AuthVerifyAgent("   "); err == nil || !strings.Contains(err.Error(), "empty token") {
		t.Fatalf("expected empty-token error, got %v", err)
	}
}
