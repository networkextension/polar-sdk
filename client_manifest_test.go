package sdk

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAuthVerify_DecodesKindTokenIDScopes(t *testing.T) {
	bodies := map[string]string{
		// session: scopes null, token_id null
		"sess": `{"user_id":"u1","username":"a","role":"admin","platform_role":"admin","module":"opera","module_role":"creator","workspace_id":"w1","expires_at":"2026-10-22T00:00:00Z","kind":"session","token_id":null,"scopes":null}`,
		// api token, scoped but nothing for this module: scopes []
		"empty": `{"user_id":"u1","username":"a","role":"member","workspace_id":"w1","expires_at":"","kind":"api_token","token_id":42,"scopes":[]}`,
		// api token with module scopes
		"scoped": `{"user_id":"u1","username":"a","role":"member","workspace_id":"w1","expires_at":"","kind":"api_token","token_id":7,"scopes":["opera:sessions:read","opera:devices:*"]}`,
		// older dock: none of the new fields
		"old": `{"user_id":"u1","username":"a","role":"member","workspace_id":"w1","expires_at":""}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := bodies[r.URL.Query().Get("token")]
		if !ok {
			http.Error(w, "invalid", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, b)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "opera", DeriveHMACKey("x"))

	sess, err := c.AuthVerify("sess")
	if err != nil {
		t.Fatal(err)
	}
	if sess.TokenKind() != "session" || sess.TokenID != nil || sess.Scopes != nil || !sess.Unscoped() {
		t.Fatalf("session: %+v", sess)
	}
	if sess.PlatformRole != "admin" || sess.Module != "opera" || sess.ModuleRole != "creator" {
		t.Fatalf("session roles: %+v", sess)
	}
	if !sess.HasScope("opera:anything:read") {
		t.Fatal("unscoped session must grant every scope")
	}

	empty, err := c.AuthVerify("empty")
	if err != nil {
		t.Fatal(err)
	}
	if empty.Scopes == nil {
		t.Fatal("scopes [] must decode to non-nil empty slice, not nil")
	}
	if len(*empty.Scopes) != 0 || empty.Unscoped() || empty.HasScope("opera:sessions:read") {
		t.Fatalf("empty-scoped token must grant nothing: %+v", empty)
	}
	if empty.TokenKind() != "api_token" || empty.TokenID == nil || *empty.TokenID != 42 {
		t.Fatalf("empty token id/kind: %+v", empty)
	}

	scoped, err := c.AuthVerify("scoped")
	if err != nil {
		t.Fatal(err)
	}
	if !scoped.HasScope("opera:sessions:read") || !scoped.HasScope("opera:devices:read") || scoped.HasScope("opera:markers:write") {
		t.Fatalf("scoped HasScope wrong: %+v", *scoped.Scopes)
	}

	old, err := c.AuthVerify("old")
	if err != nil {
		t.Fatal(err)
	}
	if old.TokenKind() != "session" || old.TokenID != nil || old.Scopes != nil {
		t.Fatalf("old dock defaults: %+v", old)
	}
}

func TestAuthVerify_CachedScopesPreserveNullVsEmptyAndDontAlias(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Query().Get("token") == "null" {
			_, _ = io.WriteString(w, `{"user_id":"u","kind":"api_token","token_id":1,"scopes":null}`)
			return
		}
		_, _ = io.WriteString(w, `{"user_id":"u","kind":"api_token","token_id":2,"scopes":[]}`)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "opera", DeriveHMACKey("x"))

	for i := 0; i < 2; i++ {
		n, err := c.AuthVerify("null")
		if err != nil || n.Scopes != nil {
			t.Fatalf("pass %d: null scopes became %v (err %v)", i, n.Scopes, err)
		}
		e, err := c.AuthVerify("empty")
		if err != nil || e.Scopes == nil || len(*e.Scopes) != 0 {
			t.Fatalf("pass %d: [] scopes became %v (err %v)", i, e.Scopes, err)
		}
		// Mutating the returned value must not poison the cache.
		*e.Scopes = append(*e.Scopes, "*")
		*e.TokenID = 99
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected 2 upstream hits (second pass cached), got %d", got)
	}
}

func TestPutManifest_SignedPutAndAck(t *testing.T) {
	key := DeriveHMACKey("polar_plugin_test")
	manifest := map[string]any{
		"module":           "opera",
		"manifest_version": "abc123",
		"scopes":           []map[string]any{{"id": "opera:sessions:read", "group": "场次", "name": "读场次", "sensitive": false}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/internal/v1/modules/opera/manifest" {
			http.Error(w, "wrong route "+r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		canonical := fmt.Sprintf("PUT\n%s\n%s\n%s", r.URL.Path, r.Header.Get("X-Polar-Plugin-Timestamp"), hex.EncodeToString(sum[:]))
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(canonical))
		if r.Header.Get("X-Polar-Plugin-Name") != "opera" || !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(r.Header.Get("X-Polar-Plugin-Sig"))) {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil || got["manifest_version"] != "abc123" {
			http.Error(w, `{"error":"bad body"}`, http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"ack":true,"changed":true,"version":"abc123"}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "opera", key)
	ack, err := c.PutManifest(context.Background(), manifest)
	if err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	if !ack.Ack || !ack.Changed || ack.Version != "abc123" {
		t.Fatalf("unexpected ack: %+v", ack)
	}
}

func TestPutManifest_ErrorsPropagate(t *testing.T) {
	for _, tc := range []struct {
		code int
		body string
	}{
		{http.StatusBadRequest, `{"error":"scope opera:x must have 3 parts"}`},
		{http.StatusForbidden, `{"error":"module mismatch"}`},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.code)
			_, _ = io.WriteString(w, tc.body)
		}))
		c := NewClient(srv.URL, "opera", DeriveHMACKey("x"))
		_, err := c.PutManifest(context.Background(), map[string]any{"module": "opera"})
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), fmt.Sprint(tc.code)) || !strings.Contains(err.Error(), "error") {
			t.Fatalf("code %d: want error with status+body, got %v", tc.code, err)
		}
	}
}

func TestPutManifest_HonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ack":true}`)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewClient(srv.URL, "opera", DeriveHMACKey("x"))
	if _, err := c.PutManifest(ctx, map[string]any{"module": "opera"}); err == nil {
		t.Fatal("expected error from cancelled context")
	}
}
