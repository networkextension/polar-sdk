package sdk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeriveHMACKey_MatchesDockServerSide(t *testing.T) {
	// Dock stores sha256(plaintext) hex as plugin_modules.plugin_key_hash
	// and uses that exact string as the HMAC key. The SDK must derive
	// the same 64-byte hex string from the same plaintext, otherwise
	// every signed request fails verification.
	plaintext := "polar_plugin_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	got := DeriveHMACKey(plaintext)
	sum := sha256.Sum256([]byte(plaintext))
	want := []byte(hex.EncodeToString(sum[:]))
	if string(got) != string(want) {
		t.Fatalf("derive: got %q want %q", got, want)
	}
	if len(got) != 64 {
		t.Fatalf("derived key length: got %d want 64", len(got))
	}
}

func TestDoSetsSignatureHeadersAndUsesDerivedKey(t *testing.T) {
	// End-to-end: spin up a dock stand-in that re-derives the HMAC the
	// same way the real middleware does and rejects mismatched sigs.
	key := DeriveHMACKey("polar_plugin_test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Header.Get("X-Polar-Plugin-Name")
		ts := r.Header.Get("X-Polar-Plugin-Timestamp")
		gotSig := r.Header.Get("X-Polar-Plugin-Sig")
		if name == "" || ts == "" || gotSig == "" {
			http.Error(w, "missing headers", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		bodySum := sha256.Sum256(body)
		canonical := strings.ToUpper(r.Method) + "\n" + r.URL.RequestURI() + "\n" + ts + "\n" + hex.EncodeToString(bodySum[:])
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(canonical))
		want := hex.EncodeToString(mac.Sum(nil))
		if !strings.EqualFold(want, gotSig) {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "true", "plugin": name})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "wg-test", key)
	resp, err := c.Do(http.MethodGet, "/internal/v1/ping", nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%q", resp.StatusCode, string(body))
	}
}

func TestAuthVerify_CachesFor30s(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(AuthVerifyResult{
			UserID: "u_test", Username: "tester", Role: "user", WorkspaceID: "t_root",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "wg", DeriveHMACKey("polar_plugin_x"))
	for i := 0; i < 5; i++ {
		got, err := c.AuthVerify("session-token-abc")
		if err != nil {
			t.Fatalf("AuthVerify[%d]: %v", i, err)
		}
		if got.UserID != "u_test" {
			t.Fatalf("AuthVerify[%d]: user_id=%q", i, got.UserID)
		}
	}
	if hits != 1 {
		t.Fatalf("upstream hits: got %d want 1 (cache should absorb the rest)", hits)
	}
}

func TestAuthVerify_BubblesNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid session"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "wg", DeriveHMACKey("polar_plugin_x"))
	_, err := c.AuthVerify("nope")
	if err == nil {
		t.Fatal("expected error on 401, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 in error, got %q", err.Error())
	}
}
