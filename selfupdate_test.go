package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestSelfUpdate_AbortsLeaveBinaryIntact covers the failure paths that must
// NOT touch the running binary: nil/empty directive, sha mismatch, and a
// non-2xx download. The success path calls os.Exit and so isn't unit-tested
// here (it's exercised by the dev smoke).
func TestSelfUpdate_AbortsLeaveBinaryIntact(t *testing.T) {
	const original = "ORIGINAL-BINARY-BYTES"

	newBin := func(t *testing.T) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "buildings-svc")
		if err := os.WriteFile(p, []byte(original), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	assertIntact := func(t *testing.T, p string) {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read binary: %v", err)
		}
		if string(b) != original {
			t.Fatalf("binary was modified on an aborted update: %q", string(b))
		}
	}

	t.Run("nil directive", func(t *testing.T) {
		p := newBin(t)
		if err := SelfUpdate(nil, p); err == nil {
			t.Fatal("expected error for nil directive")
		}
		assertIntact(t, p)
	})

	t.Run("missing url/sha", func(t *testing.T) {
		p := newBin(t)
		if err := SelfUpdate(&UpdateDirective{Version: "1"}, p); err == nil {
			t.Fatal("expected error for empty url/sha")
		}
		assertIntact(t, p)
	})

	t.Run("sha mismatch", func(t *testing.T) {
		p := newBin(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("DIFFERENT-CONTENT"))
		}))
		defer srv.Close()
		d := &UpdateDirective{Version: "2", URL: srv.URL, SHA256: hexSum("NOT-WHAT-IS-SERVED")}
		if err := SelfUpdate(d, p); err == nil {
			t.Fatal("expected sha mismatch error")
		}
		assertIntact(t, p)
		if _, err := os.Stat(p + ".bak"); err == nil {
			t.Fatal(".bak should not exist when update aborts before swap")
		}
	})

	t.Run("download 404", func(t *testing.T) {
		p := newBin(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", http.StatusNotFound)
		}))
		defer srv.Close()
		d := &UpdateDirective{Version: "2", URL: srv.URL, SHA256: hexSum("x")}
		if err := SelfUpdate(d, p); err == nil {
			t.Fatal("expected error for 404 download")
		}
		assertIntact(t, p)
	})
}

func hexSum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
