package sdk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

type tarEntry struct {
	name string
	body string
	mode int64
}

func buildTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: e.name, Mode: e.mode, Size: int64(len(e.body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// serveBytes returns an httptest server handing back the given bytes, and a
// signed UpdateDirective (format=tar.gz) pointing at it. It also pins
// POLAR_RELEASE_PUBKEY for the test so the ed25519 path is exercised.
func serveArchive(t *testing.T, archive []byte, entrypoint string) *UpdateDirective {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(srv.Close)

	sum := sha256.Sum256(archive)
	sha := hex.EncodeToString(sum[:])
	m := ReleaseManifest{
		Module: "demo", Version: "1.2.0", Channel: "dev", Platform: "darwin-arm64",
		SHA256: sha, Size: int64(len(archive)), Format: "tar.gz", Entrypoint: entrypoint,
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, m.canonicalBytes())
	t.Setenv("POLAR_RELEASE_PUBKEY", hex.EncodeToString(pub))
	mm := m
	return &UpdateDirective{
		Version: m.Version, URL: srv.URL + "/demo.tgz", SHA256: sha,
		Ed25519Sig: hex.EncodeToString(sig), Manifest: &mm,
	}
}

func TestSelfInstall_HappyPath(t *testing.T) {
	script := "#!/bin/sh\ntouch \"$POLAR_NEW_DIR/installed.marker\"\necho \"$POLAR_VERSION\" > \"$POLAR_NEW_DIR/ran-version\"\n"
	archive := buildTarGz(t, []tarEntry{
		{"install.sh", script, 0o755},
		{"bin/demo-svc", "fake-binary-bytes", 0o644},
	})
	d := serveArchive(t, archive, "install.sh")
	root := t.TempDir()

	got, err := SelfInstall(d, root)
	if err != nil {
		t.Fatalf("SelfInstall failed: %v", err)
	}
	wantDir := filepath.Join(root, "versions", "1.2.0")
	if got != wantDir {
		t.Errorf("installedDir = %q want %q", got, wantDir)
	}
	if _, err := os.Stat(filepath.Join(wantDir, "installed.marker")); err != nil {
		t.Errorf("entrypoint did not run (no marker): %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(wantDir, "ran-version")); string(b) != "1.2.0\n" {
		t.Errorf("entrypoint env POLAR_VERSION wrong: %q", b)
	}
	// current → versions/1.2.0
	link, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatalf("current symlink missing: %v", err)
	}
	if link != filepath.Join("versions", "1.2.0") {
		t.Errorf("current → %q want versions/1.2.0", link)
	}
}

func TestSelfInstall_RejectsBinaryFormat(t *testing.T) {
	d := &UpdateDirective{
		Version: "1", URL: "http://x/y", SHA256: "ab",
		Manifest: &ReleaseManifest{Module: "demo", Version: "1", Format: ""},
	}
	if _, err := SelfInstall(d, t.TempDir()); err == nil {
		t.Fatal("binary format should be rejected (use SelfUpdate)")
	}
}

func TestSelfInstall_ShaMismatch(t *testing.T) {
	archive := buildTarGz(t, []tarEntry{{"install.sh", "#!/bin/sh\ntrue\n", 0o755}})
	d := serveArchive(t, archive, "install.sh")
	d.SHA256 = "00" + d.SHA256[2:] // corrupt the expected hash
	if _, err := SelfInstall(d, t.TempDir()); err == nil {
		t.Fatal("sha256 mismatch should fail")
	}
}

func TestSelfInstall_FailedEntrypointKeepsCurrent(t *testing.T) {
	archive := buildTarGz(t, []tarEntry{{"install.sh", "#!/bin/sh\nexit 7\n", 0o755}})
	d := serveArchive(t, archive, "install.sh")
	root := t.TempDir()
	if _, err := SelfInstall(d, root); err == nil {
		t.Fatal("non-zero entrypoint should fail SelfInstall")
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !os.IsNotExist(err) {
		t.Error("current symlink must not be created when entrypoint fails")
	}
}

func TestSelfInstall_RejectsTarSlip(t *testing.T) {
	// A malicious entry that tries to escape the version dir.
	archive := buildTarGz(t, []tarEntry{
		{"install.sh", "#!/bin/sh\ntrue\n", 0o755},
		{"../escape.txt", "pwned", 0o644},
	})
	d := serveArchive(t, archive, "install.sh")
	root := t.TempDir()
	if _, err := SelfInstall(d, root); err == nil {
		t.Fatal("tar-slip entry should be rejected")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.txt")); err == nil {
		t.Fatal("tar-slip wrote a file outside the destination!")
	}
}
