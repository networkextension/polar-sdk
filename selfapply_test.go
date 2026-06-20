package sdk

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelfApply_NilDirective(t *testing.T) {
	if _, err := SelfApply(nil, "", ""); err == nil {
		t.Fatal("nil directive should error")
	}
}

func TestSelfApply_BinaryNeedsBinPath(t *testing.T) {
	d := &UpdateDirective{
		Version: "1", URL: "http://x/y", SHA256: "ab",
		Manifest: &ReleaseManifest{Module: "demo", Version: "1", Format: ""},
	}
	if _, err := SelfApply(d, "", "/tmp/dest"); err == nil {
		t.Fatal("binary artifact with empty binPath should error")
	}
}

func TestSelfApply_ArchiveNeedsDestRoot(t *testing.T) {
	d := &UpdateDirective{
		Version: "1", URL: "http://x/y", SHA256: "ab",
		Manifest: &ReleaseManifest{Module: "demo", Version: "1", Format: "tar.gz"},
	}
	if _, err := SelfApply(d, "/tmp/bin", ""); err == nil {
		t.Fatal("archive artifact with empty destRoot should error")
	}
}

// TestSelfApply_ArchiveDispatches confirms SelfApply routes an archive
// directive into SelfInstall (the full unpack + entrypoint path), reusing the
// tar.gz test fixtures from selfinstall_test.go.
func TestSelfApply_ArchiveDispatches(t *testing.T) {
	archive := buildTarGz(t, []tarEntry{
		{"install.sh", "#!/bin/sh\ntouch \"$POLAR_NEW_DIR/applied.marker\"\n", 0o755},
	})
	d := serveArchive(t, archive, "install.sh")
	root := t.TempDir()

	got, err := SelfApply(d, "", root)
	if err != nil {
		t.Fatalf("SelfApply(archive) failed: %v", err)
	}
	if got != filepath.Join(root, "versions", "1.2.0") {
		t.Errorf("installedDir = %q", got)
	}
	if _, err := os.Stat(filepath.Join(got, "applied.marker")); err != nil {
		t.Errorf("entrypoint did not run via SelfApply: %v", err)
	}
}
