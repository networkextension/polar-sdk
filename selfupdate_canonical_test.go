package sdk

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// TestReleaseManifest_LegacyGolden pins the EXACT canonical bytes for a binary
// (no format) manifest. This MUST stay byte-identical to polar-release's
// Manifest.canonicalBytes legacy output, or releases signed before the format
// field stop verifying. It mirrors the release-side golden of the same name.
func TestReleaseManifest_LegacyGolden(t *testing.T) {
	m := ReleaseManifest{
		Module: "buildings", Version: "0.0.3", Channel: "stable",
		Platform: "darwin-arm64", SHA256: strings.Repeat("ab", 32), Size: 1234,
		MinHost: "0.5.0", Notes: "fix keepalive",
	}
	want := "polar-release/v1\n" +
		"module=buildings\n" +
		"version=0.0.3\n" +
		"channel=stable\n" +
		"platform=darwin-arm64\n" +
		"sha256=" + strings.Repeat("ab", 32) + "\n" +
		"size=1234\n" +
		"min_host=0.5.0\n"
	if got := string(m.canonicalBytes()); got != want {
		t.Fatalf("legacy canonical bytes drifted from release:\n got %q\nwant %q", got, want)
	}
}

// TestVerifyReleaseSignature_ArchiveManifest proves an archive manifest
// (format+entrypoint signed) verifies, and that flipping the format after
// signing breaks verification — the consumer can't be tricked about whether
// it's running an install script.
func TestVerifyReleaseSignature_ArchiveManifest(t *testing.T) {
	m := sampleRelManifest()
	m.Format, m.Entrypoint = "tar.gz", "install.sh"
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, m.canonicalBytes())
	mm := m
	d := &UpdateDirective{
		Version: m.Version, URL: "https://prov/blob/" + m.SHA256, SHA256: m.SHA256,
		Ed25519Sig: hex.EncodeToString(sig), Manifest: &mm,
	}
	if err := verifyReleaseSignature(d, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("archive manifest signature rejected: %v", err)
	}
	d.Manifest.Format = "binary" // attacker downgrades install mode
	if err := verifyReleaseSignature(d, hex.EncodeToString(pub)); err == nil {
		t.Fatal("tampered format verified")
	}
}
