package sdk

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func signedDirective(t *testing.T, m ReleaseManifest) (*UpdateDirective, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, m.canonicalBytes())
	mm := m
	return &UpdateDirective{
		Version:    m.Version,
		URL:        "https://prov/v1/blob/" + m.SHA256 + "?token=1:2",
		SHA256:     m.SHA256,
		Ed25519Sig: hex.EncodeToString(sig),
		Manifest:   &mm,
	}, hex.EncodeToString(pub)
}

func sampleRelManifest() ReleaseManifest {
	return ReleaseManifest{
		Module: "buildings", Version: "0.0.3", Channel: "stable",
		Platform: "darwin-arm64", SHA256: strings.Repeat("ab", 32), Size: 4096, MinHost: "0.5.0",
	}
}

func TestVerifyReleaseSignature_OK(t *testing.T) {
	d, pub := signedDirective(t, sampleRelManifest())
	if err := verifyReleaseSignature(d, pub); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyReleaseSignature_TamperedManifestSHA(t *testing.T) {
	d, pub := signedDirective(t, sampleRelManifest())
	d.Manifest.SHA256 = strings.Repeat("cd", 32) // attacker swaps the content the sig covers
	if err := verifyReleaseSignature(d, pub); err == nil {
		t.Fatal("tampered manifest sha verified")
	}
}

func TestVerifyReleaseSignature_DirectiveShaMismatch(t *testing.T) {
	d, pub := signedDirective(t, sampleRelManifest())
	d.SHA256 = strings.Repeat("cd", 32) // directive installs different bytes than the manifest signs
	if err := verifyReleaseSignature(d, pub); err == nil {
		t.Fatal("directive/manifest sha mismatch passed")
	}
}

func TestVerifyReleaseSignature_WrongKey(t *testing.T) {
	d, _ := signedDirective(t, sampleRelManifest())
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := verifyReleaseSignature(d, hex.EncodeToString(otherPub)); err == nil {
		t.Fatal("verified under the wrong public key")
	}
}

func TestVerifyReleaseSignature_FailClosed(t *testing.T) {
	d, pub := signedDirective(t, sampleRelManifest())
	// directive missing the signature → reject (key is pinned).
	noSig := *d
	noSig.Ed25519Sig = ""
	if err := verifyReleaseSignature(&noSig, pub); err == nil {
		t.Error("missing signature should be rejected when key is pinned")
	}
	// directive missing the manifest → reject.
	noMan := *d
	noMan.Manifest = nil
	if err := verifyReleaseSignature(&noMan, pub); err == nil {
		t.Error("missing manifest should be rejected when key is pinned")
	}
}
