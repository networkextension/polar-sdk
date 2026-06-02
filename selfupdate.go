package sdk

// selfupdate.go — OTA self-update for plugin modules (Track 3 of the
// module-platform plan). The model is pull-based: a module's heartbeat
// (HeartbeatV2) returns an *UpdateDirective when dock wants it on a
// different binary version; the module calls SelfUpdate, which downloads +
// sha-verifies the new binary, atomically swaps it over its own on-disk
// image, and exits. A launchd/systemd supervisor with KeepAlive then
// restarts the process on the new binary — no dock→plugin push channel.
//
// The exit is deliberately NON-ZERO (ExitCodeSelfUpdated). launchd's common
// `KeepAlive={SuccessfulExit=false}` only restarts a job that exits
// unsuccessfully, so a clean exit(0) after the swap would leave the module
// down. A non-zero code restarts under BOTH that config and plain
// `KeepAlive=true`; systemd `Restart=always`/`on-failure` likewise.
//
// SelfUpdate is deliberately blunt and opt-in: callers gate it behind their
// own env flag (e.g. POLAR_SELF_UPDATE=1) so a compromised/buggy dock can
// never move a binary that the operator didn't arm.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ExitCodeSelfUpdated is the process exit code SelfUpdate uses after a
// successful swap. It is non-zero on purpose so a KeepAlive supervisor
// restarts the process on the new binary (see the package comment); it's
// also greppable in logs to distinguish an OTA restart from a crash.
const ExitCodeSelfUpdated = 42

// SelfUpdate downloads the binary named by d, verifies it against d.SHA256,
// atomically replaces the file at binPath, and then exits the process with
// ExitCodeSelfUpdated (non-zero) so the supervisor restarts it on the new
// binary. It does NOT return on success.
//
// On any failure before the swap (download error, sha mismatch, write/rename
// error) it returns a non-nil error and leaves binPath untouched, so the
// current binary keeps running. A `<binPath>.bak` copy of the previous
// binary is kept for manual rollback.
//
// binPath is typically the result of os.Executable(). Callers must ensure
// the process has write permission to its own directory (true for the
// ~/.local/bin deploy layout).
func SelfUpdate(d *UpdateDirective, binPath string) error {
	if d == nil {
		return errors.New("sdk.SelfUpdate: nil directive")
	}
	if strings.TrimSpace(d.URL) == "" || strings.TrimSpace(d.SHA256) == "" {
		return errors.New("sdk.SelfUpdate: directive missing url or sha256")
	}
	binPath = strings.TrimSpace(binPath)
	if binPath == "" {
		return errors.New("sdk.SelfUpdate: empty binPath")
	}
	binPath, err := filepath.Abs(binPath)
	if err != nil {
		return fmt.Errorf("sdk.SelfUpdate: resolve binPath: %w", err)
	}

	// Download to a sibling temp file (same dir → rename is atomic, no
	// cross-device copy) while streaming through the hasher.
	dir := filepath.Dir(binPath)
	tmp, err := os.CreateTemp(dir, ".selfupdate-*.new")
	if err != nil {
		return fmt.Errorf("sdk.SelfUpdate: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if we bail before the rename.
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(d.URL)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("sdk.SelfUpdate: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		tmp.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("sdk.SelfUpdate: download HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	h := sha256.New()
	if _, err := io.Copy(tmp, io.TeeReader(resp.Body, h)); err != nil {
		tmp.Close()
		return fmt.Errorf("sdk.SelfUpdate: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("sdk.SelfUpdate: close temp: %w", err)
	}

	got := hex.EncodeToString(h.Sum(nil))
	want := strings.ToLower(strings.TrimSpace(d.SHA256))
	if got != want {
		return fmt.Errorf("sdk.SelfUpdate: sha256 mismatch: got %s want %s", got, want)
	}

	// Authenticity gate. sha256 above proves integrity (the bytes match the
	// hash dock named); ed25519 proves the RELEASE service blessed those
	// bytes, so a compromised storage provider can't serve a malicious
	// binary even with a matching hash. Enforced only when the operator
	// pins the release public key via POLAR_RELEASE_PUBKEY — fail-closed:
	// with the key pinned, a directive lacking a valid signature is
	// rejected (the binary is NOT swapped). Unset → sha256-only, as before.
	if pub := strings.TrimSpace(os.Getenv("POLAR_RELEASE_PUBKEY")); pub != "" {
		if err := verifyReleaseSignature(d, pub); err != nil {
			return fmt.Errorf("sdk.SelfUpdate: %w", err)
		}
	}

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("sdk.SelfUpdate: chmod temp: %w", err)
	}

	// Keep a rollback copy of the current binary. Non-fatal if it fails
	// (e.g. first install); we still proceed with the swap.
	_ = copyFile(binPath, binPath+".bak")

	// Atomic swap. On POSIX, rename over a running binary is allowed (the
	// open fd keeps the old inode); the new image takes effect on restart.
	if err := os.Rename(tmpPath, binPath); err != nil {
		return fmt.Errorf("sdk.SelfUpdate: rename into place: %w", err)
	}
	cleanup = false // tmp is now binPath

	fmt.Fprintf(os.Stderr, "sdk.SelfUpdate: swapped %s -> version %s (sha %s); exiting %d for supervisor restart\n", binPath, d.Version, got, ExitCodeSelfUpdated)
	os.Exit(ExitCodeSelfUpdated)
	return nil // unreachable
}

// ReleaseManifest mirrors polar-release's signed manifest. It travels in
// the OTA directive (Manifest) so a self-updating module can reconstruct
// the exact bytes the release service signed and verify the signature.
// Field order + tags match polar-release/internal/release/manifest.go.
type ReleaseManifest struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Channel  string `json:"channel"`
	Platform string `json:"platform"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	MinHost  string `json:"min_host,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// canonicalBytes reproduces polar-release's signing input EXACTLY. Any
// drift here silently breaks verification, so keep it byte-for-byte in
// lockstep with release's Manifest.canonicalBytes (notes are NOT signed).
func (m ReleaseManifest) canonicalBytes() []byte {
	return []byte("polar-release/v1\n" +
		"module=" + m.Module + "\n" +
		"version=" + m.Version + "\n" +
		"channel=" + m.Channel + "\n" +
		"platform=" + m.Platform + "\n" +
		"sha256=" + m.SHA256 + "\n" +
		"size=" + strconv.FormatInt(m.Size, 10) + "\n" +
		"min_host=" + m.MinHost + "\n")
}

// verifyReleaseSignature checks the directive's ed25519 signature over its
// manifest against the pinned public key (hex). It also cross-checks that
// the manifest's sha256/version agree with the directive, so the signature
// can't cover different bytes than the ones being installed.
func verifyReleaseSignature(d *UpdateDirective, pubHex string) error {
	if d.Manifest == nil {
		return errors.New("ed25519 verify: directive has no manifest (release key is pinned)")
	}
	if strings.TrimSpace(d.Ed25519Sig) == "" {
		return errors.New("ed25519 verify: directive has no signature (release key is pinned)")
	}
	if !strings.EqualFold(d.Manifest.SHA256, strings.TrimSpace(d.SHA256)) {
		return fmt.Errorf("ed25519 verify: manifest sha256 != directive sha256")
	}
	pub, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("ed25519 verify: POLAR_RELEASE_PUBKEY is not a valid ed25519 public key")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(d.Ed25519Sig))
	if err != nil {
		return errors.New("ed25519 verify: signature not hex")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), d.Manifest.canonicalBytes(), sig) {
		return errors.New("ed25519 verify: signature does not match release public key")
	}
	return nil
}

// copyFile copies src to dst (0755), truncating dst. Used for the .bak
// rollback snapshot; errors are surfaced to the caller, which treats them
// as non-fatal.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
