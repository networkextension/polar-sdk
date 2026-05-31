package sdk

// selfupdate.go — OTA self-update for plugin modules (Track 3 of the
// module-platform plan). The model is pull-based: a module's heartbeat
// (HeartbeatV2) returns an *UpdateDirective when dock wants it on a
// different binary version; the module calls SelfUpdate, which downloads +
// sha-verifies the new binary, atomically swaps it over its own on-disk
// image, and exits. A launchd/systemd supervisor with KeepAlive then
// restarts the process on the new binary — no dock→plugin push channel.
//
// SelfUpdate is deliberately blunt and opt-in: callers gate it behind their
// own env flag (e.g. POLAR_SELF_UPDATE=1) so a compromised/buggy dock can
// never move a binary that the operator didn't arm.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SelfUpdate downloads the binary named by d, verifies it against d.SHA256,
// atomically replaces the file at binPath, and then calls os.Exit(0) so the
// supervisor restarts the process on the new binary. It does NOT return on
// success.
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

	fmt.Fprintf(os.Stderr, "sdk.SelfUpdate: swapped %s -> version %s (sha %s); exiting for supervisor restart\n", binPath, d.Version, got)
	os.Exit(0)
	return nil // unreachable
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
