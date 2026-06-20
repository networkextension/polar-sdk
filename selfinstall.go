package sdk

// selfinstall.go — install an ARCHIVE release (a bundle of files + an install
// script), as opposed to a single binary (selfupdate.go). The model:
//
//	resolve/heartbeat → UpdateDirective{URL, SHA256, Ed25519Sig, Manifest}
//	  with Manifest.Format ∈ {tar.gz, tgz, zip} and Manifest.Entrypoint (e.g.
//	  install.sh). SelfInstall downloads, sha256-verifies, ed25519-verifies
//	  (when POLAR_RELEASE_PUBKEY is pinned — fail-closed), unpacks into
//	  <destRoot>/versions/<version>/, runs the entrypoint from there, and on
//	  success atomically repoints <destRoot>/current at the new version dir.
//
// Unlike SelfUpdate, SelfInstall RETURNS (no os.Exit/restart) — the caller
// owns what happens next (the install script usually (re)starts services).
//
// SECURITY: the entrypoint is arbitrary code. It runs ONLY after sha256 and
// (when pinned) ed25519 verification, and the signed sha256 covers the whole
// archive including the script — so a compromised provider can't alter the
// script without invalidating the signature. Pin POLAR_RELEASE_PUBKEY on any
// host that runs install scripts. Archive entries are path-traversal-checked
// before any file is written (no zip/tar slip).

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// maxArchiveEntryBytes caps a single unpacked file (defense against zip bombs).
const maxArchiveEntryBytes = 1 << 30 // 1 GiB

// SelfInstall installs an archive release described by d into destRoot. It
// returns the path of the installed version directory (now the current
// symlink target) on success. On any failure it leaves destRoot/current
// untouched and returns a non-nil error; a partially-staged version dir may
// remain under destRoot/versions for inspection.
func SelfInstall(d *UpdateDirective, destRoot string) (string, error) {
	if d == nil {
		return "", errors.New("sdk.SelfInstall: nil directive")
	}
	if strings.TrimSpace(d.URL) == "" || strings.TrimSpace(d.SHA256) == "" {
		return "", errors.New("sdk.SelfInstall: directive missing url or sha256")
	}
	if d.Manifest == nil {
		return "", errors.New("sdk.SelfInstall: directive has no manifest (need format/entrypoint)")
	}
	format := strings.ToLower(strings.TrimSpace(d.Manifest.Format))
	switch format {
	case "", "binary":
		return "", errors.New("sdk.SelfInstall: manifest format is binary — use SelfUpdate")
	case "tar.gz", "tgz", "zip":
		// ok
	default:
		return "", fmt.Errorf("sdk.SelfInstall: unsupported format %q", format)
	}
	entrypoint := strings.TrimSpace(d.Manifest.Entrypoint)
	if entrypoint == "" {
		entrypoint = "install.sh"
	}
	version := strings.TrimSpace(d.Manifest.Version)
	if version == "" {
		version = strings.TrimSpace(d.Version)
	}
	if version == "" {
		return "", errors.New("sdk.SelfInstall: empty version")
	}
	destRoot = strings.TrimSpace(destRoot)
	if destRoot == "" {
		return "", errors.New("sdk.SelfInstall: empty destRoot")
	}
	destRoot, err := filepath.Abs(destRoot)
	if err != nil {
		return "", fmt.Errorf("sdk.SelfInstall: resolve destRoot: %w", err)
	}

	// 1. download to a temp file while hashing.
	tmp, err := os.CreateTemp("", "polar-pkg-*.dl")
	if err != nil {
		return "", fmt.Errorf("sdk.SelfInstall: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(d.URL)
	if err != nil {
		tmp.Close()
		return "", fmt.Errorf("sdk.SelfInstall: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		tmp.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("sdk.SelfInstall: download HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	h := sha256.New()
	if _, err := io.Copy(tmp, io.TeeReader(resp.Body, h)); err != nil {
		tmp.Close()
		return "", fmt.Errorf("sdk.SelfInstall: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("sdk.SelfInstall: close temp: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if want := strings.ToLower(strings.TrimSpace(d.SHA256)); got != want {
		return "", fmt.Errorf("sdk.SelfInstall: sha256 mismatch: got %s want %s", got, want)
	}

	// 2. authenticity gate (fail-closed when the release key is pinned).
	if pub := strings.TrimSpace(os.Getenv("POLAR_RELEASE_PUBKEY")); pub != "" {
		if err := verifyReleaseSignature(d, pub); err != nil {
			return "", fmt.Errorf("sdk.SelfInstall: %w", err)
		}
	}

	// 3. unpack into a fresh versions/<version> dir.
	verDir := filepath.Join(destRoot, "versions", version)
	if err := os.RemoveAll(verDir); err != nil {
		return "", fmt.Errorf("sdk.SelfInstall: clear version dir: %w", err)
	}
	if err := os.MkdirAll(verDir, 0o755); err != nil {
		return "", fmt.Errorf("sdk.SelfInstall: mkdir version dir: %w", err)
	}
	if format == "zip" {
		err = unpackZip(tmpPath, verDir)
	} else {
		err = unpackTarGz(tmpPath, verDir)
	}
	if err != nil {
		return "", fmt.Errorf("sdk.SelfInstall: unpack: %w", err)
	}

	// 4. run the entrypoint from inside the version dir.
	entryPath := filepath.Join(verDir, filepath.Clean("/" + entrypoint)[1:])
	if !strings.HasPrefix(entryPath, verDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("sdk.SelfInstall: entrypoint %q escapes version dir", entrypoint)
	}
	if fi, statErr := os.Stat(entryPath); statErr != nil || fi.IsDir() {
		return "", fmt.Errorf("sdk.SelfInstall: entrypoint %q not found in archive", entrypoint)
	}
	_ = os.Chmod(entryPath, 0o755)

	prevDir, _ := os.Readlink(filepath.Join(destRoot, "current"))
	cmd := exec.Command(entryPath)
	cmd.Dir = verDir
	cmd.Stdout = os.Stderr // install logs → stderr, never stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"POLAR_MODULE="+d.Manifest.Module,
		"POLAR_VERSION="+version,
		"POLAR_PLATFORM="+d.Manifest.Platform,
		"POLAR_NEW_DIR="+verDir,
		"POLAR_PREV_DIR="+prevDir,
	)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("sdk.SelfInstall: entrypoint %q failed (current symlink left unchanged): %w", entrypoint, err)
	}

	// 5. flip current → versions/<version> atomically (symlink rename).
	if err := repointSymlink(filepath.Join(destRoot, "current"), filepath.Join("versions", version)); err != nil {
		return "", fmt.Errorf("sdk.SelfInstall: repoint current: %w", err)
	}
	fmt.Fprintf(os.Stderr, "sdk.SelfInstall: installed %s %s -> %s (current updated)\n", d.Manifest.Module, version, verDir)
	return verDir, nil
}

// repointSymlink atomically points linkPath at target by creating a temp
// symlink in the same dir and renaming it over linkPath (rename is atomic).
func repointSymlink(linkPath, target string) error {
	dir := filepath.Dir(linkPath)
	tmp, err := os.CreateTemp(dir, ".current-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	tmp.Close()
	_ = os.Remove(tmpName) // need a non-existent path for Symlink
	if err := os.Symlink(target, tmpName); err != nil {
		return err
	}
	if err := os.Rename(tmpName, linkPath); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// safeJoin joins dir + a (possibly hostile) archive entry name, rejecting any
// path that would escape dir (absolute paths, "..", symlinked parents).
// It returns ("", nil) for the archive root entry ("." / "./", as produced by
// `tar -C dir .`), which the caller skips — that's a benign no-op, not an error.
func safeJoin(dir, name string) (string, error) {
	if name == "" {
		return "", errors.New("empty entry name")
	}
	norm := strings.ReplaceAll(name, `\`, "/")
	if filepath.IsAbs(name) || strings.HasPrefix(norm, "/") {
		return "", fmt.Errorf("absolute entry path: %q", name)
	}
	// Reject any ".." component outright — a legit install bundle never needs
	// to climb out of its own directory.
	for _, seg := range strings.Split(norm, "/") {
		if seg == ".." {
			return "", fmt.Errorf("entry escapes destination: %q", name)
		}
	}
	clean := filepath.Clean(norm)
	if clean == "" || clean == "." {
		return "", nil // archive root entry → caller skips
	}
	out := filepath.Join(dir, clean)
	if out != dir && !strings.HasPrefix(out, dir+string(os.PathSeparator)) {
		return "", fmt.Errorf("entry %q escapes destination", name)
	}
	return out, nil
}

func unpackTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target, err := safeJoin(destDir, hdr.Name)
		if err != nil {
			return err
		}
		if target == "" {
			continue // archive root entry
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777|0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, io.LimitReader(tr, maxArchiveEntryBytes)); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			// Reject links: they're a classic traversal vector and unnecessary
			// for an install bundle.
			return fmt.Errorf("archive contains a link entry %q (not allowed)", hdr.Name)
		default:
			// skip fifos/devices/etc.
		}
	}
	return nil
}

func unpackZip(archivePath, destDir string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, zf := range zr.File {
		target, err := safeJoin(destDir, zf.Name)
		if err != nil {
			return err
		}
		if target == "" {
			continue // archive root entry
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zf.Mode().Perm()|0o600)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(rc, maxArchiveEntryBytes)); err != nil {
			out.Close()
			rc.Close()
			return err
		}
		out.Close()
		rc.Close()
	}
	return nil
}
