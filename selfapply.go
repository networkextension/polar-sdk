package sdk

// selfapply.go — one entry point that picks the right installer for an OTA
// directive by its artifact format, so a consumer (a self-updating plugin's
// heartbeat loop, or a pull installer like polar-install) adopts pkg support
// with a single call instead of branching on the manifest itself:
//
//	dir, err := sdk.SelfApply(res.Update, selfBinPath(), selfDestRoot())
//
//   - binary  (Manifest.Format empty / "binary") → SelfUpdate(d, binPath):
//     swaps the executable and EXITS the process (never returns on success).
//   - archive (tar.gz/tgz/zip)                    → SelfInstall(d, destRoot):
//     unpacks + runs the entrypoint and RETURNS the installed version dir.
//
// Both halves verify sha256 and (when POLAR_RELEASE_PUBKEY is pinned) the
// ed25519 manifest signature before touching anything — see selfupdate.go /
// selfinstall.go.

import (
	"errors"
	"strings"
)

// SelfApply dispatches d to SelfUpdate (binary) or SelfInstall (archive) by
// d.Manifest.Format. For a binary it requires binPath and does not return on
// success (the process exits for the supervisor to restart). For an archive it
// requires destRoot and returns the installed version directory.
//
// A nil/empty Manifest is treated as a binary (back-compat with directives cut
// before the format field existed).
func SelfApply(d *UpdateDirective, binPath, destRoot string) (string, error) {
	if d == nil {
		return "", errors.New("sdk.SelfApply: nil directive")
	}
	format := ""
	if d.Manifest != nil {
		format = strings.ToLower(strings.TrimSpace(d.Manifest.Format))
	}
	switch format {
	case "", "binary":
		if strings.TrimSpace(binPath) == "" {
			return "", errors.New("sdk.SelfApply: binary artifact needs binPath")
		}
		// Returns only on error; on success it exits the process.
		return "", SelfUpdate(d, binPath)
	default:
		if strings.TrimSpace(destRoot) == "" {
			return "", errors.New("sdk.SelfApply: archive artifact needs destRoot")
		}
		return SelfInstall(d, destRoot)
	}
}
