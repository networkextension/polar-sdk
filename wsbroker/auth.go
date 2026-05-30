// auth.go — request-side token extraction. Mirrors dock's
// extractAccessToken (gin-auth-app/internal/app/dock/middleware.go)
// so wsbroker authenticates identically to /ws/chat: Bearer header
// wins (third-party / mobile-bearer flow), cookie fallback (browser
// cross-subdomain flow when dock issues access_token with the
// parent-domain cookie scope).
//
// Kept package-private — public surface is just the Handler, which
// internally calls this and then sdk.Client.AuthVerify.

package wsbroker

import (
	"net/http"
	"strings"

	sdk "github.com/networkextension/polar-sdk"
)

// accessCookieName is the cookie dock sets on login. Hard-coded
// rather than imported so wsbroker doesn't need a build-time
// dependency on the dock package; if dock ever renames it, both
// sides must move in lockstep (deploy ordering: dock first).
const accessCookieName = "access_token"

func extractAccessToken(r *http.Request) string {
	if header := r.Header.Get("Authorization"); header != "" {
		if parts := strings.SplitN(header, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			if tok := strings.TrimSpace(parts[1]); tok != "" {
				return tok
			}
		}
	}
	if cookie, err := r.Cookie(accessCookieName); err == nil && cookie != nil {
		return cookie.Value
	}
	return ""
}

// resolveWorkspace picks the workspace this connection belongs to.
// Order:
//  1. Explicit X-Workspace-Id header — mobile clients always set this
//     so a multi-workspace user's connection lands in the right room.
//  2. The user's default workspace from AuthVerify (web fallback when
//     the browser doesn't have a workspace context yet).
//
// Returns "" when neither is available; Handler treats that as 400.
func resolveWorkspace(r *http.Request, auth *sdk.AuthVerifyResult) string {
	if hdr := strings.TrimSpace(r.Header.Get("X-Workspace-Id")); hdr != "" {
		return hdr
	}
	if auth != nil {
		return strings.TrimSpace(auth.WorkspaceID)
	}
	return ""
}
