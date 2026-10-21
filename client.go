// Package sdk is the in-tree plugin SDK for talking to dock's
// /internal/v1/* surface. Phase 3 will extract this into a stand-alone
// repo (github.com/<org>/polar-plugin-sdk-go) — for now wg-svc imports
// it directly. The shape is intentionally small so the eventual
// extraction is a literal `git mv`.
//
// What it provides:
//   - Client.Do(method, path, body) — signs + sends a request
//   - Client.AuthVerify(token) — wraps GET /auth/verify with a 30s cache
//   - Client.Heartbeat(opts) — wraps POST /plugin-registry/heartbeat
//   - Client.PutManifest(ctx, m) — wraps PUT /modules/{name}/manifest
//
// What you bring:
//   - DockBase           — e.g. "http://127.0.0.1:8080"
//   - PluginName         — must match the plugin_modules.name row in dock
//   - HMACKey ([]byte)   — the 64-byte hex string returned by
//     hex.EncodeToString(sha256.Sum256([]byte(plaintext)))
//     NOT the plaintext token dock printed once
//   - HTTP (optional)    — replace for tests / timeouts
package sdk

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client signs and dispatches HMAC-authenticated requests to dock's
// /internal/v1/* surface.
type Client struct {
	DockBase   string
	PluginName string
	// HMACKey is the *derived* key, not the plaintext. See package doc.
	HMACKey []byte
	HTTP    *http.Client

	authMu         sync.Mutex
	authCache      map[string]authCacheEntry
	agentAuthCache map[string]agentAuthCacheEntry
}

// AuthVerifyResult mirrors GET /internal/v1/auth/verify response body.
type AuthVerifyResult struct {
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	Role         string `json:"role"`
	PlatformRole string `json:"platform_role,omitempty"`
	Module       string `json:"module,omitempty"`
	ModuleRole   string `json:"module_role,omitempty"`
	WorkspaceID  string `json:"workspace_id"`
	ExpiresAt    string `json:"expires_at"`

	// Kind is "session" for a browser session token or "api_token" for a
	// long-lived polar_ API token. Older dock builds omit it; read it via
	// TokenKind() to get the "session" default.
	Kind string `json:"kind,omitempty"`
	// TokenID is the api token's id; nil for sessions.
	TokenID *int64 `json:"token_id"`
	// Scopes are the token's scopes filtered to the calling module
	// ("<module>:…" entries plus "*" when present).
	//   nil        → unscoped: a session, or an api token with no stored
	//                scopes (dock treats that as full access)
	//   &[]{}      → the token is scoped, but has nothing for this module
	// Keep the nil vs empty distinction — they mean opposite things.
	Scopes *[]string `json:"scopes"`
}

// TokenKind returns Kind, defaulting to "session" when dock omitted it.
func (r *AuthVerifyResult) TokenKind() string {
	if r == nil || r.Kind == "" {
		return "session"
	}
	return r.Kind
}

// Unscoped reports whether the token carries no scope restriction
// (Scopes == nil).
func (r *AuthVerifyResult) Unscoped() bool { return r == nil || r.Scopes == nil }

// HasScope reports whether the token grants scope. Unscoped tokens grant
// everything; "*" and "<module>:*" wildcards are honoured.
func (r *AuthVerifyResult) HasScope(scope string) bool {
	if r == nil || r.Scopes == nil {
		return true
	}
	for _, s := range *r.Scopes {
		if s == scope || s == "*" {
			return true
		}
		if strings.HasSuffix(s, ":*") && strings.HasPrefix(scope, strings.TrimSuffix(s, "*")) {
			return true
		}
	}
	return false
}

// clone returns a copy whose TokenID/Scopes don't alias the cached entry.
func (r AuthVerifyResult) clone() AuthVerifyResult {
	if r.TokenID != nil {
		id := *r.TokenID
		r.TokenID = &id
	}
	if r.Scopes != nil {
		sc := append([]string{}, (*r.Scopes)...)
		r.Scopes = &sc
	}
	return r
}

// ManifestAck mirrors the PUT /internal/v1/modules/{module}/manifest
// response body.
type ManifestAck struct {
	Ack     bool   `json:"ack"`
	Changed bool   `json:"changed"`
	Version string `json:"version"`
}

// AgentVerifyResult mirrors GET /internal/v1/auth/verify-agent response body.
type AgentVerifyResult struct {
	TokenID     string `json:"token_id"`
	UserID      string `json:"user_id"`
	WorkspaceID string `json:"workspace_id"`
}

type agentAuthCacheEntry struct {
	res     AgentVerifyResult
	storeAt time.Time
}

type authCacheEntry struct {
	res     AuthVerifyResult
	storeAt time.Time
}

// UIRoute is one sidebar nav entry a plugin offers. Heartbeated up
// to dock and aggregated into the dynamic sidebar source for
// polar-dock-ui. See task #196 / project-llm-billing-state.
//
// Plugins that have no UI surface (polar-packtunnel, polar-agent)
// either omit UIRoutes from HeartbeatOpts or pass an empty slice;
// dock preserves the existing value when UIRoutes is nil/empty so
// a heartbeat that doesn't carry routes never blanks the column.
type UIRoute struct {
	Path      string `json:"path"`                 // "/expense.html"
	Label     string `json:"label"`                // "家庭账本"
	Icon      string `json:"icon,omitempty"`       // lucide icon name (optional)
	AdminOnly bool   `json:"admin_only,omitempty"` // UI hint: hide for non-admin role
	Order     int    `json:"order,omitempty"`      // UI sort hint; ties broken by label
}

// HeartbeatOpts is the POST /internal/v1/plugin-registry/heartbeat body.
// Name is filled in automatically from c.PluginName so callers can pass
// {} when they only want to refresh the timestamp.
type HeartbeatOpts struct {
	Version       string    `json:"version,omitempty"`
	Endpoint      string    `json:"endpoint,omitempty"`
	UptimeSeconds int64     `json:"uptime_seconds,omitempty"`
	MetricsURL    string    `json:"metrics_url,omitempty"`
	UIRoutes      []UIRoute `json:"ui_routes,omitempty"`

	// OS/Arch identify which prebuilt binary this instance runs, so dock
	// can hand back a matching OTA update directive (see HeartbeatV2).
	// Callers pass runtime.GOOS / runtime.GOARCH.
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`

	// PublicBaseURL is this plugin's externally reachable origin, e.g.
	// "https://hosts.4950.store:2443". dock joins it with each UIRoute.Path
	// to build absolute cross-subdomain links in the platform nav (GET
	// /api/nav). A plugin that omits it is left out of the shared nav (it
	// can still ship its own). Self-describing so 3rd-party modules on any
	// domain need no central map.
	PublicBaseURL string `json:"public_base_url,omitempty"`
}

// HeartbeatResult is dock's heartbeat response. Update is non-nil when dock
// wants this plugin to roll its binary to a different version (OTA pull
// model — Track 3 of the module-platform plan). Old dock builds return an
// empty body, which decodes to a zero HeartbeatResult (Update == nil).
type HeartbeatResult struct {
	Update *UpdateDirective `json:"update,omitempty"`
}

// UpdateDirective instructs the plugin to self-update: fetch the binary at
// URL, verify it against SHA256 (hex), then swap + restart. Consumed by
// SelfUpdate.
type UpdateDirective struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`

	// Authenticity (release-backed OTA). When dock resolves the update via
	// polar-release it includes the ed25519 signature + the signed manifest;
	// SelfUpdate verifies them against POLAR_RELEASE_PUBKEY when that key is
	// pinned. Empty on the legacy through-dock path (sha256-only).
	Ed25519Sig string           `json:"ed25519_sig,omitempty"`
	Manifest   *ReleaseManifest `json:"manifest,omitempty"`
}

// NewClient builds a Client with a sane default HTTP timeout (15s).
// Override .HTTP afterwards if you need a different policy.
func NewClient(dockBase, pluginName string, hmacKey []byte) *Client {
	return &Client{
		DockBase:       strings.TrimRight(dockBase, "/"),
		PluginName:     pluginName,
		HMACKey:        hmacKey,
		HTTP:           &http.Client{Timeout: 15 * time.Second},
		authCache:      make(map[string]authCacheEntry),
		agentAuthCache: make(map[string]agentAuthCacheEntry),
	}
}

// Do signs + sends a request. body is JSON-marshalled if non-nil; pass
// nil for GET / DELETE.
func (c *Client) Do(method, path string, body any) (*http.Response, error) {
	return c.DoContext(context.Background(), method, path, body)
}

// DoContext is Do with a request context.
func (c *Client) DoContext(ctx context.Context, method, path string, body any) (*http.Response, error) {
	if c == nil {
		return nil, errors.New("sdk.Client: nil receiver")
	}
	if len(c.HMACKey) == 0 || c.PluginName == "" {
		return nil, errors.New("sdk.Client: missing HMACKey or PluginName")
	}
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal: %w", err)
		}
		bodyBytes = b
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	bodySum := sha256.Sum256(bodyBytes)
	canonical := fmt.Sprintf("%s\n%s\n%s\n%s",
		strings.ToUpper(method), path, ts, hex.EncodeToString(bodySum[:]))
	mac := hmac.New(sha256.New, c.HMACKey)
	mac.Write([]byte(canonical))
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, method, c.DockBase+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Polar-Plugin-Name", c.PluginName)
	req.Header.Set("X-Polar-Plugin-Timestamp", ts)
	req.Header.Set("X-Polar-Plugin-Sig", sig)
	return c.HTTP.Do(req)
}

// readJSON unmarshals a 2xx response body into out, or returns an
// error wrapping the raw body for 4xx/5xx.
func readJSON(resp *http.Response, out any) error {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

// AuthVerify resolves an end-user session token via dock. Cached for
// 30 seconds per the v1 spec. Returns the user's personal workspace.
func (c *Client) AuthVerify(token string) (*AuthVerifyResult, error) {
	return c.AuthVerifyWS(token, "")
}

// AuthVerifyWS is AuthVerify with an active-workspace hint: pass the
// browser's X-Workspace-Id so dock resolves WorkspaceID to the caller's
// SELECTED workspace (when they're a member) instead of the personal
// default. Empty workspaceID behaves exactly like AuthVerify. Cached 30s
// per (token, workspaceID).
func (c *Client) AuthVerifyWS(token, workspaceID string) (*AuthVerifyResult, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("AuthVerify: empty token")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	key := token + "\x00" + workspaceID
	c.authMu.Lock()
	if entry, ok := c.authCache[key]; ok && time.Since(entry.storeAt) < 30*time.Second {
		c.authMu.Unlock()
		res := entry.res.clone()
		return &res, nil
	}
	c.authMu.Unlock()

	path := "/internal/v1/auth/verify?token=" + url.QueryEscape(token)
	if workspaceID != "" {
		path += "&workspace_id=" + url.QueryEscape(workspaceID)
	}
	resp, err := c.Do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var out AuthVerifyResult
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	c.authMu.Lock()
	c.authCache[key] = authCacheEntry{res: out.clone(), storeAt: time.Now()}
	// Cheap GC: when the cache passes 1000 entries, drop anything
	// older than the 30s window. Hot prod will see way fewer than
	// that; this is just to keep a misbehaving caller from leaking.
	if len(c.authCache) > 1000 {
		cutoff := time.Now().Add(-30 * time.Second)
		for k, e := range c.authCache {
			if e.storeAt.Before(cutoff) {
				delete(c.authCache, k)
			}
		}
	}
	c.authMu.Unlock()
	return &out, nil
}

// AuthVerifyAgent resolves an AGENT bearer token (polar_agent_…) via dock's
// /internal/v1/auth/verify-agent. This is what lets a plugin authenticate an
// agent: agent tokens are neither sessions nor polar_ keys, so until this
// endpoint existed only dock could verify them — trapping agent-authenticated
// surfaces (e.g. the compute-task claim API) inside dock. Cached 30s per token,
// mirroring AuthVerify. Returns the token's owner + the owner's personal
// workspace. An invalid/revoked token returns an error (dock answers 401).
func (c *Client) AuthVerifyAgent(token string) (*AgentVerifyResult, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("AuthVerifyAgent: empty token")
	}
	c.authMu.Lock()
	if entry, ok := c.agentAuthCache[token]; ok && time.Since(entry.storeAt) < 30*time.Second {
		c.authMu.Unlock()
		res := entry.res
		return &res, nil
	}
	c.authMu.Unlock()

	resp, err := c.Do(http.MethodGet, "/internal/v1/auth/verify-agent?token="+url.QueryEscape(token), nil)
	if err != nil {
		return nil, err
	}
	var out AgentVerifyResult
	if err := readJSON(resp, &out); err != nil {
		return nil, err // non-2xx (invalid/revoked) propagates; nothing cached
	}
	c.authMu.Lock()
	if c.agentAuthCache == nil {
		c.agentAuthCache = make(map[string]agentAuthCacheEntry)
	}
	c.agentAuthCache[token] = agentAuthCacheEntry{res: out, storeAt: time.Now()}
	if len(c.agentAuthCache) > 1000 {
		cutoff := time.Now().Add(-30 * time.Second)
		for k, e := range c.agentAuthCache {
			if e.storeAt.Before(cutoff) {
				delete(c.agentAuthCache, k)
			}
		}
	}
	c.authMu.Unlock()
	return &out, nil
}

// Heartbeat pings dock to refresh last_heartbeat + version + endpoint,
// discarding dock's response. Call once at startup and on a timer (every
// 60s is the recommended cadence — dock's GC sweeps stale plugins after
// 5m). Modules that want OTA self-update call HeartbeatV2 instead.
func (c *Client) Heartbeat(opts HeartbeatOpts) error {
	_, err := c.HeartbeatV2(opts)
	return err
}

// HeartbeatV2 is Heartbeat that also returns dock's response, including any
// OTA update directive (Result.Update). It is wire-compatible with the
// legacy heartbeat: a dock build that returns an empty body yields a zero
// HeartbeatResult (Update == nil), so callers can adopt it without a dock
// upgrade. Pair with SelfUpdate to act on a non-nil Update.
func (c *Client) HeartbeatV2(opts HeartbeatOpts) (*HeartbeatResult, error) {
	body := map[string]any{
		"name":           c.PluginName,
		"version":        opts.Version,
		"endpoint":       opts.Endpoint,
		"uptime_seconds": opts.UptimeSeconds,
		"metrics_url":    opts.MetricsURL,
		"os":             opts.OS,
		"arch":           opts.Arch,
	}
	if len(opts.UIRoutes) > 0 {
		body["ui_routes"] = opts.UIRoutes
	}
	if opts.PublicBaseURL != "" {
		body["public_base_url"] = opts.PublicBaseURL
	}
	resp, err := c.Do(http.MethodPost, "/internal/v1/plugin-registry/heartbeat", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("heartbeat HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out HeartbeatResult
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("heartbeat decode: %w", err)
		}
	}
	// Dock returns the update URL as a dock-relative path so the module
	// pulls the binary over the same base it heartbeats on (avoids any
	// public-vs-internal hostname mismatch behind a reverse proxy).
	// Resolve it here against DockBase so SelfUpdate gets an absolute URL.
	if out.Update != nil && strings.HasPrefix(out.Update.URL, "/") {
		out.Update.URL = c.DockBase + out.Update.URL
	}
	return &out, nil
}

// PutManifest submits this module's permission manifest (roles, scopes,
// presets, routes) to dock via a signed
// PUT /internal/v1/modules/{PluginName}/manifest. dock rejects a module
// other than the calling plugin (403) and invalid manifests (400, body
// {"error": "..."}); both surface as an error. manifest is JSON-marshalled
// as-is (a struct or map[string]any). Idempotent: resubmitting the same
// manifest_version returns Changed == false. Call at startup, after the
// first heartbeat.
func (c *Client) PutManifest(ctx context.Context, manifest any) (ManifestAck, error) {
	if c == nil {
		return ManifestAck{}, errors.New("sdk.Client: nil receiver")
	}
	if manifest == nil {
		return ManifestAck{}, errors.New("PutManifest: nil manifest")
	}
	path := "/internal/v1/modules/" + url.PathEscape(c.PluginName) + "/manifest"
	resp, err := c.DoContext(ctx, http.MethodPut, path, manifest)
	if err != nil {
		return ManifestAck{}, err
	}
	var out ManifestAck
	if err := readJSON(resp, &out); err != nil {
		return ManifestAck{}, fmt.Errorf("PutManifest: %w", err)
	}
	return out, nil
}

// DeriveHMACKey turns the plaintext token dock printed at plugin
// creation into the actual HMAC key the SDK needs. Plugin operators
// run this *once* at setup and store the result in their secrets vault;
// the plaintext can then be discarded.
func DeriveHMACKey(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return []byte(hex.EncodeToString(sum[:]))
}
