// extras.go — convenience wrappers around dock's /internal/v1/* surface
// for the read-mostly endpoints that plugins call frequently. Kept in a
// separate file from client.go so the Phase-3 SDK extraction (git mv to
// polar-plugin-sdk-go) stays a one-line operation.
//
// Caching policy:
//   - UserGet / TeamGet — 30 s, mirrors AuthVerify. Public-ish profile
//     data, refresh-on-staleness is fine; safe to cache.
//   - LLMConfigGet, BotUserGet, ChatThreadGet — NO cache. They include
//     sensitive fields (api_key for LLM, ownership for bot, last-msg
//     for thread) and the bot/llm-config marketplace lets workspace
//     access shift mid-session; cached "OK" would be a security hole.
//   - AgentDispatch, AgentPresenceGet, AgentLLMCallRecord — no cache;
//     they're write-side / live-state ops.

package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Types mirror dock's /internal/v1/* response bodies ───────────────

// User is the public profile shape returned by GET /internal/v1/users/:id.
// Email + password_hash + sessions are deliberately omitted server-side.
type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	IconURL   string `json:"icon_url"`
	Bio       string `json:"bio"`
	IsBot     bool   `json:"is_bot"`
	CreatedAt string `json:"created_at"`
}

// Team is the shape returned by GET /internal/v1/teams/:id.
type Team struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	OwnerUserID string `json:"owner_user_id"`
	CreatedAt   string `json:"created_at"`
}

// LLMConfig is the shape returned by GET /internal/v1/llm-configs/:id.
// APIKey is the *plaintext* upstream provider key — handle accordingly.
type LLMConfig struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	BaseURL  string `json:"base_url"`
	Model    string `json:"model"`
	APIKey   string `json:"api_key"`
	ProxyURL string `json:"proxy_url"`
	IsSystem bool   `json:"is_system"`
	IsShared bool   `json:"is_shared"`
}

// BotUser is the shape returned by GET /internal/v1/bot-users/:id.
// Subset of dock's BotUser struct — strips ownership audit fields that
// plugins don't need.
type BotUser struct {
	ID            int64  `json:"id"`
	BotUserID     string `json:"bot_user_id"`
	WorkspaceID   string `json:"workspace_id"`
	OwnerUserID   string `json:"owner_user_id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	LLMConfigID   int64  `json:"llm_config_id,omitempty"`
	BotKind       string `json:"bot_kind"`
	PreferredTool string `json:"preferred_tool"`
	HostSkillID   *int64 `json:"host_skill_id,omitempty"`
	ModelOverride string `json:"model_override,omitempty"`
}

// ChatThread is the shape returned by GET /internal/v1/chat-threads/:id.
// LastMessage is intentionally an excerpt (≤200 chars server-side) so
// the response stays small; plugins that need full thread history call
// the dock chat surface directly via the end-user's token.
type ChatThread struct {
	ID            int64  `json:"id"`
	UserLow       string `json:"user_low"`
	UserHigh      string `json:"user_high"`
	LastMessage   string `json:"last_message"`
	LastMessageAt string `json:"last_message_at,omitempty"`
	CreatedAt     string `json:"created_at"`
}

// AgentPresence is the shape returned by GET /internal/v1/agent-presence/:bot_id.
// Attached=false + LastSeenAt zero means the bot has never had an agent
// attach; Attached=false + LastSeenAt non-zero means the agent
// disconnected (used by projects to decide whether to retry vs surface
// "agent offline" in the UI).
type AgentPresence struct {
	BotUserID  string `json:"bot_user_id"`
	Attached   bool   `json:"attached"`
	HostID     string `json:"host_id,omitempty"`
	Tool       string `json:"tool,omitempty"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
}

// AgentDispatchRequest mirrors POST /internal/v1/agent/dispatch. Fields
// are a strict subset of dock's aiAgentTask — plugin tasks don't get to
// pin per-task workdir or git-remote overrides (those are project-level
// metadata dock resolves on its side).
type AgentDispatchRequest struct {
	ThreadID        int64  `json:"thread_id"`
	LLMThreadID     *int64 `json:"llm_thread_id,omitempty"`
	UserID          string `json:"user_id"`
	ResponderUserID string `json:"responder_user_id"`
	ResponderName   string `json:"responder_name"`
	Content         string `json:"content"`
}

type AgentDispatchResponse struct {
	Queued bool `json:"queued"`
}

// AgentLLMCallRecord mirrors POST /internal/v1/agent/llm-call-record.
// Plugins that drive their own LLM dispatch (i.e. anything that doesn't
// go through AgentDispatch) call this to keep the cost ledger
// consistent — same shape as dock's internal recordAgentLLMCall helper.
type AgentLLMCallRecord struct {
	WorkspaceID      string  `json:"workspace_id"`
	LLMConfigID      int64   `json:"llm_config_id"`
	ModelRequested   string  `json:"model_requested"`
	ModelResolved    string  `json:"model_resolved"`
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	LatencyMS        int     `json:"latency_ms"`
	StatusCode       int     `json:"status_code"`
	ErrorText        string  `json:"error_text,omitempty"`
	CostOverrideUSD *float64 `json:"cost_override_usd,omitempty"`
}

// AgentTokenIssueRequest mirrors POST /internal/v1/agent-tokens/issue.
// Used by polar-hosts (and any future plugin that mints agent tokens)
// to write the canonical row into dock's ideamesh.agent_tokens so the
// dock-owned /ws/agent auth path resolves the token. The plugin keeps
// its own local copy alongside this for read-path queries until the
// Phase-2 cleanup that moves reads to the dock surface.
//
// ID is generated by the caller and MUST match the plugin-side copy
// (dock does NOT mint a new id). TokenHash is the sha256-hex of the
// raw token; the raw token never crosses this wire — the plugin
// returns it directly to the enrolling agent.
//
// CoderConfigJSON is the literal JSON string the plugin writes to its
// own row (pending-enrollment marker or {}), so dock's
// consumeEnrollmentToken sees the same marker shape.
type AgentTokenIssueRequest struct {
	ID              string `json:"id"`
	UserID          string `json:"user_id"`
	Name            string `json:"name"`
	TokenHash       string `json:"token_hash"`
	CoderConfigJSON string `json:"coder_config_json,omitempty"`
}

type AgentTokenIssueResponse struct {
	ID      string `json:"id"`
	Deduped bool   `json:"deduped,omitempty"`
}

// HostIssueRequest mirrors POST /internal/v1/hosts/issue. Same intent
// as AgentTokenIssueRequest: the plugin generated the id locally and
// is asking dock to record the canonical hosts row so dock's
// getHostByAgentToken (called on every /ws/agent message) resolves.
// Slug is computed plugin-side to keep dock from re-running the
// uniqueness probe.
//
// Deprecated: v4 splits hosts ↔ agents. See doc/arch/agent-identity-v4.md.
// The MachineUUID field below is retained for read-side compatibility
// while the v3-v4 cutover proceeds; new code MUST use AgentRegister.
type HostIssueRequest struct {
	ID           string `json:"id"`
	WorkspaceID  string `json:"workspace_id"`
	Slug         string `json:"slug"`
	Name         string `json:"name"`
	AgentTokenID string `json:"agent_token_id,omitempty"`
	OS           string `json:"os,omitempty"`
	Arch         string `json:"arch,omitempty"`
	// Deprecated: v4 splits hosts ↔ agents. See doc/arch/agent-identity-v4.md.
	MachineUUID string `json:"machine_uuid,omitempty"`
}

type HostIssueResponse struct {
	ID      string `json:"id"`
	Deduped bool   `json:"deduped,omitempty"`
}

// ── v4 Agent identity surface ───────────────────────────────────────
//
// See doc/arch/agent-identity-v4.md for the full design.
//
// v3 conflated "physical machine" with "logical agent" via
// hosts.machine_uuid + UNIQUE(workspace_id, machine_uuid). v4 splits:
//
//   hosts   = physical asset, PK = sha256(salt + raw_machine_uuid)
//   agents  = logical agent instance, PK = ag_<random32hex>, FK → hosts
//
// One host : N agents. The raw machine_uuid is sent once per register
// (hashed server-side, never persisted raw); agent.toml then persists
// the server-issued agent_id for re-attach.

// AgentRegisterRequest is the body of POST /internal/v1/agents/register.
// Plugin-authed (HMAC) — polar-hosts calls this from its agent-facing
// /api/hosts/register handler after consuming the enroll token. The
// plugin does NOT pre-generate agent_id (server mints + returns it).
//
// Field contract:
//   - EnrollToken       — already consumed by the calling plugin; dock
//                         uses it only for audit ("who issued this agent_id").
//   - Name              — operator-chosen label; UNIQUE per workspace at
//                         the agents table level (server returns 409 on dup).
//   - MachineUUIDRaw    — raw IOPlatformUUID / machine-id / smbios UUID.
//                         Hashed via sha256(salt + raw) to derive host_id;
//                         the raw value is dropped immediately and NEVER
//                         persisted. Required for v4 (legacy "" path is
//                         gone).
//   - HostInfo          — hw_model / cpu_brand / cpu_cores / mem_total_bytes
//                         / os_name / os_version / etc. UPSERT'd into the
//                         hosts row keyed on the derived host_id.
//   - BotUserID         — optional. When non-empty dock skips bot
//                         auto-create and binds the agent to this
//                         existing bot. Empty → dock auto-creates a bot
//                         named "bot-<agent_name>-<short_id>" bound to
//                         the workspace's agent-pool llm_proxy_token.
type AgentRegisterRequest struct {
	EnrollToken    string         `json:"enroll_token"`
	WorkspaceID    string         `json:"workspace_id"`
	Name           string         `json:"name"`
	MachineUUIDRaw string         `json:"machine_uuid_raw"`
	HostInfo       map[string]any `json:"host_info,omitempty"`
	OS             string         `json:"os,omitempty"`
	Arch           string         `json:"arch,omitempty"`
	BotUserID      string         `json:"bot_user_id,omitempty"`
}

// AgentRegisterResponse is what /internal/v1/agents/register returns.
//
//   - AgentID    — server-minted "ag_<random32hex>". Persisted in
//                  agent.toml on the polar-agent box.
//   - HostID     — sha256(salt + raw)[:32] hex. Stable across re-installs
//                  on the same hardware (operator backs up agent.toml,
//                  reinstalls OS, same host_id resolves).
//   - BotUserID  — bot the agent should attach as. Either the existing
//                  bot the caller passed in via BotUserID, or the
//                  freshly-auto-created one.
//   - AgentTokenRaw — raw "polar_agent_<...>" auth credential. Plaintext;
//                  shown once, agent persists it in agent.toml. Server
//                  only retains the sha256 hash via agent_tokens. JSON
//                  wire tag is "agent_token_raw" to match the public
//                  polar-hosts /api/hosts/register response shape — that
//                  endpoint is what polar-agent CLI parses, so the SDK
//                  uses the same name (rather than the older "token"
//                  which left two field names for one value).
//   - Server     — canonical control-plane URL the agent should use for
//                  /ws/agent (defaultServer echoed back; lets the CLI
//                  fall back to a sane value when --server wasn't passed).
//   - ProxyToken / ProxyBaseURL / DefaultModel — the agent's per-agent
//                  LLM proxy credential (named agent:<id>) + the dock
//                  proxy origin (…/api/proxy/v1) + the workspace default
//                  model. Lets the agent call dock's billed/audited LLM
//                  proxy directly for its own (non-dispatched) calls.
//                  Plaintext shown once; persist alongside AgentTokenRaw.
type AgentRegisterResponse struct {
	AgentID       string `json:"agent_id"`
	HostID        string `json:"host_id"`
	BotUserID     string `json:"bot_user_id"`
	AgentTokenRaw string `json:"agent_token_raw"`
	Server        string `json:"server"`
	ProxyToken    string `json:"proxy_token,omitempty"`
	ProxyBaseURL  string `json:"proxy_base_url,omitempty"`
	DefaultModel  string `json:"default_model,omitempty"`
}

// WorkspaceProxyTokenEnsureRequest mirrors POST
// /internal/v1/workspace-proxy-tokens/ensure. Idempotent: returns the
// existing llm_proxy_tokens row matching (WorkspaceID, Name), or
// creates one with sensible defaults when none exists. polar-hosts'
// registerAgent calls this with Name="agent-pool" so every
// auto-created bot binds to one workspace-scoped proxy token (single
// SQL groups all auto-bot LLM spend per workspace).
type WorkspaceProxyTokenEnsureRequest struct {
	WorkspaceID string `json:"workspace_id"`
	OwnerUserID string `json:"owner_user_id"`
	Name        string `json:"name"`
}

// WorkspaceProxyTokenEnsureResponse — ID is the bigserial PK of
// llm_proxy_tokens; bot_users.llm_config_id is NOT this id (the
// auto-created bot uses an LLM config keyed back to this token via
// llm_configs.proxy_token_id). Created=true means we minted, false
// means we returned an existing row.
type WorkspaceProxyTokenEnsureResponse struct {
	ID      int64 `json:"id"`
	Created bool  `json:"created,omitempty"`
}

// BotForAgentCreateRequest mirrors POST
// /internal/v1/bots/create-for-agent. Idempotent on (WorkspaceID, Name)
// — if a bot with that name already exists in the workspace, dock
// returns the existing row's bot_user_id rather than 409'ing.
//
// LLMConfig carries the upstream-binding hint (e.g.
// {"proxy_token_id": 42}) so dock knows which llm_configs row to
// associate the bot with. Empty map → bot is created without an
// llm_config; the agent uses the platform default (rare; the normal
// path is "bind to agent-pool proxy token").
type BotForAgentCreateRequest struct {
	WorkspaceID string         `json:"workspace_id"`
	OwnerUserID string         `json:"owner_user_id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	LLMConfig   map[string]any `json:"llm_config,omitempty"`
}

type BotForAgentCreateResponse struct {
	BotUserID string `json:"bot_user_id"`
	Created   bool   `json:"created,omitempty"`
}

// VideoShotCallRecord mirrors POST /internal/v1/billing/video-shots.
// Video plugins (polar-video and any future Kling/Runway/Pika sibling)
// call this once per successfully-generated shot so the per-shot cost
// shows up in the same per-workspace ledger as text-LLM usage.
//
// Idempotent: dock dedupes on ShotID, so a re-post (e.g. retry after
// transient network blip) returns 200 with {recorded: true,
// deduped: true} rather than 409.
//
// CostUSD = 0 is a legitimate value (price table missed but the row
// is still recorded for forensic review) — don't omit on zero. The
// BillingMeta map should carry the raw pricing-table snapshot used
// so a future audit can reproduce the math.
type VideoShotCallRecord struct {
	WorkspaceID        string         `json:"workspace_id"`
	ProjectID          int64          `json:"project_id"`
	ShotID             int64          `json:"shot_id"`
	Provider           string         `json:"provider"`
	Model              string         `json:"model,omitempty"`
	Resolution         string         `json:"resolution,omitempty"`
	DurationChargedSec float64        `json:"duration_charged_sec,omitempty"`
	FPS                int            `json:"fps,omitempty"`
	FramesTotal        int            `json:"frames_total,omitempty"`
	CostUSD            float64        `json:"cost_usd"`
	CostPerFrameUSD    float64        `json:"cost_per_frame_usd,omitempty"`
	BillingMeta        map[string]any `json:"billing_meta,omitempty"`
}

// ── Caching scaffolding ─────────────────────────────────────────────

type cacheEntry[T any] struct {
	value   T
	storeAt time.Time
}

type ttlCache[T any] struct {
	mu    sync.Mutex
	ttl   time.Duration
	store map[string]cacheEntry[T]
}

func newTTLCache[T any](ttl time.Duration) *ttlCache[T] {
	return &ttlCache[T]{ttl: ttl, store: make(map[string]cacheEntry[T])}
}

func (c *ttlCache[T]) get(key string) (T, bool) {
	var zero T
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.store[key]
	if !ok {
		return zero, false
	}
	if time.Since(e.storeAt) > c.ttl {
		delete(c.store, key)
		return zero, false
	}
	return e.value, true
}

func (c *ttlCache[T]) put(key string, v T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = cacheEntry[T]{value: v, storeAt: time.Now()}
	// Same opportunistic GC as AuthVerify cache.
	if len(c.store) > 1000 {
		cutoff := time.Now().Add(-c.ttl)
		for k, e := range c.store {
			if e.storeAt.Before(cutoff) {
				delete(c.store, k)
			}
		}
	}
}

// Lazy-init caches on first use so existing NewClient callers keep
// working without a code change.
var (
	userCacheInit sync.Once
	userCacheVal  *ttlCache[User]
	teamCacheInit sync.Once
	teamCacheVal  *ttlCache[Team]
)

func userCache() *ttlCache[User] {
	userCacheInit.Do(func() { userCacheVal = newTTLCache[User](30 * time.Second) })
	return userCacheVal
}

func teamCache() *ttlCache[Team] {
	teamCacheInit.Do(func() { teamCacheVal = newTTLCache[Team](30 * time.Second) })
	return teamCacheVal
}

// ── Wrappers ────────────────────────────────────────────────────────

// UserGet wraps GET /internal/v1/users/:id with a 30s cache.
func (c *Client) UserGet(id string) (*User, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errInvalid("UserGet: empty id")
	}
	if v, ok := userCache().get(id); ok {
		out := v
		return &out, nil
	}
	resp, err := c.Do(http.MethodGet, "/internal/v1/users/"+id, nil)
	if err != nil {
		return nil, err
	}
	var u User
	if err := readJSON(resp, &u); err != nil {
		return nil, err
	}
	userCache().put(id, u)
	return &u, nil
}

// TeamGet wraps GET /internal/v1/teams/:id with a 30s cache.
func (c *Client) TeamGet(id string) (*Team, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errInvalid("TeamGet: empty id")
	}
	if v, ok := teamCache().get(id); ok {
		out := v
		return &out, nil
	}
	resp, err := c.Do(http.MethodGet, "/internal/v1/teams/"+id, nil)
	if err != nil {
		return nil, err
	}
	var t Team
	if err := readJSON(resp, &t); err != nil {
		return nil, err
	}
	teamCache().put(id, t)
	return &t, nil
}

// LLMConfigGet wraps GET /internal/v1/llm-configs/:id?workspace_id=<wid>.
// NOT cached — api_key plaintext + workspace-marketplace state changes.
func (c *Client) LLMConfigGet(id int64, workspaceID string) (*LLMConfig, error) {
	if id <= 0 {
		return nil, errInvalid("LLMConfigGet: id required")
	}
	if strings.TrimSpace(workspaceID) == "" {
		return nil, errInvalid("LLMConfigGet: workspace_id required")
	}
	path := "/internal/v1/llm-configs/" + strconv.FormatInt(id, 10) +
		"?workspace_id=" + workspaceID
	resp, err := c.Do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var cfg LLMConfig
	if err := readJSON(resp, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// BotUserGet wraps GET /internal/v1/bot-users/:id. id is the bot's
// user_id (the "u_..." string, NOT the bigserial PK row id).
func (c *Client) BotUserGet(id string) (*BotUser, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errInvalid("BotUserGet: empty id")
	}
	resp, err := c.Do(http.MethodGet, "/internal/v1/bot-users/"+id, nil)
	if err != nil {
		return nil, err
	}
	var b BotUser
	if err := readJSON(resp, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// ChatThreadGet wraps GET /internal/v1/chat-threads/:id.
func (c *Client) ChatThreadGet(id int64) (*ChatThread, error) {
	if id <= 0 {
		return nil, errInvalid("ChatThreadGet: id required")
	}
	resp, err := c.Do(http.MethodGet, "/internal/v1/chat-threads/"+strconv.FormatInt(id, 10), nil)
	if err != nil {
		return nil, err
	}
	var t ChatThread
	if err := readJSON(resp, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// AgentPresenceGet wraps GET /internal/v1/agent-presence/:bot_id.
// Returns the live attach state for one bot user. Plugins use this to
// decide whether to enqueue an agent task vs surface "agent offline".
func (c *Client) AgentPresenceGet(botUserID string) (*AgentPresence, error) {
	botUserID = strings.TrimSpace(botUserID)
	if botUserID == "" {
		return nil, errInvalid("AgentPresenceGet: empty bot_user_id")
	}
	resp, err := c.Do(http.MethodGet, "/internal/v1/agent-presence/"+botUserID, nil)
	if err != nil {
		return nil, err
	}
	var p AgentPresence
	if err := readJSON(resp, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// AgentDispatch wraps POST /internal/v1/agent/dispatch. Server returns
// {queued: true} immediately; the actual LLM round-trip happens
// asynchronously inside dock's aiAgent loop, and the result lands on
// the chat_thread as a new message (caller poll-or-WS-watches that).
func (c *Client) AgentDispatch(req AgentDispatchRequest) (*AgentDispatchResponse, error) {
	resp, err := c.Do(http.MethodPost, "/internal/v1/agent/dispatch", req)
	if err != nil {
		return nil, err
	}
	var out AgentDispatchResponse
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AgentLLMCallRecord wraps POST /internal/v1/agent/llm-call-record.
// Use this when a plugin runs an LLM call directly (not via
// AgentDispatch) and wants the cost surfaced in the same per-workspace
// ledger admins see in /llm-billing.html.
func (c *Client) AgentLLMCallRecord(req AgentLLMCallRecord) error {
	resp, err := c.Do(http.MethodPost, "/internal/v1/agent/llm-call-record", req)
	if err != nil {
		return err
	}
	return readJSON(resp, nil)
}

// WorkspacePluginAccessResp mirrors the dock response for
// GET /internal/v1/workspace-plugin-access?workspace_id=&plugin=
type WorkspacePluginAccessResp struct {
	WorkspaceID string `json:"workspace_id"`
	Plugin      string `json:"plugin"`
	Enabled     bool   `json:"enabled"`
}

// WorkspacePluginAccess asks dock whether the given workspace may
// use this plugin. Closed-by-default semantics — missing config
// rows return Enabled=false. Root workspace always returns true.
//
// Recommended caller pattern: cache the answer for ~60s, since
// access grants change rarely (admin grants once, leaves it).
//
// Plugins call this in their auth middleware AFTER the dock has
// verified the bearer token + resolved workspace_id, but BEFORE
// dispatching to business handlers.
func (c *Client) WorkspacePluginAccess(workspaceID, plugin string) (*WorkspacePluginAccessResp, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	plugin = strings.TrimSpace(plugin)
	if workspaceID == "" {
		return nil, errInvalid("workspaceID required")
	}
	if plugin == "" {
		return nil, errInvalid("plugin required")
	}
	resp, err := c.Do(http.MethodGet,
		"/internal/v1/workspace-plugin-access?workspace_id="+url.QueryEscape(workspaceID)+"&plugin="+url.QueryEscape(plugin),
		nil,
	)
	if err != nil {
		return nil, err
	}
	var out WorkspacePluginAccessResp
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VideoShotCallRecord wraps POST /internal/v1/billing/video-shots.
// Best-effort: callers should log + continue on failure — the
// downstream poll loop will retry next tick, and dock dedupes by
// ShotID so retries are safe.
func (c *Client) VideoShotCallRecord(req VideoShotCallRecord) error {
	resp, err := c.Do(http.MethodPost, "/internal/v1/billing/video-shots", req)
	if err != nil {
		return err
	}
	return readJSON(resp, nil)
}

// IssueAgentToken wraps POST /internal/v1/agent-tokens/issue. Plugins
// that mint agent_tokens locally (currently only polar-hosts) call this
// right after their own INSERT so the canonical row lands in dock too.
//
// Idempotent: dock's INSERT ... ON CONFLICT (id) DO NOTHING returns
// 200 with {deduped: true} if the row already exists, so a retry on
// transient network failure is safe.
//
// Caller contract: if this errors, the caller MUST roll back the local
// INSERT before returning to the operator. Otherwise the plugin DB and
// dock DB drift, which is exactly the split-brain this method exists
// to prevent.
func (c *Client) IssueAgentToken(req AgentTokenIssueRequest) (*AgentTokenIssueResponse, error) {
	if strings.TrimSpace(req.ID) == "" {
		return nil, errInvalid("IssueAgentToken: id required")
	}
	if strings.TrimSpace(req.UserID) == "" {
		return nil, errInvalid("IssueAgentToken: user_id required")
	}
	if strings.TrimSpace(req.TokenHash) == "" {
		return nil, errInvalid("IssueAgentToken: token_hash required")
	}
	resp, err := c.Do(http.MethodPost, "/internal/v1/agent-tokens/issue", req)
	if err != nil {
		return nil, err
	}
	var out AgentTokenIssueResponse
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IssueHost wraps POST /internal/v1/hosts/issue. Companion to
// IssueAgentToken — call right after the plugin's local INSERT INTO
// hosts. Same retry / rollback contract.
func (c *Client) IssueHost(req HostIssueRequest) (*HostIssueResponse, error) {
	if strings.TrimSpace(req.ID) == "" {
		return nil, errInvalid("IssueHost: id required")
	}
	if strings.TrimSpace(req.WorkspaceID) == "" {
		return nil, errInvalid("IssueHost: workspace_id required")
	}
	if strings.TrimSpace(req.Slug) == "" {
		return nil, errInvalid("IssueHost: slug required")
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, errInvalid("IssueHost: name required")
	}
	resp, err := c.Do(http.MethodPost, "/internal/v1/hosts/issue", req)
	if err != nil {
		return nil, err
	}
	var out HostIssueResponse
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AgentRegister wraps POST /internal/v1/agents/register. See
// AgentRegisterRequest for the v4 protocol; this is the entry point
// polar-hosts' /api/hosts/register handler calls after consuming an
// enroll token. Dock takes ownership of host_id derivation (hashing
// MachineUUIDRaw with its private salt), agent_id minting, agent_token
// + bot auto-create. Plugin only adds its own agents-table row after
// this returns and persists the AgentID for future hello frames.
//
// HMAC-plugin-authed; raw machine_uuid crosses the wire but never
// persists. If you must log this request body, scrub MachineUUIDRaw
// before write.
func (c *Client) AgentRegister(req AgentRegisterRequest) (*AgentRegisterResponse, error) {
	if strings.TrimSpace(req.Name) == "" {
		return nil, errInvalid("AgentRegister: name required")
	}
	if strings.TrimSpace(req.WorkspaceID) == "" {
		return nil, errInvalid("AgentRegister: workspace_id required")
	}
	if strings.TrimSpace(req.MachineUUIDRaw) == "" {
		return nil, errInvalid("AgentRegister: machine_uuid_raw required (v4)")
	}
	resp, err := c.Do(http.MethodPost, "/internal/v1/agents/register", req)
	if err != nil {
		return nil, err
	}
	var out AgentRegisterResponse
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnsureWorkspaceAgentPoolProxyToken wraps POST
// /internal/v1/workspace-proxy-tokens/ensure. Idempotent;
// safe to call on every register.
func (c *Client) EnsureWorkspaceAgentPoolProxyToken(req WorkspaceProxyTokenEnsureRequest) (*WorkspaceProxyTokenEnsureResponse, error) {
	if strings.TrimSpace(req.WorkspaceID) == "" {
		return nil, errInvalid("EnsureWorkspaceAgentPoolProxyToken: workspace_id required")
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = "agent-pool"
	}
	resp, err := c.Do(http.MethodPost, "/internal/v1/workspace-proxy-tokens/ensure", req)
	if err != nil {
		return nil, err
	}
	var out WorkspaceProxyTokenEnsureResponse
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateBotForAgent wraps POST /internal/v1/bots/create-for-agent.
// Idempotent on (workspace_id, name) — if the named bot already
// exists dock returns its existing bot_user_id with Created=false.
func (c *Client) CreateBotForAgent(req BotForAgentCreateRequest) (*BotForAgentCreateResponse, error) {
	if strings.TrimSpace(req.WorkspaceID) == "" {
		return nil, errInvalid("CreateBotForAgent: workspace_id required")
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, errInvalid("CreateBotForAgent: name required")
	}
	resp, err := c.Do(http.MethodPost, "/internal/v1/bots/create-for-agent", req)
	if err != nil {
		return nil, err
	}
	var out BotForAgentCreateResponse
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func errInvalid(msg string) error { return &invalidErr{msg: msg} }

type invalidErr struct{ msg string }

func (e *invalidErr) Error() string { return e.msg }

// ── Assets ──────────────────────────────────────────────────────────
//
// The Polar assets module is a unified file/object store: platform
// internals (LLM weights, polar-agent binaries) live alongside tenant
// uploads (S3-style backing store, link-share, team-share, media
// migration target). Dock owns the catalog + router; the actual blob
// bytes are served by `polar-assets-svc` provider plugins, one per
// region. See doc/arch/assets-module.md.
//
// Plugins call these wrappers when they need to fetch a model file,
// stat a known sha256, or eventually upload an artifact (e.g. video
// modules migrating generated MP4s into the central store).
//
// Cache: none. Asset metadata can change (visibility flipped, asset
// deleted, pinned toggled) and stale "OK" answers are operationally
// scary in a permission-gated store.

// AssetMeta mirrors the row shape returned by GET
// /internal/v1/assets/by-name and GET /internal/v1/assets/:id.
// WorkspaceID is nil for platform-owned assets.
type AssetMeta struct {
	ID          int64          `json:"id"`
	WorkspaceID *string        `json:"workspace_id,omitempty"`
	Kind        string         `json:"kind"`
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	SHA256      string         `json:"sha256"`
	SizeBytes   int64          `json:"size_bytes"`
	Mime        string         `json:"mime"`
	Visibility  string         `json:"visibility"`
	SourceURL   *string        `json:"source_url,omitempty"`
	UploadedBy  string         `json:"uploaded_by"`
	Pinned      bool           `json:"pinned"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at"`
}

// AssetUploadInput is the write-side shape passed to AssetUpload.
// Body is delivered separately as an io.Reader so callers can stream
// large blobs without keeping them in memory.
//
// WorkspaceID nil = "platform asset" (admin-only at the server gate).
// SourceURL is provenance only — recorded so future humans know where
// the bytes came from; never auto-fetched.
type AssetUploadInput struct {
	WorkspaceID *string        `json:"workspace_id,omitempty"`
	Kind        string         `json:"kind"`    // model|package|lib|media|app_data
	Name        string         `json:"name"`    // path-like
	Version     string         `json:"version"` // default "v1" if empty
	Visibility  string         `json:"visibility,omitempty"`
	SourceURL   string         `json:"source_url,omitempty"`
	Mime        string         `json:"mime,omitempty"`
	Pinned      bool           `json:"pinned,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// AssetListResponse wraps GET /internal/v1/assets list responses.
type AssetListResponse struct {
	Assets []AssetMeta `json:"assets"`
}

// AssetGet looks up a single asset by composite key. workspaceID is
// nil for platform assets ("" string is treated as nil to match the
// SQL UNIQUE NULLS NOT DISTINCT semantics).
func (c *Client) AssetGet(workspaceID *string, kind, name, version string) (*AssetMeta, error) {
	if strings.TrimSpace(kind) == "" {
		return nil, errInvalid("AssetGet: kind required")
	}
	if strings.TrimSpace(name) == "" {
		return nil, errInvalid("AssetGet: name required")
	}
	if strings.TrimSpace(version) == "" {
		version = "v1"
	}
	q := url.Values{}
	q.Set("kind", kind)
	q.Set("name", name)
	q.Set("version", version)
	if workspaceID != nil && *workspaceID != "" {
		q.Set("workspace_id", *workspaceID)
	}
	resp, err := c.Do(http.MethodGet, "/internal/v1/assets/by-name?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var out AssetMeta
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AssetStat looks up an asset by its content hash. Useful when a caller
// already knows the sha256 (e.g. recorded in some downstream table) and
// wants the canonical metadata without re-deriving name/version.
func (c *Client) AssetStat(sha256 string) (*AssetMeta, error) {
	if strings.TrimSpace(sha256) == "" {
		return nil, errInvalid("AssetStat: sha256 required")
	}
	resp, err := c.Do(http.MethodGet, "/internal/v1/assets/by-sha256/"+sha256, nil)
	if err != nil {
		return nil, err
	}
	var out AssetMeta
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AssetDelete removes the catalog row + cascades to share_links +
// asks each provider to drop the blob. Returns nil on 200; an error
// on any non-2xx (including 404 for already-gone, which callers may
// want to treat as success — caller's choice).
func (c *Client) AssetDelete(id int64) error {
	if id <= 0 {
		return errInvalid("AssetDelete: id must be > 0")
	}
	resp, err := c.Do(http.MethodDelete, "/internal/v1/assets/"+strconv.FormatInt(id, 10), nil)
	if err != nil {
		return err
	}
	return readJSON(resp, nil)
}

// blobHTTPClient streams blob bytes directly to/from a provider via a
// dock-signed URL. No timeout — blobs can be large; the dock-call
// client (c.HTTP, 15s) is only for the small grant/finalize JSON hops.
var blobHTTPClient = &http.Client{}

// AssetDownload returns an open *http.Response whose Body streams the
// blob bytes. Caller owns the body lifecycle — MUST defer Close().
//
// Direct path (v0.6.0): it first asks dock for a short-lived signed
// provider URL (GET /assets/:id/download-url) and streams the blob
// straight from the provider — the bytes never traverse dock. If the
// dock has providers disabled (503) it falls back to the through-dock
// blob stream, so callers work in both deployments.
//
// For sha256 verification, wrap resp.Body in a sha256 hasher and
// compare against ref.SHA256 as bytes flow — don't trust the catalog
// alone for tamper detection.
func (c *Client) AssetDownload(ref *AssetMeta) (*http.Response, error) {
	if ref == nil || ref.ID <= 0 {
		return nil, errInvalid("AssetDownload: ref.ID required")
	}
	idStr := strconv.FormatInt(ref.ID, 10)

	// Try the direct (dock-bypassing) path first. Carry the asset's own
	// workspace_id so dock authorizes a workspace-private blob (without it
	// dock 404s tenant-scoped assets, falling back to the through-dock path).
	dlPath := "/internal/v1/assets/" + idStr + "/download-url"
	if ref.WorkspaceID != nil && *ref.WorkspaceID != "" {
		dlPath += "?workspace_id=" + url.QueryEscape(*ref.WorkspaceID)
	}
	resp, err := c.Do(http.MethodGet, dlPath, nil)
	if err == nil && resp.StatusCode/100 == 2 {
		var grant struct {
			URL string `json:"url"`
		}
		if jerr := readJSON(resp, &grant); jerr == nil && grant.URL != "" {
			req, rerr := http.NewRequest(http.MethodGet, grant.URL, nil)
			if rerr != nil {
				return nil, rerr
			}
			return blobHTTPClient.Do(req)
		}
	} else if resp != nil {
		resp.Body.Close()
	}

	// Fallback: stream through dock (provider mode off, or grant path
	// unavailable on an older dock).
	return c.Do(http.MethodGet, "/internal/v1/assets/"+idStr+"/blob", nil)
}

// AssetDownloadURL returns a signed, time-limited, publicly-fetchable
// HTTPS URL for the asset's bytes — the provider's signed GET URL. Use
// this where a device or browser fetches the blob directly with no Polar
// session: the iOS OTA install .plist (<url> → .ipa for itms-services /
// QR install) and <img>/<video> src. The URL is short-lived, so mint a
// fresh one per request rather than caching it.
//
// Errors if the dock has providers disabled (no signed URL to hand out) —
// in that deployment the caller must proxy bytes itself via AssetDownload.
func (c *Client) AssetDownloadURL(assetID int64) (string, error) {
	return c.AssetDownloadURLWS(assetID, "")
}

// AssetDownloadURLWS is AssetDownloadURL scoped to a workspace. Pass the
// caller's workspace_id so dock can authorize a workspace-private asset;
// without it dock only hands out URLs for public assets and returns 404
// for tenant-scoped blobs (e.g. a plugin's per-workspace screenshots).
// Use AssetDownloadURL (ws="") only for genuinely public assets.
func (c *Client) AssetDownloadURLWS(assetID int64, workspaceID string) (string, error) {
	if assetID <= 0 {
		return "", errInvalid("AssetDownloadURL: assetID required")
	}
	path := "/internal/v1/assets/" + strconv.FormatInt(assetID, 10) + "/download-url"
	if workspaceID != "" {
		path += "?workspace_id=" + url.QueryEscape(workspaceID)
	}
	resp, err := c.Do(http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	var grant struct {
		URL string `json:"url"`
	}
	if err := readJSON(resp, &grant); err != nil {
		return "", err
	}
	if grant.URL == "" {
		return "", errInvalid("AssetDownloadURL: empty url (dock provider mode off)")
	}
	return grant.URL, nil
}

// assetUploadGrantResp mirrors POST /internal/v1/assets/upload-grant.
type assetUploadGrantResp struct {
	AssetID    int64  `json:"asset_id"`
	SHA256     string `json:"sha256"`
	Exists     bool   `json:"exists"`
	PutURL     string `json:"put_url"`
	ProviderID int64  `json:"provider_id"`
}

// AssetUpload registers bytes in the assets catalog via the direct,
// dock-bypassing signed-PUT path (doc/arch/release-system.md):
//
//  1. spool `body` to a temp file while computing sha256 + size
//     (sha is the content-addressed key, so it must be known first);
//  2. POST /assets/upload-grant → {asset_id, put_url} (or exists);
//  3. PUT the bytes straight to the provider's signed URL — dock never
//     sees them;
//  4. POST /assets/finalize → mark the blob ready + bump usage.
//
// Pass input.WorkspaceID = nil for a platform-owned asset (module
// binary / release artifact / model weights): no tenant quota, public
// by default. Returns the catalog AssetMeta.
func (c *Client) AssetUpload(input AssetUploadInput, body io.Reader) (*AssetMeta, error) {
	if strings.TrimSpace(input.Kind) == "" || strings.TrimSpace(input.Name) == "" {
		return nil, errInvalid("AssetUpload: kind + name required")
	}
	if body == nil {
		return nil, errInvalid("AssetUpload: body required")
	}
	if input.Version == "" {
		input.Version = "v1"
	}
	mime := input.Mime
	if mime == "" {
		mime = "application/octet-stream"
	}

	// 1. Spool to temp while hashing + sizing.
	tmp, err := os.CreateTemp("", "polar-asset-*.upload")
	if err != nil {
		return nil, fmt.Errorf("AssetUpload: temp: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), body)
	if err != nil {
		return nil, fmt.Errorf("AssetUpload: spool: %w", err)
	}
	if size == 0 {
		return nil, errInvalid("AssetUpload: empty body")
	}
	sha := hex.EncodeToString(h.Sum(nil))

	// 2. Ask dock for a grant.
	ws := ""
	if input.WorkspaceID != nil {
		ws = *input.WorkspaceID
	}
	grantBody := map[string]any{
		"workspace_id": ws,
		"kind":         input.Kind,
		"name":         input.Name,
		"version":      input.Version,
		"sha256":       sha,
		"size_bytes":   size,
		"mime":         mime,
		"visibility":   input.Visibility,
		"pinned":       input.Pinned,
		"source_url":   input.SourceURL,
		"metadata":     input.Metadata,
	}
	resp, err := c.Do(http.MethodPost, "/internal/v1/assets/upload-grant", grantBody)
	if err != nil {
		return nil, fmt.Errorf("AssetUpload: grant: %w", err)
	}
	var grant assetUploadGrantResp
	if err := readJSON(resp, &grant); err != nil {
		return nil, fmt.Errorf("AssetUpload: grant: %w", err)
	}

	// 3. PUT bytes direct to the provider — unless the content already
	//    exists (dedup), in which case skip straight to the metadata.
	if !grant.Exists && grant.PutURL != "" {
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("AssetUpload: rewind: %w", err)
		}
		req, err := http.NewRequest(http.MethodPut, grant.PutURL, tmp)
		if err != nil {
			return nil, fmt.Errorf("AssetUpload: put req: %w", err)
		}
		req.Header.Set("Content-Type", mime)
		req.ContentLength = size
		putResp, err := blobHTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("AssetUpload: put: %w", err)
		}
		if err := readJSON(putResp, nil); err != nil {
			return nil, fmt.Errorf("AssetUpload: put: %w", err)
		}

		// 4. Finalize: mark ready + bump usage.
		finResp, err := c.Do(http.MethodPost, "/internal/v1/assets/finalize", map[string]any{
			"asset_id":    grant.AssetID,
			"provider_id": grant.ProviderID,
		})
		if err != nil {
			return nil, fmt.Errorf("AssetUpload: finalize: %w", err)
		}
		var meta AssetMeta
		if err := readJSON(finResp, &meta); err != nil {
			return nil, fmt.Errorf("AssetUpload: finalize: %w", err)
		}
		return &meta, nil
	}

	// Content already present (or provider off): return current metadata.
	getResp, err := c.Do(http.MethodGet, "/internal/v1/assets/"+strconv.FormatInt(grant.AssetID, 10)+"?workspace_id="+url.QueryEscape(ws), nil)
	if err != nil {
		return nil, fmt.Errorf("AssetUpload: meta: %w", err)
	}
	var meta AssetMeta
	if err := readJSON(getResp, &meta); err != nil {
		return nil, fmt.Errorf("AssetUpload: meta: %w", err)
	}
	return &meta, nil
}

// ErrAssetUploadNotImplemented is retained for back-compat with callers
// that branched on it during the stub era (v0.3.0–v0.5.x). AssetUpload
// no longer returns it as of v0.6.0.
//
// Deprecated: AssetUpload is implemented; this is never returned.
var ErrAssetUploadNotImplemented = errors.New("sdk.AssetUpload: implemented since v0.6.0")
