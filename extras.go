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
	"net/http"
	"net/url"
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

func errInvalid(msg string) error { return &invalidErr{msg: msg} }

type invalidErr struct{ msg string }

func (e *invalidErr) Error() string { return e.msg }
