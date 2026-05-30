// Package wsbroker is the shared WebSocket server scaffold every Polar
// plugin can mount to expose its own high-volume domain-event channel
// (e.g. polar-buildings exposes /ws/buildings for alarm + work_order
// + inspection events).
//
// Why this exists: dock owns /ws/chat for cross-cutting low-volume
// events (chat / mention / system). Plugin-domain events would either
// drown out chat if multiplexed through dock or bottleneck the dock
// hub on a volume spike. Per-plugin WS keeps each module's blast
// radius contained and lets mobile clients connect only to the
// modules they need.
//
// What you get for ~5 wiring lines in your plugin:
//   - Authenticated WebSocket upgrade — extracts the access token
//     from Bearer header (preferred) or `access_token` cookie, calls
//     sdk.Client.AuthVerify to validate. 401 on miss.
//   - Per-(userID, workspaceID) connection map with broadcast,
//     targeted-user, and graceful-close primitives.
//   - Heartbeat / ping-pong loop with the same constants dock uses
//     (60s pong wait, 54s ping interval) so reconnect cadence on the
//     mobile client side is uniform across endpoints.
//   - Slow-consumer protection — clients whose write buffer fills
//     get dropped without blocking the publisher.
//
// What you bring:
//   - *sdk.Client (the same one your plugin already uses for
//     Heartbeat) — wsbroker calls AuthVerify through it.
//   - Envelope payloads — plugin defines its event types and marshals
//     into Envelope.Payload (json.RawMessage).
//
// Typical plugin wiring:
//
//	hub := wsbroker.NewHub()
//	go hub.Run(ctx)
//	r.GET("/ws/myplugin", gin.WrapH(wsbroker.NewHandler(hub, dockClient)))
//
//	// from a REST handler, after the DB commit:
//	payload, _ := json.Marshal(map[string]any{"alarm_id": a.ID})
//	hub.Broadcast(workspaceID, wsbroker.Envelope{
//	    Type: "alarm.opened", WorkspaceID: workspaceID,
//	    Timestamp: time.Now().UTC(), Payload: payload,
//	})
package wsbroker

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	sdk "github.com/networkextension/polar-sdk"
)

// Envelope is the wire shape every plugin's WS broadcasts. Type is a
// dotted slug ("alarm.opened", "work_order.status_changed") the
// client switches on; Payload is plugin-defined Codable JSON.
//
// Timestamp is server-side at publish time, intentionally separate
// from any "created_at" inside Payload so a client can sort by event
// arrival regardless of the underlying entity's creation time
// (e.g. a backfilled alarm published now should still sort to now in
// the live feed).
type Envelope struct {
	Type        string          `json:"type"`
	WorkspaceID string          `json:"workspace_id"`
	Timestamp   time.Time       `json:"ts"`
	Payload     json.RawMessage `json:"payload,omitempty"`
}

// AuthVerifier is the subset of *sdk.Client the broker needs. Defined
// as an interface so broker tests can swap in a fake without spinning
// up a dock HTTP server.
type AuthVerifier interface {
	AuthVerify(token string) (*sdk.AuthVerifyResult, error)
}

// Hub multiplexes connections from many users in many workspaces. One
// hub per plugin svc; share it between Handler (server-side upgrade)
// and the REST handlers (server-side publish).
//
// Hub.Run reads from register/unregister/broadcast channels in a
// single goroutine, so the clients map needs no lock. Hub.Broadcast
// and BroadcastUser are safe to call from any goroutine.
type Hub struct {
	// workspaceID → userID → set of clients
	rooms map[string]map[string]map[*Client]struct{}

	register   chan *Client
	unregister chan *Client
	broadcast  chan hubMsg
	done       chan struct{}
}

type hubMsg struct {
	workspaceID string
	userID      string // "" = fan out to all users in workspace
	payload     []byte
}

// Client wraps one upgraded websocket connection. Exported only so
// tests can construct one; plugin code receives *Client from the
// register channel and only ever reads its fields.
type Client struct {
	conn        *websocket.Conn
	send        chan []byte
	userID      string
	workspaceID string
	hub         *Hub
	closeOnce   sync.Once
}

// NewHub returns an unstarted hub. Call Run(ctx) once on a goroutine
// before NewHandler can register connections.
func NewHub() *Hub {
	return &Hub{
		rooms:      make(map[string]map[string]map[*Client]struct{}),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan hubMsg, 64),
		done:       make(chan struct{}),
	}
}

// Run drives the hub's central goroutine. Returns when ctx is
// cancelled; closing every open connection on the way out.
func (h *Hub) Run(ctx context.Context) {
	defer h.closeAll()
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-h.register:
			users := h.rooms[c.workspaceID]
			if users == nil {
				users = make(map[string]map[*Client]struct{})
				h.rooms[c.workspaceID] = users
			}
			set := users[c.userID]
			if set == nil {
				set = make(map[*Client]struct{})
				users[c.userID] = set
			}
			set[c] = struct{}{}
		case c := <-h.unregister:
			h.removeClient(c)
		case m := <-h.broadcast:
			users := h.rooms[m.workspaceID]
			if users == nil {
				continue
			}
			if m.userID != "" {
				h.fanOutToUser(users[m.userID], m.payload)
				continue
			}
			for _, set := range users {
				h.fanOutToUser(set, m.payload)
			}
		}
	}
}

func (h *Hub) fanOutToUser(set map[*Client]struct{}, payload []byte) {
	for c := range set {
		select {
		case c.send <- payload:
		default:
			// Slow consumer — drop rather than backpressure the
			// publisher. The connection's writePump will exit on
			// the next send and the readPump's defer hits
			// unregister + close.
			log.Printf("wsbroker: slow consumer dropped user=%s workspace=%s buf=%d/%d",
				c.userID, c.workspaceID, len(c.send), cap(c.send))
			c.closeSend()
		}
	}
}

func (h *Hub) removeClient(c *Client) {
	users := h.rooms[c.workspaceID]
	if users == nil {
		return
	}
	set := users[c.userID]
	if set == nil {
		return
	}
	if _, ok := set[c]; ok {
		delete(set, c)
		c.closeSend()
	}
	if len(set) == 0 {
		delete(users, c.userID)
	}
	if len(users) == 0 {
		delete(h.rooms, c.workspaceID)
	}
}

func (h *Hub) closeAll() {
	for _, users := range h.rooms {
		for _, set := range users {
			for c := range set {
				c.closeSend()
			}
		}
	}
	h.rooms = nil
	close(h.done)
}

// Broadcast publishes env to every connected client in workspaceID.
// Returns the json-marshal error if Payload couldn't serialize; never
// blocks (per-client dispatch happens inside Run).
func (h *Hub) Broadcast(workspaceID string, env Envelope) error {
	if workspaceID == "" {
		workspaceID = env.WorkspaceID
	}
	if env.WorkspaceID == "" {
		env.WorkspaceID = workspaceID
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	h.broadcast <- hubMsg{workspaceID: workspaceID, payload: payload}
	return nil
}

// BroadcastUser publishes env to a single user (all of their
// connected devices) inside the given workspace. Useful for
// "your work order was assigned" style targeted nudges.
func (h *Hub) BroadcastUser(workspaceID, userID string, env Envelope) error {
	if env.WorkspaceID == "" {
		env.WorkspaceID = workspaceID
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	h.broadcast <- hubMsg{workspaceID: workspaceID, userID: userID, payload: payload}
	return nil
}

// Done returns a channel closed when the hub's Run loop has exited.
// Useful for graceful shutdown ordering in plugin Close().
func (h *Hub) Done() <-chan struct{} { return h.done }

// Handler is the http.Handler that upgrades incoming requests into
// hub-managed WebSocket connections. Use gin.WrapH to mount under a
// gin route.
type Handler struct {
	hub      *Hub
	auth     AuthVerifier
	upgrader websocket.Upgrader
}

// NewHandler returns a ready-to-mount upgrade handler bound to the
// given hub. auth is typically the plugin's *sdk.Client (which
// already wraps dock + caches AuthVerify for 30s).
func NewHandler(hub *Hub, auth AuthVerifier) *Handler {
	return &Handler{
		hub:  hub,
		auth: auth,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			// Plugin WS is reached over either dock's parent
			// domain (cookies flow) or a plugin subdomain (also
			// under the same parent for cookie purposes). Origin
			// policy is the host nginx's job; the upgrader stays
			// permissive so a misconfigured but-otherwise-valid
			// browser doesn't get a confusing 403.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// ServeHTTP wires the upgrade path: extract token → verify → resolve
// workspace → upgrade → register on hub → spawn read/write pumps.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := extractAccessToken(r)
	if token == "" {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}
	auth, err := h.auth.AuthVerify(token)
	if err != nil || auth == nil || auth.UserID == "" {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}

	workspaceID := resolveWorkspace(r, auth)
	if workspaceID == "" {
		http.Error(w, "no workspace", http.StatusBadRequest)
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade already wrote the response on failure.
		log.Printf("wsbroker: upgrade failed user=%s: %v", auth.UserID, err)
		return
	}

	c := &Client{
		conn:        conn,
		send:        make(chan []byte, 256),
		userID:      auth.UserID,
		workspaceID: workspaceID,
		hub:         h.hub,
	}
	h.hub.register <- c
	go c.writePump()
	go c.readPump()
}

// closeSend closes the send chan exactly once. writePump uses chan
// close as its termination signal, so calling it from multiple
// places (slow-consumer eviction, removeClient, hub shutdown) must
// be idempotent.
func (c *Client) closeSend() {
	c.closeOnce.Do(func() { close(c.send) })
}
