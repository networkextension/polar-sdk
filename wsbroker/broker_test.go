package wsbroker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	sdk "github.com/networkextension/polar-sdk"
)

// fakeAuth lets tests inject AuthVerify outcomes without spinning
// up a dock HTTP server.
type fakeAuth struct {
	mu  sync.Mutex
	res *sdk.AuthVerifyResult
	err error
	got string
}

func (f *fakeAuth) AuthVerify(token string) (*sdk.AuthVerifyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = token
	return f.res, f.err
}

func TestEnvelopeRoundTrip(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"alarm_id": 42, "title": "leak"})
	env := Envelope{
		Type:        "alarm.opened",
		WorkspaceID: "ws-1",
		Timestamp:   time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
		Payload:     payload,
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var back Envelope
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Type != env.Type || back.WorkspaceID != env.WorkspaceID {
		t.Fatalf("round-trip drift: %+v", back)
	}
	var got map[string]any
	if err := json.Unmarshal(back.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if int(got["alarm_id"].(float64)) != 42 {
		t.Errorf("payload alarm_id lost: %v", got["alarm_id"])
	}
}

func TestExtractAccessToken(t *testing.T) {
	mkRequest := func(setup func(*http.Request)) *http.Request {
		r, _ := http.NewRequest("GET", "/x", nil)
		setup(r)
		return r
	}
	cases := []struct {
		name  string
		setup func(*http.Request)
		want  string
	}{
		{"empty", func(r *http.Request) {}, ""},
		{"bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc") }, "abc"},
		{"bearer-mixed-case", func(r *http.Request) { r.Header.Set("Authorization", "bearer abc") }, "abc"},
		{"cookie", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: accessCookieName, Value: "ck"}) }, "ck"},
		{"bearer-beats-cookie", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer bear")
			r.AddCookie(&http.Cookie{Name: accessCookieName, Value: "ck"})
		}, "bear"},
		{"empty-bearer-ignored", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }, ""},
		{"non-bearer-ignored", func(r *http.Request) { r.Header.Set("Authorization", "Basic xxx") }, ""},
	}
	for _, c := range cases {
		got := extractAccessToken(mkRequest(c.setup))
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestResolveWorkspace(t *testing.T) {
	r, _ := http.NewRequest("GET", "/x", nil)
	r.Header.Set("X-Workspace-Id", "explicit")
	auth := &sdk.AuthVerifyResult{WorkspaceID: "default"}
	if got := resolveWorkspace(r, auth); got != "explicit" {
		t.Errorf("header should win: got %q", got)
	}
	r2, _ := http.NewRequest("GET", "/x", nil)
	if got := resolveWorkspace(r2, auth); got != "default" {
		t.Errorf("fallback to auth default: got %q", got)
	}
	r3, _ := http.NewRequest("GET", "/x", nil)
	if got := resolveWorkspace(r3, nil); got != "" {
		t.Errorf("no auth, no header: got %q", got)
	}
}

func TestHandlerRejectsMissingToken(t *testing.T) {
	hub := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	srv := httptest.NewServer(NewHandler(hub, &fakeAuth{}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: got %d want 401", resp.StatusCode)
	}
}

func TestHandlerRejectsBadToken(t *testing.T) {
	hub := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	auth := &fakeAuth{err: errors.New("bad")}
	srv := httptest.NewServer(NewHandler(hub, auth))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer rotten")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad token: got %d want 401", resp.StatusCode)
	}
	if auth.got != "rotten" {
		t.Errorf("AuthVerify saw token %q", auth.got)
	}
}

func TestBroadcastReachesOnlyMatchingWorkspace(t *testing.T) {
	hub := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	// Both connections have the same user but different workspaces.
	authA := &fakeAuth{res: &sdk.AuthVerifyResult{UserID: "u1", WorkspaceID: "wsA"}}
	srvA := httptest.NewServer(NewHandler(hub, authA))
	defer srvA.Close()

	authB := &fakeAuth{res: &sdk.AuthVerifyResult{UserID: "u1", WorkspaceID: "wsB"}}
	srvB := httptest.NewServer(NewHandler(hub, authB))
	defer srvB.Close()

	connA := dialTestWS(t, srvA.URL, "tokenA", "")
	defer connA.Close()
	connB := dialTestWS(t, srvB.URL, "tokenB", "")
	defer connB.Close()

	// Give the hub a beat to process both register events.
	time.Sleep(50 * time.Millisecond)

	payload, _ := json.Marshal(map[string]any{"v": 1})
	if err := hub.Broadcast("wsA", Envelope{
		Type:    "test.event",
		Payload: payload,
	}); err != nil {
		t.Fatal(err)
	}

	// connA should receive it.
	connA.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, msg, err := connA.ReadMessage()
	if err != nil {
		t.Fatalf("connA expected message: %v", err)
	}
	var got Envelope
	if err := json.Unmarshal(msg, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != "test.event" || got.WorkspaceID != "wsA" {
		t.Errorf("connA got wrong envelope: %+v", got)
	}

	// connB should NOT receive it within a short window.
	connB.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := connB.ReadMessage(); err == nil {
		t.Errorf("connB should not have received cross-workspace event")
	}
}

func TestBroadcastUserTargetsOneUser(t *testing.T) {
	hub := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	authU1 := &fakeAuth{res: &sdk.AuthVerifyResult{UserID: "u1", WorkspaceID: "ws"}}
	srvU1 := httptest.NewServer(NewHandler(hub, authU1))
	defer srvU1.Close()

	authU2 := &fakeAuth{res: &sdk.AuthVerifyResult{UserID: "u2", WorkspaceID: "ws"}}
	srvU2 := httptest.NewServer(NewHandler(hub, authU2))
	defer srvU2.Close()

	c1 := dialTestWS(t, srvU1.URL, "t1", "")
	defer c1.Close()
	c2 := dialTestWS(t, srvU2.URL, "t2", "")
	defer c2.Close()

	time.Sleep(50 * time.Millisecond)

	if err := hub.BroadcastUser("ws", "u1", Envelope{Type: "ping"}); err != nil {
		t.Fatal(err)
	}

	c1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err := c1.ReadMessage(); err != nil {
		t.Fatalf("u1 should have received: %v", err)
	}
	c2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := c2.ReadMessage(); err == nil {
		t.Errorf("u2 should not have received targeted-user event")
	}
}

func TestHubShutdownClosesConnections(t *testing.T) {
	hub := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	go hub.Run(ctx)

	auth := &fakeAuth{res: &sdk.AuthVerifyResult{UserID: "u1", WorkspaceID: "ws"}}
	srv := httptest.NewServer(NewHandler(hub, auth))
	defer srv.Close()

	c := dialTestWS(t, srv.URL, "t", "")
	defer c.Close()
	time.Sleep(50 * time.Millisecond)

	cancel()
	select {
	case <-hub.Done():
	case <-time.After(time.Second):
		t.Fatal("hub.Done never closed after cancel")
	}
}

// dialTestWS opens a client websocket against a test handler URL,
// injecting the bearer token + an optional X-Workspace-Id header.
func dialTestWS(t *testing.T, httpURL, token, workspace string) *websocket.Conn {
	t.Helper()
	u, err := url.Parse(httpURL)
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	if workspace != "" {
		h.Set("X-Workspace-Id", workspace)
	}
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), h)
	if err != nil {
		t.Fatalf("dial %s: %v", u.String(), err)
	}
	return conn
}
