// pumps.go — per-connection read/write loops + ping/pong heartbeat.
// Constants mirror dock's wsHub so reconnect cadence on the mobile
// client side is uniform across /ws/chat and /ws/<plugin>.

package wsbroker

import (
	"time"

	"github.com/gorilla/websocket"
)

const (
	wsWriteWait     = 10 * time.Second
	wsPongWait      = 60 * time.Second
	wsPingPeriod    = (wsPongWait * 9) / 10 // 54 s
	wsMaxMessage    = 4 * 1024              // plugin WS is publish-down; client→server rare and small
	wsSendChanDepth = 256                   // matches dock; tested for slow-consumer eviction
)

// readPump exists primarily to drive pong-handling — the broker
// itself doesn't expect client→server messages today (plugin clients
// are read-only subscribers). Any inbound frame is read and dropped.
// When ReadMessage errors (timeout, network, client close), defer
// unregister + close.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		_ = c.conn.Close()
	}()
	c.conn.SetReadLimit(wsMaxMessage)
	_ = c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
		// Drop frame. Future "client sends subscribe-by-event-type
		// filter" lands here.
	}
}

// writePump fans envelope payloads from c.send onto the wire and
// emits ping frames every wsPingPeriod. Exits when send is closed
// (by hub eviction or shutdown) or any write fails.
func (c *Client) writePump() {
	ticker := time.NewTicker(wsPingPeriod)
	defer func() {
		ticker.Stop()
		_ = c.conn.Close()
	}()
	for {
		select {
		case msg, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
