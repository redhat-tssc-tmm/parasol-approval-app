package ws

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type Message struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type client struct {
	conn   *websocket.Conn
	tenant string
}

type Hub struct {
	clients    map[*websocket.Conn]*client
	broadcast  chan Message
	register   chan *client
	unregister chan *websocket.Conn
	mu         sync.RWMutex

	onTenantChange func(activeTenants []string)
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*websocket.Conn]*client),
		broadcast:  make(chan Message, 256),
		register:   make(chan *client),
		unregister: make(chan *websocket.Conn),
	}
}

func (h *Hub) OnTenantChange(fn func(activeTenants []string)) {
	h.onTenantChange = fn
}

func (h *Hub) activeTenants() []string {
	seen := make(map[string]bool)
	for _, c := range h.clients {
		if c.tenant != "" {
			seen[c.tenant] = true
		}
	}
	tenants := make([]string, 0, len(seen))
	for t := range seen {
		tenants = append(tenants, t)
	}
	return tenants
}

func (h *Hub) Run() {
	log.Println("[ws-hub] Hub running")
	for {
		select {
		case c := <-h.register:
			h.mu.Lock()
			h.clients[c.conn] = c
			count := len(h.clients)
			tenants := h.activeTenants()
			h.mu.Unlock()
			log.Printf("[ws-hub] Client connected: tenant=%s (total=%d, active_tenants=%v)", c.tenant, count, tenants)
			if h.onTenantChange != nil {
				h.onTenantChange(tenants)
			}

		case conn := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[conn]; ok {
				delete(h.clients, conn)
				conn.Close()
			}
			count := len(h.clients)
			tenants := h.activeTenants()
			h.mu.Unlock()
			log.Printf("[ws-hub] Client disconnected (total=%d, active_tenants=%v)", count, tenants)
			if h.onTenantChange != nil {
				h.onTenantChange(tenants)
			}

		case msg := <-h.broadcast:
			data, err := json.Marshal(msg)
			if err != nil {
				log.Printf("[ws-hub] ERROR marshaling message: %v", err)
				continue
			}

			h.mu.RLock()
			for conn := range h.clients {
				if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
					log.Printf("[ws-hub] ERROR writing to client: %v", err)
					go func(c *websocket.Conn) {
						h.unregister <- c
					}(conn)
				}
			}
			h.mu.RUnlock()
		}
	}
}

func (h *Hub) Broadcast(msg Message) {
	h.broadcast <- msg
}

func (h *Hub) ActiveTenants() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.activeTenants()
}

func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	log.Printf("[ws-hub] WebSocket upgrade request from %s tenant=%s", r.RemoteAddr, tenant)

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws-hub] ERROR upgrading WebSocket: %v", err)
		return
	}

	h.register <- &client{conn: conn, tenant: tenant}

	go func() {
		defer func() {
			h.unregister <- conn
		}()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					log.Printf("[ws-hub] Unexpected close: %v", err)
				}
				break
			}
		}
	}()
}
