package ws

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"relay-server/config"
	"relay-server/internal/panel"
	"relay-server/internal/session"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Traefik handles security
	},
	ReadBufferSize:  4096,
	WriteBufferSize: 1048576,
}

// viewerConn wraps a websocket.Conn and implements session.ViewerConn
type viewerConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (v *viewerConn) SendBinary(data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (v *viewerConn) SendHostStatus(connected bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	status := byte(0x00)
	if connected {
		status = 0x01
	}
	return v.conn.WriteMessage(websocket.BinaryMessage, []byte{0x02, status})
}

func (v *viewerConn) Close() {
	v.conn.Close()
}

func (v *viewerConn) RemoteAddr() string {
	return v.conn.RemoteAddr().String()
}

// Server handles WebSocket connections from browser viewers
type Server struct {
	cfg      *config.Config
	sessions *session.Manager
	panel    *panel.Client
}

func NewServer(cfg *config.Config, sessions *session.Manager, panelClient *panel.Client) *Server {
	return &Server{
		cfg:      cfg,
		sessions: sessions,
		panel:    panelClient,
	}
}

func (s *Server) Listen(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/view/", s.handleViewer)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Relay.WSPort)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Printf("[WS] Listening on %s", addr)

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("WS listen: %w", err)
	}
	return nil
}

func (s *Server) handleViewer(w http.ResponseWriter, r *http.Request) {
	// Extract UUID from path: /view/{UUID}
	path := strings.TrimPrefix(r.URL.Path, "/view/")
	uuid := strings.TrimSuffix(path, "/")
	if uuid == "" {
		http.Error(w, "missing uuid", http.StatusBadRequest)
		return
	}

	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}

	remoteIP := getRealIP(r)
	log.Printf("[WS] Viewer connecting: UUID=%s IP=%s", uuid, remoteIP)

	// Authenticate with panel
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Panel.AuthTimeout)
	defer cancel()

	authResp, err := s.panel.Authenticate(ctx, uuid, key, "viewer")
	if err != nil || !authResp.Allowed {
		reason := "panel error"
		if authResp != nil {
			reason = authResp.Reason
		}
		log.Printf("[WS] Auth denied UUID=%s: %s", uuid, reason)
		s.panel.SendEvent(uuid, "viewer", "auth_failed", remoteIP)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] Upgrade error: %v", err)
		return
	}

	vc := &viewerConn{conn: conn}

	// Register viewer - must have an active host session
	sess, ok := s.sessions.RegisterViewer(uuid, vc)
	if !ok {
		log.Printf("[WS] No host session for UUID=%s, closing viewer", uuid)
		// Send host offline status then close
		vc.SendHostStatus(false)
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(4001, "host not connected"))
		conn.Close()
		return
	}

	// Notify panel
	s.panel.SendEvent(uuid, "viewer", "viewer_connected", remoteIP)
	log.Printf("[WS] Viewer connected: UUID=%s", uuid)

	// Send initial host status = connected
	vc.SendHostStatus(true)

	// Notify host that a viewer is now watching
	if host := sess.GetHost(); host != nil {
		host.SendViewerStatus(true)
	}

	// Read loop for input events from browser
	defer func() {
		conn.Close()
		s.sessions.UnregisterViewer(uuid)
		s.panel.SendEvent(uuid, "viewer", "viewer_disconnected", remoteIP)
		log.Printf("[WS] Viewer disconnected: UUID=%s", uuid)

		// Notify host that viewer is gone
		if host := sess.GetHost(); host != nil {
			host.SendViewerStatus(false)
		}
	}()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}

		// Parse JSON input event
		var event map[string]interface{}
		if err := json.Unmarshal(msg, &event); err != nil {
			continue
		}

		eventType, _ := event["type"].(string)
		inputPacket := buildInputPacket(eventType, event)
		if inputPacket == nil {
			continue
		}

		// Forward to host
		host := sess.GetHost()
		if host != nil {
			if err := host.SendToHost(inputPacket); err != nil {
				log.Printf("[WS] Failed to send input to host UUID=%s: %v", uuid, err)
			}
		}
	}
}

// buildInputPacket converts JSON event to C# TCP input packet
// Format: [4 magic=0x494E5054][1 type][4 X][4 Y][4 Value] = 17 bytes
func buildInputPacket(eventType string, event map[string]interface{}) []byte {
	const magic = 0x494E5054

	// Input type constants
	const (
		MouseMove      = 1
		MouseLeftDown  = 2
		MouseLeftUp    = 3
		MouseRightDown = 4
		MouseRightUp   = 5
		MouseWheel     = 6
		KeyDown        = 7
		KeyUp          = 8
	)

	buf := make([]byte, 17)
	binary.BigEndian.PutUint32(buf[0:4], magic)

	getFloat := func(key string) float64 {
		v, _ := event[key].(float64)
		return v
	}
	getInt := func(key string) int {
		v, _ := event[key].(float64)
		return int(v)
	}

	switch eventType {
	case "mouse_move":
		x := uint32(getFloat("x") * 65535)
		y := uint32(getFloat("y") * 65535)
		buf[4] = MouseMove
		binary.BigEndian.PutUint32(buf[5:9], x)
		binary.BigEndian.PutUint32(buf[9:13], y)
		binary.BigEndian.PutUint32(buf[13:17], 0)

	case "mouse_down":
		button, _ := event["button"].(string)
		buf[5] = 0
		if button == "right" {
			buf[4] = MouseRightDown
		} else {
			buf[4] = MouseLeftDown
		}
		binary.BigEndian.PutUint32(buf[5:9], 0)
		binary.BigEndian.PutUint32(buf[9:13], 0)
		binary.BigEndian.PutUint32(buf[13:17], 0)

	case "mouse_up":
		button, _ := event["button"].(string)
		if button == "right" {
			buf[4] = MouseRightUp
		} else {
			buf[4] = MouseLeftUp
		}
		binary.BigEndian.PutUint32(buf[5:9], 0)
		binary.BigEndian.PutUint32(buf[9:13], 0)
		binary.BigEndian.PutUint32(buf[13:17], 0)

	case "mouse_wheel":
		delta := int32(getInt("delta"))
		buf[4] = MouseWheel
		binary.BigEndian.PutUint32(buf[5:9], 0)
		binary.BigEndian.PutUint32(buf[9:13], 0)
		binary.BigEndian.PutUint32(buf[13:17], uint32(delta))

	case "key_down":
		key := getInt("key")
		buf[4] = KeyDown
		binary.BigEndian.PutUint32(buf[5:9], 0)
		binary.BigEndian.PutUint32(buf[9:13], 0)
		binary.BigEndian.PutUint32(buf[13:17], uint32(key))

	case "key_up":
		key := getInt("key")
		buf[4] = KeyUp
		binary.BigEndian.PutUint32(buf[5:9], 0)
		binary.BigEndian.PutUint32(buf[9:13], 0)
		binary.BigEndian.PutUint32(buf[13:17], uint32(key))

	case "request_control", "release_control":
		// These are informational - no TCP packet needed for now
		return nil

	default:
		return nil
	}

	return buf
}

// getRealIP extracts real IP considering Traefik proxy headers
func getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}
