package tcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"relay-server/config"
	"relay-server/internal/panel"
	"relay-server/internal/session"
	"sync"
	"time"
)

// Magic bytes
var (
	magicHOST = [4]byte{0x48, 0x4F, 0x53, 0x54} // "HOST"
	magicOKAY = [4]byte{0x4F, 0x4B, 0x41, 0x59} // "OKAY"
	magicDENY = [4]byte{0x44, 0x45, 0x4E, 0x59} // "DENY"
	magicRDRD = [4]byte{0x52, 0x44, 0x52, 0x44} // 0x52445244 video frame
	magicRDPI = [4]byte{0x52, 0x44, 0x50, 0x49} // 0x52445049 ping
	magicRDPP = [4]byte{0x52, 0x44, 0x50, 0x50} // 0x52445050 pong
)

// hostConn wraps a net.Conn and implements session.HostConn
type hostConn struct {
	conn net.Conn
	mu   sync.Mutex
}

func (h *hostConn) SendToHost(data []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.conn.Write(data)
	return err
}

func (h *hostConn) Close() {
	h.conn.Close()
}

func (h *hostConn) RemoteAddr() string {
	return h.conn.RemoteAddr().String()
}

// Server listens for TCP connections from C# hosts
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
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Relay.TCPPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("TCP listen: %w", err)
	}
	defer ln.Close()

	log.Printf("[TCP] Listening on %s", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("[TCP] Accept error: %v", err)
				continue
			}
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	remoteIP := conn.RemoteAddr().String()
	log.Printf("[TCP] New connection from %s", remoteIP)

	// Step 1: Read handshake [4 HOST][36 UUID][32 KEY]
	buf := make([]byte, 4+36+32)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Printf("[TCP] Handshake read error from %s: %v", remoteIP, err)
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{}) // clear deadline

	// Validate magic
	var magic [4]byte
	copy(magic[:], buf[0:4])
	if magic != magicHOST {
		log.Printf("[TCP] Invalid magic from %s", remoteIP)
		conn.Close()
		return
	}

	uuid := string(buf[4:40])
	key := string(buf[40:72])

	log.Printf("[TCP] Host handshake: UUID=%s IP=%s", uuid, remoteIP)

	// Step 2: Authenticate with panel
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Panel.AuthTimeout)
	defer cancel()

	authResp, err := s.panel.Authenticate(ctx, uuid, key, "host")
	if err != nil || !authResp.Allowed {
		reason := "panel error"
		if authResp != nil {
			reason = authResp.Reason
		}
		log.Printf("[TCP] Auth denied for UUID=%s: %s", uuid, reason)
		conn.Write(magicDENY[:])
		conn.Close()
		s.panel.SendEvent(uuid, "host", "auth_failed", remoteIP)
		return
	}

	// Step 3: Register in session manager
	hc := &hostConn{conn: conn}
	sess, ok := s.sessions.RegisterHost(uuid, hc)
	if !ok {
		log.Printf("[TCP] UUID=%s already has a host connected, rejecting", uuid)
		conn.Write(magicDENY[:])
		conn.Close()
		return
	}

	// Send OKAY
	conn.Write(magicOKAY[:])
	s.panel.SendEvent(uuid, "host", "host_connected", remoteIP)
	log.Printf("[TCP] Host connected: UUID=%s", uuid)

	// Step 4: Handle packets
	s.readLoop(conn, sess, uuid, remoteIP)
}

func (s *Server) readLoop(conn net.Conn, sess *session.Session, uuid, remoteIP string) {
	defer func() {
		conn.Close()
		s.sessions.UnregisterHost(uuid)
		s.panel.SendEvent(uuid, "host", "host_disconnected", remoteIP)
		log.Printf("[TCP] Host disconnected: UUID=%s", uuid)

		// Notify viewer
		if viewer := sess.GetViewer(); viewer != nil {
			viewer.SendHostStatus(false)
			viewer.Close()
		}
	}()

	magicBuf := make([]byte, 4)

	for {
		// Read 4-byte magic
		if _, err := io.ReadFull(conn, magicBuf); err != nil {
			return
		}

		var magic [4]byte
		copy(magic[:], magicBuf)

		switch magic {
		case magicRDRD:
			// Video frame: [4 length][1 isKey][8 timestamp][2 curX][2 curY][N data]
			if err := s.handleVideoFrame(conn, sess); err != nil {
				log.Printf("[TCP] Video frame error UUID=%s: %v", uuid, err)
				return
			}

		case magicRDPI:
			// Ping from host → reply with Pong immediately (simpler than forwarding)
			pong := magicRDPP
			if _, err := conn.Write(pong[:]); err != nil {
				return
			}

		case magicRDPP:
			// Pong from host (shouldn't happen, but ignore)

		default:
			log.Printf("[TCP] Unknown magic %X from UUID=%s", magic, uuid)
			return
		}
	}
}

func (s *Server) handleVideoFrame(conn net.Conn, sess *session.Session) error {
	// Read header: [4 length][1 isKey][8 timestamp][2 curX][2 curY]
	headerBuf := make([]byte, 4+1+8+2+2)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return err
	}

	dataLen := binary.BigEndian.Uint32(headerBuf[0:4])
	isKeyFrame := headerBuf[4]
	// timestamp := binary.BigEndian.Uint64(headerBuf[5:13]) // available if needed
	cursorX := binary.BigEndian.Uint16(headerBuf[13:15])
	cursorY := binary.BigEndian.Uint16(headerBuf[15:17])

	// Read H264 data
	h264Data := make([]byte, dataLen)
	if _, err := io.ReadFull(conn, h264Data); err != nil {
		return err
	}

	// Build WebSocket binary packet for viewer:
	// [1 type=0x01][1 isKey][2 curX][2 curY][4 dataLen][N h264]
	viewer := sess.GetViewer()
	if viewer == nil {
		// No viewer - drop frame
		return nil
	}

	packet := make([]byte, 1+1+2+2+4+len(h264Data))
	packet[0] = 0x01 // video type
	packet[1] = isKeyFrame
	binary.BigEndian.PutUint16(packet[2:4], cursorX)
	binary.BigEndian.PutUint16(packet[4:6], cursorY)
	binary.BigEndian.PutUint32(packet[6:10], dataLen)
	copy(packet[10:], h264Data)

	if err := viewer.SendBinary(packet); err != nil {
		// Viewer send failed - viewer probably disconnected
		sess.ClearViewer()
	}

	return nil
}
