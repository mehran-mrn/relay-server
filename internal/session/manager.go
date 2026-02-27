package session

import (
	"sync"
	"time"
)

// HostConn represents an active host TCP connection
type HostConn interface {
	// SendToHost sends raw bytes to the C# host (input packets)
	SendToHost(data []byte) error
	// SendViewerStatus notifies host whether a viewer is watching
	SendViewerStatus(connected bool) error
	// Close closes the connection
	Close()
	// RemoteAddr returns IP string
	RemoteAddr() string
}

// ViewerConn represents an active viewer WebSocket connection
type ViewerConn interface {
	// SendBinary sends binary data to browser
	SendBinary(data []byte) error
	// SendHostStatus sends host status packet [0x02][status]
	SendHostStatus(connected bool) error
	// Close closes the connection
	Close()
	// RemoteAddr returns IP string
	RemoteAddr() string
}

// Session holds one UUID session: one host + zero or one viewer
type Session struct {
	UUID      string
	Host      HostConn
	Viewer    ViewerConn
	CreatedAt time.Time
	mu        sync.RWMutex
}

func newSession(uuid string) *Session {
	return &Session{
		UUID:      uuid,
		CreatedAt: time.Now(),
	}
}

func (s *Session) SetViewer(v ViewerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Viewer = v
}

func (s *Session) GetViewer() ViewerConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Viewer
}

func (s *Session) SetHost(h HostConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Host = h
}

func (s *Session) GetHost() HostConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Host
}

func (s *Session) ClearViewer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Viewer = nil
}

func (s *Session) ClearHost() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Host = nil
}

// Manager manages all active sessions
type Manager struct {
	sessions sync.Map // map[uuid string]*Session
}

func NewManager() *Manager {
	return &Manager{}
}

// GetOrCreateForHost returns existing session or creates new one, sets Host.
// Returns false if UUID already has a host connected.
func (m *Manager) RegisterHost(uuid string, host HostConn) (*Session, bool) {
	// Try to load existing session
	if val, ok := m.sessions.Load(uuid); ok {
		sess := val.(*Session)
		sess.mu.Lock()
		if sess.Host != nil {
			sess.mu.Unlock()
			return nil, false // already has a host
		}
		sess.Host = host
		sess.mu.Unlock()
		return sess, true
	}

	// Create new session
	sess := newSession(uuid)
	sess.Host = host
	actual, loaded := m.sessions.LoadOrStore(uuid, sess)
	if loaded {
		// Someone else stored first, retry logic
		existing := actual.(*Session)
		existing.mu.Lock()
		if existing.Host != nil {
			existing.mu.Unlock()
			return nil, false
		}
		existing.Host = host
		existing.mu.Unlock()
		return existing, true
	}
	return sess, true
}

// RegisterViewer attaches a viewer to an existing session.
// Returns false if no host session exists for the UUID.
func (m *Manager) RegisterViewer(uuid string, viewer ViewerConn) (*Session, bool) {
	val, ok := m.sessions.Load(uuid)
	if !ok {
		return nil, false
	}
	sess := val.(*Session)
	// Replace existing viewer if any (kick old viewer)
	sess.mu.Lock()
	old := sess.Viewer
	sess.Viewer = viewer
	sess.mu.Unlock()

	if old != nil {
		// Kick old viewer - send disconnect then close
		_ = old.SendHostStatus(false)
		old.Close()
	}
	return sess, true
}

// UnregisterHost removes host from session and cleans up if viewer is also gone
func (m *Manager) UnregisterHost(uuid string) *Session {
	val, ok := m.sessions.Load(uuid)
	if !ok {
		return nil
	}
	sess := val.(*Session)
	sess.mu.Lock()
	sess.Host = nil
	viewer := sess.Viewer
	sess.mu.Unlock()

	// If no viewer either, remove session entirely
	if viewer == nil {
		m.sessions.Delete(uuid)
	}
	return sess
}

// UnregisterViewer removes viewer from session
func (m *Manager) UnregisterViewer(uuid string) {
	val, ok := m.sessions.Load(uuid)
	if !ok {
		return
	}
	sess := val.(*Session)
	sess.mu.Lock()
	sess.Viewer = nil
	host := sess.Host
	sess.mu.Unlock()

	// If no host either, remove session
	if host == nil {
		m.sessions.Delete(uuid)
	}
}

// Get returns session if exists
func (m *Manager) Get(uuid string) (*Session, bool) {
	val, ok := m.sessions.Load(uuid)
	if !ok {
		return nil, false
	}
	return val.(*Session), true
}

// Count returns number of active sessions
func (m *Manager) Count() int {
	count := 0
	m.sessions.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
