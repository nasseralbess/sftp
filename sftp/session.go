package sftp

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SessionState represents the current state of a client session
type SessionState int

const (
	// SessionStateNew represents a newly created session
	SessionStateNew SessionState = iota
	// SessionStateKeyExchange represents a session in key exchange phase
	SessionStateKeyExchange
	// SessionStateAuthenticating represents a session in authentication phase
	SessionStateAuthenticating
	// SessionStateAuthenticated represents a successfully authenticated session
	SessionStateAuthenticated
	// SessionStateTransferring represents a session actively transferring files
	SessionStateTransferring
	// SessionStateClosed represents a closed/terminated session
	SessionStateClosed
)

// Session represents a client connection and its associated state
type Session struct {
	ID               string
	Username         string
	State            SessionState
	KeyExchange      *KeyExchange
	SecureChannel    *SecureChannel
	CreatedAt        time.Time
	LastActivityTime time.Time
	RemoteAddr       string
	UserPermissions  []string
	TransferManager  *FileTransferManager
	mutex            sync.Mutex
}

// SessionManager manages all active sessions
type SessionManager struct {
	sessions      map[string]*Session
	authenticator *Authenticator
	rootPath      string
	mutex         sync.RWMutex
	sessionTTL    time.Duration // Time-to-live for inactive sessions
}

// NewSessionManager creates a new session manager
func NewSessionManager(auth *Authenticator, rootPath string) *SessionManager {
	return &SessionManager{
		sessions:      make(map[string]*Session),
		authenticator: auth,
		rootPath:      rootPath,
		sessionTTL:    30 * time.Minute, // Default 30 minutes TTL
	}
}

// SetSessionTTL sets the time-to-live for inactive sessions
func (sm *SessionManager) SetSessionTTL(ttl time.Duration) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.sessionTTL = ttl
}

// CreateSession creates a new session and registers it with the session manager
func (sm *SessionManager) CreateSession(remoteAddr string) (*Session, error) {
	// Generate a new session ID
	sessionID := GenerateUUID()

	// Create transfer manager for this session
	transferManager, err := NewFileTransferManager(sm.rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create transfer manager: %v", err)
	}

	// Create a new key exchange for this session
	keyExchange, err := NewKeyExchange()
	if err != nil {
		return nil, fmt.Errorf("failed to create key exchange: %v", err)
	}

	// Create and register the session
	session := &Session{
		ID:               sessionID,
		State:            SessionStateNew,
		KeyExchange:      keyExchange,
		CreatedAt:        time.Now(),
		LastActivityTime: time.Now(),
		RemoteAddr:       remoteAddr,
		TransferManager:  transferManager,
	}

	sm.mutex.Lock()
	sm.sessions[sessionID] = session
	sm.mutex.Unlock()

	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, error) {
	sm.mutex.RLock()
	session, exists := sm.sessions[sessionID]
	sm.mutex.RUnlock()

	if !exists {
		return nil, errors.New("session not found")
	}

	// Update last activity time
	session.UpdateActivity()
	return session, nil
}

// CloseSession closes and removes a session
func (sm *SessionManager) CloseSession(sessionID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	// Update session state to closed
	session.mutex.Lock()
	session.State = SessionStateClosed
	session.mutex.Unlock()

	// Remove from sessions map
	delete(sm.sessions, sessionID)
	return nil
}

// CleanupInactiveSessions removes sessions that have been inactive longer than the TTL
func (sm *SessionManager) CleanupInactiveSessions() int {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now()
	count := 0

	// Find and remove expired sessions
	for id, session := range sm.sessions {
		session.mutex.Lock()
		inactive := now.Sub(session.LastActivityTime) > sm.sessionTTL
		session.mutex.Unlock()

		if inactive {
			delete(sm.sessions, id)
			count++
		}
	}

	return count
}

// StartCleanupRoutine starts a background routine to periodically clean up inactive sessions
func (sm *SessionManager) StartCleanupRoutine(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			count := sm.CleanupInactiveSessions()
			if count > 0 {
				fmt.Printf("Cleaned up %d inactive sessions\n", count)
			}
		}
	}()
}

// ActiveSessionCount returns the number of active sessions
func (sm *SessionManager) ActiveSessionCount() int {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return len(sm.sessions)
}

// GetActiveSessionsInfo returns basic information about all active sessions
func (sm *SessionManager) GetActiveSessionsInfo() []map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	result := make([]map[string]interface{}, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		session.mutex.Lock()
		info := map[string]interface{}{
			"id":            session.ID,
			"username":      session.Username,
			"state":         session.State,
			"remoteAddr":    session.RemoteAddr,
			"createdAt":     session.CreatedAt,
			"lastActivity":  session.LastActivityTime,
			"authenticated": session.State == SessionStateAuthenticated || session.State == SessionStateTransferring,
		}
		session.mutex.Unlock()
		result = append(result, info)
	}

	return result
}

// UpdateActivity updates the last activity time for a session
func (s *Session) UpdateActivity() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.LastActivityTime = time.Now()
}

// SetState updates the session state
func (s *Session) SetState(state SessionState) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.State = state
	s.LastActivityTime = time.Now()
}

// ProcessKeyExchange handles the key exchange phase for this session
func (s *Session) ProcessKeyExchange(remotePubKey []byte) ([]byte, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Set remote public key
	if err := s.KeyExchange.SetRemotePublicKey(remotePubKey); err != nil {
		return nil, fmt.Errorf("failed to set remote public key: %v", err)
	}

	// Compute the shared secret
	if err := s.KeyExchange.ComputeSharedSecret(); err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %v", err)
	}

	// Get our public key to send back
	localPubKey, err := s.KeyExchange.GetPublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get local public key: %v", err)
	}

	// Create the secure channel using the shared secret
	sharedSecret, err := s.KeyExchange.GetSharedSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to get shared secret: %v", err)
	}

	saltInput := append([]byte{}, remotePubKey...)
	saltInput = append(saltInput, localPubKey...)
	sessionSalt := sha256.Sum256(saltInput)

	// Initialize secure channel with the shared secret and the generated salt
	// Pass the generated salt here VVVVVVVVVVVVVVV
	s.SecureChannel, err = NewSecureChannel(sharedSecret, sessionSalt[:])
	if err != nil {
		s.State = SessionStateClosed // Mark session as failed/closed
		return nil, fmt.Errorf("failed to create secure channel: %v", err)
	}

	// Update session state
	s.State = SessionStateAuthenticating
	s.LastActivityTime = time.Now()

	return localPubKey, nil
}

// ProcessAuthentication handles authentication requests for this session
func (s *Session) ProcessAuthentication(authReq *UserAuthRequest, authenticator *Authenticator) (*UserAuthResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check session state
	if s.State != SessionStateAuthenticating && s.State != SessionStateKeyExchange {
		return nil, errors.New("session not in authentication state")
	}

	// Process authentication
	authResp, err := authenticator.Authenticate(authReq)
	if err != nil {
		return nil, err
	}

	// If authentication was successful, update session
	if authResp.Success {
		s.Username = authReq.Username
		s.State = SessionStateAuthenticated
		// Set user permissions based on role (could be expanded)
		s.UserPermissions = []string{"read", "write", "delete"}
	}

	s.LastActivityTime = time.Now()
	return authResp, nil
}

// ProcessFileTransfer handles file transfer operations for this session
func (s *Session) ProcessFileTransfer(req *FileTransferRequest) (*FileTransferResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check session state
	if s.State != SessionStateAuthenticated && s.State != SessionStateTransferring {
		return nil, errors.New("session not authenticated")
	}

	// Update session state if needed
	if s.State == SessionStateAuthenticated {
		s.State = SessionStateTransferring
	}

	// Process the file transfer request
	resp, err := s.TransferManager.ProcessRequest(req, s.ID)
	if err != nil {
		return nil, err
	}

	s.LastActivityTime = time.Now()
	return resp, nil
}

// EncryptMessage encrypts a message using the session's secure channel
func (s *Session) EncryptMessage(plaintext []byte) ([]byte, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.SecureChannel == nil {
		return nil, errors.New("secure channel not established")
	}

	return s.SecureChannel.Encrypt(plaintext)
}

// DecryptMessage decrypts a message using the session's secure channel
func (s *Session) DecryptMessage(ciphertext []byte) ([]byte, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.SecureChannel == nil {
		return nil, errors.New("secure channel not established")
	}

	return s.SecureChannel.Decrypt(ciphertext)
}

// CheckPermission checks if the user has the specified permission
func (s *Session) CheckPermission(permission string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, p := range s.UserPermissions {
		if p == permission {
			return true
		}
	}
	return false
}

// GenerateUUID generates a unique identifier for sessions
// In a production environment, consider using a proper UUID library
func GenerateUUID() string {
	// Simple implementation for demo purposes
	return fmt.Sprintf("session-%d", time.Now().UnixNano())
}
