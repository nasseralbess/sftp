package sftp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// AuthMethod represents different authentication methods
type AuthMethod string

const (
	// AuthMethodPassword represents password-based authentication
	AuthMethodPassword AuthMethod = "password"

	// AuthMethodPublicKey represents public key authentication
	AuthMethodPublicKey AuthMethod = "public_key"
)

// UserAuthRequest represents an authentication request from a user
type UserAuthRequest struct {
	Username  string     `json:"username"`
	Method    AuthMethod `json:"method"`
	Password  string     `json:"password,omitempty"`
	PublicKey []byte     `json:"public_key,omitempty"`
	Signature []byte     `json:"signature,omitempty"`
	// Challenge is some random value the server sends to the client,
	// the client is meant to sign it using its private key to prove
	// its identity.
	Challenge []byte `json:"challenge,omitempty"`
}

// UserAuthResponse represents an authentication response to a user
type UserAuthResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	Challenge   []byte `json:"challenge,omitempty"`
	RequiresMFA bool   `json:"requires_mfa,omitempty"`
}

// User represents a user account
type User struct {
	Username         string           `json:"username"`
	PasswordHash     []byte           `json:"password_hash,omitempty"`
	PublicKey        *ecdsa.PublicKey `json:"-"`
	PublicKeyPEM     []byte           `json:"public_key_pem,omitempty"`
	MFAEnabled       bool             `json:"mfa_enabled"`
	LastLogin        time.Time        `json:"last_login"`
	AccountLocked    bool             `json:"account_locked"`
	FailedLoginCount int              `json:"failed_login_count"`
}

// UserStore provides storage and retrieval of user accounts
type UserStore interface {
	GetUser(username string) (*User, error)
	SaveUser(user *User) error
	UserExists(username string) bool
}

// MemoryUserStore implements UserStore using in-memory storage
type MemoryUserStore struct {
	users map[string]*User
	mutex sync.RWMutex
}

// NewMemoryUserStore creates a new in-memory user store
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		users: make(map[string]*User),
	}
}

// GetUser retrieves a user by username
func (s *MemoryUserStore) GetUser(username string) (*User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	user, exists := s.users[username]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// SaveUser stores a user account
func (s *MemoryUserStore) SaveUser(user *User) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if user == nil || user.Username == "" {
		return errors.New("invalid user")
	}
	s.users[user.Username] = user
	return nil
}

// UserExists checks if a user exists
func (s *MemoryUserStore) UserExists(username string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	_, exists := s.users[username]
	return exists
}

// Authenticator handles user authentication
type Authenticator struct {
	store UserStore
}

// NewAuthenticator creates a new authenticator with the given user store
func NewAuthenticator(store UserStore) *Authenticator {
	return &Authenticator{
		store: store,
	}
}

// GenerateChallenge generates a random challenge for public key authentication
func (a *Authenticator) GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	return challenge, nil
}

// RegisterUser creates a new user account
func (a *Authenticator) RegisterUser(username, password string, publicKeyPEM []byte) error {
	if a.store.UserExists(username) {
		return errors.New("user already exists")
	}

	user := &User{
		Username:         username,
		MFAEnabled:       false,
		LastLogin:        time.Time{},
		AccountLocked:    false,
		FailedLoginCount: 0,
	}

	// Set password if provided
	if password != "" {
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		user.PasswordHash = passwordHash
	}

	// Set public key if provided
	if len(publicKeyPEM) > 0 {
		publicKey, err := DecodePublicKey(publicKeyPEM)
		if err != nil {
			return err
		}
		user.PublicKey = publicKey
		user.PublicKeyPEM = publicKeyPEM
	}

	return a.store.SaveUser(user)
}

// Authenticate handles authentication requests
func (a *Authenticator) Authenticate(authReq *UserAuthRequest) (*UserAuthResponse, error) {
	// Check if user exists
	user, err := a.store.GetUser(authReq.Username)
	if err != nil {
		return &UserAuthResponse{
			Success: false,
			Message: "Authentication failed",
		}, nil
	}

	// Check if account is locked
	if user.AccountLocked {
		return &UserAuthResponse{
			Success: false,
			Message: "Account is locked",
		}, nil
	}

	var authSuccess bool

	// Handle different authentication methods
	switch authReq.Method {
	case AuthMethodPassword:
		authSuccess = a.authenticatePassword(user, authReq.Password)

	case AuthMethodPublicKey:
		if len(authReq.Challenge) == 0 {
			// First phase: send challenge
			challenge, err := a.GenerateChallenge()
			if err != nil {
				return nil, err
			}
			return &UserAuthResponse{
				Success:   false,
				Message:   "Challenge issued",
				Challenge: challenge,
			}, nil
		}
		// Second phase: verify signature
		authSuccess = a.authenticatePublicKey(user, authReq.Challenge, authReq.Signature)

	default:
		return &UserAuthResponse{
			Success: false,
			Message: "Unsupported authentication method",
		}, nil
	}

	// Update login attempts
	if authSuccess {
		user.FailedLoginCount = 0
		user.LastLogin = time.Now()
		a.store.SaveUser(user)

		// Generate session ID
		sessionID := generateSessionID()

		return &UserAuthResponse{
			Success:     true,
			Message:     "Authentication successful",
			SessionID:   sessionID,
			RequiresMFA: user.MFAEnabled,
		}, nil
	}

	// Handle failed authentication
	user.FailedLoginCount++
	if user.FailedLoginCount >= 5 {
		user.AccountLocked = true
	}
	a.store.SaveUser(user)

	return &UserAuthResponse{
		Success: false,
		Message: "Authentication failed",
	}, nil
}

// authenticatePassword verifies a password
func (a *Authenticator) authenticatePassword(user *User, password string) bool {
	if len(user.PasswordHash) == 0 {
		return false
	}

	err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password))
	return err == nil
}

// authenticatePublicKey verifies a challenge signature
func (a *Authenticator) authenticatePublicKey(user *User, challenge, signature []byte) bool {
	if user.PublicKey == nil {
		return false
	}

	// Hash the challenge
	hash := sha256.Sum256(challenge)

	curveByteSize := user.PublicKey.Curve.Params().BitSize / 8
	expectedSigLen := 2 * curveByteSize

	if len(signature) != expectedSigLen {
		log.Printf("authenticatePublicKey: Incorrect signature length. Expected %d, got %d", expectedSigLen, len(signature))
		return false
	}

	// Parse signature (r, s) using the correct size
	r := new(big.Int).SetBytes(signature[:curveByteSize])
	s := new(big.Int).SetBytes(signature[curveByteSize:])

	// Verify signature
	return ecdsa.Verify(user.PublicKey, hash[:], r, s)
}

// EncodeUserAuthRequest encodes an authentication request to JSON
func EncodeUserAuthRequest(req *UserAuthRequest) ([]byte, error) {
	return json.Marshal(req)
}

// DecodeUserAuthRequest decodes an authentication request from JSON
func DecodeUserAuthRequest(data []byte) (*UserAuthRequest, error) {
	var req UserAuthRequest
	err := json.Unmarshal(data, &req)
	return &req, err
}

// EncodeUserAuthResponse encodes an authentication response to JSON
func EncodeUserAuthResponse(resp *UserAuthResponse) ([]byte, error) {
	return json.Marshal(resp)
}

// DecodeUserAuthResponse decodes an authentication response from JSON
func DecodeUserAuthResponse(data []byte) (*UserAuthResponse, error) {
	var resp UserAuthResponse
	err := json.Unmarshal(data, &resp)
	return &resp, err
}

// Helper functions
func generateSessionID() string {
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)

	sessionID := ""
	for _, b := range randomBytes {
		sessionID += string('a' + (b % 26))
	}

	return sessionID
}
