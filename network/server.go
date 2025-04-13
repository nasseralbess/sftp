// server.go
package network // Or a suitable package like 'cmd/server'

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sftp-protocol/sftp"
	"time"
)

// Server handles listening for connections and managing sessions.
type Server struct {
	listener       net.Listener
	sessionManager *sftp.SessionManager
	authenticator  *sftp.Authenticator
	address        string
	isRunning      bool
}

// NewServer creates a new SFTP server instance.
func NewServer(address string, sm *sftp.SessionManager, auth *sftp.Authenticator) *Server {
	return &Server{
		address:        address,
		sessionManager: sm,
		authenticator:  auth,
	}
}

// Start listens for incoming connections and handles them.
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.address, err)
	}
	s.listener = listener
	s.isRunning = true
	// Update address if ":0" was used
	s.address = listener.Addr().String()
	log.Printf("Server listening on %s", s.address)

	// Start session cleanup routine
	s.sessionManager.StartCleanupRoutine(5 * time.Minute) // Adjust interval as needed

	for s.isRunning {
		conn, err := s.listener.Accept()
		if err != nil {
			if !s.isRunning {
				log.Println("Server shutting down listener.")
				return nil // Expected error on shutdown
			}
			log.Printf("Failed to accept connection: %v", err)
			continue // Continue listening
		}

		// Handle connection in a new goroutine
		go s.handleConnection(conn)
	}
	return nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() {
	if !s.isRunning {
		return
	}
	s.isRunning = false
	if s.listener != nil {
		s.listener.Close() // This will cause the Accept loop in Start() to exit
	}
	log.Println("Server stopped.")
	// Consider adding logic to wait for active connections to finish gracefully
}

// GetAddress returns the actual address the server is listening on.
func (s *Server) GetAddress() string {
	return s.address
}

func (s *Server) handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("Accepted connection from %s", remoteAddr)

	session, err := s.sessionManager.CreateSession(remoteAddr)
	if err != nil {
		log.Printf("Error creating session for %s: %v", remoteAddr, err)
		conn.Close()
		return
	}
	log.Printf("Created session %s for %s", session.ID, remoteAddr)

	// Defer closing connection and session cleanup
	defer func() {
		log.Printf("Closing connection from %s (Session: %s)", remoteAddr, session.ID)
		conn.Close()
		s.sessionManager.CloseSession(session.ID)
		log.Printf("Closed session %s", session.ID)
	}()

	// --- Key Exchange ---
	err = s.performKeyExchange(conn, session)
	if err != nil {
		log.Printf("Key exchange failed for %s (Session: %s): %v", remoteAddr, session.ID, err)
		return // Close connection via defer
	}
	log.Printf("Key exchange successful for session %s", session.ID)

	// --- Main Message Loop (Authentication & File Transfer) ---
	for {
		// Read incoming message
		encryptedMsg, err := ReadMsg(conn)
		if err != nil {
			if err == io.EOF || !s.isRunning {
				log.Printf("Connection closed by %s (Session: %s)", remoteAddr, session.ID)
			} else {
				log.Printf("Error reading message from %s (Session: %s): %v", remoteAddr, session.ID, err)
			}
			break // Exit loop on error or EOF
		}

		// Decrypt message
		decryptedMsg, err := session.DecryptMessage(encryptedMsg)
		if err != nil {
			log.Printf("Decryption failed for %s (Session: %s): %v", remoteAddr, session.ID, err)
			// Consider sending an error response back before breaking
			s.sendErrorResponse(conn, session, "Decryption failed")
			break
		}

		// Process message based on session state
		responsePayload, err := s.processDecryptedMessage(session, decryptedMsg)
		if err != nil {
			log.Printf("Error processing message for %s (Session: %s): %v", remoteAddr, session.ID, err)
			// Send specific error back to client
			s.sendErrorResponse(conn, session, fmt.Sprintf("Processing error: %v", err))
			continue // Or break depending on error severity
		}

		// If processing was successful, send the response
		if responsePayload != nil {
			err = s.sendEncryptedResponse(conn, session, responsePayload)
			if err != nil {
				log.Printf("Error sending response to %s (Session: %s): %v", remoteAddr, session.ID, err)
				break
			}
		} else {
			// Should not happen if processDecryptedMessage doesn't return error
			log.Printf("Warning: nil response payload after successful processing for session %s", session.ID)
		}

		// Update session activity implicitly by reaching here without error
		session.UpdateActivity()
	}
}

func (s *Server) performKeyExchange(conn net.Conn, session *sftp.Session) error {
	session.SetState(sftp.SessionStateKeyExchange)

	// 1. Send Server Public Key
	serverPubKey, err := session.KeyExchange.GetPublicKeyBytes()
	if err != nil {
		return fmt.Errorf("failed to get server public key: %w", err)
	}
	err = WriteMsg(conn, serverPubKey)
	if err != nil {
		return fmt.Errorf("failed to send server public key: %w", err)
	}

	// 2. Receive Client Public Key
	clientPubKey, err := ReadMsg(conn)
	if err != nil {
		return fmt.Errorf("failed to read client public key: %w", err)
	}

	// 3. Process Key Exchange (computes secret, creates SecureChannel)
	_, err = session.ProcessKeyExchange(clientPubKey) // We don't need to send server key again here
	if err != nil {
		return fmt.Errorf("session failed to process key exchange: %w", err)
	}

	// State is now SessionStateAuthenticating (set by ProcessKeyExchange)
	return nil
}

func (s *Server) processDecryptedMessage(session *sftp.Session, decryptedMsg []byte) (interface{}, error) {
	switch session.State {
	case sftp.SessionStateAuthenticating:
		var authReq sftp.UserAuthRequest
		if err := json.Unmarshal(decryptedMsg, &authReq); err != nil {
			return nil, fmt.Errorf("failed to decode UserAuthRequest: %w", err)
		}
		// Use the authenticator associated with the SessionManager
		authResp, err := session.ProcessAuthentication(&authReq, s.authenticator)
		if err != nil {
			// This is likely an internal error during auth processing
			return nil, fmt.Errorf("internal authentication error: %w", err)
		}
		// ProcessAuthentication updates session state on success
		return authResp, nil // Return the UserAuthResponse

	case sftp.SessionStateAuthenticated, sftp.SessionStateTransferring:
		var ftReq sftp.FileTransferRequest
		if err := json.Unmarshal(decryptedMsg, &ftReq); err != nil {
			return nil, fmt.Errorf("failed to decode FileTransferRequest: %w", err)
		}
		ftResp, err := session.ProcessFileTransfer(&ftReq)
		if err != nil {
			// This could be an internal error or a file system error
			return nil, fmt.Errorf("file transfer processing error: %w", err)
		}
		// ProcessFileTransfer updates session state if needed
		return ftResp, nil // Return the FileTransferResponse

	default:
		return nil, fmt.Errorf("invalid session state for receiving message: %v", session.State)
	}
}

func (s *Server) sendEncryptedResponse(conn io.Writer, session *sftp.Session, responsePayload interface{}) error {
	// Encode response to JSON
	jsonResp, err := json.Marshal(responsePayload)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	// Encrypt JSON response
	encryptedResp, err := session.EncryptMessage(jsonResp)
	if err != nil {
		return fmt.Errorf("failed to encrypt response: %w", err)
	}

	// Send length-prefixed encrypted response
	err = WriteMsg(conn, encryptedResp)
	if err != nil {
		return fmt.Errorf("failed to write encrypted response: %w", err)
	}
	return nil
}

// sendErrorResponse tries to send a structured error back to the client.
// This is best-effort as the connection or session might be broken.
func (s *Server) sendErrorResponse(conn io.Writer, session *sftp.Session, errorMsg string) {
	// We can use FileTransferResponse for generic errors, or define a dedicated ErrorResponse struct
	errResp := sftp.FileTransferResponse{
		Success:   false,
		Operation: sftp.FileOperationError, // Use a generic error operation type
		Message:   errorMsg,
	}
	// Attempt to send it encrypted
	err := s.sendEncryptedResponse(conn, session, errResp)
	if err != nil {
		log.Printf("Failed to send error response '%s' to %s (Session: %s): %v", errorMsg, conn.(net.Conn).RemoteAddr(), session.ID, err)
	}
}

// is running
func (s *Server) IsRunning() bool {
	return s.isRunning
}
