// client.go
package network // Or a suitable package like 'cmd/client'

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sftp-protocol/sftp"
)

// Client handles connecting to the server and sending/receiving messages.
type Client struct {
	conn          net.Conn
	keyExchange   *sftp.KeyExchange
	secureChannel *sftp.SecureChannel
	isConnected   bool
}

// NewClient creates a new SFTP client instance.
func NewClient() *Client {
	return &Client{}
}

// Connect establishes a connection and performs key exchange.
func (c *Client) Connect(address string) error {
	if c.isConnected {
		return fmt.Errorf("client already connected")
	}

	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	c.conn = conn
	log.Printf("Connected to server %s", address)

	// Initialize Key Exchange
	c.keyExchange, err = sftp.NewKeyExchange()
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to initialize key exchange: %w", err)
	}

	// Perform Key Exchange
	err = c.performKeyExchange()
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("key exchange failed: %w", err)
	}

	c.isConnected = true
	log.Println("Key exchange successful, secure channel established.")
	return nil
}

func (c *Client) performKeyExchange() error {
	// 1. Send Client Public Key
	clientPubKey, err := c.keyExchange.GetPublicKeyBytes()
	if err != nil {
		return fmt.Errorf("failed to get client public key: %w", err)
	}
	err = WriteMsg(c.conn, clientPubKey)
	if err != nil {
		return fmt.Errorf("failed to send client public key: %w", err)
	}

	// 2. Receive Server Public Key
	serverPubKey, err := ReadMsg(c.conn)
	if err != nil {
		return fmt.Errorf("failed to read server public key: %w", err)
	}

	// 3. Process keys, compute secret, create SecureChannel
	err = c.keyExchange.SetRemotePublicKey(serverPubKey)
	if err != nil {
		return fmt.Errorf("failed to set server public key: %w", err)
	}
	err = c.keyExchange.ComputeSharedSecret()
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}
	sharedSecret, err := c.keyExchange.GetSharedSecret()
	if err != nil {
		return fmt.Errorf("failed to get shared secret: %w", err)
	}

	// Derive salt (must match server's logic: remote(client) then local(server))
	saltInput := append([]byte{}, clientPubKey...)
	saltInput = append(saltInput, serverPubKey...)
	sessionSalt := sha256.Sum256(saltInput)

	c.secureChannel, err = sftp.NewSecureChannel(sharedSecret, sessionSalt[:])
	if err != nil {
		return fmt.Errorf("failed to create secure channel: %w", err)
	}

	return nil
}

// sendAndReceive handles the common pattern: marshal, encrypt, send, read, decrypt, unmarshal.
func (c *Client) sendAndReceive(request interface{}, response interface{}) error {
	if !c.isConnected || c.secureChannel == nil {
		return fmt.Errorf("client not connected or secure channel not established")
	}

	// Marshal request to JSON
	jsonReq, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Encrypt request
	encryptedReq, err := c.secureChannel.Encrypt(jsonReq)
	if err != nil {
		return fmt.Errorf("failed to encrypt request: %w", err)
	}

	// Send encrypted request
	err = WriteMsg(c.conn, encryptedReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Read encrypted response
	encryptedResp, err := ReadMsg(c.conn)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Decrypt response
	jsonResp, err := c.secureChannel.Decrypt(encryptedResp)
	if err != nil {
		return fmt.Errorf("failed to decrypt response: %w", err)
	}

	// Unmarshal JSON response into the provided response struct pointer
	err = json.Unmarshal(jsonResp, response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check for protocol-level errors if response struct supports it
	// (e.g., if response has a 'Success bool' and 'Message string' field)
	// This part depends on the specific response struct passed in.
	// Example for FileTransferResponse:
	if ftResp, ok := response.(*sftp.FileTransferResponse); ok {
		if !ftResp.Success {
			return fmt.Errorf("server error: %s", ftResp.Message)
		}
	}
	// Example for UserAuthResponse:
	if authResp, ok := response.(*sftp.UserAuthResponse); ok {
		if !authResp.Success && authResp.Challenge == nil { // Ignore challenge responses here
			return fmt.Errorf("server authentication error: %s", authResp.Message)
		}
	}

	return nil
}

// AuthenticatePassword performs password authentication.
func (c *Client) AuthenticatePassword(username, password string) (*sftp.UserAuthResponse, error) {
	req := &sftp.UserAuthRequest{
		Username: username,
		Method:   sftp.AuthMethodPassword,
		Password: password,
	}
	var resp sftp.UserAuthResponse

	err := c.sendAndReceive(req, &resp)
	if err != nil {
		// Check if the error is specifically an auth failure from sendAndReceive
		if _, ok := err.(*json.UnmarshalTypeError); !ok && err.Error() != "server authentication error: Authentication failed" {
			// Don't wrap auth failures again
			return nil, fmt.Errorf("AuthenticatePassword failed: %w", err)
		}
		// Return the response even on auth failure, as it contains the message
		return &resp, nil
	}

	return &resp, nil
}

// AuthenticatePublicKey performs public key authentication (challenge-response).
func (c *Client) AuthenticatePublicKey(username string, privateKey *ecdsa.PrivateKey) (*sftp.UserAuthResponse, error) {
	if !c.isConnected || c.secureChannel == nil {
		return nil, fmt.Errorf("client not connected or secure channel not established")
	}

	// --- Phase 1: Request Challenge ---
	initialReq := &sftp.UserAuthRequest{
		Username: username,
		Method:   sftp.AuthMethodPublicKey,
	}
	var challengeResp sftp.UserAuthResponse
	err := c.sendAndReceive(initialReq, &challengeResp)
	// We expect an "error" here because Success will be false, but Challenge should be present
	if err != nil && challengeResp.Challenge == nil {
		return nil, fmt.Errorf("failed to get challenge: %w (response: %+v)", err, challengeResp)
	}
	if challengeResp.Challenge == nil {
		return nil, fmt.Errorf("server did not provide a challenge (response: %+v)", challengeResp)
	}

	// --- Phase 2: Sign Challenge and Send Response ---
	challenge := challengeResp.Challenge
	hash := sha256.Sum256(challenge)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %w", err)
	}
	// Ensure signature components are fixed size (e.g., 64 bytes for P-384 curve keys)
	// Adjust size based on the curve used in key_exchange.go (P-384 -> 48 bytes)
	curveByteSize := privateKey.Curve.Params().BitSize / 8
	rBytes := make([]byte, curveByteSize)
	sBytes := make([]byte, curveByteSize)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)
	signature := append(rBytes, sBytes...)

	signedReq := &sftp.UserAuthRequest{
		Username:  username,
		Method:    sftp.AuthMethodPublicKey,
		Challenge: challenge,
		Signature: signature,
	}
	var finalResp sftp.UserAuthResponse
	err = c.sendAndReceive(signedReq, &finalResp)
	if err != nil {
		// Don't wrap auth failures again
		if _, ok := err.(*json.UnmarshalTypeError); !ok && err.Error() != "server authentication error: Authentication failed" {
			return nil, fmt.Errorf("AuthenticatePublicKey response phase failed: %w", err)
		}
		// Return the response even on auth failure
		return &finalResp, nil
	}

	return &finalResp, nil
}

// ListFiles requests a directory listing.
func (c *Client) ListFiles(path string) (*sftp.FileTransferResponse, error) {
	req := &sftp.FileTransferRequest{
		Operation: sftp.FileOperationList,
		Path:      path,
	}
	var resp sftp.FileTransferResponse
	err := c.sendAndReceive(req, &resp)
	if err != nil {
		return nil, fmt.Errorf("ListFiles failed for path '%s': %w", path, err)
	}
	return &resp, nil
}

// Mkdir creates a directory on the server.
func (c *Client) Mkdir(path string) (*sftp.FileTransferResponse, error) {
	req := &sftp.FileTransferRequest{
		Operation: sftp.FileOperationMkdir,
		Path:      path,
	}
	var resp sftp.FileTransferResponse
	err := c.sendAndReceive(req, &resp)
	if err != nil {
		return nil, fmt.Errorf("Mkdir failed for path '%s': %w", path, err)
	}
	return &resp, nil
}

const (
	// Default chunk size for transfers (adjust as needed)
	defaultChunkSize = 1 * 1024 * 1024 // 1MB
)

// UploadFile uploads a local file to the remote server.
func (c *Client) UploadFile(localPath, remotePath string) error {
	if !c.isConnected || c.secureChannel == nil {
		return fmt.Errorf("client not connected or secure channel not established")
	}

	// 1. Open local file
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file %s: %w", localPath, err)
	}
	defer localFile.Close()

	// 2. Get file info (for size, optional progress)
	fileInfo, err := localFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get local file info %s: %w", localPath, err)
	}
	totalSize := fileInfo.Size()
	log.Printf("Starting upload for %s (%d bytes) to %s", localPath, totalSize, remotePath)

	// 3. Read and send chunks
	buffer := make([]byte, defaultChunkSize)
	var offset int64 = 0

	for {
		bytesRead, err := localFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading local file %s: %w", localPath, err)
		}

		if bytesRead == 0 {
			break // End of file
		}

		// Prepare request for this chunk
		chunkData := buffer[:bytesRead]
		req := &sftp.FileTransferRequest{
			Operation: sftp.FileOperationUpload,
			Path:      remotePath,
			Offset:    offset,
			Data:      chunkData,
		}

		// --- Send Request ---
		jsonReq, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("upload: failed to marshal request chunk: %w", err)
		}
		encryptedReq, err := c.secureChannel.Encrypt(jsonReq)
		if err != nil {
			return fmt.Errorf("upload: failed to encrypt request chunk: %w", err)
		}
		err = WriteMsg(c.conn, encryptedReq)
		if err != nil {
			return fmt.Errorf("upload: failed to send request chunk: %w", err)
		}

		// --- Receive Response ---
		encryptedResp, err := ReadMsg(c.conn)
		if err != nil {
			return fmt.Errorf("upload: failed to read response for chunk: %w", err)
		}
		jsonResp, err := c.secureChannel.Decrypt(encryptedResp)
		if err != nil {
			return fmt.Errorf("upload: failed to decrypt response for chunk: %w", err)
		}
		var resp sftp.FileTransferResponse
		err = json.Unmarshal(jsonResp, &resp)
		if err != nil {
			return fmt.Errorf("upload: failed to unmarshal response for chunk: %w", err)
		}

		// --- Check Response ---
		if !resp.Success {
			return fmt.Errorf("server error during upload chunk (offset %d): %s", offset, resp.Message)
		}
		// Optional: Verify resp.Offset matches expected offset? Server currently sends back its current offset.
		// log.Printf("  Uploaded chunk, server offset: %d", resp.Offset)

		offset += int64(bytesRead)

		// Optional: Progress reporting
		// log.Printf("  Upload progress: %d / %d bytes (%.2f%%)", offset, totalSize, float64(offset)*100.0/float64(totalSize))

		if err == io.EOF {
			break // Finished reading file
		}
	}

	// 4. Send finalization message (empty data)
	log.Printf("Sending finalization request for %s", remotePath)
	finalReq := &sftp.FileTransferRequest{
		Operation: sftp.FileOperationUpload,
		Path:      remotePath,
		Offset:    offset, // Send the final offset
		Data:      []byte{},
	}
	// --- Send Request ---
	jsonReq, err := json.Marshal(finalReq)
	if err != nil {
		return fmt.Errorf("upload: failed to marshal final request: %w", err)
	}
	encryptedReq, err := c.secureChannel.Encrypt(jsonReq)
	if err != nil {
		return fmt.Errorf("upload: failed to encrypt final request: %w", err)
	}
	err = WriteMsg(c.conn, encryptedReq)
	if err != nil {
		return fmt.Errorf("upload: failed to send final request: %w", err)
	}

	// --- Receive Final Response ---
	encryptedResp, err := ReadMsg(c.conn)
	if err != nil {
		return fmt.Errorf("upload: failed to read final response: %w", err)
	}
	jsonResp, err := c.secureChannel.Decrypt(encryptedResp)
	if err != nil {
		return fmt.Errorf("upload: failed to decrypt final response: %w", err)
	}
	var finalResp sftp.FileTransferResponse
	err = json.Unmarshal(jsonResp, &finalResp)
	if err != nil {
		return fmt.Errorf("upload: failed to unmarshal final response: %w", err)
	}

	// --- Check Final Response ---
	if !finalResp.Success {
		return fmt.Errorf("server error during upload finalization: %s", finalResp.Message)
	}
	if finalResp.TotalSize != totalSize {
		log.Printf("Warning: Final server file size (%d) reported different from original (%d)", finalResp.TotalSize, totalSize)
	}

	log.Printf("Upload completed successfully for %s", remotePath)
	return nil
}

func (c *Client) DownloadFile(remotePath, localPath string) error {
	if !c.isConnected || c.secureChannel == nil {
		return fmt.Errorf("client not connected or secure channel not established")
	}

	// 1. Create/Open local file for writing
	localFile, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open local file %s for writing: %w", localPath, err)
	}
	defer localFile.Close()

	var currentOffset int64 = 0
	var totalSize int64 = -1 // Initialize to -1 to detect first response
	var receivedBytes int64 = 0
	var transferID string // Store the transfer ID from the first response

	log.Printf("Requesting download for %s to %s", remotePath, localPath)

	for {
		// 2. Construct the request for the current chunk
		req := &sftp.FileTransferRequest{
			Operation: sftp.FileOperationDownload,
			Path:      remotePath,
			Offset:    currentOffset,    // Tell server where we want data from
			ChunkSize: defaultChunkSize, // Inform server of preferred chunk size
			// No TransferID field in request struct
		}

		// --- Send Request ---
		jsonReq, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("download: failed to marshal request (offset %d): %w", currentOffset, err)
		}
		encryptedReq, err := c.secureChannel.Encrypt(jsonReq)
		if err != nil {
			return fmt.Errorf("download: failed to encrypt request (offset %d): %w", currentOffset, err)
		}
		// log.Printf("Sending download request: Offset=%d", currentOffset) // Debug logging
		err = WriteMsg(c.conn, encryptedReq)
		if err != nil {
			return fmt.Errorf("download: failed to send request (offset %d): %w", currentOffset, err)
		}

		// 3. Receive the response for this specific request
		// log.Printf("Waiting for download response (offset %d)...", currentOffset) // Debug logging
		encryptedResp, err := ReadMsg(c.conn)
		if err != nil {
			// EOF might be acceptable ONLY if the server sent "Download complete" in the *previous* iteration.
			// If we get EOF here, it means the server closed before sending the expected chunk/completion.
			if err == io.EOF {
				return fmt.Errorf("download: connection closed unexpectedly (EOF) while waiting for chunk at offset %d: %w", currentOffset, err)
			}
			return fmt.Errorf("download: failed to read response chunk (offset %d): %w", currentOffset, err)
		}
		jsonResp, err := c.secureChannel.Decrypt(encryptedResp)
		if err != nil {
			return fmt.Errorf("download: failed to decrypt response chunk (offset %d): %w", currentOffset, err)
		}
		var resp sftp.FileTransferResponse
		err = json.Unmarshal(jsonResp, &resp)
		if err != nil {
			return fmt.Errorf("download: failed to unmarshal response chunk (offset %d): %w", currentOffset, err)
		}
		// log.Printf("Received download response: Success=%t, Msg='%s', Offset=%d, DataLen=%d, TotalSize=%d", resp.Success, resp.Message, resp.Offset, len(resp.Data), resp.TotalSize) // Debug logging

		// --- Check Response Status ---
		if !resp.Success {
			// Attempt to remove partially downloaded file
			localFile.Close()
			os.Remove(localPath)
			return fmt.Errorf("server error during download (requested offset %d, server responded for offset %d): %s", currentOffset, resp.Offset, resp.Message)
		}

		// Store total size and transfer ID from the first valid response
		if totalSize == -1 && resp.TotalSize >= 0 {
			totalSize = resp.TotalSize
		}
		if transferID == "" && resp.TransferID != "" {
			transferID = resp.TransferID
		}

		// --- Write Data ---
		if len(resp.Data) > 0 {
			// Sanity check: Does the server's reported offset match where we expected data from?
			// The server's response offset `resp.Offset` indicates the offset *after* writing the current chunk.
			// So, the start of the data should correspond to `currentOffset`.
			expectedDataStartOffset := resp.Offset - int64(len(resp.Data))
			if expectedDataStartOffset != currentOffset {
				log.Printf("Warning: Download offset mismatch. Client requested offset %d, server sent data starting at offset %d (response offset %d with %d bytes)", currentOffset, expectedDataStartOffset, resp.Offset, len(resp.Data))
				// Decide how to handle: error out, or trust the server's data and update our offset?
				// Let's trust the server for now, but this indicates a potential issue.
				// currentOffset = expectedDataStartOffset // Adjust our view of the offset? Risky.
			}

			n, err := localFile.Write(resp.Data)
			if err != nil {
				return fmt.Errorf("download: failed to write to local file %s: %w", localPath, err)
			}
			if n != len(resp.Data) {
				return fmt.Errorf("download: short write to local file %s", localPath)
			}
			receivedBytes += int64(n)
		}

		// --- Update offset for the *next* request ---
		// The server tells us the offset *after* the chunk it just sent.
		currentOffset = resp.Offset

		// Optional: Progress Reporting
		if totalSize > 0 {
			log.Printf("  Download progress: %d / %d bytes (%.2f%%)", receivedBytes, totalSize, float64(receivedBytes)*100.0/float64(totalSize))
		} else if receivedBytes > 0 {
			log.Printf("  Downloaded %d bytes (total size unknown or 0)", receivedBytes)
		}

		// --- Check for Completion ---
		// The server sends this message in the response containing the *last* chunk.
		if resp.Message == "Download complete" {
			log.Printf("Download completed successfully for %s (TransferID: %s).", remotePath, transferID)
			// Final check: did we receive the expected amount?
			if totalSize != -1 && receivedBytes != totalSize {
				log.Printf("Warning: Download complete message received, but received bytes (%d) != expected total size (%d)", receivedBytes, totalSize)
				// This might happen if the file size changed during transfer, or if there's an off-by-one error somewhere.
			} else if totalSize == 0 && receivedBytes == 0 {
				log.Printf("Downloaded empty file.")
			} else if totalSize == -1 {
				log.Printf("Warning: Download complete but total size was never reported by server.")
			}
			break // Exit loop
		}

		// Safety break: If server sends success=true, no data, and no completion message, something is wrong.
		if len(resp.Data) == 0 && resp.Message != "Download complete" {
			log.Printf("Warning: Received empty data packet without completion signal (Offset: %d). Assuming completion.", currentOffset)
			// This might happen for zero-byte files if the server logic sends completion on the *first* response.
			// Let's check if the total size was 0.
			if totalSize == 0 && receivedBytes == 0 {
				log.Printf("Assuming empty file download complete.")
				break
			}
			// Otherwise, it's likely an error state.
			return fmt.Errorf("received empty data chunk without completion signal from server at offset %d", currentOffset)

		}
	}

	return nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	if !c.isConnected {
		return nil
	}
	c.isConnected = false
	if c.conn != nil {
		err := c.conn.Close()
		log.Println("Client connection closed.")
		return err
	}
	return nil
}

// Add other methods like UploadFile, DownloadFile, Delete, Rename following the sendAndReceive pattern
// For Upload/Download, you'll need loops and potentially modified send/receive logic
// to handle chunking within the encrypted channel.
