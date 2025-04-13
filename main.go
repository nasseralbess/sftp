/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package main

import "sftp-protocol/cmd"

func main() {
	cmd.Execute()
}

// package main

// import (
// 	"bytes"
// 	"crypto/ecdsa"
// 	"crypto/rand"
// 	"crypto/sha256"
// 	"encoding/hex"
// 	"fmt"
// 	"io/ioutil"
// 	"log"
// 	"os"
// 	"path/filepath"
// 	"sftp-protocol/network"
// 	"sftp-protocol/sftp"
// 	"sync"
// 	"time"
// )

// func main() {
// 	fmt.Println("Testing SFTP Protocol Components")
// 	log.SetFlags(log.LstdFlags | log.Lshortfile)
// 	// Test 1: Message encoding and decoding
// 	//testMessageEncodingDecoding()

// 	// Test 2: Encryption and decryption
// 	testEncryptionDecryption()

// 	// Test 3: Key exchange
// 	testKeyExchange()

// 	// Test 4: Authentication
// 	testAuthentication()

// 	// Test 5: File transfer
// 	testFileTransfer()

// 	// Test 6: Session management
// 	testSessionManagement()

// 	// Test 7: Client and server
// 	testNetworkLayer()
// }

// func testEncryptionDecryption() {
// 	fmt.Println("\n=== Encryption/Decryption Test ===")

// 	// Create a shared secret (in a real application, this would come from key exchange)
// 	sharedSecret := make([]byte, 32)
// 	for i := range sharedSecret {
// 		sharedSecret[i] = byte(i)
// 	}

// 	// Create a secure channel
// 	// Create a dummy salt for this isolated test
// 	testSalt := sha256.Sum256([]byte("test-salt-for-encryption-test"))

// 	// Create a secure channel, providing the salt
// 	channel, err := sftp.NewSecureChannel(sharedSecret, testSalt[:])
// 	if err != nil {
// 		log.Fatalf("Failed to create secure channel: %v", err)
// 	}

// 	// Original plaintext message
// 	plaintext := []byte("This is a secret message for testing encryption and decryption")
// 	fmt.Printf("Original plaintext: %s\n", plaintext)

// 	// Encrypt the message
// 	ciphertext, err := channel.Encrypt(plaintext)
// 	if err != nil {
// 		log.Fatalf("Encryption failed: %v", err)
// 	}
// 	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

// 	// Decrypt the message
// 	decrypted, err := channel.Decrypt(ciphertext)
// 	if err != nil {
// 		log.Fatalf("Decryption failed: %v", err)
// 	}
// 	fmt.Printf("Decrypted plaintext: %s\n", string(decrypted))

// 	// Verify the decrypted message matches the original
// 	if bytes.Equal(plaintext, decrypted) {
// 		fmt.Println("Encryption/decryption test PASSED")
// 	} else {
// 		fmt.Println("Encryption/decryption test FAILED")
// 	}
// }

// // Add this function to your main.go file
// func testKeyExchange() {
// 	fmt.Println("\n=== Key Exchange Test ===")

// 	// Create client-side key exchange
// 	clientKX, err := sftp.NewKeyExchange()
// 	if err != nil {
// 		log.Fatalf("Failed to create client key exchange: %v", err)
// 	}

// 	// Create server-side key exchange
// 	serverKX, err := sftp.NewKeyExchange()
// 	if err != nil {
// 		log.Fatalf("Failed to create server key exchange: %v", err)
// 	}

// 	// Get client's public key
// 	clientPubKey, err := clientKX.GetPublicKeyBytes()
// 	if err != nil {
// 		log.Fatalf("Failed to get client public key: %v", err)
// 	}
// 	fmt.Println("Client public key obtained")

// 	// Get server's public key
// 	serverPubKey, err := serverKX.GetPublicKeyBytes()
// 	if err != nil {
// 		log.Fatalf("Failed to get server public key: %v", err)
// 	}
// 	fmt.Println("Server public key obtained")

// 	// Client sets server's public key
// 	err = clientKX.SetRemotePublicKey(serverPubKey)
// 	if err != nil {
// 		log.Fatalf("Client failed to set server public key: %v", err)
// 	}
// 	fmt.Println("Client successfully set server's public key")

// 	// Server sets client's public key
// 	err = serverKX.SetRemotePublicKey(clientPubKey)
// 	if err != nil {
// 		log.Fatalf("Server failed to set client public key: %v", err)
// 	}
// 	fmt.Println("Server successfully set client's public key")

// 	// Client computes shared secret
// 	err = clientKX.ComputeSharedSecret()
// 	if err != nil {
// 		log.Fatalf("Client failed to compute shared secret: %v", err)
// 	}

// 	// Server computes shared secret
// 	err = serverKX.ComputeSharedSecret()
// 	if err != nil {
// 		log.Fatalf("Server failed to compute shared secret: %v", err)
// 	}

// 	// Get client's shared secret
// 	clientSecret, err := clientKX.GetSharedSecret()
// 	if err != nil {
// 		log.Fatalf("Failed to get client shared secret: %v", err)
// 	}
// 	fmt.Printf("Client shared secret: %s\n", hex.EncodeToString(clientSecret))

// 	// Get server's shared secret
// 	serverSecret, err := serverKX.GetSharedSecret()
// 	if err != nil {
// 		log.Fatalf("Failed to get server shared secret: %v", err)
// 	}
// 	fmt.Printf("Server shared secret: %s\n", hex.EncodeToString(serverSecret))

// 	// Verify that both parties computed the same shared secret
// 	if bytes.Equal(clientSecret, serverSecret) {
// 		fmt.Println("Key exchange test PASSED - Both parties derived the same shared secret")
// 	} else {
// 		fmt.Println("Key exchange test FAILED - Shared secrets don't match")
// 	}

// 	// Test creating a secure channel using the shared secret
// 	// Generate the salt based on exchanged keys (client perspective)
// 	// Order: Remote (server) key first, then Local (client) key
// 	clientSaltInput := append([]byte{}, serverPubKey...)
// 	clientSaltInput = append(clientSaltInput, clientPubKey...)
// 	clientSessionSalt := sha256.Sum256(clientSaltInput)

// 	// Test creating a secure channel using the shared secret and salt
// 	secureChannel, err := sftp.NewSecureChannel(clientSecret, clientSessionSalt[:])
// 	if err != nil {
// 		log.Fatalf("Failed to create secure channel: %v", err)
// 	}

// 	// Test encryption and decryption with the new secure channel
// 	testMessage := []byte("Secret message encrypted with key exchange derived secret")
// 	encrypted, err := secureChannel.Encrypt(testMessage)
// 	if err != nil {
// 		log.Fatalf("Encryption with derived key failed: %v", err)
// 	}

// 	decrypted, err := secureChannel.Decrypt(encrypted)
// 	if err != nil {
// 		log.Fatalf("Decryption with derived key failed: %v", err)
// 	}

// 	if bytes.Equal(testMessage, decrypted) {
// 		fmt.Println("Encryption/decryption with derived key test PASSED")
// 	} else {
// 		fmt.Println("Encryption/decryption with derived key test FAILED")
// 	}
// }

// func testAuthentication() {
// 	fmt.Println("\n=== Authentication Test ===")

// 	// Create user store and authenticator
// 	userStore := sftp.NewMemoryUserStore()
// 	auth := sftp.NewAuthenticator(userStore)

// 	// 1. Test user registration with password
// 	fmt.Println("1. Testing user registration with password...")
// 	username := "testuser"
// 	password := "secureP@ssw0rd"
// 	err := auth.RegisterUser(username, password, nil)
// 	if err != nil {
// 		log.Fatalf("Failed to register user: %v", err)
// 	}
// 	fmt.Println("ظ£ô User registered successfully")

// 	// 2. Test password authentication
// 	fmt.Println("2. Testing password authentication...")
// 	authReq := &sftp.UserAuthRequest{
// 		Username: username,
// 		Method:   sftp.AuthMethodPassword,
// 		Password: password,
// 	}

// 	authResp, err := auth.Authenticate(authReq)
// 	if err != nil {
// 		log.Fatalf("Authentication error: %v", err)
// 	}

// 	if authResp.Success {
// 		fmt.Printf("ظ£ô Password authentication successful. Session ID: %s\n", authResp.SessionID)
// 	} else {
// 		fmt.Printf("ظ£ù Password authentication failed: %s\n", authResp.Message)
// 		return
// 	}

// 	// 3. Test failed password authentication
// 	fmt.Println("3. Testing incorrect password...")
// 	authReq.Password = "wrongpassword"
// 	authResp, err = auth.Authenticate(authReq)
// 	if err != nil {
// 		log.Fatalf("Authentication error: %v", err)
// 	}

// 	if !authResp.Success {
// 		fmt.Println("ظ£ô Invalid password correctly rejected")
// 	} else {
// 		fmt.Println("ظ£ù Authentication succeeded with incorrect password!")
// 		return
// 	}

// 	// 4. Test public key registration and authentication
// 	fmt.Println("4. Testing public key registration and authentication...")

// 	// Generate a key pair
// 	keyPair, err := sftp.GenerateKeyPair()
// 	if err != nil {
// 		log.Fatalf("Failed to generate key pair: %v", err)
// 	}

// 	// Convert public key to PEM
// 	publicKeyPEM, err := sftp.EncodePublicKey(keyPair.PublicKey)
// 	if err != nil {
// 		log.Fatalf("Failed to encode public key: %v", err)
// 	}

// 	// Register a new user with the public key
// 	pkUsername := "pkuser"
// 	err = auth.RegisterUser(pkUsername, "", publicKeyPEM)
// 	if err != nil {
// 		log.Fatalf("Failed to register public key user: %v", err)
// 	}
// 	fmt.Println("ظ£ô User with public key registered successfully")

// 	// 5. Test public key authentication - First phase (challenge)
// 	fmt.Println("5. Testing public key authentication - challenge phase...")
// 	pkAuthReq := &sftp.UserAuthRequest{
// 		Username: pkUsername,
// 		Method:   sftp.AuthMethodPublicKey,
// 	}

// 	pkAuthResp, err := auth.Authenticate(pkAuthReq)
// 	if err != nil {
// 		log.Fatalf("Public key authentication error: %v", err)
// 	}

// 	if !pkAuthResp.Success && pkAuthResp.Challenge != nil {
// 		fmt.Println("ظ£ô Challenge received successfully")
// 	} else {
// 		fmt.Println("ظ£ù Failed to receive challenge")
// 		return
// 	}

// 	// 6. Test public key authentication - Second phase (response)
// 	fmt.Println("6. Testing public key authentication - signature phase...")

// 	// Create signature for the challenge
// 	challenge := pkAuthResp.Challenge
// 	hash := sha256.Sum256(challenge)

// 	r, s, err := ecdsa.Sign(rand.Reader, keyPair.PrivateKey, hash[:])
// 	if err != nil {
// 		log.Fatalf("Failed to sign challenge: %v", err)
// 	}

// 	// Concatenate r and s for the signature
// 	rBytes := make([]byte, 64)
// 	sBytes := make([]byte, 64)
// 	r.FillBytes(rBytes)
// 	s.FillBytes(sBytes)
// 	signature := append(rBytes, sBytes...)

// 	// Send the signed challenge back
// 	pkAuthReq.Challenge = challenge
// 	pkAuthReq.Signature = signature

// 	pkAuthResp, err = auth.Authenticate(pkAuthReq)
// 	if err != nil {
// 		log.Fatalf("Public key authentication error: %v", err)
// 	}

// 	if pkAuthResp.Success {
// 		fmt.Printf("ظ£ô Public key authentication successful. Session ID: %s\n", pkAuthResp.SessionID)
// 	} else {
// 		fmt.Printf("ظ£ù Public key authentication failed: %s\n", pkAuthResp.Message)
// 		return
// 	}

// 	// 7. Test account lockout after multiple failed attempts
// 	fmt.Println("7. Testing account lockout...")

// 	failUsername := "lockoutuser"
// 	failPassword := "initialpass"

// 	// Register user
// 	err = auth.RegisterUser(failUsername, failPassword, nil)
// 	if err != nil {
// 		log.Fatalf("Failed to register lockout test user: %v", err)
// 	}

// 	// Attempt authentication with wrong password multiple times
// 	failAuthReq := &sftp.UserAuthRequest{
// 		Username: failUsername,
// 		Method:   sftp.AuthMethodPassword,
// 		Password: "wrongpass",
// 	}

// 	// Attempt 5 failed logins to trigger lockout
// 	var lastResp *sftp.UserAuthResponse
// 	for i := 0; i < 5; i++ {
// 		lastResp, err = auth.Authenticate(failAuthReq)
// 		if err != nil {
// 			log.Fatalf("Authentication error: %v", err)
// 		}
// 		fmt.Printf("  Attempt %d: %s\n", i+1, lastResp.Message)
// 	}

// 	// Try one more time to verify account is locked
// 	lastResp, err = auth.Authenticate(failAuthReq)
// 	if err != nil {
// 		log.Fatalf("Authentication error: %v", err)
// 	}

// 	if lastResp.Message == "Account is locked" {
// 		fmt.Println("ظ£ô Account correctly locked after multiple failed attempts")
// 	} else {
// 		fmt.Println("ظ£ù Account lockout failed")
// 	}

// 	fmt.Println("Authentication module tests completed successfully!")
// }
// func testFileTransfer() {
// 	fmt.Println("\n=== File Transfer Test ===")

// 	// Create temporary test directory
// 	testDir, err := ioutil.TempDir("", "sftp-test-")
// 	if err != nil {
// 		log.Fatalf("Failed to create test directory: %v", err)
// 	}
// 	defer os.RemoveAll(testDir)

// 	fmt.Printf("Created temporary test directory: %s\n", testDir)

// 	// Create a FileTransferManager
// 	ftm, err := sftp.NewFileTransferManager(testDir)
// 	if err != nil {
// 		log.Fatalf("Failed to create FileTransferManager: %v", err)
// 	}

// 	// Set a smaller chunk size for testing
// 	ftm.SetChunkSize(1024) // 1KB chunks for testing

// 	// Generate a session ID for testing
// 	sessionID := "test-session-123"

// 	// 1. Test creating a directory
// 	fmt.Println("1. Testing directory creation...")
// 	mkdirReq := &sftp.FileTransferRequest{
// 		Operation: sftp.FileOperationMkdir,
// 		Path:      "test_folder",
// 	}

// 	mkdirResp, err := ftm.ProcessRequest(mkdirReq, sessionID)
// 	if err != nil {
// 		log.Fatalf("Failed to process mkdir request: %v", err)
// 	}

// 	if mkdirResp.Success {
// 		fmt.Println("ظ£ô Directory created successfully")
// 	} else {
// 		fmt.Printf("ظ£ù Failed to create directory: %s\n", mkdirResp.Message)
// 		return
// 	}

// 	// 2. Test uploading a file
// 	fmt.Println("2. Testing file upload...")

// 	// Create test data (~5KB)
// 	testData := make([]byte, 5120)
// 	_, err = rand.Read(testData)
// 	if err != nil {
// 		log.Fatalf("Failed to generate test data: %v", err)
// 	}

// 	// Split data into chunks
// 	chunkSize := 1024

// 	for i := 0; i < len(testData); i += chunkSize {
// 		end := i + chunkSize
// 		if end > len(testData) {
// 			end = len(testData)
// 		}

// 		chunk := testData[i:end]

// 		uploadReq := &sftp.FileTransferRequest{
// 			Operation: sftp.FileOperationUpload,
// 			Path:      "test_folder/test_file.dat",
// 			Offset:    int64(i),
// 			Data:      chunk,
// 		}

// 		uploadResp, err := ftm.ProcessRequest(uploadReq, sessionID)
// 		if err != nil {
// 			log.Fatalf("Failed to process upload request: %v", err)
// 		}

// 		if !uploadResp.Success {
// 			fmt.Printf("ظ£ù Chunk upload failed: %s\n", uploadResp.Message)
// 			return
// 		}

// 		fmt.Printf("  Uploaded chunk %d/%d bytes\n", i+len(chunk), len(testData))
// 	}

// 	// Send empty data to finalize AFTER all chunks are uploaded
// 	finalReq := &sftp.FileTransferRequest{
// 		Operation: sftp.FileOperationUpload,
// 		Path:      "test_folder/test_file.dat",
// 		Data:      []byte{},
// 	}

// 	finalResp, err := ftm.ProcessRequest(finalReq, sessionID)
// 	if err != nil {
// 		log.Fatalf("Failed to finalize upload: %v", err)
// 	}

// 	if finalResp.Success {
// 		fmt.Println("ظ£ô File upload completed successfully")
// 	} else {
// 		fmt.Printf("ظ£ù Failed to finalize upload: %s\n", finalResp.Message)
// 		return
// 	}

// 	// 3. Test listing directory contents
// 	fmt.Println("3. Testing directory listing...")
// 	listReq := &sftp.FileTransferRequest{
// 		Operation: sftp.FileOperationList,
// 		Path:      "test_folder",
// 	}

// 	listResp, err := ftm.ProcessRequest(listReq, sessionID)
// 	if err != nil {
// 		log.Fatalf("Failed to process list request: %v", err)
// 	}

// 	if listResp.Success {
// 		fmt.Printf("ظ£ô Directory listing successful, found %d entries:\n", len(listResp.Files))
// 		for _, file := range listResp.Files {
// 			fileType := "File"
// 			if file.IsDirectory {
// 				fileType = "Directory"
// 			}
// 			fmt.Printf("  - %s (%s, %d bytes)\n", file.Name, fileType, file.Size)
// 		}
// 	} else {
// 		fmt.Printf("ظ£ù Directory listing failed: %s\n", listResp.Message)
// 		return
// 	}

// 	// 4. Test downloading the file
// 	// Test downloading the file
// 	fmt.Println("4. Testing file download...")
// 	downloadReq := &sftp.FileTransferRequest{
// 		Operation: sftp.FileOperationDownload,
// 		Path:      "test_folder/test_file.dat",
// 	}

// 	downloadedData := make([]byte, 0, len(testData))
// 	var downloadID string

// 	for {
// 		downloadResp, err := ftm.ProcessRequest(downloadReq, sessionID)
// 		if err != nil {
// 			log.Fatalf("Failed to process download request: %v", err)
// 		}

// 		if !downloadResp.Success {
// 			fmt.Printf("ظ£ù Download failed: %s\n", downloadResp.Message)
// 			return
// 		}

// 		if downloadID == "" {
// 			downloadID = downloadResp.TransferID
// 			fmt.Printf("  Started download with ID: %s\n", downloadID)
// 		}

// 		// Append data only if there's actual data
// 		if len(downloadResp.Data) > 0 {
// 			downloadedData = append(downloadedData, downloadResp.Data...)
// 			fmt.Printf("  Downloaded %d/%d bytes\n", len(downloadedData), downloadResp.TotalSize)
// 		}

// 		// Check if download is complete
// 		if downloadResp.Message == "Download complete" {
// 			fmt.Println("ظ£ô File download completed")
// 			break
// 		}
// 	}

// 	// Verify downloaded data matches original
// 	if len(downloadedData) != len(testData) {
// 		fmt.Printf("ظ£ù Size mismatch: downloaded %d bytes, expected %d bytes\n",
// 			len(downloadedData), len(testData))
// 		return
// 	}

// 	if bytes.Equal(downloadedData, testData) {
// 		fmt.Println("ظ£ô Downloaded data matches original data")
// 	} else {
// 		fmt.Println("ظ£ù Downloaded data does not match original data")
// 		// Print the first few bytes of both to compare
// 		fmt.Printf("Original first 10 bytes: %v\n", testData[:10])
// 		fmt.Printf("Downloaded first 10 bytes: %v\n", downloadedData[:10])
// 		return
// 	}

// 	// 5. Test renaming a file
// 	fmt.Println("5. Testing file rename...")
// 	renameReq := &sftp.FileTransferRequest{
// 		Operation: sftp.FileOperationRename,
// 		Path:      "test_folder/test_file.dat",
// 		NewPath:   "test_folder/renamed_file.dat",
// 	}

// 	renameResp, err := ftm.ProcessRequest(renameReq, sessionID)
// 	if err != nil {
// 		log.Fatalf("Failed to process rename request: %v", err)
// 	}

// 	if renameResp.Success {
// 		fmt.Println("ظ£ô File renamed successfully")
// 	} else {
// 		fmt.Printf("ظ£ù Failed to rename file: %s\n", renameResp.Message)
// 		return
// 	}

// 	// Verify renamed file exists
// 	if _, err := os.Stat(filepath.Join(testDir, "test_folder/renamed_file.dat")); err == nil {
// 		fmt.Println("ظ£ô Renamed file exists")
// 	} else {
// 		fmt.Println("ظ£ù Renamed file does not exist")
// 		return
// 	}

// 	// 6. Test deleting a file
// 	fmt.Println("6. Testing file deletion...")
// 	deleteReq := &sftp.FileTransferRequest{
// 		Operation: sftp.FileOperationDelete,
// 		Path:      "test_folder/renamed_file.dat",
// 	}

// 	deleteResp, err := ftm.ProcessRequest(deleteReq, sessionID)
// 	if err != nil {
// 		log.Fatalf("Failed to process delete request: %v", err)
// 	}

// 	if deleteResp.Success {
// 		fmt.Println("ظ£ô File deleted successfully")
// 	} else {
// 		fmt.Printf("ظ£ù Failed to delete file: %s\n", deleteResp.Message)
// 		return
// 	}

// 	// 7. Test deleting a directory
// 	fmt.Println("7. Testing directory deletion...")
// 	deleteDirReq := &sftp.FileTransferRequest{
// 		Operation: sftp.FileOperationDelete,
// 		Path:      "test_folder",
// 	}

// 	deleteDirResp, err := ftm.ProcessRequest(deleteDirReq, sessionID)
// 	if err != nil {
// 		log.Fatalf("Failed to process directory delete request: %v", err)
// 	}

// 	if deleteDirResp.Success {
// 		fmt.Println("ظ£ô Directory deleted successfully")
// 	} else {
// 		fmt.Printf("ظ£ù Failed to delete directory: %s\n", deleteDirResp.Message)
// 		return
// 	}

// 	fmt.Println("File transfer module tests completed successfully!")
// }
// func testSessionManagement() {
// 	fmt.Println("\n=== Session Management Test ===")

// 	// Create temporary test directory
// 	testDir, err := ioutil.TempDir("", "sftp-session-test-")
// 	if err != nil {
// 		log.Fatalf("Failed to create test directory: %v", err)
// 	}
// 	defer os.RemoveAll(testDir)

// 	// Create a user store and authenticator
// 	userStore := sftp.NewMemoryUserStore()
// 	auth := sftp.NewAuthenticator(userStore)

// 	// Register a test user
// 	err = auth.RegisterUser("testuser", "password123", nil)
// 	if err != nil {
// 		log.Fatalf("Failed to register user: %v", err)
// 	}

// 	// Create a session manager
// 	sessionManager := sftp.NewSessionManager(auth, testDir)
// 	sessionManager.SetSessionTTL(5 * time.Minute)

// 	// 1. Test session creation
// 	fmt.Println("1. Testing session creation...")
// 	session, err := sessionManager.CreateSession("127.0.0.1:1234")
// 	if err != nil {
// 		log.Fatalf("Failed to create session: %v", err)
// 	}

// 	fmt.Printf("Session created with ID: %s\n", session.ID)

// 	// 2. Test key exchange
// 	fmt.Println("2. Testing key exchange within session...")

// 	// Create a client-side key exchange (simulating client)
// 	clientKX, err := sftp.NewKeyExchange()
// 	if err != nil {
// 		log.Fatalf("Failed to create client key exchange: %v", err)
// 	}

// 	// Get client's public key
// 	clientPubKey, err := clientKX.GetPublicKeyBytes()
// 	if err != nil {
// 		log.Fatalf("Failed to get client public key: %v", err)
// 	}

// 	// Process key exchange on server side
// 	serverPubKey, err := session.ProcessKeyExchange(clientPubKey)
// 	if err != nil {
// 		log.Fatalf("Failed to process key exchange: %v", err)
// 	}

// 	// Set server's public key in client key exchange
// 	err = clientKX.SetRemotePublicKey(serverPubKey)
// 	if err != nil {
// 		log.Fatalf("Client failed to set server public key: %v", err)
// 	}

// 	// Compute shared secret on client side
// 	err = clientKX.ComputeSharedSecret()
// 	if err != nil {
// 		log.Fatalf("Client failed to compute shared secret: %v", err)
// 	}

// 	// Get client's shared secret
// 	clientSecret, err := clientKX.GetSharedSecret()
// 	if err != nil {
// 		log.Fatalf("Failed to get client shared secret: %v", err)
// 	}
// 	// Generate the salt on the client side using the same logic as the server
// 	// Order: Remote (client) key first, then Local (server) key
// 	// Note: This matches the order used inside session.ProcessKeyExchange
// 	clientSaltInput := append([]byte{}, clientPubKey...)
// 	clientSaltInput = append(clientSaltInput, serverPubKey...)
// 	clientSessionSalt := sha256.Sum256(clientSaltInput)

// 	// Create client secure channel using the derived secret and salt
// 	clientSecureChannel, err := sftp.NewSecureChannel(clientSecret, clientSessionSalt[:])

// 	if err != nil {
// 		log.Fatalf("Failed to create client secure channel: %v", err)
// 	}

// 	fmt.Println("Key exchange completed successfully")

// 	// 3. Test encryption and decryption through session
// 	fmt.Println("3. Testing session encryption/decryption...")

// 	testMessage := []byte("This is a secure message through the session")

// 	// Encrypt with client's secure channel (simulating client-side encryption)
// 	encryptedByClient, err := clientSecureChannel.Encrypt(testMessage)
// 	if err != nil {
// 		log.Fatalf("Client encryption failed: %v", err)
// 	}

// 	// Decrypt with session's secure channel (server-side)
// 	decryptedByServer, err := session.DecryptMessage(encryptedByClient)
// 	if err != nil {
// 		log.Fatalf("Server decryption failed: %v", err)
// 	}

// 	// Compare original and decrypted message
// 	if bytes.Equal(testMessage, decryptedByServer) {
// 		fmt.Println("Client Server encryption/decryption works")
// 	} else {
// 		fmt.Println("Client Server encryption/decryption failed")
// 		return
// 	}

// 	// Now test the other direction
// 	responseMessage := []byte("This is a secure response from the server")

// 	// Encrypt with session's secure channel (server-side)
// 	encryptedByServer, err := session.EncryptMessage(responseMessage)
// 	if err != nil {
// 		log.Fatalf("Server encryption failed: %v", err)
// 	}

// 	// Decrypt with client's secure channel
// 	decryptedByClient, err := clientSecureChannel.Decrypt(encryptedByServer)
// 	if err != nil {
// 		log.Fatalf("Client decryption failed: %v", err)
// 	}

// 	// Compare original and decrypted response
// 	if bytes.Equal(responseMessage, decryptedByClient) {
// 		fmt.Println("Server client encryption/decryption works")
// 	} else {
// 		fmt.Println("Server Client encryption/decryption failed")
// 		return
// 	}

// 	// 4. Test authentication through session
// 	fmt.Println("4. Testing authentication through session...")

// 	// Create authentication request
// 	authReq := &sftp.UserAuthRequest{
// 		Username: "testuser",
// 		Method:   sftp.AuthMethodPassword,
// 		Password: "password123",
// 	}

// 	// Process authentication
// 	authResp, err := session.ProcessAuthentication(authReq, auth)
// 	if err != nil {
// 		log.Fatalf("Authentication process failed: %v", err)
// 	}

// 	if authResp.Success {
// 		fmt.Println("Authentication successful through session")
// 	} else {
// 		fmt.Printf("Authentication failed: %s\n", authResp.Message)
// 		return
// 	}

// 	// 5. Test file operations through session
// 	fmt.Println("5. Testing file operations through session...")

// 	// Create a directory
// 	mkdirReq := &sftp.FileTransferRequest{
// 		Operation: sftp.FileOperationMkdir,
// 		Path:      "test_session_dir",
// 	}

// 	mkdirResp, err := session.ProcessFileTransfer(mkdirReq)
// 	if err != nil {
// 		log.Fatalf("Directory creation failed: %v", err)
// 	}

// 	if mkdirResp.Success {
// 		fmt.Println("Directory created successfully through session")
// 	} else {
// 		fmt.Printf("Directory creation failed: %s\n", mkdirResp.Message)
// 		return
// 	}

// 	// 6. Test session retrieval and activity tracking
// 	fmt.Println("6. Testing session retrieval and activity...")

// 	// Get the session by ID
// 	retrievedSession, err := sessionManager.GetSession(session.ID)
// 	if err != nil {
// 		log.Fatalf("Failed to retrieve session: %v", err)
// 	}

// 	if retrievedSession.ID == session.ID {
// 		fmt.Println(" Session retrieved successfully")
// 		fmt.Printf("  Session state: %v\n", retrievedSession.State)
// 		fmt.Printf("  Username: %s\n", retrievedSession.Username)
// 		lastActivityAgo := time.Since(retrievedSession.LastActivityTime)
// 		fmt.Printf("  Last activity: %v ago\n", lastActivityAgo)
// 	} else {
// 		fmt.Println("Session retrieval failed")
// 		return
// 	}

// 	// 7. Test session listing
// 	fmt.Println("7. Testing active sessions listing...")

// 	// Create one more session for testing
// 	sessionManager.CreateSession("192.168.1.100:5678")

// 	// Get active sessions info
// 	activeSessions := sessionManager.GetActiveSessionsInfo()
// 	fmt.Printf("Active sessions: %d\n", len(activeSessions))
// 	for i, s := range activeSessions {
// 		fmt.Printf("  Session %d: ID=%s, Username=%s, Remote=%s\n",
// 			i+1, s["id"], s["username"], s["remoteAddr"])
// 	}

// 	// 8. Test session cleanup
// 	fmt.Println("8. Testing session expiration and cleanup...")

// 	// Create a session manager with a very short TTL for testing
// 	shortTTLManager := sftp.NewSessionManager(auth, testDir)
// 	shortTTLManager.SetSessionTTL(10 * time.Millisecond)

// 	// Create a session that will expire quickly
// 	tempSession, _ := shortTTLManager.CreateSession("temporary:9999")
// 	tempSessionID := tempSession.ID

// 	// Wait for expiration
// 	time.Sleep(20 * time.Millisecond)

// 	// Clean up expired sessions
// 	removedCount := shortTTLManager.CleanupInactiveSessions()
// 	fmt.Printf(" Cleaned up %d expired sessions\n", removedCount)

// 	// Try to retrieve the expired session
// 	_, err = shortTTLManager.GetSession(tempSessionID)
// 	if err != nil && err.Error() == "session not found" {
// 		fmt.Println(" Expired session was correctly removed")
// 	} else if err != nil {
// 		fmt.Printf(" Unexpected error: %v\n", err)
// 	} else {
// 		fmt.Println(" Expired session still exists")
// 	}

// 	// 9. Test session closing
// 	fmt.Println("9. Testing session close...")

// 	// Close the main session
// 	err = sessionManager.CloseSession(session.ID)
// 	if err != nil {
// 		log.Fatalf("Failed to close session: %v", err)
// 	}

// 	// Try to retrieve the closed session
// 	_, err = sessionManager.GetSession(session.ID)
// 	if err != nil && err.Error() == "session not found" {
// 		fmt.Println(" Session was closed successfully")
// 	} else if err != nil {
// 		fmt.Printf(" Unexpected error: %v\n", err)
// 	} else {
// 		fmt.Println(" Closed session still exists")
// 	}

// 	fmt.Println("Session management tests completed successfully!")
// }

// func testNetworkLayer() {
// 	fmt.Println("\n=== Network Layer Test ===")

// 	// --- Server Setup ---
// 	testDir, err := ioutil.TempDir("", "sftp-network-test-")
// 	if err != nil {
// 		log.Fatalf("Failed to create test directory: %v", err)
// 	}
// 	defer os.RemoveAll(testDir) // Cleanup server files

// 	// Local temp dir for client files
// 	localTestDir, err := ioutil.TempDir("", "sftp-local-test-")
// 	if err != nil {
// 		log.Fatalf("Failed to create local test directory: %v", err)
// 	}
// 	defer os.RemoveAll(localTestDir) // Cleanup local client files

// 	userStore := sftp.NewMemoryUserStore()
// 	auth := sftp.NewAuthenticator(userStore)
// 	sessionManager := sftp.NewSessionManager(auth, testDir)

// 	// Register a test user
// 	testUser := "netuser"
// 	testPass := "netPass123"
// 	err = auth.RegisterUser(testUser, testPass, nil)
// 	if err != nil {
// 		log.Fatalf("Failed to register network test user: %v", err)
// 	}

// 	// Register PK user
// 	pkUser := "pknetuser"
// 	pkKeyPair, err := sftp.GenerateKeyPair()
// 	if err != nil {
// 		log.Fatalf("Failed to generate PK for network test: %v", err)
// 	}
// 	pkPEM, err := sftp.EncodePublicKey(&pkKeyPair.PrivateKey.PublicKey)
// 	if err != nil {
// 		log.Fatalf("Failed to encode PK for network test: %v", err)
// 	}
// 	err = auth.RegisterUser(pkUser, "", pkPEM)
// 	if err != nil {
// 		log.Fatalf("Failed to register PK network test user: %v", err)
// 	}

// 	// Start server
// 	server := network.NewServer("127.0.0.1:0", sessionManager, auth)
// 	err = server.Start()
// 	var serverWg sync.WaitGroup
// 	serverWg.Add(1)
// go func() {
// 	defer serverWg.Done()
// 	err := server.Start()
// 	// Simplified error check for brevity
// 	if err != nil && !server.IsRunning() { // Ignore errors during shutdown
// 		log.Printf("Server exited with error: %v", err)
// 	}
// }()
// time.Sleep(100 * time.Millisecond)
// serverAddr := server.GetAddress()
// fmt.Printf("Test server started on %s\n", serverAddr)
// defer func() {
// 	fmt.Println("Stopping test server...")
// 	server.Stop()
// 	serverWg.Wait()
// 	fmt.Println("Test server stopped.")
// }()

// // --- Client Setup & Actions ---
// client := network.NewClient()
// err = client.Connect(serverAddr)
// if err != nil {
// 	log.Fatalf("Client failed to connect: %v", err)
// }
// defer client.Close() // Close the connection used for the main tests
// fmt.Println("Client connected successfully.")

// // 1. Test Password Authentication
// fmt.Println("1. Testing Password Authentication over network...")
// authResp, err := client.AuthenticatePassword(testUser, testPass)
// if err != nil || !authResp.Success {
// 	log.Fatalf("Password auth failed: %v (Resp: %+v)", err, authResp)
// }
// fmt.Printf("ظ£ô Password authentication successful (SessionID: %s)\n", authResp.SessionID)

// // 2. Test File Upload
// fmt.Println("2. Testing File Upload over network...")
// localUploadFilePath := filepath.Join(localTestDir, "upload_test.txt")
// remoteUploadPath := "uploaded_file.txt"
// // Create ~2.5MB test file
// uploadData := make([]byte, 2*1024*1024+512*1024) // 2.5 MB
// _, err = rand.Read(uploadData)
// if err != nil {
// 	log.Fatalf("Failed to generate upload data: %v", err)
// }
// err = ioutil.WriteFile(localUploadFilePath, uploadData, 0644)
// if err != nil {
// 	log.Fatalf("Failed to write local upload file: %v", err)
// }

// err = client.UploadFile(localUploadFilePath, remoteUploadPath)
// if err != nil {
// 	log.Fatalf("ظ£ù File upload failed: %v", err)
// }
// fmt.Println("ظ£ô File upload call successful")

// // Verify upload on server side
// serverFilePath := filepath.Join(testDir, remoteUploadPath)
// serverFileInfo, err := os.Stat(serverFilePath)
// if err != nil {
// 	log.Fatalf("ظ£ù Failed to stat uploaded file on server: %v", err)
// }
// if serverFileInfo.Size() != int64(len(uploadData)) {
// 	log.Fatalf("ظ£ù Size mismatch on server: expected %d, got %d", len(uploadData), serverFileInfo.Size())
// }
// fmt.Println("ظ£ô Uploaded file size verified on server")

// // Optional: Verify content
// serverFileData, err := ioutil.ReadFile(serverFilePath)
// if err != nil {
// 	log.Fatalf("ظ£ù Failed to read uploaded file on server: %v", err)
// }
// if !bytes.Equal(uploadData, serverFileData) {
// 	log.Fatalf("ظ£ù Content mismatch for uploaded file on server")
// }
// fmt.Println("ظ£ô Uploaded file content verified on server")

// // 3. Test File Download
// fmt.Println("3. Testing File Download over network...")
// localDownloadFilePath := filepath.Join(localTestDir, "downloaded_file.txt")
// err = client.DownloadFile(remoteUploadPath, localDownloadFilePath)
// if err != nil {
// 	log.Fatalf("ظ£ù File download failed: %v", err)
// }
// fmt.Println("ظ£ô File download call successful")

// // Verify downloaded file locally
// localDownloadInfo, err := os.Stat(localDownloadFilePath)
// if err != nil {
// 	log.Fatalf("ظ£ù Failed to stat downloaded file locally: %v", err)
// }
// if localDownloadInfo.Size() != int64(len(uploadData)) {
// 	log.Fatalf("ظ£ù Size mismatch for downloaded file: expected %d, got %d", len(uploadData), localDownloadInfo.Size())
// }
// fmt.Println("ظ£ô Downloaded file size verified locally")

// // Verify content
// localDownloadData, err := ioutil.ReadFile(localDownloadFilePath)
// if err != nil {
// 	log.Fatalf("ظ£ù Failed to read downloaded file locally: %v", err)
// }
// if !bytes.Equal(uploadData, localDownloadData) {
// 	log.Fatalf("ظ£ù Content mismatch for downloaded file")
// }
// fmt.Println("ظ£ô Downloaded file content verified locally")

// // 4. Test Mkdir (can be done after transfers)
// fmt.Println("4. Testing Mkdir over network...")
// mkdirPath := "network_test_dir_after_transfer"
// mkdirResp, err := client.Mkdir(mkdirPath)
// if err != nil || !mkdirResp.Success {
// 	log.Fatalf("Mkdir failed: %v (Resp: %+v)", err, mkdirResp)
// }
// fmt.Println("ظ£ô Mkdir successful")
// if _, err := os.Stat(filepath.Join(testDir, mkdirPath)); err != nil {
// 	log.Fatalf("ظ£ù Mkdir verification failed: %v", err)
// }
// fmt.Println("ظ£ô Mkdir verification successful")

// // 5. Test ListFiles (check for uploaded file and new dir)
// fmt.Println("5. Testing ListFiles over network...")
// listResp, err := client.ListFiles(".") // List root relative to testDir
// if err != nil || !listResp.Success {
// 	log.Fatalf("ListFiles failed: %v (Resp: %+v)", err, listResp)
// }
// foundUploadedFile := false
// foundMkdir := false
// fmt.Println("  Files found on server:")
// for _, f := range listResp.Files {
// 	fmt.Printf("  - %s (IsDir: %v, Size: %d)\n", f.Name, f.IsDirectory, f.Size)
// 	if f.Name == remoteUploadPath && !f.IsDirectory {
// 		foundUploadedFile = true
// 	}
// 	if f.Name == mkdirPath && f.IsDirectory {
// 		foundMkdir = true
// 	}
// }
// if !foundUploadedFile {
// 	log.Fatalf("ظ£ù ListFiles did not find the uploaded file '%s'", remoteUploadPath)
// }
// if !foundMkdir {
// 	log.Fatalf("ظ£ù ListFiles did not find the created directory '%s'", mkdirPath)
// }
// fmt.Println("ظ£ô ListFiles successful and found uploaded file and created directory")

// // 6. Test Public Key Authentication (requires new connection)
// fmt.Println("6. Testing Public Key Authentication over network...")
// client.Close() // Close previous connection explicitly before defer

// pkClient := network.NewClient()
// err = pkClient.Connect(serverAddr)
// if err != nil {
// 	log.Fatalf("PK Client failed to connect: %v", err)
// }
// defer pkClient.Close() // Close the PK client connection

// pkAuthResp, err := pkClient.AuthenticatePublicKey(pkUser, pkKeyPair.PrivateKey)
// if err != nil || !pkAuthResp.Success {
// 	log.Fatalf("Public key auth failed: %v (Resp: %+v)", err, pkAuthResp)
// }
// fmt.Printf("ظ£ô Public key authentication successful (SessionID: %s)\n", pkAuthResp.SessionID)

// fmt.Println("Network layer test PASSED")
// }
