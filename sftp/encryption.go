package sftp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// SecureChannel represents an established secure communication channel
type SecureChannel struct {
	EncryptionKey []byte
}

func NewSecureChannel(sharedSecret []byte, salt []byte) (*SecureChannel, error) { // <-- Added 'salt []byte' argument
	if len(sharedSecret) < 32 {
		return nil, errors.New("shared secret too short")
	}
	if len(salt) == 0 { // <-- Added check for empty salt
		return nil, errors.New("salt cannot be empty")
	}

	// Derive encryption and MAC keys using HKDF
	encryptionKey := make([]byte, 32) // 256 bits for AES-256

	// Salt is now provided as an argument
	// salt := []byte("Bess_Bread_Butter_Bess") // <-- REMOVE THIS LINE

	/*
	   salt is a random value that is used as an additional input to a cryptographic
	   function, such as a hash function or a key derivation function. The primary
	   purpose of a salt is to ensure that the same input (e.g., password or shared secret)
	   will produce different outputs when hashed or used to derive keys.
	   It is not secret and can be publicly known, but it should be unique for each instance.
	*/
	// Derive encryption key
	//hkdf - HMAC-based Extract-and-Expand Key Derivation Function
	// Use the provided salt argument here VVVVV
	kdfReader := hkdf.New(sha256.New, sharedSecret, salt, []byte("encryption"))
	if _, err := io.ReadFull(kdfReader, encryptionKey); err != nil {
		return nil, err
	}

	return &SecureChannel{
		EncryptionKey: encryptionKey,
	}, nil
}

// Encrypt encrypts a message using AES-GCM
func (sc *SecureChannel) Encrypt(plaintext []byte) ([]byte, error) {
	// Create the AES block cipher
	block, err := aes.NewCipher(sc.EncryptionKey)
	if err != nil {
		return nil, err
	}

	// Create a GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a nonce (IV)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and authenticate the plaintext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts a message using AES-GCM
func (sc *SecureChannel) Decrypt(ciphertext []byte) ([]byte, error) {
	// Create the AES block cipher
	block, err := aes.NewCipher(sc.EncryptionKey)
	if err != nil {
		return nil, err
	}

	// Create a GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Check if the ciphertext is valid
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and actual ciphertext
	nonce := ciphertext[:gcm.NonceSize()]
	encryptedData := ciphertext[gcm.NonceSize():]

	// Decrypt and verify the ciphertext
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
