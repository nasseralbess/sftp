package sftp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// ecdsa implements the Elliptic Curve Digital Signature Algorithm

// KeyPair represents a public-private key pair
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// KeyExchange handles the key exchange process
type KeyExchange struct {
	OurKeyPair     *KeyPair
	TheirPublicKey *ecdsa.PublicKey
	SharedSecret   []byte
	IsInitialized  bool
}

// GenerateKeyPair creates a new ECDSA key pair
func GenerateKeyPair() (*KeyPair, error) {
	// We're using P-384 curve for better security
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// NewKeyExchange creates a new key exchange instance
func NewKeyExchange() (*KeyExchange, error) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return &KeyExchange{
		OurKeyPair:    keyPair,
		IsInitialized: true,
	}, nil
}

// GetPublicKeyBytes returns the encoded public key
func (kx *KeyExchange) GetPublicKeyBytes() ([]byte, error) {
	/*
	  takes the public key from a key pair and converts it into a
	  format that can be easily transmitted over a network or stored
	  in a file. This format is called PEM (Privacy-Enhanced Mail),
	  which is a widely used encoding for cryptographic keys and
	  certificates.

	  PEM is a standard format that many systems understand, making
	  it easier to work with keys across different platforms
	*/
	if !kx.IsInitialized {
		return nil, errors.New("key exchange not initialized")
	}

	// Encode public key to PKIX, ASN.1 DER form
	/*
	  PKIX: Public Key Infrastructure (X.509).
	  ASN.1 DER: Abstract Syntax Notation One
	  (ASN.1) Distinguished Encoding Rules (DER).
	  This is a binary format used to encode
	  data structures.
	*/
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(kx.OurKeyPair.PublicKey)
	if err != nil {
		return nil, err
	}

	// PEM encode for transmission
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// SetRemotePublicKey sets the remote party's public key
func (kx *KeyExchange) SetRemotePublicKey(publicKeyPEM []byte) error {
	if !kx.IsInitialized {
		return errors.New("key exchange not initialized")
	}

	// Decode PEM block
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("failed to decode PEM block containing public key")
	}

	// Parse public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	// Ensure we got an ECDSA public key
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("not an ECDSA public key")
	}

	// Verify that key uses the expected curve
	if ecdsaPub.Curve != elliptic.P384() {
		return errors.New("remote key uses unexpected curve")
	}

	kx.TheirPublicKey = ecdsaPub
	return nil
}

// ComputeSharedSecret derives the shared secret using ECDH (Elliptic Curve Diffie-Hellman)
func (kx *KeyExchange) ComputeSharedSecret() error {
	if !kx.IsInitialized || kx.TheirPublicKey == nil {
		return errors.New("key exchange incomplete")
	}

	// Compute shared point
	x, _ := kx.TheirPublicKey.Curve.ScalarMult(
		kx.TheirPublicKey.X,
		kx.TheirPublicKey.Y,
		kx.OurKeyPair.PrivateKey.D.Bytes(),
	)

	if x == nil {
		return errors.New("key exchange failed")
	}

	// Convert shared point to bytes and hash it
	sharedPoint := x.Bytes()
	hash := sha256.Sum256(sharedPoint)

	// Store the hash as our shared secret
	kx.SharedSecret = hash[:]

	return nil
}

// GetSharedSecret returns the computed shared secret
func (kx *KeyExchange) GetSharedSecret() ([]byte, error) {
	if !kx.IsInitialized || kx.SharedSecret == nil {
		return nil, errors.New("shared secret not computed")
	}

	return kx.SharedSecret, nil
}

// EncodePublicKey encodes a public key to PEM format
func EncodePublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// DecodePublicKey decodes a public key from PEM format
func DecodePublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return ecdsaPub, nil
}

// EncodePrivateKey encodes a private key to PEM format
func EncodePrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Marshal the private key to PKCS8 format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	// Create a PEM block
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// Encode to PEM format
	return pem.EncodeToMemory(pemBlock), nil
}

// DecodePrivateKey decodes a private key from PEM format
func DecodePrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	// Decode PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	// Parse the private key
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Ensure we got an ECDSA private key
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}

	return ecdsaKey, nil
}
