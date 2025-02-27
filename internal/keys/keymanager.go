// Package keys provides cryptographic key management for the OAuth2 server.
// It handles loading, storing, and exposing RSA keys for token signing.
package keys

import (
	"cmp"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// NewKeyManager creates and initializes a new KeyManager instance.
// It loads the RSA key pair and configures the JWK Set.
type KeyManager struct {
	privateKey *rsa.PrivateKey
	keyID      string
	keySet     jwk.Set
	mu         sync.RWMutex
}

// NewKeyManager creates and initializes a new KeyManager instance that handles RSA key operations.
//
// This function performs the following steps:
//  1. Creates a KeyManager with a unique key ID based on current Unix timestamp
//  2. Loads the RSA private key from a file specified by PRIVATE_KEY_PATH environment variable
//     (defaults to "keys/private.pem" if not specified)
//  3. Parses the PEM-encoded private key in PKCS#1 format
//  4. Generates a JSON Web Key (JWK) Set containing the public key information
//
// The KeyManager is used for:
// - Signing JWT tokens with the private key
// - Providing public key information via JWKS endpoint for token verification
//
// Returns:
// - A properly initialized KeyManager pointer if successful
// - An error if any step fails (file reading, key parsing, or JWK creation)
//
// Environment variables:
// - PRIVATE_KEY_PATH: Optional path to the private key file (default: "keys/private.pem")
func NewKeyManager() (*KeyManager, error) {
	km := &KeyManager{
		keyID: fmt.Sprintf("key-%d", time.Now().Unix()),
	}

	// Load private key
	privateKeyPath := cmp.Or(os.Getenv("PRIVATE_KEY_PATH"), "keys/private.pem")

	privateKeyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key")
	}

	// Type assertion for RSA private key
	var ok bool
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key")
	}

	km.privateKey = privateKey

	// Generate public key JWK Set
	err = km.updateKeySet()
	if err != nil {
		return nil, fmt.Errorf("failed to create key set: %w", err)
	}

	return km, nil
}

// updateKeySet creates a new JWK (JSON Web Key) Set from the manager's private key.
//
// This method performs the following operations:
// 1. Locks the mutex to ensure exclusive access during update
// 2. Creates a new empty JWK Set
// 3. Extracts the public key from the manager's private key
// 4. Converts the public key to JWK format
// 5. Sets essential metadata on the JWK:
//   - Key ID (kid): Unique identifier for this key
//   - Algorithm (alg): "RS256" (RSA Signature with SHA-256)
//   - Key Usage (use): "sig" (indicates the key is for signature operations)
//
// 6. Adds the configured JWK to the set
// 7. Updates the manager's key set
//
// The resulting JWK Set follows RFC 7517 specification and can be exposed
// through the server's /.well-known/jwks.json endpoint for clients to use
// when verifying token signatures.
//
// Returns an error if any step in the JWK creation or configuration fails.
func (km *KeyManager) updateKeySet() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	ks := jwk.NewSet()

	// Create a JWK from the public key
	pubKey := &km.privateKey.PublicKey
	jwkKey, err := jwk.FromRaw(pubKey)
	if err != nil {
		return fmt.Errorf("failed to create JWK from public key: %w", err)
	}

	err = jwkKey.Set(jwk.KeyIDKey, km.keyID)
	if err != nil {
		return fmt.Errorf("failed to set key ID: %w", err)
	}

	err = jwkKey.Set(jwk.AlgorithmKey, "RS256")
	if err != nil {
		return fmt.Errorf("failed to set algorithm: %w", err)
	}

	err = jwkKey.Set(jwk.KeyUsageKey, "sig")
	if err != nil {
		return fmt.Errorf("failed to set key usage: %w", err)
	}

	ks.AddKey(jwkKey)
	km.keySet = ks

	return nil
}

// GetKeySet returns the current JWK Set containing the public key information.
//
// This method acquires a read lock to ensure thread-safe access to the key set.
// The returned JWK Set contains the public key that can be used by clients to
// verify the signatures of tokens issued by this server.
//
// The JWK Set is typically exposed through the /.well-known/jwks.json endpoint.
//
// Returns the current JWK Set.
func (km *KeyManager) GetKeySet() jwk.Set {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keySet
}

// GetKeyID returns the unique identifier for the current key.
//
// This method acquires a read lock to ensure thread-safe access to the key ID.
// The key ID is used in the "kid" claim of JWT headers to indicate which key
// was used to sign the token, allowing clients to select the correct
// validation key from the JWK Set.
//
// Returns the current key ID string.
func (km *KeyManager) GetKeyID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keyID
}

// GetPrivateKey returns the RSA private key used for signing tokens.
//
// This method acquires a read lock to ensure thread-safe access to the private key.
// The private key should only be used internally by the token service for
// signing JWTs and should never be exposed externally.
//
// Returns a pointer to the RSA private key.
func (km *KeyManager) GetPrivateKey() *rsa.PrivateKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.privateKey
}
