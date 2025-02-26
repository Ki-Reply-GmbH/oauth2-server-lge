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

type KeyManager struct {
	privateKey *rsa.PrivateKey
	keyID      string
	keySet     jwk.Set
	mu         sync.RWMutex
}

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

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// If that fails, try PKCS#8 format
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		// Check if it's an RSA key
		rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}

		key = rsaKey
	}

	km.privateKey = key

	err = km.updateKeySet()
	if err != nil {
		return nil, fmt.Errorf("failed to create key set: %w", err)
	}

	return km, nil
}

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

func (km *KeyManager) GetKeySet() jwk.Set {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keySet
}

func (km *KeyManager) GetKeyID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keyID
}

func (km *KeyManager) GetPrivateKey() *rsa.PrivateKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.privateKey
}
