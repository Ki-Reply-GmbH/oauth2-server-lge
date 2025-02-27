package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewKeyManager verifies that creating a new KeyManager works with valid keys
// and fails appropriately with invalid keys
func TestNewKeyManager(t *testing.T) {
	// Setup test environment
	tempDir := t.TempDir() // Go 1.15+ built-in temp directory that's auto-cleaned

	// Generate a valid RSA private key for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test key")

	// Create PEM encoded private key
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}
	privKeyData := pem.EncodeToMemory(privKeyPEM)

	// Create test files
	validKeyPath := filepath.Join(tempDir, "valid-key.pem")
	invalidKeyPath := filepath.Join(tempDir, "invalid-key.pem")
	nonExistentPath := filepath.Join(tempDir, "does-not-exist.pem")

	// Write valid key
	err = os.WriteFile(validKeyPath, privKeyData, 0600)
	require.NoError(t, err, "Failed to write test key file")

	// Write invalid key data
	err = os.WriteFile(invalidKeyPath, []byte("not a valid PEM key"), 0600)
	require.NoError(t, err, "Failed to write invalid key file")

	// Test cases
	testCases := []struct {
		name      string
		keyPath   string
		expectErr bool
	}{
		{name: "Valid key file", keyPath: validKeyPath, expectErr: false},
		{name: "Non-existent key file", keyPath: nonExistentPath, expectErr: true},
		{name: "Invalid key format", keyPath: invalidKeyPath, expectErr: true},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variable for this test case
			originalEnv := os.Getenv("PRIVATE_KEY_PATH")
			t.Cleanup(func() { os.Setenv("PRIVATE_KEY_PATH", originalEnv) })
			os.Setenv("PRIVATE_KEY_PATH", tc.keyPath)

			// Attempt to create KeyManager
			km, err := NewKeyManager()

			// Check results
			if tc.expectErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, km, "Expected nil KeyManager when error occurs")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.NotNil(t, km, "Expected non-nil KeyManager")

				// Verify key properties
				assert.NotNil(t, km.privateKey, "privateKey should not be nil")
				assert.NotEmpty(t, km.keyID, "keyID should not be empty")
				assert.True(t, strings.HasPrefix(km.keyID, "key-"), "keyID should have 'key-' prefix")
				assert.NotNil(t, km.keySet, "keySet should not be nil")
			}
		})
	}
}

// TestGetKeySet verifies that the KeyManager properly exposes the JWK key set
func TestGetKeySet(t *testing.T) {
	// Create a test KeyManager
	km, cleanup := createTestKeyManager(t)
	defer cleanup()

	// Get the key set
	keySet := km.GetKeySet()
	assert.NotNil(t, keySet, "GetKeySet should not return nil")
	assert.Equal(t, 1, keySet.Len(), "Key set should contain exactly one key")

	// Verify key properties
	iter := keySet.Keys(context.Background())
	assert.True(t, iter.Next(context.Background()), "Key set iterator should have at least one key")

	key := iter.Pair().Value.(jwk.Key)

	// Check key ID
	kid, ok := key.Get(jwk.KeyIDKey)
	assert.True(t, ok, "Key should have a kid property")
	assert.Equal(t, km.GetKeyID(), kid.(string), "Key ID should match")

	// Check algorithm - THIS IS THE FIX: Use jwa.SignatureAlgorithm type instead of string
	alg, ok := key.Get(jwk.AlgorithmKey)
	assert.True(t, ok, "Key should have an alg property")
	assert.Equal(t, jwa.RS256.String(), alg.(jwa.SignatureAlgorithm).String(), "Algorithm should be RS256")

	// Check usage
	use, ok := key.Get(jwk.KeyUsageKey)
	assert.True(t, ok, "Key should have a use property")
	assert.Equal(t, "sig", use.(string), "Key usage should be 'sig'")
}

// TestGetPrivateKey verifies that the private key is correctly returned and usable
func TestGetPrivateKey(t *testing.T) {
	// Create a test KeyManager
	km, cleanup := createTestKeyManager(t)
	defer cleanup()

	// Get the private key
	privateKey := km.GetPrivateKey()
	assert.NotNil(t, privateKey, "Private key should not be nil")

	// Verify the key is usable by signing and verifying data
	testData := []byte("test data for signing")
	hash := sha256.Sum256(testData)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hash[:])
	assert.NoError(t, err, "Should be able to sign data with the private key")

	// Verify signature with the public key
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, hash[:], signature)
	assert.NoError(t, err, "Should be able to verify signature with public key")
}

// TestKeyManager_ConcurrentAccess verifies thread safety of the KeyManager
func TestKeyManager_ConcurrentAccess(t *testing.T) {
	// Create a test KeyManager
	km, cleanup := createTestKeyManager(t)
	defer cleanup()

	// Number of concurrent goroutines
	const concurrentAccess = 10
	done := make(chan bool, concurrentAccess*3) // 3 methods to test

	// Test concurrent access to all getter methods
	for i := 0; i < concurrentAccess; i++ {
		// Test GetKeySet
		go func() {
			keySet := km.GetKeySet()
			assert.NotNil(t, keySet)
			done <- true
		}()

		// Test GetKeyID
		go func() {
			keyID := km.GetKeyID()
			assert.NotEmpty(t, keyID)
			done <- true
		}()

		// Test GetPrivateKey
		go func() {
			privateKey := km.GetPrivateKey()
			assert.NotNil(t, privateKey)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrentAccess*3; i++ {
		<-done
	}
}

// Helper function to create a test KeyManager with temporary files
// Returns the KeyManager and a cleanup function
func createTestKeyManager(t *testing.T) (*KeyManager, func()) {
	// Create temporary directory
	tempDir := t.TempDir()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test key")

	// Encode the key
	privKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privKeyData := pem.EncodeToMemory(privKeyPEM)

	// Write to file
	keyPath := filepath.Join(tempDir, "test-key.pem")
	err = os.WriteFile(keyPath, privKeyData, 0600)
	require.NoError(t, err, "Failed to write test key file")

	// Save original environment and set new one
	originalEnv := os.Getenv("PRIVATE_KEY_PATH")
	os.Setenv("PRIVATE_KEY_PATH", keyPath)

	// Create KeyManager
	km, err := NewKeyManager()
	require.NoError(t, err, "Failed to create test KeyManager")

	// Return manager and cleanup function
	cleanup := func() {
		os.Setenv("PRIVATE_KEY_PATH", originalEnv)
	}

	return km, cleanup
}
