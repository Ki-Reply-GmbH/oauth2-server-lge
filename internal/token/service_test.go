package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kireply.de/simple-oauth2-server/internal/keys"
)

// setupTestKeys creates temporary RSA key files for testing
func setupTestKeys(t *testing.T) (string, func()) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "oauth-test-keys-*")
	require.NoError(t, err)

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode private key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Write private key to file
	privateKeyPath := filepath.Join(tempDir, "private.pem")
	err = os.WriteFile(privateKeyPath, privateKeyPEM, 0600)
	require.NoError(t, err)

	// Setup cleanup function
	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return privateKeyPath, cleanup
}

// setupTestKeyManager creates a KeyManager configured for testing
func setupTestKeyManager(t *testing.T) (*keys.KeyManager, func()) {
	// Setup test keys
	privateKeyPath, cleanup := setupTestKeys(t)

	// Set environment variable for the key manager to use
	os.Setenv("PRIVATE_KEY_PATH", privateKeyPath)

	// Create the key manager
	keyManager, err := keys.NewKeyManager()
	require.NoError(t, err)

	// Return key manager and cleanup function
	return keyManager, func() {
		cleanup()
		os.Unsetenv("PRIVATE_KEY_PATH")
	}
}

func TestNewService(t *testing.T) {
	// Setup
	keyManager, cleanup := setupTestKeyManager(t)
	defer cleanup()

	// Test default values
	t.Run("DefaultValues", func(t *testing.T) {
		// Unset environment variables for this test
		os.Unsetenv("TOKEN_ISSUER")
		os.Unsetenv("TOKEN_TTL_SECONDS")

		service := NewService(keyManager)

		assert.Equal(t, "https://cariad-oauth2-server.example.com", service.issuer)
		assert.Equal(t, 3600*time.Second, service.ttl)
	})

	// Test with custom environment values
	t.Run("CustomValues", func(t *testing.T) {
		os.Setenv("TOKEN_ISSUER", "https://custom-issuer.example.com")
		os.Setenv("TOKEN_TTL_SECONDS", "1800")
		defer os.Unsetenv("TOKEN_ISSUER")
		defer os.Unsetenv("TOKEN_TTL_SECONDS")

		service := NewService(keyManager)

		assert.Equal(t, "https://custom-issuer.example.com", service.issuer)
		assert.Equal(t, 1800*time.Second, service.ttl)
	})

	// Test with invalid TTL
	t.Run("InvalidTTL", func(t *testing.T) {
		os.Setenv("TOKEN_TTL_SECONDS", "invalid")
		defer os.Unsetenv("TOKEN_TTL_SECONDS")

		service := NewService(keyManager)

		// Should fall back to default
		assert.Equal(t, 3600*time.Second, service.ttl)
	})
}

func TestTokenTTL(t *testing.T) {
	keyManager, cleanup := setupTestKeyManager(t)
	defer cleanup()

	service := NewService(keyManager)

	assert.Equal(t, 3600*time.Second, service.TokenTTL())
}

func TestCreateToken(t *testing.T) {
	keyManager, cleanup := setupTestKeyManager(t)
	defer cleanup()

	service := NewService(keyManager)
	service.issuer = "https://test-issuer.example.com"
	service.ttl = 3600 * time.Second

	// Test token creation
	clientID := "test-client"
	scope := "read write"

	tokenString, err := service.CreateToken(clientID, scope)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Parse and verify the token
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return &keyManager.GetPrivateKey().PublicKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	// Verify claims
	claims, ok := token.Claims.(*TokenClaims)
	assert.True(t, ok)
	assert.Equal(t, clientID, claims.ClientID)
	assert.Equal(t, scope, claims.Scope)
	assert.Equal(t, "https://test-issuer.example.com", claims.Issuer)
	assert.Equal(t, clientID, claims.Subject)

	// Verify expiration is in the future
	expTime, err := claims.GetExpirationTime()
	assert.NoError(t, err)
	assert.True(t, expTime.After(time.Now()))

	// Verify token header contains key ID
	assert.Equal(t, keyManager.GetKeyID(), token.Header["kid"])

	// Verify token algorithm
	assert.Equal(t, "RS256", token.Header["alg"])
}

func TestVerifyToken(t *testing.T) {
	keyManager, cleanup := setupTestKeyManager(t)
	defer cleanup()

	service := NewService(keyManager)
	service.issuer = "https://test-issuer.example.com"
	service.ttl = 3600 * time.Second

	clientID := "test-client"
	scope := "read write"

	// Create a valid token
	t.Run("ValidToken", func(t *testing.T) {
		tokenString, err := service.CreateToken(clientID, scope)
		assert.NoError(t, err)

		claims, err := service.VerifyToken(tokenString)
		assert.NoError(t, err)
		assert.Equal(t, clientID, claims.ClientID)
		assert.Equal(t, scope, claims.Scope)
	})

	// Test expired token
	t.Run("ExpiredToken", func(t *testing.T) {
		// Create a token that's already expired
		service.ttl = -1 * time.Hour // Set negative TTL to create expired token
		tokenString, err := service.CreateToken(clientID, scope)
		assert.NoError(t, err)

		claims, err := service.VerifyToken(tokenString)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "token is expired")
	})

	// Test tampered token
	t.Run("TamperedToken", func(t *testing.T) {
		service.ttl = 3600 * time.Second // Reset TTL
		tokenString, err := service.CreateToken(clientID, scope)
		assert.NoError(t, err)

		// Tamper with the token by changing a character
		tokenParts := []byte(tokenString)
		tokenParts[len(tokenParts)/2]++ // Change a character in the middle
		tamperedToken := string(tokenParts)

		claims, err := service.VerifyToken(tamperedToken)
		assert.Error(t, err)
		assert.Nil(t, claims)
	})
}

func TestGetIntrospectionResponse(t *testing.T) {
	keyManager, cleanup := setupTestKeyManager(t)
	defer cleanup()

	service := NewService(keyManager)
	service.issuer = "https://test-issuer.example.com"

	clientID := "test-client"
	scope := "read write"

	// Test valid token introspection
	t.Run("ValidToken", func(t *testing.T) {
		tokenString, err := service.CreateToken(clientID, scope)
		assert.NoError(t, err)

		response := service.GetIntrospectionResponse(tokenString)
		assert.True(t, response["active"].(bool))
		assert.Equal(t, clientID, response["client_id"])
		assert.Equal(t, scope, response["scope"])
		assert.Equal(t, "https://test-issuer.example.com", response["iss"])
		assert.Equal(t, clientID, response["sub"])

		// Verify timestamps
		assert.NotNil(t, response["exp"])
		assert.NotNil(t, response["iat"])
		assert.Greater(t, response["exp"].(int64), time.Now().Unix())
	})

	// Test invalid token introspection
	t.Run("InvalidToken", func(t *testing.T) {
		response := service.GetIntrospectionResponse("invalid.token.string")
		assert.False(t, response["active"].(bool))
		assert.Len(t, response, 1) // Only contains "active" field
	})

	// Test expired token introspection
	t.Run("ExpiredToken", func(t *testing.T) {
		service.ttl = -1 * time.Hour // Set negative TTL to create expired token
		tokenString, err := service.CreateToken(clientID, scope)
		assert.NoError(t, err)

		response := service.GetIntrospectionResponse(tokenString)
		assert.False(t, response["active"].(bool))
	})
}
