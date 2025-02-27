// Package token provides functionality for creating, validating, and introspecting OAuth2 tokens.
// It uses JSON Web Tokens (JWTs) with RSA signatures for secure token creation and validation.
package token

import (
	"cmp"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"kireply.de/simple-oauth2-server/internal/keys"
)

// Service manages token operations including creation, verification, and introspection.
// It works with the KeyManager to handle cryptographic operations and maintains
// configuration for token issuance.
type Service struct {
	keyManager *keys.KeyManager
	issuer     string
	ttl        time.Duration
}

// TokenClaims extends the standard JWT claims with OAuth2-specific fields.
// It contains both the registered JWT claims (like issuer, expiration time) and
// additional claims specific to OAuth2 (like client_id and scope).
type TokenClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

// NewService creates and initializes a new token service with the provided key manager.
//
// The service is configured using environment variables:
// - TOKEN_ISSUER: The issuer claim to include in tokens (default: "https://cariad-oauth2-server.example.com")
// - TOKEN_TTL_SECONDS: The lifetime of tokens in seconds (default: 3600 seconds/1 hour)
//
// The service uses the key manager to:
// - Access the private key for signing tokens
// - Access the key ID for including in token headers
//
// Returns a properly configured token service ready for use in OAuth2 operations.
func NewService(keyManager *keys.KeyManager) *Service {
	issuer := cmp.Or(os.Getenv("TOKEN_ISSUER"), "https://cariad-oauth2-server.example.com")

	ttlStr := os.Getenv("TOKEN_TTL_SECONDS")
	ttl := 3600 * time.Second
	if ttlStr != "" {
		if ttlSeconds, err := strconv.Atoi(ttlStr); err == nil && ttlSeconds > 0 {
			ttl = time.Duration(ttlSeconds) * time.Second
		}
	}

	return &Service{
		keyManager: keyManager,
		issuer:     issuer,
		ttl:        ttl,
	}
}

// TokenTTL returns the configured time-to-live duration for tokens.
//
// This duration determines how long generated tokens will be valid before they expire.
// The value is initially set during service creation based on the TOKEN_TTL_SECONDS
// environment variable.
//
// Returns the token lifetime as a time.Duration.
func (s *Service) TokenTTL() time.Duration {
	return s.ttl
}

// CreateToken generates a new signed JWT for the given client ID and scope.
//
// This method creates a token with the following properties:
// - Signed using RS256 algorithm with the private key from the key manager
// - Contains registered JWT claims (issuer, subject, issuance time, expiration time, etc.)
// - Contains OAuth2-specific claims (client_id, scope)
// - Includes a "kid" (key ID) header to identify which key was used for signing
//
// Parameters:
// - clientID: The identifier of the client the token is being issued to (used for both subject and client_id claims)
// - scope: Space-separated list of OAuth2 scopes granted to the token (can be empty)
//
// Returns:
// - The signed token string if successful
// - An error if token creation or signing fails
func (s *Service) CreateToken(clientID, scope string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(s.ttl)

	claims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   clientID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			ID:        fmt.Sprintf("%d-%s", now.Unix(), clientID),
		},
		ClientID: clientID,
		Scope:    scope,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyManager.GetKeyID()

	signedToken, err := token.SignedString(s.keyManager.GetPrivateKey())
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// VerifyToken validates a token string and returns its claims if valid.
//
// This method performs several security checks:
// - Verifies the token signature using the public key
// - Ensures the signing algorithm is RS256
// - Validates the token hasn't expired
// - Extracts and returns the token claims
//
// Parameters:
// - tokenString: The JWT token string to verify
//
// Returns:
// - A pointer to TokenClaims containing the validated claims if successful
// - An error if validation fails for any reason (invalid signature, expired token, etc.)
func (s *Service) VerifyToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify that the signing method is RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// For RS256, we use the public key
		return &s.keyManager.GetPrivateKey().PublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// GetIntrospectionResponse creates a token introspection response according to RFC 7662.
//
// This method:
// - Verifies the provided token
// - If valid, returns an "active" response with token metadata
// - If invalid, returns an "active: false" response
//
// The response follows the standard OAuth 2.0 Token Introspection format, which includes:
// - active: A boolean indicating if the token is active and valid
// - scope: Space-separated list of scopes associated with the token
// - client_id: The client identifier for which the token was issued
// - exp: Expiration timestamp
// - iat: Issuance timestamp
// - sub: Subject of the token
// - iss: Issuer of the token
// - jti: Unique identifier for the token
//
// Parameters:
// - tokenString: The token to introspect
//
// Returns a map containing the introspection response fields.
func (s *Service) GetIntrospectionResponse(tokenString string) map[string]interface{} {
	claims, err := s.VerifyToken(tokenString)
	if err != nil {
		return map[string]interface{}{
			"active": false,
		}
	}

	expiry, _ := claims.GetExpirationTime()
	issuedAt, _ := claims.GetIssuedAt()

	return map[string]interface{}{
		"active":    true,
		"scope":     claims.Scope,
		"client_id": claims.ClientID,
		"exp":       expiry.Unix(),
		"iat":       issuedAt.Unix(),
		"sub":       claims.Subject,
		"iss":       claims.Issuer,
		"jti":       claims.ID,
	}
}
