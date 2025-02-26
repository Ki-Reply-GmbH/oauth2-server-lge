package token

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"kireply.de/simple-oauth2-server/src/internal/keys"
)

type Service struct {
	keyManager *keys.KeyManager
	issuer     string
	ttl        time.Duration
}

type TokenClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

func NewService(keyManager *keys.KeyManager) *Service {
	issuer := os.Getenv("TOKEN_ISSUER")
	if issuer == "" {
		issuer = "https://cariad-oauth2-server.example.com"
	}

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

func (s *Service) TokenTTL() time.Duration {
	return s.ttl
}

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
