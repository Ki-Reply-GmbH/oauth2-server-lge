package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"kireply.de/simple-oauth2-server/internal/keys"
	"kireply.de/simple-oauth2-server/internal/token"
)

type TokenRequest struct {
	GrantType string `json:"grant_type"`
	Scope     string `json:"scope"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

type HealthResponse struct {
	Status string `json:"status"`
}

type Application struct {
	auth struct {
		username string
		password string
	}
	keyManager   *keys.KeyManager
	tokenService *token.Service
}

func main() {
	// Initialize application
	app := new(Application)

	// Get basic auth username + password from environment
	app.auth.username = os.Getenv("AUTH_USERNAME")
	app.auth.password = os.Getenv("AUTH_PASSWORD")

	// Fail if username is empty
	if app.auth.username == "" {
		log.Fatal("basic auth username must be provided")
	}
	// Fail if password is empty
	if app.auth.password == "" {
		log.Fatal("basic auth password must be provided")
	}

	// Initialize key manager
	keyManager, err := keys.NewKeyManager()
	if err != nil {
		log.Fatalf("Failed to initialize key manager: %v", err)
	}
	app.keyManager = keyManager

	// Initialize token service
	app.tokenService = token.NewService(keyManager)

	// Set up routes
	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.healthHandler)
	mux.HandleFunc("/token", app.basicAuth(app.tokenHandler))
	mux.HandleFunc("/introspect", app.basicAuth(app.introspectionHandler))

	// Initialize server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("starting OAuth2 server on %s", server.Addr)
	// TODO Look into ListenAndServeTLS to make the endpoint secure
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func (app *Application) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(app.auth.username))
			expectedPasswordHash := sha256.Sum256([]byte(app.auth.password))

			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				next.ServeHTTP(writer, request)
				return
			}
		}

		// Return unauthorized if Basic Auth fails
		writer.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
	})
}

func (app *Application) tokenHandler(writer http.ResponseWriter, request *http.Request) {
	// Only accept POST method
	if request.Method != http.MethodPost {
		sendJSONError(writer, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse content type
	contentType := request.Header.Get("Content-Type")
	var grantType, scope string

	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		// Parse form data
		err := request.ParseForm()
		if err != nil {
			sendJSONError(writer, "invalid_request", "Invalid form data", http.StatusBadRequest)
			return
		}
		grantType = request.Form.Get("grant_type")
		scope = request.Form.Get("scope")
	} else if strings.Contains(contentType, "application/json") {
		// Parse JSON data
		var tokenRequest TokenRequest
		err := json.NewDecoder(request.Body).Decode(&tokenRequest)
		if err != nil {
			sendJSONError(writer, "invalid_request", "Invalid JSON data", http.StatusBadRequest)
			return
		}
		grantType = tokenRequest.GrantType
		scope = tokenRequest.Scope
	} else {
		sendJSONError(writer, "invalid_request", "Unsupported content type", http.StatusBadRequest)
		return
	}

	// Validate grant type
	if grantType != "client_credentials" {
		sendJSONError(writer, "unsupported_grant_type", "Only client_credentials grant type is supported", http.StatusBadRequest)
		return
	}

	// Get client ID from basic auth
	clientID, _, _ := request.BasicAuth()

	// Create a token
	tokenString, err := app.tokenService.CreateToken(clientID, scope)
	if err != nil {
		sendJSONError(writer, "server_error", "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Send token response
	ttlSeconds := int(app.tokenService.TokenTTL().Seconds())
	response := TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   ttlSeconds,
		Scope:       scope,
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func (app *Application) introspectionHandler(writer http.ResponseWriter, request *http.Request) {
	// Only accept POST method
	if request.Method != http.MethodPost {
		sendJSONError(writer, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	err := request.ParseForm()
	if err != nil {
		sendJSONError(writer, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}

	// Get token from request
	tokenString := request.Form.Get("token")
	if tokenString == "" {
		sendJSONError(writer, "invalid_request", "Token parameter is required", http.StatusBadRequest)
		return
	}

	// Introspect token
	response := app.tokenService.GetIntrospectionResponse(tokenString)

	// Send introspection response
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func (app *Application) healthHandler(writer http.ResponseWriter, request *http.Request) {
	response := HealthResponse{Status: "ok"}

	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		http.Error(writer, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func sendJSONError(writer http.ResponseWriter, error string, description string, statusCode int) {
	response := ErrorResponse{
		Error:       error,
		Description: description,
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		log.Printf("Failed to encode error response: %v", err)
	}
}
