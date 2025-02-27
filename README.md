# Cariad OAuth2 Server

A simple OAuth2 server that issues JWT Access Tokens using the Client Credentials Grant with Basic Authentication. The server implements RFC6749 (OAuth 2.0), RFC7519 (JWT), and RFC7662 (Token Introspection).

## Task
- Create a Golang http server that issues JWT Access Tokens (rfc7519) using Client Credentials Grant with Basic Authentication (rfc6749) in endpoint /token
- Sign the tokens with a self-made RS256 key
- Provide an endpoint to list the signing keys (rfc7517)
- Provide deployment manifests to deploy the server in Kubernetes cluster
- Create an Introspection endpoint (rfc7662) to introspect the issued JWT Access Tokens
### Remarks
- Publish the exercise in a git server and grant us access to review it.
- Avoid a single commit with the whole solution, we want to see how the solution was developed incrementally.
- Provide instructions to execute it

## Features

- Issues JWT Access Tokens using the Client Credentials Grant
- Signs tokens with RS256
- Provides a JWKS endpoint (RFC7517) to list the signing keys
- Implements token introspection (RFC7662)
- Includes Kubernetes deployment manifests //TODO

## API Endpoints

- `/token` - OAuth2 token endpoint (POST)
- `/.well-known/jwks.json` - JSON Web Key Set endpoint (GET)
- `/introspect` - Token introspection endpoint (POST)
- `/health` - Health check endpoint (GET)

## Prerequisites

- Go 1.22+
- OpenSSL (for generating keys)
- Docker (optional, for containerization)
- Kubernetes (optional, for deployment)

## Development Setup

1. Clone the repository
   ```bash
   git clone https://github.com/yourusername/cariad-oauth2-server.git
   cd cariad-oauth2-server
   ```

2. Generate RSA keys for JWT signing
   ```bash
   mkdir -p keys
   openssl genrsa -out keys/private.pem 2048
   openssl rsa -in keys/private.pem -pubout -out keys/public.pem
   ```

3. Set up environment variables
   ```bash
   export AUTH_USERNAME=dev
   export AUTH_PASSWORD=dev
   export TOKEN_ISSUER=http://localhost:8080
   export TOKEN_TTL_SECONDS=3600
   export PRIVATE_KEY_PATH=keys/private.pem
   ```

4. Build and run the application
   ```bash
   go mod download
   go run main.go
   ```

5. Or use the development script
   ```bash
   chmod +x dev.sh
   ./dev.sh run
   ```

## Using Docker

1. Build the Docker image
   ```bash
   docker build -t oauth2-server .
   ```

2. Run the container
   ```bash
   docker run -p 8080:8080 \
     -e AUTH_USERNAME=dev \
     -e AUTH_PASSWORD=dev \
     -v $(pwd)/keys:/keys \
     oauth2-server
   ```

3. Or use the development script
   ```bash
   ./dev.sh up
   ```

## Kubernetes Deployment
   ```bash
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
   ```


2. Verify the deployment
   ```bash
kubectl get pods
kubectl get svc
kubectl get ingress
   ```

## Testing the API

### 1. Request a Token

```bash
curl -X POST https://auth.cariad.example.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n dev:dev | base64)" \
  -d "grant_type=client_credentials&scope=read write"
```

Expected response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xNjc4OTk4NDQ1In0...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

### 2. Get JWKS

```bash
curl https://auth.cariad.example.com/.well-known/jwks.json
```

Expected response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-1678998445",
      "alg": "RS256",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### 3. Introspect a Token

```bash
curl -X POST http://localhost:8080/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n dev:dev | base64)" \
  -d "token=YOUR_TOKEN_HERE"
```

Expected response for a valid token:
```json
{
  "active": true,
  "client_id": "dev",
  "exp": 1678998445,
  "iat": 1678994845,
  "iss": "http://localhost:8080",
  "jti": "1678994845-dev",
  "scope": "read write",
  "sub": "dev"
}
```

## Project Structure

```
├── cmd
│   ├── main.go       # Main application
├── docs              # Swagger Docs
├── internal
│   ├── keys          # Key management service
│   └── token         # Token service
├── k8s               # Kubernetes deployment files
├── keys              # RSA key files
├── tls               # TLS key files
├── Dockerfile
├── dev.sh            # Development script
├── go.mod
├── go.sum
└── README.md
```