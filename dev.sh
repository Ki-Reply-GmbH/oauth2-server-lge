#!/bin/bash

# Dev script for OAuth2 Server
# Usage: dev [command]

# Configuration
APP_PORT=8080
USERNAME="dev"
PASSWORD="dev"
NAME="cariad-exercise"

# Generate RSA keys for JWT signing if they don't exist
generate_keys() {
  mkdir -p keys
  if [ ! -f keys/private.pem ]; then
    echo "Generating RSA keys for JWT signing..."
    openssl genrsa -out keys/private.pem 2048
    openssl rsa -in keys/private.pem -pubout -out keys/public.pem
  fi
  create_secrets
}

create_secrets() {
    echo "Creating k8s/secrets.yaml..."
    PRIVATE_KEY=$(cat keys/private.pem | base64 -w 0)
    PUBLIC_KEY=$(cat keys/public.pem | base64 -w 0)
    # Create the secrets.yaml file
    cat > k8s/secrets.yaml << EOF
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-credentials
type: Opaque
stringData:
  username: ${USERNAME}
  password: ${PASSWORD}

---
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-keys
type: Opaque
data:
  private.pem: ${PRIVATE_KEY}
  public.pem: ${PUBLIC_KEY}
EOF
  echo "Kubernetes secrets file generated at k8s/secrets.yaml"
  echo "RSA keys have been generated and encoded"
}

# Run the application locally
run() {
  generate_keys
  echo "Starting OAuth2 server on port $APP_PORT..."
  export AUTH_USERNAME=$USERNAME
  export AUTH_PASSWORD=$PASSWORD
  go run src/main.go
}

build() {
    echo "Building..."
    docker build . --tag $NAME
}

# Run the application locally in a docker container
up() {
    down
    build
    generate_keys
    echo "Starting the application in a docker container"
    docker run -d -t -i -e AUTH_USERNAME=$USERNAME -e AUTH_PASSWORD=$PASSWORD -e APP_PORT=$APP_PORT -p $APP_PORT:8080 --name $NAME "$NAME:latest"
}

# Stops the application
down() {
    CONTAINER_ID=$(docker ps -a -f "name=$name" --format "{{.ID}}")
    docker stop $CONTAINER_ID
    docker rm $CONTAINER_ID
}

# Show help
show_help() {
  echo "Usage: dev [run|up|down|build|help]"
}

# Main command dispatcher
case "$1" in
    run)
        run
        ;;
    up)
        up
        ;;
    down)
        down
        ;;
    build)
        build
        ;;
    generate_keys)
        generate_keys
        ;;
    *)
        show_help
        ;;
esac