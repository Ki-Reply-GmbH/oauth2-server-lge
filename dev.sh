#!/bin/bash

# Dev script for OAuth2 Server
# Usage: dev [command]

# Configuration
APP_PORT=8080
USERNAME="dev"
PASSWORD="dev"
NAME="cariard-exercise"

# Generate RSA keys for JWT signing if they don't exist
generate_keys() {
  mkdir -p keys
  if [ ! -f keys/private.pem ]; then
    echo "Generating RSA keys for JWT signing..."
    openssl genrsa -out keys/private.pem 2048
    openssl rsa -in keys/private.pem -pubout -out keys/public.pem
    echo "Keys generated successfully"
  fi
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
    echo "Starting the application in a docker container"
    docker run -d -t -i -e AUTH_USERNAME=$USERNAME -e AUTH_PASSWORD=$PASSWORD -p 8080:8080 --name $NAME "$NAME:latest"
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
    *)
        show_help
        ;;
esac