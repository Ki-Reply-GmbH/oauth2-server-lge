# Stage 1: Build
FROM golang:1.24.0-alpine3.21 AS build

WORKDIR /app
COPY src src
COPY go.mod .
COPY go.sum .
RUN mkdir keys
COPY keys keys

# Build the server
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./src

# Stage 2: Run
FROM alpine:edge

WORKDIR /app

COPY --from=build /app/server .
RUN mkdir keys
COPY --from=build /app/keys keys

EXPOSE 8080
ENTRYPOINT ["/app/server"]