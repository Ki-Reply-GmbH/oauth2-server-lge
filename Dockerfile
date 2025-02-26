FROM golang:latest

WORKDIR /app
COPY src src
COPY go.mod .

# Build the server
RUN go build -o server ./src

EXPOSE 8080
CMD ["./server"]