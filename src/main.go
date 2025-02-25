package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type TokenResponse struct {
	Token string `json:"Token"`
}

func main() {
	http.HandleFunc("/token", getToken)

	// Start server
	fmt.Println("Starting OAuth2 server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func getToken(writer http.ResponseWriter, request *http.Request) {
	response := TokenResponse{Token: "xxx"}

	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		http.Error(writer, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
