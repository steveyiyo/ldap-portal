package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/steveyiyo/ldap-portal/internal/webserver"
)

// Gin Engine
func main() {

	// Load .env
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}
	webServerListen := os.Getenv("WEBSERVER_LISTEN")

	if webServerListen == "" {
		log.Println("Error to loading environment. Use Port 8972 as Web Server Port.")
		webServerListen = "0.0.0.0:8972"
	}

	webserver.Init(webServerListen)
}
