package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"relay-server/config"
	"relay-server/internal/panel"
	"relay-server/internal/session"
	"relay-server/internal/tcp"
	"relay-server/internal/ws"
	"syscall"
)

func main() {
	cfg := config.Load()

	log.Printf("Starting Relay Server")
	log.Printf("  TCP (Host)    : :%d", cfg.Relay.TCPPort)
	log.Printf("  WS  (Viewer)  : :%d", cfg.Relay.WSPort)
	log.Printf("  Panel API     : %s", cfg.Panel.APIURL)

	// Core components
	panelClient := panel.NewClient(cfg.Panel.APIURL, cfg.Panel.APIKey, cfg.Panel.AuthTimeout)
	sessionManager := session.NewManager()

	// Servers
	tcpServer := tcp.NewServer(cfg, sessionManager, panelClient)
	wsServer := ws.NewServer(cfg, sessionManager, panelClient)

	// Graceful shutdown context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start TCP server
	go func() {
		if err := tcpServer.Listen(ctx); err != nil {
			log.Printf("[TCP] Server error: %v", err)
			cancel()
		}
	}()

	// Start WebSocket server
	go func() {
		if err := wsServer.Listen(ctx); err != nil {
			log.Printf("[WS] Server error: %v", err)
			cancel()
		}
	}()

	// Wait for signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Printf("Received signal: %v, shutting down...", sig)
		cancel()
	case <-ctx.Done():
	}

	log.Println("Relay Server stopped.")
}
