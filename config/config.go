package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Relay  RelayConfig
	Panel  PanelConfig
	Limits LimitsConfig
}

type RelayConfig struct {
	TCPPort      int
	WSPort       int
	TrustedProxy bool
}

type PanelConfig struct {
	APIURL      string
	APIKey      string
	AuthTimeout time.Duration
}

type LimitsConfig struct {
	MaxHosts     int
	MaxViewers   int
	BufferSize   int
	PingInterval time.Duration
	PingTimeout  time.Duration
}

func Load() *Config {
	return &Config{
		Relay: RelayConfig{
			TCPPort:      getEnvInt("TCP_PORT", 9000),
			WSPort:       getEnvInt("WS_PORT", 9001),
			TrustedProxy: true,
		},
		Panel: PanelConfig{
			APIURL:      getEnv("PANEL_API_URL", "https://panel.example.com"),
			APIKey:      getEnv("PANEL_API_KEY", ""),
			AuthTimeout: 5 * time.Second,
		},
		Limits: LimitsConfig{
			MaxHosts:     10000,
			MaxViewers:   10000,
			BufferSize:   1048576,
			PingInterval: 3 * time.Second,
			PingTimeout:  5 * time.Second,
		},
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
