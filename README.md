# Relay Server

TCP/WebSocket relay for NAT traversal between C# Host and Browser Viewer.

## Architecture

```
[C# Host] ──TCP:9000──→ [Traefik TLS] ──TCP plain──→ [Go Relay :9000]
[Browser] ──WSS──→ [Traefik HTTPS] ──WS plain──→ [Go Relay :9001/view/UUID?key=...]
[Go Relay] ──HTTPS──→ [Laravel Panel API]
```

## Packet Flow

```
Host connects → Handshake [HOST][UUID][KEY] → Panel auth → OKAY/DENY
Viewer connects → ws://.../view/UUID?key=KEY → Panel auth → stream begins
Host sends H264 frame → Relay parses → forwards to Viewer as binary WS
Browser sends mouse/keyboard JSON → Relay converts → sends TCP to Host
Host disconnects → Relay sends [0x02][0x00] to Viewer → closes WS
```

## Local Development

```bash
go mod tidy
go run ./cmd/main.go
```

## Server Deployment

```bash
# First time
git clone https://github.com/mehran-mrn/relay-server.git
cd relay-server
cp .env.example .env
# Edit .env with real values
docker compose up -d --build

# Every update
git pull origin main
docker compose up -d --build
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| TCP_PORT | Port for C# Host TCP connections | 9000 |
| WS_PORT | Port for Browser WebSocket connections | 9001 |
| PANEL_API_URL | Laravel panel base URL | - |
| PANEL_API_KEY | Shared secret for panel API auth | - |
| RELAY_DOMAIN | Domain for Traefik routing | - |

## Traefik TCP Config (add to Traefik static config)

```yaml
entryPoints:
  relay-tcp:
    address: ":9000"
```

```yaml
# Dynamic config
tcp:
  routers:
    relay-host:
      entryPoints:
        - relay-tcp
      rule: "HostSNI(`relay.example.com`)"
      tls:
        passthrough: false
        certResolver: mytlschallenge
      service: relay-host-svc
  services:
    relay-host-svc:
      loadBalancer:
        servers:
          - address: "relay:9000"
```
