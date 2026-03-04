package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

type AuthResponse struct {
	Allowed   bool   `json:"allowed"`
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}

type EventPayload struct {
	UUID      string `json:"uuid"`
	Type      string `json:"type"`
	Event     string `json:"event"`
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"`
}

func NewClient(baseURL, apiKey string, timeout time.Duration) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Authenticate checks with the panel if the UUID+Key combo is valid
// connType is "host" or "viewer"
func (c *Client) Authenticate(ctx context.Context, uuid, key, connType string) (*AuthResponse, error) {
	params := fmt.Sprintf("uuid=%s&key=%s&type=%s",
		url.QueryEscape(uuid),
		url.QueryEscape(key),
		url.QueryEscape(connType),
	)
	fullURL := fmt.Sprintf("%s/api/relay/auth?%s", c.baseURL, params)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[Panel] Auth request failed UUID=%s: %v", uuid, err)
		return nil, err
	}
	defer resp.Body.Close()

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		log.Printf("[Panel] Auth response decode failed UUID=%s status=%d: %v", uuid, resp.StatusCode, err)
		return nil, err
	}

	log.Printf("[Panel] Auth UUID=%s type=%s allowed=%v reason=%s", uuid, connType, authResp.Allowed, authResp.Reason)
	return &authResp, nil
}

// SendEvent notifies the panel about connection events
func (c *Client) SendEvent(uuid, connType, event, ip string) {
	payload := EventPayload{
		UUID:      uuid,
		Type:      connType,
		Event:     event,
		IP:        ip,
		Timestamp: time.Now().Unix(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/relay/event", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	// Fire and forget - we don't block on events
	go func() {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
	}()
}