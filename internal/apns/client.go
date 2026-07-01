package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	EnvironmentProduction = "production"
	EnvironmentSandbox    = "sandbox"

	defaultProductionURL = "https://api.push.apple.com"
	defaultSandboxURL    = "https://api.sandbox.push.apple.com"
	defaultExpirationTTL = 15 * time.Minute
	jwtRefreshAge        = 50 * time.Minute
)

var terminalReasons = map[string]bool{
	"BadDeviceToken":         true,
	"DeviceTokenNotForTopic": true,
	"Unregistered":           true,
}

var providerTokenReasons = map[string]bool{
	"ExpiredProviderToken":        true,
	"InvalidProviderToken":        true,
	"MissingProviderToken":        true,
	"TooManyProviderTokenUpdates": true,
}

type Config struct {
	TeamID        string
	KeyID         string
	KeyPath       string
	ProductionURL string
	SandboxURL    string
	HTTPClient    *http.Client
	ExpirationTTL time.Duration
}

type Client struct {
	teamID        string
	keyID         string
	key           *ecdsa.PrivateKey
	productionURL string
	sandboxURL    string
	expirationTTL time.Duration
	http          *http.Client
	now           func() time.Time

	jwtMu       sync.Mutex
	jwtToken    string
	jwtIssuedAt time.Time
}

type Request struct {
	Token          string
	Environment    string
	Topic          string
	Mode           string
	ServerDeviceID string
	DeliveryID     string
	Badge          *int
	CollapseID     *string
}

type Result struct {
	APNsID     string
	StatusCode int
	Reason     string
	RetryAfter time.Duration
	Terminal   bool
}

type Error struct {
	Result Result
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Result.Reason != "" {
		return fmt.Sprintf("apns rejected notification: %s", e.Result.Reason)
	}
	return fmt.Sprintf("apns rejected notification: HTTP %d", e.Result.StatusCode)
}

func (e *Error) Retryable() bool {
	if e == nil {
		return false
	}
	status := e.Result.StatusCode
	return !e.Result.Terminal || status == http.StatusTooManyRequests || status >= 500 || status == 0
}

func New(cfg Config) (*Client, error) {
	keyPEM, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read APNs key: %w", err)
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	productionURL := strings.TrimRight(strings.TrimSpace(cfg.ProductionURL), "/")
	if productionURL == "" {
		productionURL = defaultProductionURL
	}
	sandboxURL := strings.TrimRight(strings.TrimSpace(cfg.SandboxURL), "/")
	if sandboxURL == "" {
		sandboxURL = defaultSandboxURL
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	expirationTTL := cfg.ExpirationTTL
	if expirationTTL <= 0 {
		expirationTTL = defaultExpirationTTL
	}
	return &Client{
		teamID:        strings.TrimSpace(cfg.TeamID),
		keyID:         strings.TrimSpace(cfg.KeyID),
		key:           key,
		productionURL: productionURL,
		sandboxURL:    sandboxURL,
		expirationTTL: expirationTTL,
		http:          httpClient,
		now:           time.Now,
	}, nil
}

func parsePrivateKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("APNs key is not PEM encoded")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse APNs private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("APNs private key is not an ECDSA key")
	}
	if key.Curve == nil || key.Params() == nil || key.Params().Name != "P-256" {
		return nil, errors.New("APNs private key must use the P-256 curve for ES256")
	}
	return key, nil
}

func (c *Client) Send(ctx context.Context, req Request) (Result, error) {
	if c == nil {
		return Result{}, errors.New("APNs client is not configured")
	}
	token, err := c.jwt()
	if err != nil {
		return Result{}, err
	}
	body, pushType, priority, err := buildPayload(req)
	if err != nil {
		return Result{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(req.Environment, req.Token), bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("apns-topic", req.Topic)
	httpReq.Header.Set("apns-push-type", pushType)
	httpReq.Header.Set("apns-priority", priority)
	httpReq.Header.Set("apns-expiration", strconv.FormatInt(c.now().Add(c.expirationTTL).Unix(), 10))
	if req.CollapseID != nil && strings.TrimSpace(*req.CollapseID) != "" {
		httpReq.Header.Set("apns-collapse-id", strings.TrimSpace(*req.CollapseID))
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return Result{StatusCode: 0}, &Error{Result: Result{StatusCode: 0, Reason: "network_error"}}
	}
	defer func() { _ = resp.Body.Close() }()

	result := Result{
		APNsID:     resp.Header.Get("apns-id"),
		StatusCode: resp.StatusCode,
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), c.now()),
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return result, nil
	}

	result.Reason = readReason(resp.Body)
	result.Terminal = terminalReasons[result.Reason] && !providerTokenReasons[result.Reason]
	return result, &Error{Result: result}
}

func (c *Client) endpoint(environment, token string) string {
	if environment == EnvironmentProduction {
		return c.productionURL + "/3/device/" + token
	}
	return c.sandboxURL + "/3/device/" + token
}

func buildPayload(req Request) ([]byte, string, string, error) {
	aps := map[string]any{
		"content-available": 1,
	}
	if req.Badge != nil {
		aps["badge"] = *req.Badge
	}
	payload := map[string]any{"aps": aps}
	if deliveryID := strings.TrimSpace(req.DeliveryID); deliveryID != "" {
		payload["silo_delivery_id"] = deliveryID
	}
	switch req.Mode {
	case "background_wake":
		body, err := json.Marshal(payload)
		return body, "background", "5", err
	default:
		aps["alert"] = map[string]string{
			"title": "Silo",
			"body":  "New notification available",
		}
		aps["mutable-content"] = 1
		aps["sound"] = "default"
		body, err := json.Marshal(payload)
		return body, "alert", "10", err
	}
}

func readReason(body io.Reader) string {
	var parsed struct {
		Reason string `json:"reason"`
	}
	data, _ := io.ReadAll(io.LimitReader(body, 16<<10))
	_ = json.Unmarshal(data, &parsed)
	return parsed.Reason
}

func (c *Client) jwt() (string, error) {
	now := c.now()
	c.jwtMu.Lock()
	defer c.jwtMu.Unlock()
	if c.jwtToken != "" && now.Sub(c.jwtIssuedAt) < jwtRefreshAge {
		return c.jwtToken, nil
	}
	token, err := c.signJWT(now)
	if err != nil {
		return "", err
	}
	c.jwtToken = token
	c.jwtIssuedAt = now
	return token, nil
}

func (c *Client) signJWT(now time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": c.keyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{"iss": c.teamID, "iat": now.Unix()})
	if err != nil {
		return "", err
	}
	unsigned := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(unsigned))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign APNs provider token: %w", err)
	}
	signature := fixedWidth(r, 32)
	signature = append(signature, fixedWidth(s, 32)...)
	return unsigned + "." + b64(signature), nil
}

func fixedWidth(v *big.Int, width int) []byte {
	out := make([]byte, width)
	b := v.Bytes()
	copy(out[width-len(b):], b)
	return out
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func parseRetryAfter(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	if seconds, err := time.ParseDuration(header + "s"); err == nil && seconds > 0 {
		return seconds
	}
	if at, err := http.ParseTime(header); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}
