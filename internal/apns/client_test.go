package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPath := t.TempDir() + "/AuthKey_TEST.p8"
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(Config{
		TeamID:        "TEAM123456",
		KeyID:         "KEY1234567",
		KeyPath:       keyPath,
		ProductionURL: server.URL,
		SandboxURL:    server.URL,
		HTTPClient:    server.Client(),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return client
}

func TestSendBuildsAPNsRequest(t *testing.T) {
	var got struct {
		path        string
		auth        string
		topic       string
		pushType    string
		priority    string
		expiration  string
		collapseID  string
		contentType string
		payload     map[string]any
	}
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		got.auth = r.Header.Get("Authorization")
		got.topic = r.Header.Get("apns-topic")
		got.pushType = r.Header.Get("apns-push-type")
		got.priority = r.Header.Get("apns-priority")
		got.expiration = r.Header.Get("apns-expiration")
		got.collapseID = r.Header.Get("apns-collapse-id")
		got.contentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&got.payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.Header().Set("apns-id", "apns-1")
		w.WriteHeader(http.StatusOK)
	})

	collapse := "delivery-1"
	deliveryID := "01DELIVERY"
	result, err := client.Send(context.Background(), Request{
		Token:       strings.Repeat("a", 64),
		Environment: EnvironmentSandbox,
		Topic:       "org.siloserver.silo",
		Mode:        "private_alert",
		DeliveryID:  deliveryID,
		CollapseID:  &collapse,
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if result.APNsID != "apns-1" || result.StatusCode != http.StatusOK {
		t.Fatalf("result = %+v", result)
	}
	if got.path != "/3/device/"+strings.Repeat("a", 64) {
		t.Fatalf("path = %q", got.path)
	}
	if !strings.HasPrefix(got.auth, "Bearer ") || strings.Count(strings.TrimPrefix(got.auth, "Bearer "), ".") != 2 {
		t.Fatalf("authorization is not a provider token: %q", got.auth)
	}
	wantExpiration := strconv.FormatInt(time.Unix(1_800_000_000, 0).Add(defaultExpirationTTL).Unix(), 10)
	if got.topic != "org.siloserver.silo" || got.pushType != "alert" || got.priority != "10" || got.expiration != wantExpiration {
		t.Fatalf("headers not set correctly: %+v", got)
	}
	if got.collapseID != collapse {
		t.Fatalf("collapse id = %q", got.collapseID)
	}
	if got.payload["silo_delivery_id"] != deliveryID {
		t.Fatalf("silo delivery id = %#v", got.payload["silo_delivery_id"])
	}
	aps := got.payload["aps"].(map[string]any)
	if aps["sound"] != "default" || aps["content-available"].(float64) != 1 {
		t.Fatalf("payload aps = %#v", aps)
	}
	if aps["mutable-content"].(float64) != 1 {
		t.Fatalf("mutable-content = %#v", aps["mutable-content"])
	}
	alert := aps["alert"].(map[string]any)
	if alert["title"] != "Silo" || alert["body"] != "New notification available" {
		t.Fatalf("alert = %#v", alert)
	}
	if strings.Contains(string(mustJSON(t, got.payload)), "Episode Title") {
		t.Fatalf("payload leaked rendered notification metadata: %#v", got.payload)
	}
}

func TestProviderJWTIsCachedUntilRefreshAge(t *testing.T) {
	var authHeaders []string
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	})
	now := time.Unix(1_800_000_000, 0)
	client.now = func() time.Time { return now }
	req := Request{
		Token:       strings.Repeat("a", 64),
		Environment: EnvironmentSandbox,
		Topic:       "org.siloserver.silo",
		Mode:        "private_alert",
	}

	if _, err := client.Send(context.Background(), req); err != nil {
		t.Fatalf("send 1: %v", err)
	}
	now = now.Add(49 * time.Minute)
	if _, err := client.Send(context.Background(), req); err != nil {
		t.Fatalf("send 2: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := client.Send(context.Background(), req); err != nil {
		t.Fatalf("send 3: %v", err)
	}
	if len(authHeaders) != 3 {
		t.Fatalf("auth headers = %d, want 3", len(authHeaders))
	}
	if authHeaders[0] != authHeaders[1] {
		t.Fatal("provider token was not reused before refresh age")
	}
	if authHeaders[1] == authHeaders[2] {
		t.Fatal("provider token was not refreshed after refresh age")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return out
}

func TestSendMapsTerminalAPNsReason(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"reason":"BadDeviceToken"}`))
	})

	result, err := client.Send(context.Background(), Request{
		Token:       strings.Repeat("a", 64),
		Environment: EnvironmentProduction,
		Topic:       "org.siloserver.silo",
		Mode:        "private_alert",
	})
	if err == nil {
		t.Fatal("send error = nil, want APNs error")
	}
	apnsErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("error type = %T, want *Error", err)
	}
	if !result.Terminal || !apnsErr.Result.Terminal || apnsErr.Retryable() {
		t.Fatalf("terminal mapping failed: result=%+v err=%+v", result, apnsErr.Result)
	}
	if result.Reason != "BadDeviceToken" {
		t.Fatalf("reason = %q", result.Reason)
	}
}

func TestSendMapsRetryableAPNsFailure(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"reason":"TooManyRequests"}`))
	})

	result, err := client.Send(context.Background(), Request{
		Token:       strings.Repeat("a", 64),
		Environment: EnvironmentProduction,
		Topic:       "org.siloserver.silo",
		Mode:        "private_alert",
	})
	if err == nil {
		t.Fatal("send error = nil, want APNs error")
	}
	apnsErr := err.(*Error)
	if !apnsErr.Retryable() || result.Terminal || result.RetryAfter != 30*time.Second {
		t.Fatalf("retry mapping failed: result=%+v err=%+v", result, apnsErr.Result)
	}
}

func TestProviderTokenAPNsFailureIsRetryable(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason":"InvalidProviderToken"}`))
	})

	result, err := client.Send(context.Background(), Request{
		Token:       strings.Repeat("a", 64),
		Environment: EnvironmentProduction,
		Topic:       "org.siloserver.silo",
		Mode:        "private_alert",
	})
	if err == nil {
		t.Fatal("send error = nil, want APNs error")
	}
	apnsErr := err.(*Error)
	if result.Terminal || apnsErr.Result.Terminal || !apnsErr.Retryable() {
		t.Fatalf("provider-token error mapping failed: result=%+v err=%+v", result, apnsErr.Result)
	}
}

func TestNewRejectsNonP256APNsKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPath := t.TempDir() + "/AuthKey_TEST.p8"
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if _, err := New(Config{TeamID: "TEAM123456", KeyID: "KEY1234567", KeyPath: keyPath}); err == nil {
		t.Fatal("New accepted a non-P-256 APNs key")
	}
}
