package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"

	"github.com/Silo-Server/silo-push-relay/internal/accounts"
	"github.com/Silo-Server/silo-push-relay/internal/config"
	"github.com/Silo-Server/silo-push-relay/internal/observability"
)

type fakeDeploymentRegistrar struct {
	input  accounts.DeploymentRegistration
	called bool
	logs   []accounts.OpLogEntry
	err    error
}

func (f *fakeDeploymentRegistrar) RegisterDeployment(_ context.Context, input accounts.DeploymentRegistration) (accounts.DeploymentRegistrationResult, error) {
	f.input = input
	f.called = true
	if f.err != nil {
		return accounts.DeploymentRegistrationResult{}, f.err
	}
	return accounts.DeploymentRegistrationResult{
		Account: accounts.Account{ID: "01DEPLOYMENT"},
		Key:     accounts.APIKey{KeyPrefix: "rk_live_prefix"},
		Token:   "rk_live_returned-secret",
	}, nil
}

func (f *fakeDeploymentRegistrar) WriteOpLog(_ context.Context, entry accounts.OpLogEntry) error {
	f.logs = append(f.logs, entry)
	return nil
}

func registerHandlerForTest(reg *fakeDeploymentRegistrar) *deploymentRegistrationHandler {
	return &deploymentRegistrationHandler{
		accounts: reg,
		config: &config.Config{
			RegistrationAPNsTopics: []string{"org.siloserver.silo"},
		},
		logger: observability.NewLogger("error", io.Discard),
	}
}

func registerRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/deployments/register", strings.NewReader(body))
	return req.WithContext(context.WithValue(req.Context(), requestIDKey, "req-test"))
}

func TestDeploymentRegistrationHandlerSuccess(t *testing.T) {
	reg := &fakeDeploymentRegistrar{}
	h := registerHandlerForTest(reg)

	rec := httptest.NewRecorder()
	h.handleRegister(rec, registerRequest(`{"deployment_id":"01OLDDEPLOYMENT"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if !reg.called {
		t.Fatal("RegisterDeployment was not called")
	}
	if reg.input.DeploymentID != "01OLDDEPLOYMENT" || reg.input.Name != "" {
		t.Fatalf("registration input = %+v", reg.input)
	}
	if got := reg.input.APNsTopics; len(got) != 1 || got[0] != "org.siloserver.silo" {
		t.Fatalf("APNs topics = %v", got)
	}
	var resp deploymentRegistrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.APIKey != "rk_live_returned-secret" || resp.DeploymentID != "01DEPLOYMENT" {
		t.Fatalf("response = %+v", resp)
	}
	if len(reg.logs) != 1 || reg.logs[0].Outcome != "accepted" {
		t.Fatalf("logs = %+v", reg.logs)
	}
}

func TestDeploymentRegistrationHandlerRejectsLegacyOnboardingToken(t *testing.T) {
	reg := &fakeDeploymentRegistrar{}
	h := registerHandlerForTest(reg)

	rec := httptest.NewRecorder()
	h.handleRegister(rec, registerRequest(`{"onboarding_token":"bootstrap-token-long-enough"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if reg.called {
		t.Fatal("RegisterDeployment was called for a legacy token request")
	}
}

func TestDeploymentRegistrationHandlerDisabledAccount(t *testing.T) {
	reg := &fakeDeploymentRegistrar{err: accounts.ErrDisabled}
	h := registerHandlerForTest(reg)

	rec := httptest.NewRecorder()
	h.handleRegister(rec, registerRequest(`{"deployment_id":"01DEPLOYMENT"}`))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if len(reg.logs) != 1 || reg.logs[0].ErrorCode != "deployment_disabled" {
		t.Fatalf("logs = %+v", reg.logs)
	}
}

func TestDeploymentRegistrationRateLimitKeyDoesNotExposeIP(t *testing.T) {
	h := &deploymentRegistrationHandler{pepper: []byte("test-pepper")}
	key := h.registrationRateLimitKey("203.0.113.42")

	if !strings.HasPrefix(key, "register:ip:") {
		t.Fatalf("key = %q, want register:ip prefix", key)
	}
	if strings.Contains(key, "203.0.113.42") {
		t.Fatalf("rate limit key exposes raw IP: %q", key)
	}
	if key == h.registrationRateLimitKey("203.0.113.43") {
		t.Fatal("different IPs produced the same rate limit key")
	}
}

func testHTTPRedis(t *testing.T) *redis.Client {
	t.Helper()
	url := os.Getenv("RELAY_TEST_REDIS_URL")
	if url == "" {
		t.Skip("set RELAY_TEST_REDIS_URL to run Redis-backed HTTP tests")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parse redis url: %v", err)
	}
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis ping: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func TestDeploymentRegistrationLimiterCapsDeploymentAndSetsTTLs(t *testing.T) {
	rdb := testHTTPRedis(t)
	h := &deploymentRegistrationHandler{
		redis:  rdb,
		pepper: []byte("registration-limit-" + idSuffix()),
	}
	ctx := context.Background()
	ip := "203.0.113." + idSuffix()
	deploymentID := "deployment-" + idSuffix()

	for i := 0; i < int(registrationDeploymentRateLimitMax); i++ {
		allowed, _, err := h.registrationAllowed(ctx, ip, deploymentID)
		if err != nil {
			t.Fatalf("registrationAllowed %d: %v", i+1, err)
		}
		if !allowed {
			t.Fatalf("registrationAllowed %d denied, want allowed", i+1)
		}
	}
	allowed, retryAfter, err := h.registrationAllowed(ctx, ip, deploymentID)
	if err != nil {
		t.Fatalf("registrationAllowed over limit: %v", err)
	}
	if allowed || retryAfter <= 0 {
		t.Fatalf("over deployment limit = allowed %v retry %s, want denied with retry", allowed, retryAfter)
	}
	for _, key := range []string{
		h.registrationScopedRateLimitKey("global", "all"),
		h.registrationRateLimitKey(ip),
		h.registrationScopedRateLimitKey("deployment", deploymentID),
	} {
		if ttl := rdb.TTL(ctx, key).Val(); ttl <= 0 {
			t.Fatalf("key %s TTL = %s, want positive", key, ttl)
		}
	}
}

func TestAuthFailureLimiterRepairsMissingTTL(t *testing.T) {
	rdb := testHTTPRedis(t)
	a := &authenticator{rdb: rdb}
	ctx := context.Background()
	ip := "auth-test-" + idSuffix()
	key := "authfail:" + ip
	if err := rdb.Set(ctx, key, authFailThreshold+1, 0).Err(); err != nil {
		t.Fatalf("seed auth failure key: %v", err)
	}

	if !a.tooManyAuthFailures(ctx, ip) {
		t.Fatal("tooManyAuthFailures = false, want true")
	}
	if ttl := rdb.TTL(ctx, key).Val(); ttl <= 0 || ttl > authFailWindow {
		t.Fatalf("repaired TTL = %s, want within %s", ttl, authFailWindow)
	}

	_ = rdb.Del(ctx, key).Err()
	a.recordAuthFailure(ctx, ip)
	if ttl := rdb.TTL(ctx, key).Val(); ttl <= 0 || ttl > authFailWindow {
		t.Fatalf("recorded TTL = %s, want within %s", ttl, authFailWindow)
	}
	if count := rdb.Get(ctx, key).Val(); count != "1" {
		t.Fatalf("recorded count = %q, want 1", count)
	}
}
