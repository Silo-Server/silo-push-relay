package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Silo-Server/silo-push-relay/internal/accounts"
	"github.com/Silo-Server/silo-push-relay/internal/config"
)

const (
	registrationRateLimitWindow        = time.Hour
	registrationIPRateLimitMax         = int64(30)
	registrationGlobalRateLimitMax     = int64(100)
	registrationDeploymentRateLimitMax = int64(5)
)

const registrationRateLimitScript = `
local allowed = 1
local retry_after = 0
local window = tonumber(ARGV[#KEYS + 1])
for i, key in ipairs(KEYS) do
  local limit = tonumber(ARGV[i])
  local count = redis.call('INCR', key)
  local ttl = redis.call('TTL', key)
  if ttl < 0 then
    redis.call('EXPIRE', key, window)
    ttl = window
  end
  if count > limit then
    allowed = 0
    if ttl > retry_after then retry_after = ttl end
  end
end
return {allowed, retry_after}
`

var registrationLimiterScript = redis.NewScript(registrationRateLimitScript)

type deploymentRegistrar interface {
	RegisterDeployment(context.Context, accounts.DeploymentRegistration) (accounts.DeploymentRegistrationResult, error)
	WriteOpLog(context.Context, accounts.OpLogEntry) error
}

type deploymentRegistrationHandler struct {
	accounts deploymentRegistrar
	config   *config.Config
	redis    *redis.Client
	pepper   []byte
	trusted  []netip.Prefix
	logger   *slog.Logger
}

func newDeploymentRegistrationHandler(d Deps) *deploymentRegistrationHandler {
	return &deploymentRegistrationHandler{
		accounts: d.Accounts,
		config:   d.Config,
		redis:    d.Redis,
		pepper:   d.Pepper,
		trusted:  d.TrustedProxies,
		logger:   d.Logger,
	}
}

type deploymentRegistrationRequest struct {
	DeploymentID string `json:"deployment_id"`
}

type deploymentRegistrationResponse struct {
	RequestID    string   `json:"request_id"`
	DeploymentID string   `json:"deployment_id"`
	APIKey       string   `json:"api_key"`
	KeyPrefix    string   `json:"key_prefix"`
	APNsTopics   []string `json:"apns_topics"`
}

func (h *deploymentRegistrationHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	rid := RequestIDFromContext(r.Context())
	if h == nil || h.accounts == nil || h.config == nil {
		writeError(w, http.StatusServiceUnavailable, "registration_unavailable", "deployment registration is not configured", rid)
		return
	}

	req, aerr := decodeDeploymentRegistrationRequest(r)
	if aerr != nil {
		writeError(w, aerr.Status, aerr.Code, aerr.Message, rid)
		return
	}

	allowed, retryAfter, err := h.registrationAllowed(r.Context(), resolveClientIP(r, h.trusted), req.DeploymentID)
	if err != nil {
		h.audit(r.Context(), accounts.OpLogEntry{
			RequestID:  rid,
			Event:      "deployment.register",
			Actor:      "self-service",
			Outcome:    "rejected",
			StatusCode: http.StatusServiceUnavailable,
			ErrorCode:  "registration_rate_limiter_unavailable",
		})
		if h.logger != nil {
			h.logger.Error("deployment registration rate limiter unavailable", "request_id", rid, "err", err)
		}
		writeError(w, http.StatusServiceUnavailable, "registration_rate_limiter_unavailable", "registration rate limiter unavailable", rid)
		return
	}
	if !allowed {
		h.audit(r.Context(), accounts.OpLogEntry{
			RequestID:  rid,
			Event:      "deployment.register",
			Actor:      "self-service",
			Outcome:    "rejected",
			StatusCode: http.StatusTooManyRequests,
			ErrorCode:  "rate_limited",
		})
		writeRetryAfter(w, retryAfter.Seconds())
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many deployment registrations from this network", rid)
		return
	}

	result, err := h.accounts.RegisterDeployment(r.Context(), accounts.DeploymentRegistration{
		DeploymentID: req.DeploymentID,
		Env:          "live",
		APNsTopics:   h.config.RegistrationAPNsTopics,
	})
	if err != nil {
		status := http.StatusInternalServerError
		code := "registration_failed"
		message := "failed to register deployment"
		if errors.Is(err, accounts.ErrDisabled) {
			status = http.StatusForbidden
			code = "deployment_disabled"
			message = "deployment is disabled"
		}
		h.audit(r.Context(), accounts.OpLogEntry{
			AccountID:  req.DeploymentID,
			RequestID:  rid,
			Event:      "deployment.register",
			Actor:      "self-service",
			Outcome:    "rejected",
			StatusCode: status,
			ErrorCode:  code,
		})
		if h.logger != nil {
			h.logger.Warn("deployment registration failed", "request_id", rid, "error", err)
		}
		writeError(w, status, code, message, rid)
		return
	}

	h.audit(r.Context(), accounts.OpLogEntry{
		AccountID:  result.Account.ID,
		RequestID:  rid,
		Event:      "deployment.register",
		Actor:      "self-service",
		Outcome:    "accepted",
		StatusCode: http.StatusOK,
	})
	writeJSON(w, http.StatusOK, deploymentRegistrationResponse{
		RequestID:    rid,
		DeploymentID: result.Account.ID,
		APIKey:       result.Token,
		KeyPrefix:    result.Key.KeyPrefix,
		APNsTopics:   h.config.RegistrationAPNsTopics,
	})
}

func decodeDeploymentRegistrationRequest(r *http.Request) (deploymentRegistrationRequest, *apiError) {
	var req deploymentRegistrationRequest
	if err := decodeJSON(r, &req); err != nil {
		return req, err
	}
	req.DeploymentID = strings.TrimSpace(req.DeploymentID)
	if req.DeploymentID != "" && len(req.DeploymentID) > 128 {
		return req, badRequest("invalid_field", "deployment_id must be at most 128 characters")
	}
	return req, nil
}

func (h *deploymentRegistrationHandler) registrationAllowed(ctx context.Context, clientIP, deploymentID string) (bool, time.Duration, error) {
	if h == nil || h.redis == nil {
		return true, 0, nil
	}
	keys := []string{
		h.registrationScopedRateLimitKey("global", "all"),
		h.registrationRateLimitKey(clientIP),
	}
	args := []any{
		registrationGlobalRateLimitMax,
		registrationIPRateLimitMax,
	}
	if deploymentID != "" {
		keys = append(keys, h.registrationScopedRateLimitKey("deployment", deploymentID))
		args = append(args, registrationDeploymentRateLimitMax)
	}
	args = append(args, int64(registrationRateLimitWindow/time.Second))

	raw, err := registrationLimiterScript.Run(ctx, h.redis, keys, args...).Slice()
	if err != nil {
		return false, 0, err
	}
	allowed, _ := raw[0].(int64)
	retrySeconds, _ := raw[1].(int64)
	if allowed == 1 {
		return true, 0, nil
	}
	if retrySeconds <= 0 {
		retrySeconds = int64(registrationRateLimitWindow / time.Second)
	}
	return false, time.Duration(retrySeconds) * time.Second, nil
}

func (h *deploymentRegistrationHandler) registrationRateLimitKey(clientIP string) string {
	return h.registrationScopedRateLimitKey("ip", clientIP)
}

func (h *deploymentRegistrationHandler) registrationScopedRateLimitKey(scope, value string) string {
	mac := hmac.New(sha256.New, h.pepper)
	_, _ = mac.Write([]byte("deployment-registration:"))
	_, _ = mac.Write([]byte(scope))
	_, _ = mac.Write([]byte(":"))
	_, _ = mac.Write([]byte(value))
	return "register:" + scope + ":" + hex.EncodeToString(mac.Sum(nil))
}

func (h *deploymentRegistrationHandler) audit(ctx context.Context, entry accounts.OpLogEntry) {
	if h == nil || h.accounts == nil {
		return
	}
	if err := h.accounts.WriteOpLog(ctx, entry); err != nil && h.logger != nil {
		h.logger.Warn("deployment registration op-log write failed", "request_id", entry.RequestID, "err", err)
	}
}
