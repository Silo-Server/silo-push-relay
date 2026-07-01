package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Silo-Server/silo-push-relay/internal/accounts"
	"github.com/Silo-Server/silo-push-relay/internal/apns"
	"github.com/Silo-Server/silo-push-relay/internal/idempotency"
	"github.com/Silo-Server/silo-push-relay/internal/ratelimit"
)

const maxIdempotencyKeyLen = 255

type appleSendResponse struct {
	RequestID string `json:"request_id"`
	APNsID    string `json:"apns_id"`
	Status    string `json:"status"`
}

// sendHandlers holds the collaborators for the two send endpoints.
type sendHandlers struct {
	accounts *accounts.Store
	limiter  *ratelimit.Limiter
	idem     *idempotency.Store
	apns     APNsSender
	logger   *slog.Logger
}

func newSendHandlers(d Deps) *sendHandlers {
	return &sendHandlers{accounts: d.Accounts, limiter: d.Limiter, idem: d.Idempotency, apns: d.APNs, logger: d.Logger}
}

func (h *sendHandlers) handleApple(w http.ResponseWriter, r *http.Request) {
	rid := RequestIDFromContext(r.Context())
	info, _ := authFromContext(r.Context())

	idemKey, ok := idempotencyKey(w, r, rid)
	if !ok {
		return
	}
	req, aerr := decodeAppleRequest(r)
	if aerr != nil {
		writeError(w, aerr.Status, aerr.Code, aerr.Message, rid)
		return
	}

	tokenHash := sha256Hex(req.Token)
	canon := canonicalHash("apple", req.Environment, req.Topic, req.Mode, req.ServerDeviceID, req.DeliveryID, badgeStr(req.Badge), strDeref(req.CollapseID), tokenHash)

	begin, done := h.beginIdempotent(w, r, info.AccountID, idemKey, canon, rid)
	if done {
		return
	}

	allowed, err := h.accounts.APNsTopicAllowed(r.Context(), info.AccountID, req.Topic)
	if err != nil {
		h.releaseIdempotent(r.Context(), info.AccountID, idemKey, begin.Nonce)
		h.logger.Error("apns allowlist check failed", "request_id", rid, "err", err)
		writeError(w, http.StatusServiceUnavailable, "upstream_unavailable", "allowlist backend unavailable", rid)
		return
	}
	if !allowed {
		h.releaseIdempotent(r.Context(), info.AccountID, idemKey, begin.Nonce)
		writeError(w, http.StatusForbidden, "topic_not_allowed", "topic is not allowlisted for this account", rid)
		return
	}

	if h.apns == nil {
		h.writeAppleResult(w, r.Context(), info, idemKey, begin.Nonce, canon, tokenHash, appleUpstreamResult{
			status:  http.StatusServiceUnavailable,
			code:    "upstream_unavailable",
			msg:     "APNs upstream is not configured",
			outcome: "retryable",
			reason:  "not_configured",
		}, rid)
		return
	}
	if !h.chargeTokenRate(w, r, info.AccountID, idemKey, tokenHash, begin.Nonce, rid) {
		return
	}
	if !h.chargeDailyQuota(w, r, info.AccountID, idemKey, begin.Nonce, rid) {
		return
	}

	started := time.Now()
	result, err := h.apns.Send(r.Context(), apns.Request{
		Token:          req.Token,
		Environment:    req.Environment,
		Topic:          req.Topic,
		Mode:           req.Mode,
		ServerDeviceID: req.ServerDeviceID,
		DeliveryID:     req.DeliveryID,
		Badge:          req.Badge,
		CollapseID:     req.CollapseID,
	})
	h.writeAppleResult(w, r.Context(), info, idemKey, begin.Nonce, canon, tokenHash, appleResultFromAPNs(result, err), rid, time.Since(started))
}

func (h *sendHandlers) handleFCM(w http.ResponseWriter, r *http.Request) {
	rid := RequestIDFromContext(r.Context())
	info, _ := authFromContext(r.Context())

	idemKey, ok := idempotencyKey(w, r, rid)
	if !ok {
		return
	}
	req, aerr := decodeFCMRequest(r)
	if aerr != nil {
		writeError(w, aerr.Status, aerr.Code, aerr.Message, rid)
		return
	}

	tokenHash := sha256Hex(req.Token)
	canon := canonicalHash("fcm", req.ProjectID, req.PackageName, req.Mode, req.ServerDeviceID, req.DeliveryID, strDeref(req.CollapseKey), tokenHash)

	begin, done := h.beginIdempotent(w, r, info.AccountID, idemKey, canon, rid)
	if done {
		return
	}

	projectOK, packageOK, err := h.accounts.FCMPairAllowed(r.Context(), info.AccountID, req.ProjectID, req.PackageName)
	if err != nil {
		h.releaseIdempotent(r.Context(), info.AccountID, idemKey, begin.Nonce)
		h.logger.Error("fcm allowlist check failed", "request_id", rid, "err", err)
		writeError(w, http.StatusServiceUnavailable, "upstream_unavailable", "allowlist backend unavailable", rid)
		return
	}
	if !projectOK {
		h.releaseIdempotent(r.Context(), info.AccountID, idemKey, begin.Nonce)
		writeError(w, http.StatusForbidden, "project_not_allowed", "project is not allowlisted for this account", rid)
		return
	}
	if !packageOK {
		h.releaseIdempotent(r.Context(), info.AccountID, idemKey, begin.Nonce)
		writeError(w, http.StatusForbidden, "package_not_allowed", "package is not allowlisted for this account", rid)
		return
	}

	body, _ := json.Marshal(errorResponse{Error: errorDetail{
		Code:      "not_implemented",
		Message:   "FCM upstream delivery is not implemented",
		RequestID: rid,
	}})

	h.releaseIdempotent(r.Context(), info.AccountID, idemKey, begin.Nonce)
	h.opLog(r.Context(), accounts.OpLogEntry{
		AccountID: info.AccountID, RequestID: rid, Event: "send.fcm", Provider: "fcm",
		Outcome: "rejected", StatusCode: http.StatusNotImplemented, ErrorCode: "not_implemented",
		TokenHash: tokenHash, EgressIP: info.ClientIP,
	})
	writeRaw(w, http.StatusNotImplemented, body)
}

// idempotencyKey reads and validates the required Idempotency-Key header.
func idempotencyKey(w http.ResponseWriter, r *http.Request, rid string) (string, bool) {
	k := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if k == "" {
		writeError(w, http.StatusBadRequest, "missing_idempotency_key", "Idempotency-Key header is required", rid)
		return "", false
	}
	if len(k) > maxIdempotencyKeyLen {
		writeError(w, http.StatusBadRequest, "invalid_field", "Idempotency-Key is too long", rid)
		return "", false
	}
	return k, true
}

// beginIdempotent acquires the lock. When it returns done=true it has already
// written the response (replay / 409 / 422 / 503) and the caller must return.
// When done=false the returned begin is the Proceed result (lock held).
func (h *sendHandlers) beginIdempotent(w http.ResponseWriter, r *http.Request, accountID, idemKey, canon, rid string) (begin idempotency.BeginResult, done bool) {
	begin, err := h.idem.Begin(r.Context(), accountID, idemKey, canon)
	if errors.Is(err, idempotency.ErrUnavailable) {
		writeError(w, http.StatusServiceUnavailable, "upstream_unavailable", "idempotency store unavailable", rid)
		return begin, true
	}
	switch begin.Outcome {
	case idempotency.Replay:
		writeRaw(w, begin.Stored.Status, begin.Stored.Body)
		return begin, true
	case idempotency.Conflict:
		writeError(w, http.StatusConflict, "idempotency_conflict", "a request with this Idempotency-Key is in progress", rid)
		return begin, true
	case idempotency.Mismatch:
		writeError(w, http.StatusUnprocessableEntity, "idempotency_key_reuse", "Idempotency-Key reused with a different payload", rid)
		return begin, true
	default:
		return begin, false
	}
}

func (h *sendHandlers) chargeDailyQuota(w http.ResponseWriter, r *http.Request, accountID, idemKey, nonce, rid string) bool {
	res := h.limiter.ChargeDaily(r.Context(), accountID)
	if res.Degraded {
		h.logger.Warn("rate_limit.degraded", "account", accountID, "request_id", rid, "limit", res.Limit)
	}
	if res.Allowed {
		return true
	}
	h.releaseIdempotent(r.Context(), accountID, idemKey, nonce)
	writeRetryAfter(w, res.RetryAfter.Seconds())
	writeError(w, http.StatusTooManyRequests, "rate_limited", "account daily quota exceeded", rid)
	return false
}

// chargeTokenRate applies the coarse per-(account, token) cap to genuinely-new
// sends only (replays already returned above). On denial it releases the
// idempotency lock so the caller's backed-off retry can proceed, then writes 429.
func (h *sendHandlers) chargeTokenRate(w http.ResponseWriter, r *http.Request, accountID, idemKey, tokenHash, nonce, rid string) bool {
	res := h.limiter.CheckToken(r.Context(), accountID, tokenHash)
	if res.Allowed {
		return true
	}
	h.releaseIdempotent(r.Context(), accountID, idemKey, nonce)
	writeRetryAfter(w, res.RetryAfter.Seconds())
	writeError(w, http.StatusTooManyRequests, "rate_limited", "device rate limit exceeded", rid)
	return false
}

func (h *sendHandlers) finishIdempotent(ctx context.Context, accountID, idemKey, nonce, canon string, status int, body []byte, upstreamID, rid string) {
	persisted, err := h.idem.Complete(ctx, accountID, idemKey, nonce, canon, idempotency.Stored{Status: status, Body: body, UpstreamID: upstreamID})
	if err != nil {
		h.logger.Warn("idempotency complete failed", "request_id", rid, "err", err)
		return
	}
	if !persisted {
		h.logger.Warn("idempotency complete skipped", "request_id", rid, "reason", "stale_nonce")
	}
}

func (h *sendHandlers) releaseIdempotent(ctx context.Context, accountID, idemKey, nonce string) {
	h.idem.Release(ctx, accountID, idemKey, nonce)
}

type appleUpstreamResult struct {
	status     int
	code       string
	msg        string
	outcome    string
	apnsID     string
	reason     string
	retryAfter time.Duration
	terminal   bool
}

func appleResultFromAPNs(result apns.Result, err error) appleUpstreamResult {
	if err == nil {
		return appleUpstreamResult{
			status:  http.StatusOK,
			outcome: "accepted",
			apnsID:  result.APNsID,
		}
	}
	reason := result.Reason
	if reason == "" {
		reason = "upstream_error"
	}
	out := appleUpstreamResult{
		status:     http.StatusServiceUnavailable,
		code:       "upstream_unavailable",
		msg:        "APNs upstream unavailable",
		outcome:    "retryable",
		apnsID:     result.APNsID,
		reason:     reason,
		retryAfter: result.RetryAfter,
		terminal:   result.Terminal,
	}
	if result.StatusCode == http.StatusTooManyRequests {
		out.status = http.StatusTooManyRequests
		out.code = "upstream_rate_limited"
		out.msg = "APNs upstream rate limited the request"
		return out
	}
	if result.Terminal {
		out.status = http.StatusUnprocessableEntity
		out.code = "apns_rejected"
		out.msg = "APNs rejected the notification: " + reason
		out.outcome = "rejected"
		return out
	}
	return out
}

func (h *sendHandlers) writeAppleResult(w http.ResponseWriter, ctx context.Context, info authInfo, idemKey, nonce, canon, tokenHash string, result appleUpstreamResult, rid string, elapsed ...time.Duration) {
	latencyMS := 0
	if len(elapsed) > 0 {
		latencyMS = int(elapsed[0].Milliseconds())
	}
	if result.status == http.StatusOK {
		body, _ := json.Marshal(appleSendResponse{RequestID: rid, APNsID: result.apnsID, Status: "accepted"})
		h.finishIdempotent(ctx, info.AccountID, idemKey, nonce, canon, http.StatusOK, body, result.apnsID, rid)
		h.opLog(ctx, accounts.OpLogEntry{
			AccountID: info.AccountID, RequestID: rid, Event: "send.apns", Provider: "apns",
			Outcome: "accepted", StatusCode: http.StatusOK, TokenHash: tokenHash, EgressIP: info.ClientIP,
			LatencyMS: latencyMS,
		})
		writeRaw(w, http.StatusOK, body)
		return
	}
	if result.retryAfter > 0 {
		writeRetryAfter(w, result.retryAfter.Seconds())
	}
	body, _ := json.Marshal(errorResponse{Error: errorDetail{
		Code:      result.code,
		Message:   result.msg,
		RequestID: rid,
	}})
	if result.terminal {
		h.finishIdempotent(ctx, info.AccountID, idemKey, nonce, canon, result.status, body, result.apnsID, rid)
	} else {
		h.releaseIdempotent(ctx, info.AccountID, idemKey, nonce)
	}
	h.opLog(ctx, accounts.OpLogEntry{
		AccountID: info.AccountID, RequestID: rid, Event: "send.apns", Provider: "apns",
		Outcome: result.outcome, StatusCode: result.status, ErrorCode: result.code,
		UpstreamReason: result.reason, TokenHash: tokenHash, EgressIP: info.ClientIP,
		LatencyMS: latencyMS,
	})
	writeRaw(w, result.status, body)
}

func (h *sendHandlers) opLog(ctx context.Context, e accounts.OpLogEntry) {
	if err := h.accounts.WriteOpLog(ctx, e); err != nil {
		h.logger.Warn("op-log write failed", "request_id", e.RequestID, "err", err)
	}
}

func writeRaw(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// canonicalHash hashes the validated request fields with the device token
// already replaced by its SHA-256 hash — the raw token is never part of the
// canonical form (privacy invariant, spec §10.2).
func canonicalHash(parts ...string) string {
	var b strings.Builder
	for _, part := range parts {
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte(':')
		b.WriteString(part)
	}
	return sha256Hex(b.String())
}

func badgeStr(b *int) string {
	if b == nil {
		return ""
	}
	return strconv.Itoa(*b)
}

func strDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
