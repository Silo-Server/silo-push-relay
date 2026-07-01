package httpapi

import (
	"context"
	"net/http"
	"time"
)

type readyResponse struct {
	Status string `json:"status"`
}

// handleReadyz is the readiness probe (spec §5.4): it reports 503 until the
// relay's dependencies (PostgreSQL now; Redis/credentials later) are healthy, so
// a load balancer holds traffic off an instance that cannot serve. Liveness
// (/healthz) stays 200 regardless.
func handleReadyz(ready ReadyFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ready != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			if err := ready(ctx); err != nil {
				writeError(w, http.StatusServiceUnavailable, "not_ready", "dependencies not ready", RequestIDFromContext(r.Context()))
				return
			}
		}
		writeJSON(w, http.StatusOK, readyResponse{Status: "ready"})
	}
}
