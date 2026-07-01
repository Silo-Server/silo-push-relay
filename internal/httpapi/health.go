package httpapi

import "net/http"

type healthResponse struct {
	Status string `json:"status"`
}

// handleHealthz is an unauthenticated liveness probe with no dependency checks
// (spec §5.3). Readiness (/readyz, including datastore and per-provider
// credential health) lands in a later phase.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}
