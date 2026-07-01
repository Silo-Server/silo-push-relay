package httpapi

import "net/http"

// handleNotFound returns the standard error envelope (spec §5.5) for any
// request that matches no registered route, so even 404s carry a request ID and
// a machine-readable code rather than the net/http plaintext default.
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "not_found", "resource not found", RequestIDFromContext(r.Context()))
}
