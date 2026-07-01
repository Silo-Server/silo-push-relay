package httpapi

import "net/http"

// newRouter builds the HTTP handler: the route table plus the middleware chain.
// Execution order (outermost first) is: recoverer → requestID → logging →
// maxBytes → routes. recoverer is outermost so a panic anywhere in the chain
// (including in logging or maxBytes) becomes a 500 rather than a dropped
// connection; RequestIDFromContext safely returns "" if requestID had not yet
// run.
func newRouter(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", handleReadyz(d.Ready))

	// Send endpoints exist only when the Phase 2 collaborators are wired. They
	// run behind the auth → rate-limit chain; the rest of the pipeline
	// (decode/validate/allowlist/idempotency) lives in the handlers, which need
	// the parsed request.
	if d.Accounts != nil {
		auth := newAuthenticator(d)
		rl := &rateLimiter{limiter: d.Limiter, logger: d.Logger}
		send := newSendHandlers(d)
		deployments := newDeploymentRegistrationHandler(d)
		guard := func(next http.Handler) http.Handler {
			return auth.middleware(rl.middleware(next))
		}
		mux.HandleFunc("POST /v1/deployments/register", deployments.handleRegister)
		mux.Handle("POST /v1/apple/send", guard(http.HandlerFunc(send.handleApple)))
		mux.Handle("POST /v1/fcm/send", guard(http.HandlerFunc(send.handleFCM)))
	}

	mux.HandleFunc("/", handleNotFound)

	var h http.Handler = mux
	h = maxBytes(d.Config.MaxBodyBytes)(h)
	h = logging(d.Logger)(h)
	h = requestID(h)
	h = recoverer(d.Logger)(h)
	return h
}
