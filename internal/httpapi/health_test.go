package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Silo-Server/silo-push-relay/internal/config"
	"github.com/Silo-Server/silo-push-relay/internal/observability"
)

func testDeps(ready ReadyFunc) Deps {
	cfg := &config.Config{
		ListenAddr:        ":0",
		Environment:       "development",
		LogLevel:          "error",
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       time.Second,
		WriteTimeout:      time.Second,
		IdleTimeout:       time.Second,
		ShutdownTimeout:   time.Second,
		MaxHeaderBytes:    1 << 20,
		MaxBodyBytes:      16 << 10,
	}
	return Deps{Config: cfg, Logger: observability.NewLogger("error", io.Discard), Ready: ready}
}

func testRouter(t *testing.T) http.Handler {
	t.Helper()
	return newRouter(testDeps(nil))
}

func TestHealthz(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	testRouter(t).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("X-Request-Id"); got == "" {
		t.Error("missing X-Request-Id header")
	}
	var body healthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
}

func TestReadyzReady(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	// nil Ready means no dependencies wired → ready.
	newRouter(testDeps(nil)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body readyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
}

func TestReadyzNotReady(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	failing := func(context.Context) error { return errors.New("db down") }
	newRouter(testDeps(failing)).ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	var body errorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "not_ready" {
		t.Errorf("error.code = %q, want not_ready", body.Error.Code)
	}
}

func TestUnknownRoute404(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	testRouter(t).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	if got := rr.Header().Get("X-Request-Id"); got == "" {
		t.Error("missing X-Request-Id header on 404")
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q, want JSON error envelope", ct)
	}
	var body errorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 404 body: %v", err)
	}
	if body.Error.Code != "not_found" {
		t.Errorf("error.code = %q, want not_found", body.Error.Code)
	}
}
