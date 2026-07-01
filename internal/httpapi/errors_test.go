package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestWriteError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeError(rr, 400, "unexpected_field", "unexpected field in request", "01TESTREQUESTID0000000000")

	if rr.Code != 400 {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q, want application/json; charset=utf-8", ct)
	}
	var got errorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Error.Code != "unexpected_field" {
		t.Errorf("code = %q, want unexpected_field", got.Error.Code)
	}
	if got.Error.Message == "" {
		t.Error("message is empty")
	}
	if got.Error.RequestID != "01TESTREQUESTID0000000000" {
		t.Errorf("request_id = %q", got.Error.RequestID)
	}
}
