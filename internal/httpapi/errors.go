package httpapi

import (
	"encoding/json"
	"net/http"
)

// errorResponse is the fixed error envelope returned by every relay endpoint
// (spec §5.5):
//
//	{ "error": { "code": "string_code", "message": "human readable", "request_id": "01..." } }
type errorResponse struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// writeJSON encodes v as JSON with the given status code and the JSON
// content type.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes the standard error envelope with the given status, machine
// code, human message, and request ID.
func writeError(w http.ResponseWriter, status int, code, message, requestID string) {
	writeJSON(w, status, errorResponse{Error: errorDetail{
		Code:      code,
		Message:   message,
		RequestID: requestID,
	}})
}
