package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// apiError is a validation/decoding failure mapped to a caller-facing code.
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string { return e.Code }

func badRequest(code, msg string) *apiError {
	return &apiError{Status: http.StatusBadRequest, Code: code, Message: msg}
}

// appleSendRequest mirrors spec §5.1 exactly. No other fields are accepted.
type appleSendRequest struct {
	Token          string  `json:"token"`
	Environment    string  `json:"environment"`
	Topic          string  `json:"topic"`
	Mode           string  `json:"mode"`
	ServerDeviceID string  `json:"server_device_id"`
	DeliveryID     string  `json:"delivery_id"`
	Badge          *int    `json:"badge"`
	CollapseID     *string `json:"collapse_id"`
}

// fcmSendRequest mirrors spec §5.2 exactly.
type fcmSendRequest struct {
	Token          string  `json:"token"`
	ProjectID      string  `json:"project_id"`
	PackageName    string  `json:"package_name"`
	Mode           string  `json:"mode"`
	ServerDeviceID string  `json:"server_device_id"`
	DeliveryID     string  `json:"delivery_id"`
	Badge          *int    `json:"badge"`
	CollapseKey    *string `json:"collapse_key"`
}

var (
	apnsTokenRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	fcmTokenRe  = regexp.MustCompile(`^[\x21-\x7E]+$`) // printable ASCII, no spaces
)

// decodeJSON strictly decodes a single JSON object, rejecting unknown fields
// with 400 unexpected_field (the content-free guarantee, spec §12).
func decodeJSON(r *http.Request, dst any) *apiError {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return &apiError{Status: http.StatusRequestEntityTooLarge, Code: "payload_too_large", Message: "request body is too large"}
		}
		if strings.Contains(err.Error(), "unknown field") {
			return badRequest("unexpected_field", "request contains an unexpected field")
		}
		return badRequest("invalid_json", "request body is not valid JSON")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return badRequest("invalid_json", "request body must be a single JSON object")
	}
	return nil
}

func decodeAppleRequest(r *http.Request) (appleSendRequest, *apiError) {
	var req appleSendRequest
	if err := decodeJSON(r, &req); err != nil {
		return req, err
	}
	if err := validateApple(&req); err != nil {
		return req, err
	}
	return req, nil
}

func decodeFCMRequest(r *http.Request) (fcmSendRequest, *apiError) {
	var req fcmSendRequest
	if err := decodeJSON(r, &req); err != nil {
		return req, err
	}
	if err := validateFCM(&req); err != nil {
		return req, err
	}
	return req, nil
}

func validateApple(req *appleSendRequest) *apiError {
	if l := len(req.Token); l < 64 || l > 256 || !apnsTokenRe.MatchString(req.Token) {
		return badRequest("invalid_token", "token must be 64-256 hex characters")
	}
	if req.Environment != "production" && req.Environment != "sandbox" {
		return badRequest("invalid_environment", "environment must be production or sandbox")
	}
	if req.Mode != "private_alert" && req.Mode != "background_wake" {
		return badRequest("invalid_mode", "mode must be private_alert or background_wake")
	}
	if req.Topic == "" {
		return badRequest("invalid_field", "topic is required")
	}
	if err := validateOpaqueID("server_device_id", req.ServerDeviceID); err != nil {
		return err
	}
	if err := validateOpaqueID("delivery_id", req.DeliveryID); err != nil {
		return err
	}
	if err := validateBadge(req.Badge); err != nil {
		return err
	}
	if req.CollapseID != nil && len(*req.CollapseID) > 64 {
		return badRequest("invalid_collapse_id", "collapse_id must be at most 64 bytes")
	}
	return nil
}

func validateFCM(req *fcmSendRequest) *apiError {
	if l := len(req.Token); l < 100 || l > 4096 || !fcmTokenRe.MatchString(req.Token) {
		return badRequest("invalid_token", "token is not a plausible FCM registration token")
	}
	if req.ProjectID == "" {
		return badRequest("invalid_field", "project_id is required")
	}
	if req.PackageName == "" {
		return badRequest("invalid_field", "package_name is required")
	}
	if req.Mode != "private_data" && req.Mode != "background_wake" {
		return badRequest("invalid_mode", "mode must be private_data or background_wake")
	}
	if err := validateOpaqueID("server_device_id", req.ServerDeviceID); err != nil {
		return err
	}
	if err := validateOpaqueID("delivery_id", req.DeliveryID); err != nil {
		return err
	}
	if err := validateBadge(req.Badge); err != nil {
		return err
	}
	if req.CollapseKey != nil && len(*req.CollapseKey) > 64 {
		return badRequest("invalid_collapse_key", "collapse_key must be at most 64 bytes")
	}
	return nil
}

func validateOpaqueID(field, v string) *apiError {
	if v == "" || len(v) > 128 {
		return badRequest("invalid_field", field+" must be 1-128 characters")
	}
	return nil
}

func validateBadge(badge *int) *apiError {
	if badge != nil && (*badge < 0 || *badge > 9999) {
		return badRequest("invalid_field", "badge must be between 0 and 9999")
	}
	return nil
}
