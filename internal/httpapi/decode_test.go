package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func appleBody(over map[string]any) string {
	m := map[string]any{
		"token":            strings.Repeat("a", 64),
		"environment":      "production",
		"topic":            "com.continuum.app.ios",
		"mode":             "private_alert",
		"server_device_id": "01DEVICE",
		"delivery_id":      "01DELIVERY",
	}
	for k, v := range over {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func decodeApple(body string) *apiError {
	r := httptest.NewRequest("POST", "/v1/apple/send", strings.NewReader(body))
	_, err := decodeAppleRequest(r)
	return err
}

func TestDecodeAppleValid(t *testing.T) {
	if err := decodeApple(appleBody(nil)); err != nil {
		t.Fatalf("valid apple body rejected: %+v", err)
	}
}

func TestDecodeAppleErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
		code string
	}{
		{"unknown field", appleBody(map[string]any{"title": "hi"}), "unexpected_field"},
		{"short token", appleBody(map[string]any{"token": "abcd"}), "invalid_token"},
		{"non-hex token", appleBody(map[string]any{"token": strings.Repeat("z", 64)}), "invalid_token"},
		{"bad environment", appleBody(map[string]any{"environment": "prod"}), "invalid_environment"},
		{"bad mode", appleBody(map[string]any{"mode": "loud"}), "invalid_mode"},
		{"empty server_device_id", appleBody(map[string]any{"server_device_id": ""}), "invalid_field"},
		{"badge too high", appleBody(map[string]any{"badge": 10000}), "invalid_field"},
		{"collapse too long", appleBody(map[string]any{"collapse_id": strings.Repeat("x", 65)}), "invalid_collapse_id"},
		{"not json", "{", "invalid_json"},
		{"trailing object", appleBody(nil) + `{}`, "invalid_json"},
	}
	for _, c := range cases {
		err := decodeApple(c.body)
		if err == nil {
			t.Errorf("%s: expected error %q, got nil", c.name, c.code)
			continue
		}
		if err.Code != c.code {
			t.Errorf("%s: code = %q, want %q", c.name, err.Code, c.code)
		}
	}
}

func TestDecodeJSONOversizedBody(t *testing.T) {
	body := appleBody(map[string]any{"delivery_id": strings.Repeat("x", 1024)})
	r := httptest.NewRequest("POST", "/v1/apple/send", strings.NewReader(body))
	rr := httptest.NewRecorder()
	r.Body = http.MaxBytesReader(rr, r.Body, 64)

	var req appleSendRequest
	err := decodeJSON(r, &req)
	if err == nil {
		t.Fatal("decodeJSON oversized body = nil, want error")
	}
	if err.Status != http.StatusRequestEntityTooLarge || err.Code != "payload_too_large" {
		t.Fatalf("oversized error = %+v, want 413 payload_too_large", err)
	}
}

func fcmBody(over map[string]any) string {
	m := map[string]any{
		"token":            strings.Repeat("t", 152),
		"project_id":       "continuum-prod-android",
		"package_name":     "com.continuum.app.android",
		"mode":             "private_data",
		"server_device_id": "01DEVICE",
		"delivery_id":      "01DELIVERY",
	}
	for k, v := range over {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func decodeFCM(body string) *apiError {
	r := httptest.NewRequest("POST", "/v1/fcm/send", strings.NewReader(body))
	_, err := decodeFCMRequest(r)
	return err
}

func TestDecodeFCM(t *testing.T) {
	if err := decodeFCM(fcmBody(nil)); err != nil {
		t.Fatalf("valid fcm body rejected: %+v", err)
	}
	cases := []struct {
		name string
		body string
		code string
	}{
		{"unknown field", fcmBody(map[string]any{"notification": "x"}), "unexpected_field"},
		{"short token", fcmBody(map[string]any{"token": "short"}), "invalid_token"},
		{"bad mode", fcmBody(map[string]any{"mode": "private_alert"}), "invalid_mode"},
		{"empty project", fcmBody(map[string]any{"project_id": ""}), "invalid_field"},
		{"collapse too long", fcmBody(map[string]any{"collapse_key": strings.Repeat("x", 65)}), "invalid_collapse_key"},
	}
	for _, c := range cases {
		err := decodeFCM(c.body)
		if err == nil {
			t.Errorf("%s: expected error %q, got nil", c.name, c.code)
			continue
		}
		if err.Code != c.code {
			t.Errorf("%s: code = %q, want %q", c.name, err.Code, c.code)
		}
	}
}
