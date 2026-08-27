package backend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONRequestAcceptsExactlyOneKnownDocument(t *testing.T) {
	type requestBody struct {
		Confirm bool `json:"confirm"`
	}
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "single document", body: `{"confirm":true}`},
		{name: "unknown field", body: `{"confirm":true,"unexpected":1}`, wantErr: true},
		{name: "second document", body: `{"confirm":true} {"confirm":false}`, wantErr: true},
		{name: "oversized", body: `{"confirm":true}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/admin/test", strings.NewReader(tt.body))
			var decoded requestBody
			limit := int64(1 << 20)
			if tt.name == "oversized" {
				limit = 4
			}
			err := decodeJSONRequest(httptest.NewRecorder(), request, limit, &decoded)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeJSONRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCSRFRequestAllowed(t *testing.T) {
	t.Setenv("POLICYWEB_TRUST_PROXY_HEADERS", "")
	tests := []struct {
		name    string
		headers map[string]string
		allowed bool
	}{
		{name: "cross-site fetch", headers: map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{name: "same-origin fetch", headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, allowed: true},
		{name: "matching origin", headers: map[string]string{"Origin": "https://policy.example.test"}, allowed: true},
		{name: "foreign origin", headers: map[string]string{"Origin": "https://attacker.example"}},
		{name: "legacy ExtJS", headers: map[string]string{"X-Requested-With": "XMLHttpRequest"}, allowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://policy.example.test/admin/policy", nil)
			for key, value := range tt.headers {
				r.Header.Set(key, value)
			}
			if got := csrfRequestAllowed(r); got != tt.allowed {
				t.Fatalf("csrfRequestAllowed() = %v, want %v", got, tt.allowed)
			}
		})
	}
}

func TestMaintenanceRequestAllowed(t *testing.T) {
	p := &editablePolicy{Users: []editableUser{
		{Email: "admin@example.org", Role: "admin"},
		{Email: "editor@example.org", Role: "editor"},
	}}
	if !maintenanceRequestAllowed(false, p, "editor@example.org") {
		t.Fatal("normal operation rejected editor")
	}
	if !maintenanceRequestAllowed(true, p, "admin@example.org") {
		t.Fatal("maintenance mode rejected administrator")
	}
	if maintenanceRequestAllowed(true, p, "editor@example.org") {
		t.Fatal("maintenance mode accepted non-administrator")
	}
}

func TestBootstrapTokenAllowed(t *testing.T) {
	t.Setenv("POLICYWEB_BOOTSTRAP_TOKEN", "one-time-secret")
	r := httptest.NewRequest(http.MethodPost, "http://policy.example.test/admin/bootstrap", nil)
	if bootstrapTokenAllowed(r) {
		t.Fatal("missing bootstrap token was accepted")
	}
	r.Header.Set("X-PolicyWeb-Bootstrap-Token", "wrong")
	if bootstrapTokenAllowed(r) {
		t.Fatal("wrong bootstrap token was accepted")
	}
	r.Header.Set("X-PolicyWeb-Bootstrap-Token", "one-time-secret")
	if !bootstrapTokenAllowed(r) {
		t.Fatal("correct bootstrap token was rejected")
	}
	t.Setenv("POLICYWEB_BOOTSTRAP_TOKEN", "")
	if bootstrapTokenAllowed(r) {
		t.Fatal("bootstrap was enabled without server-side configuration")
	}
}
