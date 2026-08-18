package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeFortiGate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.URL.Query().Get("vdom"); got != "root" {
			t.Errorf("vdom = %q", got)
		}
		json.NewEncoder(w).Encode(map[string]any{"results": map[string]string{"version": "v7.6.2", "serial": "FGT01"}})
	}))
	defer server.Close()
	t.Setenv("FGT_TOKEN", "secret")
	target := FortinetTarget{Name: "edge", Type: "fortigate", URL: server.URL, VDOM: "root", TokenEnv: "FGT_TOKEN", InsecureSkipVerify: true}
	got := probeFortinet(target)
	if !got.Online || got.Version != "v7.6.2" || got.Serial != "FGT01" {
		t.Fatalf("probeFortinet() = %#v", got)
	}
}

func TestProbeFortiManager(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		switch body["method"] {
		case "exec":
			json.NewEncoder(w).Encode(map[string]any{"session": "session-id", "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		case "get":
			json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{"data": map[string]string{"Version": "v7.4.6", "Serial Number": "FMG01"}}}})
		}
	}))
	defer server.Close()
	t.Setenv("FMG_USER", "api-user")
	t.Setenv("FMG_PASSWORD", "secret")
	target := FortinetTarget{Name: "manager", Type: "fortimanager", URL: server.URL, ADOM: "prod", UsernameEnv: "FMG_USER", PasswordEnv: "FMG_PASSWORD", InsecureSkipVerify: true}
	got := probeFortinet(target)
	if !got.Online || got.Version != "v7.4.6" || got.Serial != "FMG01" {
		t.Fatalf("probeFortinet() = %#v", got)
	}
	if requests != 3 {
		t.Errorf("requests = %d, want login, status and logout", requests)
	}
}

func TestFortinetTargetValidation(t *testing.T) {
	tests := []FortinetTarget{
		{},
		{Name: "x", Type: "unknown", URL: "https://example"},
		{Name: "x", Type: "fortigate", URL: "http://example", TokenEnv: "TOKEN"},
		{Name: "x", Type: "fortigate", URL: "https://example"},
		{Name: "x", Type: "fortimanager", URL: "https://example"},
	}
	for _, target := range tests {
		if target.validate() == nil {
			t.Errorf("validate(%#v) succeeded", target)
		}
	}
	if err := (FortinetTarget{Name: "x", Type: "fortigate", URL: "https://example", TokenEnv: "TOKEN"}).validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPostRPCReportsFortiManagerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{"status": map[string]any{"code": -11, "message": "No permission"}}}})
	}))
	defer server.Close()
	var response map[string]any
	err := postRPC(server.Client(), server.URL, map[string]any{"id": 1}, &response)
	if err == nil || err.Error() != "FortiManager error -11: No permission" {
		t.Fatalf("postRPC() error = %v", err)
	}
}
