package backend

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFortinetClientNeverForwardsAuthenticatedRedirects(t *testing.T) {
	client, err := (FortinetTarget{Type: "fortimanager"}).httpClient()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://redirect.example", nil)
	if err := client.CheckRedirect(request, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy error = %v", err)
	}
}

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
	caFile := filepath.Join(t.TempDir(), "fortigate-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	target := FortinetTarget{Name: "edge", Type: "fortigate", URL: server.URL, VDOM: "root", TokenEnv: "FGT_TOKEN", CAFile: caFile}
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
	caFile := filepath.Join(t.TempDir(), "fortimanager-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	target := FortinetTarget{Name: "manager", Type: "fortimanager", URL: server.URL, ADOM: "prod", UsernameEnv: "FMG_USER", PasswordEnv: "FMG_PASSWORD", CAFile: caFile}
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
	if err := (FortinetTarget{Name: "x", Type: "fortigate", URL: "https://example", TokenEnv: "TOKEN", AllowDeploy: true}).validate(); err == nil {
		t.Fatal("deployment target without target_contexts was accepted")
	}
	if err := (FortinetTarget{Name: "x", Type: "fortimanager", URL: "https://example", UsernameEnv: "USER", PasswordEnv: "PASS", AllowDeploy: true, TargetContexts: []string{"prod"}}).validate(); err == nil {
		t.Fatal("FortiManager deployment target without policy_package was accepted")
	}
	if err := (FortinetTarget{
		Name: "x", Type: "fortigate", URL: "https://example", VDOM: "root", TokenEnv: "TOKEN",
		AllowDeploy: true, PolicyInsertBefore: "POLICYWEB-END", TargetContexts: []string{"prod"}, ZoneInterfaces: map[string]string{"GDMZ": "port2"},
	}).validate(); err != nil {
		t.Fatal(err)
	}
	if err := (FortinetTarget{
		Name: "x", Type: "fortigate", URL: "https://example", VDOM: "root", TokenEnv: "TOKEN",
		AllowDeploy: true, PolicyInsertBefore: "POLICYWEB-END", TargetContexts: []string{"prod"}, InsecureSkipVerify: true,
	}).validate(); err == nil {
		t.Fatal("deployable target with disabled TLS verification was accepted")
	}
	if err := (FortinetTarget{
		Name: "fmg", Type: "fortimanager", URL: "https://example", UsernameEnv: "USER", PasswordEnv: "PASS", InsecureSkipVerify: true,
	}).validate(); err == nil {
		t.Fatal("authenticated FortiManager target with disabled TLS verification was accepted")
	}
	for _, anchor := range []string{" POLICYWEB-END", "POLICYWEB-END ", "POLICYWEB\nEND", "POLICYWEB\u0085END", strings.Repeat("x", 36)} {
		target := FortinetTarget{
			Name: "x", Type: "fortigate", URL: "https://example", VDOM: "root", TokenEnv: "TOKEN", AllowDeploy: true,
			PolicyInsertBefore: anchor, TargetContexts: []string{"prod"}, ZoneInterfaces: map[string]string{"GDMZ": "port2"},
		}
		if err := target.validate(); err == nil {
			t.Errorf("unsafe policy_insert_before %q was accepted", anchor)
		}
	}
	for _, vdom := range []string{"*", "root,other", " root", "root ", "root\nother", "12345678901234567890123456789012"} {
		if err := (FortinetTarget{Name: "x", Type: "fortigate", URL: "https://example", VDOM: vdom, TokenEnv: "TOKEN", TargetContexts: []string{"prod"}}).validate(); err == nil {
			t.Errorf("unsafe VDOM %q was accepted", vdom)
		}
	}
	for _, name := range []string{" edge", "edge ", "edge\nother", strings.Repeat("x", 65)} {
		if err := (FortinetTarget{Name: name, Type: "fortigate", URL: "https://example", TokenEnv: "TOKEN"}).validate(); err == nil {
			t.Errorf("unsafe target name %q was accepted", name)
		}
	}
	if err := (FortinetTarget{Name: "x", Type: "fortigate", URL: "https://user:secret@example", TokenEnv: "TOKEN"}).validate(); err == nil {
		t.Fatal("target URL containing credentials was accepted")
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
