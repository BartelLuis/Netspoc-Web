package backend

import (
	"context"
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

func TestFortiGateReadOnlySetting(t *testing.T) {
	for name, test := range map[string]struct {
		value string
		want  bool
	}{
		"unset": {},
		"false": {value: "false"},
		"true":  {value: "true", want: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(fortiGateReadOnlyEnv, test.value)
			got, err := fortiGateReadOnlySetting()
			if err != nil || got != test.want {
				t.Fatalf("fortiGateReadOnlySetting() = %v, %v; want %v, nil", got, err, test.want)
			}
		})
	}

	t.Setenv(fortiGateReadOnlyEnv, "sometimes")
	if _, err := fortiGateReadOnlySetting(); err == nil || !strings.Contains(err.Error(), "true or false") {
		t.Fatalf("invalid read-only setting error = %v", err)
	}
}

func TestFortiGateReadOnlyBlocksMutationsButAllowsReads(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "results": []any{}})
	}))
	defer server.Close()
	t.Setenv("READ_ONLY_FGT_TOKEN", "secret")
	t.Setenv(fortiGateReadOnlyEnv, "true")
	target := FortinetTarget{Name: "edge", Type: "fortigate", URL: server.URL, VDOM: "root", TokenEnv: "READ_ONLY_FGT_TOKEN"}

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if _, err := fortiGateCall(context.Background(), server.Client(), target, method, "/api/v2/cmdb/firewall/address", nil, map[string]any{"name": "blocked"}); !errors.Is(err, errFortiGateReadOnly) {
			t.Errorf("%s error = %v; want read-only error", method, err)
		}
	}
	if requests != 0 {
		t.Fatalf("read-only mutations reached FortiGate %d times", requests)
	}
	if _, err := fortiGateCall(context.Background(), server.Client(), target, http.MethodGet, "/api/v2/cmdb/firewall/address", nil, nil); err != nil {
		t.Fatalf("read-only GET failed: %v", err)
	}
	if requests != 1 {
		t.Fatalf("GET requests = %d, want 1", requests)
	}

	t.Setenv(fortiGateReadOnlyEnv, "false")
	if _, err := fortiGateCall(context.Background(), server.Client(), target, http.MethodPost, "/api/v2/cmdb/firewall/address", nil, map[string]any{"name": "allowed"}); err != nil {
		t.Fatalf("write with read-only disabled failed: %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests after enabled write = %d, want 2", requests)
	}
}

func TestInvalidFortiGateReadOnlySettingFailsClosed(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	t.Setenv(fortiGateReadOnlyEnv, "invalid")
	target := FortinetTarget{Name: "edge", Type: "fortigate", URL: server.URL}

	if _, err := fortiGateCall(context.Background(), server.Client(), target, http.MethodPost, "/api/v2/cmdb/firewall/address", nil, nil); err == nil || !strings.Contains(err.Error(), "true or false") {
		t.Fatalf("invalid setting mutation error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("mutation reached FortiGate despite invalid setting")
	}
}

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
	if err == nil || err.Error() != "FortiManager returned error code -11" || strings.Contains(err.Error(), "No permission") {
		t.Fatalf("postRPC() error = %v", err)
	}
}

func TestFortiGateApplicationErrorNeverReturnsRemoteMessage(t *testing.T) {
	const remoteSecret = `token\"with\\json-escaping`
	err := fortiGateApplicationError(map[string]any{"status": "error", "http_status": 403, "message": remoteSecret})
	if err == nil || err.Error() != "FortiGate rejected the request" || strings.Contains(err.Error(), remoteSecret) {
		t.Fatalf("application error = %v", err)
	}
}
