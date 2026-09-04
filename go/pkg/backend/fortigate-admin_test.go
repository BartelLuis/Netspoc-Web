package backend

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDiscoverFortiGateVDOMsPaginatesBeyondOneHundred(t *testing.T) {
	const token = "vdom-discovery-token"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/cmdb/system/vdom" || r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		end := start + 100
		if end > 125 {
			end = 125
		}
		results := make([]map[string]any, 0, end-start)
		for index := start; index < end; index++ {
			results = append(results, map[string]any{"name": fmt.Sprintf("tenant-%03d", index)})
		}
		response := map[string]any{"revision": "stable-vdom-revision", "results": results, "limit_reached": end < 125}
		if end < 125 {
			response["next_idx"] = end - 1
		}
		writeFakeFortiGate(w, response)
	}))
	defer server.Close()
	target := FortinetTarget{
		Name: "scan", Type: "fortigate", URL: server.URL, TokenEnv: "managed:scan",
		managedToken: token,
		managedCAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
	}
	client, err := target.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	vdoms, err := discoverFortiGateVDOMs(context.Background(), client, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(vdoms) != 125 || vdoms[0] != "tenant-000" || vdoms[124] != "tenant-124" {
		t.Fatalf("discovered VDOMs = %d, first=%q last=%q", len(vdoms), vdoms[0], vdoms[len(vdoms)-1])
	}
}

type managedFortiGateAPIResponse struct {
	Success    bool                   `json:"success"`
	Record     managedFortiGateView   `json:"record"`
	Records    []managedFortiGateView `json:"records"`
	TotalCount int                    `json:"totalCount"`
}

type managedFortiGateTestAPIResponse struct {
	Success bool           `json:"success"`
	Record  fortinetStatus `json:"record"`
}

type managedFortiGateStatusAPIResponse struct {
	Success    bool             `json:"success"`
	Records    []fortinetStatus `json:"records"`
	TotalCount int              `json:"totalCount"`
}

func managedFortiGateTestState(t *testing.T, users ...editableUser) *state {
	t.Helper()
	s := workflowTestState(t, users...)
	p := validEditablePolicy()
	p.Users[0].Role = "admin"
	p.Users = append(p.Users, users...)
	if err := s.publishPolicy(p); err != nil {
		t.Fatal(err)
	}
	return s
}

func callManagedFortiGateAdmin(t *testing.T, s *state, method, rawBody, email string) *httptest.ResponseRecorder {
	t.Helper()
	request, _ := ownerRequest(method, "/admin/fortigates", rawBody, email)
	if rawBody != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	s.adminFortiGates(recorder, request)
	return recorder
}

func callManagedFortiGateJSON(t *testing.T, s *state, method, email string, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return callManagedFortiGateAdmin(t, s, method, string(encoded), email)
}

func createManagedFortiGateForTest(t *testing.T, s *state, name, endpoint, token string, enabled bool) (managedFortiGateView, managedFortiGate) {
	t.Helper()
	response := callManagedFortiGateJSON(t, s, http.MethodPost, "admin@example.net", map[string]any{
		"name": name, "url": endpoint, "vdom": "root", "token": token, "enabled": enabled,
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("create response = %d, body = %s", response.Code, response.Body.String())
	}
	var decoded managedFortiGateAPIResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	stored, err := s.readManagedFortiGate(decoded.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	return decoded.Record, stored
}

func pointManagedFortiGateAtTLSServerForTest(t *testing.T, s *state, server *httptest.Server, token string) (managedFortiGateView, managedFortiGate) {
	t.Helper()
	view, stored := createManagedFortiGateForTest(t, s, "managed-tls-edge", "https://managed-tls-edge.example.net", token, true)
	stored.URL = server.URL
	stored.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	stored.Revision++
	if err := s.replaceManagedFortiGate(stored, view.Revision); err != nil {
		t.Fatal(err)
	}
	view.URL = stored.URL
	view.Revision = stored.Revision
	view.CAConfigured = true
	return view, stored
}

func callManagedFortiGateTest(t *testing.T, s *state, id, email string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(managedFortiGateTestRequest{ID: id})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := ownerRequest(http.MethodPost, "/admin/fortigates/test", string(body), email)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	s.adminTestFortiGate(recorder, request)
	return recorder
}

func assertSecretAbsentFromManagedFortiGateStores(t *testing.T, s *state, secret string, responseBodies ...string) {
	t.Helper()
	for _, body := range responseBodies {
		if strings.Contains(body, secret) {
			t.Fatal("FortiGate API response disclosed the API token")
		}
		if strings.Contains(body, `"credential_id"`) {
			t.Fatal("FortiGate API response disclosed the credential reference")
		}
	}

	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id, canonical_name, name, url, vdom, ca_pem, credential_id, created_by, updated_by FROM managed_fortigate`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var values [9]string
		if err := rows.Scan(&values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6], &values[7], &values[8]); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		for _, value := range values {
			if strings.Contains(value, secret) {
				rows.Close()
				t.Fatal("managed_fortigate persisted the API token")
			}
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	auditRows, err := db.Query(`SELECT actor, action, result, metadata FROM policy_audit WHERE action LIKE 'fortigate.%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer auditRows.Close()
	for auditRows.Next() {
		var actor, action, result, metadata string
		if err := auditRows.Scan(&actor, &action, &result, &metadata); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join([]string{actor, action, result, metadata}, "\n"), secret) {
			t.Fatal("FortiGate audit event disclosed the API token")
		}
	}
	if err := auditRows.Err(); err != nil {
		t.Fatal(err)
	}

	// SQLite may keep recent writes in its WAL. Scan both durable database files
	// so a future schema or audit change cannot accidentally persist the token.
	for _, suffix := range []string{"", "-wal"} {
		data, readErr := os.ReadFile(filepath.Join(s.config.NetspocData, "policyweb.sqlite") + suffix)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			t.Fatal(readErr)
		}
		if strings.Contains(string(data), secret) {
			t.Fatalf("policyweb.sqlite%s contains the API token", suffix)
		}
	}
}

func TestManagedFortiGateCRUDIsAdminOnly(t *testing.T) {
	s := managedFortiGateTestState(t,
		editableUser{Email: "editor@example.net", Role: "editor"},
		editableUser{Email: "reviewer@example.net", Role: "reviewer"},
		editableUser{Email: "deployer@example.net", Role: "deployer"},
		editableUser{Email: "viewer@example.net", Role: "viewer"},
	)
	body := `{"name":"blocked","url":"https://blocked.example.net","vdom":"root","token":"must-not-be-stored"}`
	for _, email := range []string{"editor@example.net", "reviewer@example.net", "deployer@example.net", "viewer@example.net", "unknown@example.net"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
			response := callManagedFortiGateAdmin(t, s, method, body, email)
			if response.Code != http.StatusForbidden {
				t.Errorf("%s %s response = %d, want 403", email, method, response.Code)
			}
		}
	}
	records, err := s.readManagedFortiGates(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("denied requests changed managed FortiGates: %#v", records)
	}
	if _, err := os.Stat(filepath.Join(s.config.UserDir, ".fortigate-credentials")); !os.IsNotExist(err) {
		t.Fatalf("denied requests touched credential storage: %v", err)
	}

	response := callManagedFortiGateAdmin(t, s, http.MethodPatch, "", "admin@example.net")
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported admin method response = %d, want 405", response.Code)
	}
}

func TestManagedFortiGateCreatePersistsCredentialSafelyAndMergesAtRuntime(t *testing.T) {
	const secret = "managed-token-that-must-never-leak-123456"
	s := managedFortiGateTestState(t)
	t.Setenv("STATIC_FGT_TOKEN", "static-secret")
	staticTarget := FortinetTarget{
		Name: "static-edge", Type: "fortigate", URL: "https://static-edge.example.net", VDOM: "root", TokenEnv: "STATIC_FGT_TOKEN",
	}
	s.config.FortinetTargets = []FortinetTarget{staticTarget}

	createResponse := callManagedFortiGateJSON(t, s, http.MethodPost, "admin@example.net", map[string]any{
		"name": "managed-edge", "url": "https://MANAGED-edge.example.net:443/", "vdom": "root", "token": secret,
	})
	createBody := createResponse.Body.String()
	if createResponse.Code != http.StatusCreated || createResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create response = %d cache=%q body=%s", createResponse.Code, createResponse.Header().Get("Cache-Control"), createBody)
	}
	var created managedFortiGateAPIResponse
	if err := json.Unmarshal([]byte(createBody), &created); err != nil {
		t.Fatal(err)
	}
	if !created.Success || created.Record.Name != "managed-edge" || created.Record.URL != "https://managed-edge.example.net" ||
		created.Record.VDOM != "root" || created.Record.Revision != 1 || !created.Record.Editable ||
		created.Record.ManagedBy != "web" || !created.Record.TokenConfigured || !created.Record.Enabled {
		t.Fatalf("created view = %#v", created.Record)
	}
	stored, err := s.readManagedFortiGate(created.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	credentialDir := filepath.Join(s.config.UserDir, ".fortigate-credentials")
	directoryInfo, err := os.Stat(credentialDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("credential directory mode = %o, want 700", got)
	}
	credentialPath := filepath.Join(credentialDir, stored.CredentialID)
	credentialInfo, err := os.Stat(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := credentialInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("credential mode = %o, want 600", got)
	}
	credential, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(credential) != secret {
		t.Fatal("credential file does not contain the exact submitted token")
	}

	listResponse := callManagedFortiGateAdmin(t, s, http.MethodGet, "", "admin@example.net")
	listBody := listResponse.Body.String()
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list response = %d body=%s", listResponse.Code, listBody)
	}
	var listed managedFortiGateAPIResponse
	if err := json.Unmarshal([]byte(listBody), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.TotalCount != 2 || len(listed.Records) != 2 {
		t.Fatalf("listed records = %#v", listed)
	}
	var configured, managed *managedFortiGateView
	for index := range listed.Records {
		record := &listed.Records[index]
		switch record.Name {
		case "static-edge":
			configured = record
		case "managed-edge":
			managed = record
		}
	}
	if configured == nil || configured.Editable || configured.ManagedBy != "configuration" || !configured.TokenConfigured {
		t.Fatalf("configured target view = %#v", configured)
	}
	if managed == nil || !managed.Editable || managed.ManagedBy != "web" || !managed.TokenConfigured {
		t.Fatalf("managed target view = %#v", managed)
	}
	assertSecretAbsentFromManagedFortiGateStores(t, s, secret, createBody, listBody)

	targets, err := s.routingFortinetTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].Name != "static-edge" || targets[1].Name != "managed-edge" || targets[1].AllowDeploy || len(targets[1].TargetContexts) != 0 {
		t.Fatalf("runtime targets = %#v", targets)
	}
	if token, err := targets[1].apiToken(); err != nil || token != secret {
		t.Fatalf("managed runtime credential unavailable: token-length=%d err=%v", len(token), err)
	}

	// A newly constructed state simulates a process restart. Both metadata and
	// the credential must be recovered solely from persistent stores.
	restarted := &state{
		config: &config{NetspocData: s.config.NetspocData, UserDir: s.config.UserDir, FortinetTargets: []FortinetTarget{staticTarget}},
		cache:  newCache(s.config.NetspocData, 8),
	}
	restartedTargets, err := restarted.routingFortinetTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(restartedTargets) != 2 || restartedTargets[1].managedID != created.Record.ID {
		t.Fatalf("restart did not reload managed target: %#v", restartedTargets)
	}
	if token, err := restartedTargets[1].apiToken(); err != nil || token != secret {
		t.Fatalf("restart did not reload credential: token-length=%d err=%v", len(token), err)
	}
}

func TestManagedFortiGateUpdateRequiresTokenForURLChangeAndChecksRevision(t *testing.T) {
	const oldSecret = "old-managed-token-123"
	const newSecret = "new-managed-token-456"
	s := managedFortiGateTestState(t)
	view, original := createManagedFortiGateForTest(t, s, "edge", "https://edge.example.net", oldSecret, true)
	oldCredentialPath := filepath.Join(s.config.UserDir, ".fortigate-credentials", original.CredentialID)

	withoutToken := map[string]any{
		"id": view.ID, "revision": view.Revision, "name": "edge", "url": "https://new-edge.example.net", "vdom": "root", "enabled": true,
	}
	response := callManagedFortiGateJSON(t, s, http.MethodPut, "admin@example.net", withoutToken)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "requires a new API token") {
		t.Fatalf("URL change without token response = %d body=%s", response.Code, response.Body.String())
	}
	unchanged, err := s.readManagedFortiGate(view.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.URL != original.URL || unchanged.Revision != original.Revision || unchanged.CredentialID != original.CredentialID {
		t.Fatalf("rejected URL change modified record: %#v", unchanged)
	}

	stale := map[string]any{
		"id": view.ID, "revision": view.Revision + 1, "name": "edge-renamed", "url": original.URL, "vdom": "root", "enabled": true,
	}
	response = callManagedFortiGateJSON(t, s, http.MethodPut, "admin@example.net", stale)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale update response = %d body=%s", response.Code, response.Body.String())
	}

	valid := map[string]any{
		"id": view.ID, "revision": view.Revision, "name": "edge-renamed", "url": "https://new-edge.example.net", "vdom": "tenant-a", "enabled": true, "token": newSecret,
	}
	response = callManagedFortiGateJSON(t, s, http.MethodPut, "admin@example.net", valid)
	validBody := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("valid update response = %d body=%s", response.Code, validBody)
	}
	var updatedResponse managedFortiGateAPIResponse
	if err := json.Unmarshal([]byte(validBody), &updatedResponse); err != nil {
		t.Fatal(err)
	}
	if updatedResponse.Record.Revision != view.Revision+1 || updatedResponse.Record.Name != "edge-renamed" || updatedResponse.Record.URL != "https://new-edge.example.net" {
		t.Fatalf("updated view = %#v", updatedResponse.Record)
	}
	updated, err := s.readManagedFortiGate(view.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.CredentialID == original.CredentialID {
		t.Fatal("credential rotation reused the old credential identifier")
	}
	if _, err := os.Stat(oldCredentialPath); !os.IsNotExist(err) {
		t.Fatalf("old credential was not removed: %v", err)
	}
	if token, err := s.readManagedFortiGateCredential(updated.CredentialID); err != nil || token != newSecret {
		t.Fatalf("rotated credential unavailable: token-length=%d err=%v", len(token), err)
	}
	assertSecretAbsentFromManagedFortiGateStores(t, s, oldSecret, validBody)
	assertSecretAbsentFromManagedFortiGateStores(t, s, newSecret, validBody)

	response = callManagedFortiGateJSON(t, s, http.MethodPut, "admin@example.net", valid)
	if response.Code != http.StatusConflict {
		t.Fatalf("replayed update response = %d body=%s", response.Code, response.Body.String())
	}
}

func TestManagedFortiGateDeleteAndStaticTargetsRemainReadOnly(t *testing.T) {
	s := managedFortiGateTestState(t)
	t.Setenv("STATIC_DELETE_TOKEN", "static-token")
	staticTarget := FortinetTarget{Name: "static", Type: "fortigate", URL: "https://static.example.net", VDOM: "root", TokenEnv: "STATIC_DELETE_TOKEN"}
	s.config.FortinetTargets = []FortinetTarget{staticTarget}
	view, stored := createManagedFortiGateForTest(t, s, "managed", "https://managed.example.net", "delete-me-token", true)
	credentialPath := filepath.Join(s.config.UserDir, ".fortigate-credentials", stored.CredentialID)

	staticID := configuredFortiGateID(staticTarget)
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		response := callManagedFortiGateJSON(t, s, method, "admin@example.net", map[string]any{
			"id": staticID, "revision": 1, "name": "changed", "url": "https://changed.example.net", "vdom": "root", "token": "replacement",
		})
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s configured target response = %d body=%s", method, response.Code, response.Body.String())
		}
	}
	if !reflect.DeepEqual(s.config.FortinetTargets[0], staticTarget) {
		t.Fatal("attempt to edit configured target changed static configuration")
	}

	response := callManagedFortiGateJSON(t, s, http.MethodDelete, "admin@example.net", map[string]any{"id": view.ID, "revision": view.Revision + 1})
	if response.Code != http.StatusConflict {
		t.Fatalf("stale delete response = %d body=%s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(credentialPath); err != nil {
		t.Fatalf("stale delete removed credential: %v", err)
	}

	response = callManagedFortiGateJSON(t, s, http.MethodDelete, "admin@example.net", map[string]any{"id": view.ID, "revision": view.Revision})
	deleteBody := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("delete response = %d body=%s", response.Code, deleteBody)
	}
	if _, err := s.readManagedFortiGate(view.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted record is still readable: %v", err)
	}
	if _, err := os.Stat(credentialPath); !os.IsNotExist(err) {
		t.Fatalf("deleted credential is still present: %v", err)
	}
	targets, err := s.routingFortinetTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Name != staticTarget.Name {
		t.Fatalf("runtime targets after delete = %#v", targets)
	}
	assertSecretAbsentFromManagedFortiGateStores(t, s, "delete-me-token", deleteBody)

	listResponse := callManagedFortiGateAdmin(t, s, http.MethodGet, "", "admin@example.net")
	var listed managedFortiGateAPIResponse
	if err := json.NewDecoder(listResponse.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Records) != 1 || listed.Records[0].ID != staticID || listed.Records[0].Editable {
		t.Fatalf("static record after managed delete = %#v", listed.Records)
	}
}

func TestManagedFortiGateEnabledStateAndConflictValidation(t *testing.T) {
	s := managedFortiGateTestState(t)
	t.Setenv("STATIC_CONFLICT_TOKEN", "static-token")
	s.config.FortinetTargets = []FortinetTarget{{Name: "static-edge", Type: "fortigate", URL: "https://static.example.net", VDOM: "root", TokenEnv: "STATIC_CONFLICT_TOKEN"}}

	disabled, _ := createManagedFortiGateForTest(t, s, "disabled-edge", "https://disabled.example.net", "disabled-token", false)
	targets, err := s.routingFortinetTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Name != "static-edge" {
		t.Fatalf("disabled target entered runtime merge: %#v", targets)
	}

	response := callManagedFortiGateJSON(t, s, http.MethodPut, "admin@example.net", map[string]any{
		"id": disabled.ID, "revision": disabled.Revision, "name": disabled.Name, "url": disabled.URL, "vdom": disabled.VDOM, "enabled": true,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("enable response = %d body=%s", response.Code, response.Body.String())
	}
	targets, err = s.routingFortinetTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[1].Name != "disabled-edge" {
		t.Fatalf("enabled target missing from runtime merge: %#v", targets)
	}

	for name, body := range map[string]map[string]any{
		"configured name":  {"name": "STATIC-EDGE", "url": "https://other.example.net", "vdom": "root", "token": "token-one"},
		"configured scope": {"name": "other", "url": "https://static.example.net", "vdom": "root", "token": "token-two"},
		"managed name":     {"name": "DISABLED-EDGE", "url": "https://third.example.net", "vdom": "root", "token": "token-three"},
		"managed scope":    {"name": "fourth", "url": "https://disabled.example.net", "vdom": "root", "token": "token-four"},
	} {
		t.Run(name, func(t *testing.T) {
			result := callManagedFortiGateJSON(t, s, http.MethodPost, "admin@example.net", body)
			if result.Code != http.StatusConflict {
				t.Fatalf("conflict response = %d body=%s", result.Code, result.Body.String())
			}
		})
	}
	records, err := s.readManagedFortiGates(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("conflicting creates changed records: %#v", records)
	}
}

func TestManagedFortiGateRequestValidationDoesNotCreateSecrets(t *testing.T) {
	s := managedFortiGateTestState(t)
	tests := map[string]string{
		"unknown field": `{"name":"edge","url":"https://edge.example.net","vdom":"root","token":"hidden","unexpected":true}`,
		"trailing JSON": `{"name":"edge","url":"https://edge.example.net","vdom":"root","token":"hidden"}{}`,
		"path endpoint": `{"name":"edge","url":"https://edge.example.net/proxy","vdom":"root","token":"hidden"}`,
		"loopback":      `{"name":"edge","url":"https://127.0.0.1","vdom":"root","token":"hidden"}`,
		"empty name":    `{"name":"","url":"https://edge.example.net","vdom":"root","token":"hidden"}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			response := callManagedFortiGateAdmin(t, s, http.MethodPost, body, "admin@example.net")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("response = %d body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "hidden") {
				t.Fatal("validation error disclosed submitted token")
			}
		})
	}
	records, err := s.readManagedFortiGates(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("invalid requests created records: %#v", records)
	}
	if entries, err := os.ReadDir(filepath.Join(s.config.UserDir, ".fortigate-credentials")); err == nil && len(entries) != 0 {
		t.Fatalf("invalid requests left credential files: %#v", entries)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestManagedFortiGateTestAndStatusUseStoredTokenVDOMAndCA(t *testing.T) {
	const secret = "managed-tls-token-that-must-not-leak"
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/v2/monitor/system/status" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+secret {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.URL.Query().Get("vdom"); got != "root" {
			t.Errorf("vdom = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": map[string]string{"version": "v7.4.7", "serial": "FGT-MANAGED-01"},
		})
	}))
	defer server.Close()

	s := managedFortiGateTestState(t)
	view, _ := pointManagedFortiGateAtTLSServerForTest(t, s, server, secret)

	testResponse := callManagedFortiGateTest(t, s, view.ID, "admin@example.net")
	testBody := testResponse.Body.String()
	if testResponse.Code != http.StatusOK || testResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("test response = %d cache=%q body=%s", testResponse.Code, testResponse.Header().Get("Cache-Control"), testBody)
	}
	var tested managedFortiGateTestAPIResponse
	if err := json.Unmarshal([]byte(testBody), &tested); err != nil {
		t.Fatal(err)
	}
	if !tested.Success || !tested.Record.Online || tested.Record.Version != "v7.4.7" || tested.Record.Serial != "FGT-MANAGED-01" || tested.Record.Scope != "root" {
		t.Fatalf("tested record = %#v", tested.Record)
	}

	statusRequest, _ := ownerRequest(http.MethodGet, "/fortinet/status", "", "admin@example.net")
	statusResponse := httptest.NewRecorder()
	s.getFortinetStatus(statusResponse, statusRequest)
	statusBody := statusResponse.Body.String()
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("status response = %d body=%s", statusResponse.Code, statusBody)
	}
	var status managedFortiGateStatusAPIResponse
	if err := json.Unmarshal([]byte(statusBody), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Success || status.TotalCount != 1 || len(status.Records) != 1 || !status.Records[0].Online || status.Records[0].Serial != "FGT-MANAGED-01" {
		t.Fatalf("status response = %#v", status)
	}
	if requests != 2 {
		t.Fatalf("FortiGate requests = %d, want test and status", requests)
	}
	assertSecretAbsentFromManagedFortiGateStores(t, s, secret, testBody, statusBody)
}

func TestManagedFortiGateTestSuppressesRemoteErrorBodies(t *testing.T) {
	const secret = "managed+token/with sensitive value"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("rejected token " + secret + " and managed%2Btoken%2Fwith+sensitive+value"))
	}))
	defer server.Close()

	s := managedFortiGateTestState(t)
	view, _ := pointManagedFortiGateAtTLSServerForTest(t, s, server, secret)
	response := callManagedFortiGateTest(t, s, view.ID, "admin@example.net")
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("response = %d body=%s", response.Code, body)
	}
	var decoded managedFortiGateTestAPIResponse
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Record.Online || decoded.Record.Error != "Fortinet endpoint returned HTTP 502" {
		t.Fatalf("sanitized status = %#v", decoded.Record)
	}
	if strings.Contains(body, secret) || strings.Contains(body, "managed%2Btoken%2Fwith+sensitive+value") || strings.Contains(body, "rejected token") {
		t.Fatal("test endpoint disclosed a remote error body")
	}
	assertSecretAbsentFromManagedFortiGateStores(t, s, secret, body)
}

func TestManagedFortiGateTestDistinguishesLookupFailures(t *testing.T) {
	s := managedFortiGateTestState(t, editableUser{Email: "editor@example.net", Role: "editor"})
	view, stored := createManagedFortiGateForTest(t, s, "lookup-edge", "https://lookup-edge.example.net", "lookup-secret", true)

	denied := callManagedFortiGateTest(t, s, view.ID, "editor@example.net")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin test response = %d body=%s", denied.Code, denied.Body.String())
	}

	missing := callManagedFortiGateTest(t, s, strings.Repeat("a", 32), "admin@example.net")
	if missing.Code != http.StatusNotFound || !strings.Contains(missing.Body.String(), errManagedFortiGateNotFound.Error()) {
		t.Fatalf("missing target response = %d body=%s", missing.Code, missing.Body.String())
	}

	if err := s.removeManagedFortiGateCredential(stored.CredentialID); err != nil {
		t.Fatal(err)
	}
	unavailable := callManagedFortiGateTest(t, s, view.ID, "admin@example.net")
	if unavailable.Code != http.StatusConflict || !strings.Contains(unavailable.Body.String(), errManagedFortiGateCredentialUnavailable.Error()) {
		t.Fatalf("missing credential response = %d body=%s", unavailable.Code, unavailable.Body.String())
	}

	blockedPath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedPath, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousData := s.config.NetspocData
	s.config.NetspocData = blockedPath
	_, err := s.findOperationalFortiGate(strings.Repeat("b", 32))
	s.config.NetspocData = previousData
	if err == nil || errors.Is(err, errManagedFortiGateNotFound) {
		t.Fatalf("store failure was collapsed to not found: %v", err)
	}
}

func TestManagedFortiGateCredentialCleanupIsDurableAndReferenceSafe(t *testing.T) {
	s := managedFortiGateTestState(t)
	view, stored := createManagedFortiGateForTest(t, s, "cleanup-edge", "https://cleanup-edge.example.net", "active-secret", true)
	activePath := filepath.Join(s.config.UserDir, ".fortigate-credentials", stored.CredentialID)

	if err := s.queueManagedFortiGateCredentialCleanup(stored.CredentialID, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.cleanupManagedFortiGateCredentials(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(activePath); err != nil {
		t.Fatalf("cleanup removed an actively referenced credential: %v", err)
	}

	orphanID, err := randomFortiGateID(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.queueManagedFortiGateCredentialCleanup(orphanID, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.writeManagedFortiGateCredentialWithID(orphanID, "orphan-secret"); err != nil {
		t.Fatal(err)
	}
	orphanPath := filepath.Join(s.config.UserDir, ".fortigate-credentials", orphanID)
	if err := s.cleanupManagedFortiGateCredentials(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Fatalf("queued orphan credential remains: %v", err)
	}

	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var markers int
	if err := db.QueryRow(`SELECT COUNT(*) FROM managed_fortigate_credential_cleanup`).Scan(&markers); err != nil {
		t.Fatal(err)
	}
	if markers != 0 {
		t.Fatalf("credential cleanup markers = %d, want 0", markers)
	}
	if _, err := s.readManagedFortiGate(view.ID); err != nil {
		t.Fatalf("credential cleanup changed the managed target: %v", err)
	}
}
