package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMaintenanceStatus(t *testing.T) {
	s := persistentMaintenanceTestState(t)
	s.config.MaintenanceMode = true
	s.config.MaintenanceMessage = "Wartung bis 18 Uhr"
	r := httptest.NewRequest(http.MethodGet, "/maintenance-status", nil)
	w := httptest.NewRecorder()
	s.maintenanceStatus(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var result struct {
		MaintenanceMode bool   `json:"maintenance_mode"`
		Message         string `json:"message"`
	}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !result.MaintenanceMode || result.Message != "Wartung bis 18 Uhr" {
		t.Fatalf("result = %#v", result)
	}
}

func TestMaintenanceStatusDefaultMessage(t *testing.T) {
	s := persistentMaintenanceTestState(t)
	s.config.MaintenanceMode = true
	w := httptest.NewRecorder()
	s.maintenanceStatus(w, httptest.NewRequest(http.MethodGet, "/maintenance-status", nil))
	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["message"] == "" {
		t.Fatal("default maintenance message is empty")
	}
}

func TestMaintenanceLoginOnlyAllowsPolicyAdminsAndDevelopers(t *testing.T) {
	p := &editablePolicy{Users: []editableUser{
		{Email: "admin@example.org", Role: "admin"},
		{Email: "developer@example.org", Role: policyDeveloperRole},
		{Email: "editor@example.org", Role: "editor"},
	}}
	if !maintenanceLoginAllowed(p, " ADMIN@example.org ") {
		t.Fatal("administrator was rejected")
	}
	if !maintenanceLoginAllowed(p, "developer@example.org") {
		t.Fatal("developer was rejected")
	}
	if maintenanceLoginAllowed(p, "editor@example.org") {
		t.Fatal("editor was accepted")
	}
	if maintenanceLoginAllowed(p, "guest") {
		t.Fatal("guest was accepted")
	}
}

func persistentMaintenanceTestState(t *testing.T) *state {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "policies")
	return &state{
		config: &config{NetspocData: dataDir},
		cache:  newCache(dataDir, 2),
	}
}

func storeRawMaintenanceSettings(t *testing.T, s *state, enabled any, startsAt, endsAt string) {
	t.Helper()
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ensureMaintenanceTable(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO maintenance_settings(id, enabled, message, starts_at, ends_at, updated_by, updated_at)
		VALUES(1, ?, 'stored message', ?, ?, 'tester@example.net', '2026-08-27T08:00:00Z')`, enabled, startsAt, endsAt); err != nil {
		t.Fatal(err)
	}
}

func TestMissingMaintenanceRowUsesConfiguredSettings(t *testing.T) {
	s := persistentMaintenanceTestState(t)
	s.config.MaintenanceMode = true
	s.config.MaintenanceMessage = "configured message"

	settings, err := s.loadMaintenanceSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.Enabled || settings.Message != "configured message" {
		t.Fatalf("settings = %#v", settings)
	}
}

func TestMaintenanceDatabaseFailureIsFailClosedAndPublicStatusIsSafe(t *testing.T) {
	root := t.TempDir()
	dataPath := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(dataPath, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &state{config: &config{
		NetspocData:        dataPath,
		MaintenanceMode:    false,
		MaintenanceMessage: "must not be used",
	}}

	active, settings, err := s.effectiveMaintenanceWithError()
	if err == nil {
		t.Fatal("database failure was hidden by configuration fallback")
	}
	if !active || !settings.Enabled || settings.Message != "" {
		t.Fatalf("fail-closed result = active %v, settings %#v", active, settings)
	}

	w := httptest.NewRecorder()
	s.maintenanceStatus(w, httptest.NewRequest(http.MethodGet, "/maintenance-status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var result struct {
		MaintenanceMode bool   `json:"maintenance_mode"`
		Message         string `json:"message"`
	}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !result.MaintenanceMode || result.Message == "" || result.Message == "must not be used" {
		t.Fatalf("unsafe public status = %#v", result)
	}
	if strings.Contains(result.Message, dataPath) || strings.Contains(strings.ToLower(result.Message), "database") {
		t.Fatalf("public status leaked internal error details: %q", result.Message)
	}
}

func TestMaintenanceSchemaFailureIsFailClosedButAdminsRemainAllowed(t *testing.T) {
	s := persistentMaintenanceTestState(t)
	p := validEditablePolicy()
	seedPolicyTestAccounts(t, s, p.Users...)
	if err := s.storePublication("maintenance-schema-auth", p); err != nil {
		t.Fatal(err)
	}
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE maintenance_settings (id INTEGER PRIMARY KEY)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	active, settings, loadErr := s.effectiveMaintenanceWithError()
	if loadErr == nil || !active || !settings.Enabled {
		t.Fatalf("schema failure was not fail-closed: active %v, settings %#v, error %v", active, settings, loadErr)
	}
	admin := p.Users[0].Email
	if !maintenanceRequestAllowed(active, s.authorizationPolicy(), admin) {
		t.Fatal("fail-closed maintenance rejected an administrator")
	}
	if maintenanceRequestAllowed(active, s.authorizationPolicy(), "viewer@example.net") {
		t.Fatal("fail-closed maintenance accepted a non-administrator")
	}

	session := newSession()
	session.Put("email", admin)
	request := httptest.NewRequest(http.MethodGet, "/admin/maintenance", nil)
	request = request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, session))
	w := httptest.NewRecorder()
	s.adminMaintenance(w, request)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("admin GET status = %d, body = %s", w.Code, w.Body.String())
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "column") || !strings.Contains(w.Body.String(), "Wartungsmodus") {
		t.Fatalf("admin GET returned unsafe or unclear response: %s", w.Body.String())
	}
}

func TestMaintenanceScanFailureIsFailClosed(t *testing.T) {
	s := persistentMaintenanceTestState(t)
	storeRawMaintenanceSettings(t, s, "not-an-integer", "", "")

	active, settings, err := s.effectiveMaintenanceWithError()
	if err == nil || !active || !settings.Enabled {
		t.Fatalf("scan failure was not fail-closed: active %v, settings %#v, error %v", active, settings, err)
	}
}

func TestInvalidStoredMaintenanceTimeIsFailClosed(t *testing.T) {
	s := persistentMaintenanceTestState(t)
	// Even an otherwise disabled row is unsafe when its persisted schedule is
	// malformed: the application cannot reliably determine the intended state.
	storeRawMaintenanceSettings(t, s, 0, "not-rfc3339", "")

	active, settings, err := s.effectiveMaintenanceWithError()
	if err == nil || !active || !settings.Enabled {
		t.Fatalf("invalid stored timestamp was not fail-closed: active %v, settings %#v, error %v", active, settings, err)
	}
	if !maintenanceActiveAt(maintenanceSettings{Enabled: false, StartsAt: "invalid"}, time.Now().UTC()) {
		t.Fatal("maintenanceActiveAt failed open for an invalid schedule")
	}
}
