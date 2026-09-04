package backend

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	setupTestToken    = "bootstrap-super-secret"
	setupTestPassword = "correct horse battery staple"
)

func newSetupTestState(t *testing.T) *state {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "policies")
	return &state{
		config: &config{NetspocData: data, UserDir: filepath.Join(root, "users")},
		cache:  newCache(data, 8),
	}
}

func setupRequestBody(email, password string) string {
	encoded, _ := json.Marshal(setupRequest{
		Email:                email,
		Password:             password,
		PasswordConfirmation: password,
	})
	return string(encoded)
}

func performSetupRequest(s *state, body, token, contentType string) (*httptest.ResponseRecorder, *GoSession) {
	request := httptest.NewRequest(http.MethodPost, "https://policy.example.test/setup", strings.NewReader(body))
	if token != "" {
		request.Header.Set("X-PolicyWeb-Bootstrap-Token", token)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	session := newSession()
	request = request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, session))
	recorder := httptest.NewRecorder()
	requireBootstrapToken(http.HandlerFunc(s.setup)).ServeHTTP(recorder, request)
	return recorder, session
}

func TestSetupCreatesPublishedAdminCredentialAndAuthenticatedSession(t *testing.T) {
	t.Setenv("POLICYWEB_BOOTSTRAP_TOKEN", setupTestToken)
	s := newSetupTestState(t)
	body := `{"email":" Admin.User@Example.TEST ","password":"` + setupTestPassword + `","password_confirmation":"` + setupTestPassword + `","policy_name":"initial-policy","owner_name":"network-admins"}`
	recorder, session := performSetupRequest(s, body, setupTestToken, "application/json; charset=utf-8")

	if recorder.Code != http.StatusCreated {
		t.Fatalf("setup status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if session.Get("loggedIn") != true || session.Get("email") != "admin.user@example.test" {
		t.Fatalf("setup did not authenticate canonical account: %#v", session.Data)
	}
	if !s.policyInitialized() {
		t.Fatal("setup did not initialize policy administration")
	}
	policy, err := s.latestPublication()
	if err != nil {
		t.Fatal(err)
	}
	if policy == nil || policy.Name != "initial-policy" || policyRole(policy, "admin.user@example.test") != "admin" {
		t.Fatalf("unexpected initial policy: %#v", policy)
	}
	if len(policy.Owners) != 1 || policy.Owners[0].Name != "network-admins" || len(policy.Owners[0].Admins) != 1 || policy.Owners[0].Admins[0] != "admin.user@example.test" {
		t.Fatalf("initial owner does not grant administrator access: %#v", policy.Owners)
	}
	if err := validateEditablePolicy(policy); err != nil {
		t.Fatalf("published initial policy is invalid: %v", err)
	}

	userFile, err := safeUserFile(s.config.UserDir, "admin.user@example.test")
	if err != nil {
		t.Fatal(err)
	}
	store, err := GetUserStore(userFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(store.Hash, "$argon2id$") || !store.CheckPassword(setupTestPassword) {
		t.Fatalf("setup credential is not a valid Argon2id hash: %q", store.Hash)
	}
	if info, err := os.Stat(userFile); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode = %#o, want 0600", info.Mode().Perm())
	}

	response := recorder.Body.String()
	if strings.Contains(response, setupTestPassword) || strings.Contains(response, setupTestToken) || strings.Contains(response, store.Hash) {
		t.Fatalf("setup response exposed a credential: %s", response)
	}
	database, err := os.ReadFile(filepath.Join(s.config.NetspocData, "policyweb.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(database), setupTestPassword) || strings.Contains(string(database), setupTestToken) {
		t.Fatal("a setup secret was written to SQLite")
	}
}

func TestSetupRequiresConfiguredBootstrapToken(t *testing.T) {
	s := newSetupTestState(t)
	body := setupRequestBody("admin@example.test", setupTestPassword)

	t.Setenv("POLICYWEB_BOOTSTRAP_TOKEN", setupTestToken)
	for name, token := range map[string]string{"missing": "", "wrong": "wrong-token"} {
		t.Run(name, func(t *testing.T) {
			recorder, _ := performSetupRequest(s, body, token, "application/json")
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("setup status = %d, want 403", recorder.Code)
			}
		})
	}
	t.Setenv("POLICYWEB_BOOTSTRAP_TOKEN", "")
	recorder, _ := performSetupRequest(s, body, setupTestToken, "application/json")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("setup without server token status = %d, want 403", recorder.Code)
	}
	if s.policyInitialized() {
		t.Fatal("unauthorized setup initialized policy administration")
	}
}

func TestSetupAcceptsOnlyStrictBoundedJSON(t *testing.T) {
	t.Setenv("POLICYWEB_BOOTSTRAP_TOKEN", setupTestToken)
	valid := setupRequestBody("admin@example.test", setupTestPassword)
	tests := []struct {
		name        string
		body        string
		contentType string
		status      int
	}{
		{name: "missing content type", body: valid, status: http.StatusUnsupportedMediaType},
		{name: "wrong content type", body: valid, contentType: "text/plain", status: http.StatusUnsupportedMediaType},
		{name: "unknown field", body: strings.TrimSuffix(valid, "}") + `,"is_admin":true}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "second document", body: valid + ` {}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "malformed", body: `{"email":`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "oversized", body: `{"email":"admin@example.test","password":"` + strings.Repeat("x", setupRequestLimit) + `"}`, contentType: "application/json", status: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newSetupTestState(t)
			recorder, _ := performSetupRequest(s, test.body, setupTestToken, test.contentType)
			if recorder.Code != test.status {
				t.Fatalf("setup status = %d, want %d; body=%s", recorder.Code, test.status, recorder.Body.String())
			}
			if s.policyInitialized() {
				t.Fatal("invalid request initialized policy administration")
			}
		})
	}
}

func TestSetupValidatesAccountPasswordAndNames(t *testing.T) {
	t.Setenv("POLICYWEB_BOOTSTRAP_TOKEN", setupTestToken)
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid email", body: `{"email":"not-an-email","password":"` + setupTestPassword + `","password_confirmation":"` + setupTestPassword + `"}`},
		{name: "short password", body: `{"email":"admin@example.test","password":"too-short","password_confirmation":"too-short"}`},
		{name: "mismatched confirmation", body: `{"email":"admin@example.test","password":"` + setupTestPassword + `","password_confirmation":"something completely different"}`},
		{name: "invalid policy name", body: `{"email":"admin@example.test","password":"` + setupTestPassword + `","password_confirmation":"` + setupTestPassword + `","policy_name":"../policy"}`},
		{name: "invalid owner name", body: `{"email":"admin@example.test","password":"` + setupTestPassword + `","password_confirmation":"` + setupTestPassword + `","owner_name":"owner name"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newSetupTestState(t)
			recorder, session := performSetupRequest(s, test.body, setupTestToken, "application/json")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("setup status = %d, want 400; body=%s", recorder.Code, recorder.Body.String())
			}
			if session.Get("loggedIn") == true || s.policyInitialized() {
				t.Fatal("invalid setup authenticated a session or initialized a policy")
			}
		})
	}
}

func TestSetupCannotRunAfterInitialization(t *testing.T) {
	t.Setenv("POLICYWEB_BOOTSTRAP_TOKEN", setupTestToken)
	s := newSetupTestState(t)
	first, _ := performSetupRequest(s, setupRequestBody("first@example.test", setupTestPassword), setupTestToken, "application/json")
	if first.Code != http.StatusCreated {
		t.Fatalf("first setup failed: %d %s", first.Code, first.Body.String())
	}
	secondPassword := "a different secure password"
	second, secondSession := performSetupRequest(s, setupRequestBody("second@example.test", secondPassword), setupTestToken, "application/json")
	if second.Code != http.StatusConflict {
		t.Fatalf("second setup status = %d, want 409; body=%s", second.Code, second.Body.String())
	}
	if secondSession.Get("loggedIn") == true {
		t.Fatal("repeated setup authenticated its anonymous session")
	}
	secondFile, _ := safeUserFile(s.config.UserDir, "second@example.test")
	if _, err := os.Stat(secondFile); !os.IsNotExist(err) {
		t.Fatalf("repeated setup created a second credential: %v", err)
	}
	policy, err := s.latestPublication()
	if err != nil || policy == nil || policy.Users[0].Email != "first@example.test" {
		t.Fatalf("repeated setup replaced initial policy: policy=%#v err=%v", policy, err)
	}
}

func TestSetupDoesNotOverwriteExistingLocalCredential(t *testing.T) {
	t.Setenv("POLICYWEB_BOOTSTRAP_TOKEN", setupTestToken)
	s := newSetupTestState(t)
	oldPassword := "operator-created password"
	if err := SetUserPassword(s.config.UserDir, "admin@example.test", oldPassword); err != nil {
		t.Fatal(err)
	}
	recorder, _ := performSetupRequest(s, setupRequestBody("admin@example.test", setupTestPassword), setupTestToken, "application/json")
	if recorder.Code != http.StatusConflict {
		t.Fatalf("setup status = %d, want 409; body=%s", recorder.Code, recorder.Body.String())
	}
	userFile, _ := safeUserFile(s.config.UserDir, "admin@example.test")
	store, err := GetUserStore(userFile)
	if err != nil {
		t.Fatal(err)
	}
	if !store.CheckPassword(oldPassword) || store.CheckPassword(setupTestPassword) {
		t.Fatal("setup overwrote an operator-created local credential")
	}
	if s.policyInitialized() {
		t.Fatal("credential conflict still initialized policy administration")
	}
}

func TestSetupCredentialCreateOnlyAndCompareBeforeRollback(t *testing.T) {
	userDir := t.TempDir()
	userFile, setupHash, err := createSetupUserPassword(userDir, "admin@example.test", setupTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := createSetupUserPassword(userDir, "admin@example.test", "another secure password"); !errors.Is(err, errSetupAccountExists) {
		t.Fatalf("create-only credential overwrote an existing account: %v", err)
	}
	operatorPassword := "operator changed this password"
	if err := SetUserPassword(userDir, "admin@example.test", operatorPassword); err != nil {
		t.Fatal(err)
	}
	rollbackSetupCredential(userFile, setupHash)
	store, err := GetUserStore(userFile)
	if err != nil {
		t.Fatalf("rollback removed an operator-updated credential: %v", err)
	}
	if !store.CheckPassword(operatorPassword) {
		t.Fatal("operator-updated credential was changed during rollback")
	}

	secondFile, secondHash, err := createSetupUserPassword(userDir, "second@example.test", setupTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	rollbackSetupCredential(secondFile, secondHash)
	if _, err := os.Stat(secondFile); !os.IsNotExist(err) {
		t.Fatalf("unchanged setup credential was not rolled back: %v", err)
	}
}

func TestSetupRollsBackCredentialWhenPublicationFails(t *testing.T) {
	t.Setenv("POLICYWEB_BOOTSTRAP_TOKEN", setupTestToken)
	s := newSetupTestState(t)
	if err := os.MkdirAll(s.config.NetspocData, 0o750); err != nil {
		t.Fatal(err)
	}
	// Publication requires current to be absent or a symlink. A regular file
	// deterministically fails after the password has been written.
	if err := os.WriteFile(filepath.Join(s.config.NetspocData, "current"), []byte("blocked"), 0o640); err != nil {
		t.Fatal(err)
	}
	recorder, session := performSetupRequest(s, setupRequestBody("admin@example.test", setupTestPassword), setupTestToken, "application/json")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("setup status = %d, want 500; body=%s", recorder.Code, recorder.Body.String())
	}
	userFile, _ := safeUserFile(s.config.UserDir, "admin@example.test")
	if _, err := os.Stat(userFile); !os.IsNotExist(err) {
		t.Fatalf("failed setup left a usable credential behind: %v", err)
	}
	if session.Get("loggedIn") == true || s.policyInitialized() {
		t.Fatal("failed setup authenticated a session or published authorization")
	}
	if strings.Contains(recorder.Body.String(), setupTestPassword) || strings.Contains(recorder.Body.String(), setupTestToken) {
		t.Fatal("failed setup exposed a secret")
	}
	if err := os.Remove(filepath.Join(s.config.NetspocData, "current")); err != nil {
		t.Fatal(err)
	}
	retry, _ := performSetupRequest(s, setupRequestBody("admin@example.test", setupTestPassword), setupTestToken, "application/json")
	if retry.Code != http.StatusCreated {
		t.Fatalf("setup claim was not rolled back after failure: %d %s", retry.Code, retry.Body.String())
	}
}

func TestParallelSetupSucceedsAtMostOnce(t *testing.T) {
	t.Setenv("POLICYWEB_BOOTSTRAP_TOKEN", setupTestToken)
	s := newSetupTestState(t)
	const attempts = 8
	start := make(chan struct{})
	var wait sync.WaitGroup
	statuses := make(chan int, attempts)
	for i := 0; i < attempts; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			email := fmt.Sprintf("admin-%d@example.test", index)
			recorder, _ := performSetupRequest(s, setupRequestBody(email, setupTestPassword), setupTestToken, "application/json")
			statuses <- recorder.Code
		}(i)
	}
	close(start)
	wait.Wait()
	close(statuses)

	created, conflicts := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("parallel setup returned unexpected status %d", status)
		}
	}
	if created != 1 || conflicts != attempts-1 {
		t.Fatalf("parallel results: created=%d conflicts=%d", created, conflicts)
	}
	policy, err := s.latestPublication()
	if err != nil || policy == nil || len(policy.Users) != 1 {
		t.Fatalf("parallel setup produced invalid publication: policy=%#v err=%v", policy, err)
	}
	files, err := os.ReadDir(s.config.UserDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name() != policy.Users[0].Email {
		t.Fatalf("parallel setup credentials = %#v, published user = %q", files, policy.Users[0].Email)
	}
}

func TestSetupClaimIsSharedByIndependentStates(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "policies")
	config := &config{NetspocData: data, UserDir: filepath.Join(root, "users")}
	first := &state{config: config, cache: newCache(data, 8)}
	second := &state{config: config, cache: newCache(data, 8)}

	release, err := first.acquireSetupClaim()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.acquireSetupClaim(); !errors.Is(err, errSetupAlreadyClaimed) {
		t.Fatalf("independent state acquired the same setup claim: %v", err)
	}
	release.Release()
	release, err = second.acquireSetupClaim()
	if err != nil {
		t.Fatalf("rolled-back setup claim remained reserved: %v", err)
	}
	release.Release()
	finalRelease, err := first.acquireSetupClaim()
	if err != nil {
		t.Fatalf("released setup claim remained reserved: %v", err)
	}
	finalRelease.Release()
}

func TestSetupClaimRecoversAfterExpiredLeaseWithoutDeletingNewOwner(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "policies")
	config := &config{NetspocData: data, UserDir: filepath.Join(root, "users")}
	first := &state{config: config, cache: newCache(data, 8)}
	second := &state{config: config, cache: newCache(data, 8)}

	staleRelease, err := first.acquireSetupClaim()
	if err != nil {
		t.Fatal(err)
	}
	db, err := first.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`UPDATE policy_setup_guard SET claimed_at=? WHERE id=1`, time.Now().Add(-setupClaimLease-time.Minute).Unix())
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}

	activeRelease, err := second.acquireSetupClaim()
	if err != nil {
		t.Fatalf("expired setup lease was not recovered: %v", err)
	}
	staleRelease.Release()
	if _, err := first.acquireSetupClaim(); !errors.Is(err, errSetupAlreadyClaimed) {
		t.Fatalf("stale release removed the active claim: %v", err)
	}
	activeRelease.Release()
	finalRelease, err := first.acquireSetupClaim()
	if err != nil {
		t.Fatalf("active claim was not released: %v", err)
	}
	finalRelease.Release()
}

func TestExpiredSetupClaimRemovesOnlyItsExactOrphanCredential(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "policies")
	config := &config{NetspocData: data, UserDir: filepath.Join(root, "users")}
	first := &state{config: config, cache: newCache(data, 8)}
	second := &state{config: config, cache: newCache(data, 8)}

	staleClaim, err := first.acquireSetupClaim()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := prepareSetupUserPassword(config.UserDir, "orphan@example.test", setupTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.recordSetupClaimCredential(staleClaim.ID, "orphan@example.test", credential.Digest, newPolicyVersion(), credential.Digest, 0); err != nil {
		t.Fatal(err)
	}
	if err := createPreparedSetupCredential(credential); err != nil {
		t.Fatal(err)
	}
	db, err := first.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`UPDATE policy_setup_guard SET claimed_at=? WHERE id=1`, time.Now().Add(-setupClaimLease-time.Minute).Unix())
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := second.acquireSetupClaim()
	if err != nil {
		t.Fatalf("stale setup with credential was not recovered: %v", err)
	}
	if _, err := os.Stat(credential.UserFile); !os.IsNotExist(err) {
		t.Fatalf("stale setup credential remains after takeover: %v", err)
	}
	staleClaim.Release()
	if _, err := first.acquireSetupClaim(); !errors.Is(err, errSetupAlreadyClaimed) {
		t.Fatalf("old release removed recovered setup claim: %v", err)
	}
	recovered.Release()

	operatorCredential, err := prepareSetupUserPassword(config.UserDir, "preserved@example.test", setupTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := createPreparedSetupCredential(operatorCredential); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(operatorCredential.UserFile, []byte(`{"hash":"operator-managed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStaleSetupCredential(config.UserDir, "preserved@example.test", operatorCredential.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(operatorCredential.UserFile); err != nil {
		t.Fatalf("stale cleanup removed an operator-modified credential: %v", err)
	}
}

func TestSetupCleanupFailureRetainsImmediatelyRecoverableJournal(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "policies")
	config := &config{NetspocData: data, UserDir: filepath.Join(root, "users")}
	first := &state{config: config, cache: newCache(data, 8)}
	second := &state{config: config, cache: newCache(data, 8)}

	staleClaim, err := first.acquireSetupClaim()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := prepareSetupUserPassword(config.UserDir, "retry@example.test", setupTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.recordSetupClaimCredential(staleClaim.ID, "retry@example.test", credential.Digest, newPolicyVersion(), credential.Digest, 0); err != nil {
		t.Fatal(err)
	}
	// A directory at the exact credential path deterministically makes the
	// compare-before-remove read fail, including when tests run as root.
	if err := os.MkdirAll(credential.UserFile, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := first.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE policy_setup_guard SET claimed_at=0 WHERE id=1`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	if _, err := second.acquireSetupClaim(); err == nil {
		t.Fatal("cleanup failure unexpectedly discarded the setup journal")
	}
	// The old process may still unwind after the recovery CAS. Its release must
	// not delete the new recovery owner or any journal metadata.
	staleClaim.Release()
	db, err = first.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	var email, digest string
	var claimedAt int64
	if err := db.QueryRow(`SELECT claimed_at, credential_email, credential_digest FROM policy_setup_guard WHERE id=1`).Scan(&claimedAt, &email, &digest); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	if claimedAt != 0 || email != "retry@example.test" || digest != credential.Digest {
		t.Fatalf("cleanup failure lost recovery metadata: claimed_at=%d email=%q digest=%q", claimedAt, email, digest)
	}

	if err := os.Remove(credential.UserFile); err != nil {
		t.Fatal(err)
	}
	if err := createPreparedSetupCredential(credential); err != nil {
		t.Fatal(err)
	}
	recovered, err := second.acquireSetupClaim()
	if err != nil {
		t.Fatalf("repairable setup journal was not recovered: %v", err)
	}
	defer recovered.Release()
	if _, err := os.Stat(credential.UserFile); !os.IsNotExist(err) {
		t.Fatalf("recovered setup left its exact orphan credential: %v", err)
	}
}

func TestCommittedSetupJournalRestoresDraftAndCurrentPointer(t *testing.T) {
	s := newSetupTestState(t)
	email, policy, err := validateSetupRequest(setupRequest{
		Email:                "recovered@example.test",
		Password:             setupTestPassword,
		PasswordConfirmation: setupTestPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	normalizeEditablePolicy(policy)
	if err := derivePolicyNames(policy); err != nil {
		t.Fatal(err)
	}
	policyDigest, err := setupPolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	version := newPolicyVersion()
	claim, err := s.acquireSetupClaim()
	if err != nil {
		t.Fatal(err)
	}
	defer claim.Release()
	credential, err := prepareSetupUserPassword(s.config.UserDir, email, setupTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.recordSetupClaimCredential(claim.ID, email, credential.Digest, version, policyDigest, 0); err != nil {
		t.Fatal(err)
	}
	if err := createPreparedSetupCredential(credential); err != nil {
		t.Fatal(err)
	}
	if err := s.publishSetupPolicyVersion(policy, version, claim.ID); err != nil {
		t.Fatal(err)
	}

	// Simulate the rollback that follows an ambiguous Commit error.
	if err := os.Remove(filepath.Join(s.config.NetspocData, "current")); err != nil {
		t.Fatal(err)
	}
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM policy_draft WHERE id=1`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE policy_setup_guard SET claimed_at=0 WHERE id=1`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	if err := s.reconcileStaleSetupClaim(); err != nil {
		t.Fatalf("committed setup was not reconciled: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(s.config.NetspocData, "current")); err != nil || target != version {
		t.Fatalf("recovered current pointer = %q, err=%v; want %q", target, err, version)
	}
	if policyRole(s.readDraft(), email) != "admin" {
		t.Fatal("recovered draft does not contain the setup administrator")
	}
	if store, err := GetUserStore(credential.UserFile); err != nil || !store.CheckPassword(setupTestPassword) {
		t.Fatalf("recovery removed or changed the committed setup credential: %v", err)
	}
	// A partial rollback may leave current correct while restoring only the old
	// draft. Recovery must repair that draft before treating the link as proof
	// that every compatibility artifact is consistent.
	db, err = s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM policy_draft WHERE id=1`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	if err := s.restoreSetupPublicationArtifacts(version, policyDigest, 0, policy); err != nil {
		t.Fatalf("recovery with correct current and rolled-back draft failed: %v", err)
	}
	if policyRole(s.readDraft(), email) != "admin" {
		t.Fatal("recovery left a rolled-back draft behind a correct current pointer")
	}
	metaBefore, err := s.draftInfo()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.restoreSetupPublicationArtifacts(version, policyDigest, 0, policy); err != nil {
		t.Fatalf("idempotent setup recovery failed: %v", err)
	}
	metaAfter, err := s.draftInfo()
	if err != nil {
		t.Fatal(err)
	}
	if metaAfter.Version != metaBefore.Version {
		t.Fatalf("idempotent recovery changed draft version from %d to %d", metaBefore.Version, metaAfter.Version)
	}
	editedDraft := *policy
	editedDraft.Name = "administrator-working-copy"
	if err := s.saveDraft(&editedDraft); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.config.NetspocData, "current")); err != nil {
		t.Fatal(err)
	}
	editedMeta, err := s.draftInfo()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.restoreSetupPublicationArtifacts(version, policyDigest, 0, policy); err != nil {
		t.Fatalf("recovery with a newer draft failed: %v", err)
	}
	if draft := s.readDraft(); draft.Name != editedDraft.Name {
		t.Fatalf("recovery overwrote newer administrator draft %q with %q", editedDraft.Name, draft.Name)
	}
	if finalMeta, err := s.draftInfo(); err != nil || finalMeta.Version != editedMeta.Version {
		t.Fatalf("recovery changed newer draft version: before=%d after=%d err=%v", editedMeta.Version, finalMeta.Version, err)
	}
	db, err = s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_setup_guard`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("reconciled setup journal count=%d err=%v", count, err)
	}
}

func TestSetupPublicationInspectionKeepsUnreadableStateUnknown(t *testing.T) {
	s := newSetupTestState(t)
	version := newPolicyVersion()
	claim, err := s.acquireSetupClaim()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := prepareSetupUserPassword(s.config.UserDir, "unknown@example.test", setupTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest := strings.Repeat("0", sha256.Size*2)
	if err := s.recordSetupClaimCredential(claim.ID, "unknown@example.test", credential.Digest, version, expectedDigest, 0); err != nil {
		t.Fatal(err)
	}
	if err := createPreparedSetupCredential(credential); err != nil {
		t.Fatal(err)
	}
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO policy_publication(version, document, published_at, published_by, source_revision)
		VALUES(?, '{invalid-json', ?, '', ?)`, version, time.Now().UTC().Format(time.RFC3339Nano), version)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	db, err = s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE policy_setup_guard SET claimed_at=0 WHERE id=1`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	if state, _ := s.inspectSetupPublication(version, expectedDigest); state != setupPublicationUnknown {
		t.Fatalf("unreadable committed publication state=%d, want unknown", state)
	}
	if err := s.reconcileStaleSetupClaim(); err == nil {
		t.Fatal("unreadable publication was treated as safely absent")
	}
	claim.Release()
	if _, err := os.Stat(credential.UserFile); err != nil {
		t.Fatalf("unknown publication state removed credential: %v", err)
	}
	db, err = s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	var claimedAt int64
	var email, credentialDigest, storedVersion, storedDigest string
	if err := db.QueryRow(`SELECT claimed_at, credential_email, credential_digest, publication_version, publication_digest
		FROM policy_setup_guard WHERE id=1`).Scan(&claimedAt, &email, &credentialDigest, &storedVersion, &storedDigest); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if claimedAt != 0 || email != "unknown@example.test" || credentialDigest != credential.Digest || storedVersion != version || storedDigest != expectedDigest {
		db.Close()
		t.Fatalf("unknown state lost journal metadata: at=%d email=%q credential=%q version=%q publication=%q", claimedAt, email, credentialDigest, storedVersion, storedDigest)
	}
	if _, err := db.Exec(`DELETE FROM policy_publication WHERE version=?`, version); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	if err := s.reconcileStaleSetupClaim(); err != nil {
		t.Fatalf("safe absence did not reconcile journal: %v", err)
	}
	if _, err := os.Stat(credential.UserFile); !os.IsNotExist(err) {
		t.Fatalf("safe absence left exact orphan credential: %v", err)
	}
}

func TestSetupRecoveryNeverRollsBackNewerPublication(t *testing.T) {
	s := newSetupTestState(t)
	email, setupPolicy, err := validateSetupRequest(setupRequest{
		Email:                "superseded@example.test",
		Password:             setupTestPassword,
		PasswordConfirmation: setupTestPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	normalizeEditablePolicy(setupPolicy)
	if err := derivePolicyNames(setupPolicy); err != nil {
		t.Fatal(err)
	}
	digest, err := setupPolicyDigest(setupPolicy)
	if err != nil {
		t.Fatal(err)
	}
	setupVersion := newPolicyVersion()
	claim, err := s.acquireSetupClaim()
	if err != nil {
		t.Fatal(err)
	}
	defer claim.Release()
	credential, err := prepareSetupUserPassword(s.config.UserDir, email, setupTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.recordSetupClaimCredential(claim.ID, email, credential.Digest, setupVersion, digest, 0); err != nil {
		t.Fatal(err)
	}
	if err := createPreparedSetupCredential(credential); err != nil {
		t.Fatal(err)
	}
	if err := s.publishSetupPolicyVersion(setupPolicy, setupVersion, claim.ID); err != nil {
		t.Fatal(err)
	}
	newerPolicy := *setupPolicy
	newerPolicy.Name = "newer-policy"
	if err := s.publishPolicy(&newerPolicy); err != nil {
		t.Fatal(err)
	}
	newerVersion, err := s.latestPublicationVersion()
	if err != nil || newerVersion == setupVersion {
		t.Fatalf("newer publication missing: version=%q err=%v", newerVersion, err)
	}
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE policy_setup_guard SET claimed_at=0 WHERE id=1`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	if err := s.reconcileStaleSetupClaim(); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(s.config.NetspocData, "current")); err != nil || target != newerVersion {
		t.Fatalf("setup recovery rolled current back to an older policy: target=%q err=%v", target, err)
	}
	if draft := s.readDraft(); draft.Name != "newer-policy" {
		t.Fatalf("setup recovery rolled draft back: name=%q", draft.Name)
	}
	if _, err := os.Stat(credential.UserFile); err != nil {
		t.Fatalf("superseded committed setup credential was removed: %v", err)
	}
}

func TestLostSetupClaimCannotFinalizePublication(t *testing.T) {
	s := newSetupTestState(t)
	_, policy, err := validateSetupRequest(setupRequest{
		Email:                "fenced@example.test",
		Password:             setupTestPassword,
		PasswordConfirmation: setupTestPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.acquireSetupClaim()
	if err != nil {
		t.Fatal(err)
	}
	defer claim.Release()
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE policy_setup_guard SET claim_id='replacement-claim', claimed_at=? WHERE id=1`, time.Now().Unix()); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	if err := s.publishSetupPolicyVersion(policy, newPolicyVersion(), claim.ID); !errors.Is(err, errSetupAlreadyClaimed) {
		t.Fatalf("lost setup claim finalized publication: %v", err)
	}
	if version, err := s.latestPublicationVersion(); err != nil || version != "" {
		t.Fatalf("lost setup claim published version %q: %v", version, err)
	}
}

func TestLegacyBootstrapSharesSetupClaim(t *testing.T) {
	s := newSetupTestState(t)
	claim, err := s.acquireSetupClaim()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(validEditablePolicy())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/bootstrap", strings.NewReader(string(payload)))
	response := httptest.NewRecorder()
	s.adminBootstrap(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("legacy bootstrap bypassed setup claim: %d body=%s", response.Code, response.Body.String())
	}
	if version, err := s.latestPublicationVersion(); err != nil || version != "" {
		t.Fatalf("blocked legacy bootstrap published version %q: %v", version, err)
	}
	claim.Release()

	request = httptest.NewRequest(http.MethodPost, "/admin/bootstrap", strings.NewReader(string(payload)))
	response = httptest.NewRecorder()
	s.adminBootstrap(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("released legacy bootstrap response = %d body=%s", response.Code, response.Body.String())
	}
}
