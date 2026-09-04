package backend

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func accountRegressionState(t *testing.T) *state {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "policies")
	if err := os.MkdirAll(data, 0o750); err != nil {
		t.Fatal(err)
	}
	return &state{
		config: &config{NetspocData: data, UserDir: filepath.Join(root, "users")},
		cache:  newCache(data, 8),
	}
}

func seedRegressionAccounts(t *testing.T, s *state, users ...editableUser) int64 {
	t.Helper()
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := s.seedSetupAccountsTx(tx, users, "test-bootstrap"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_, version, err := s.accountCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func regressionAccount(t *testing.T, users []editableUser, email string) editableUser {
	t.Helper()
	for _, user := range users {
		if strings.EqualFold(user.Email, email) {
			return user
		}
	}
	t.Fatalf("account %q not found in %#v", email, users)
	return editableUser{}
}

func legacyAccountPolicyJSON(t *testing.T, name string, users []editableUser) string {
	t.Helper()
	document, err := json.Marshal(struct {
		Name  string         `json:"name"`
		Users []editableUser `json:"users"`
	}{Name: name, Users: users})
	if err != nil {
		t.Fatal(err)
	}
	return string(document)
}

func accountAdminRequest(t *testing.T, s *state, method, actor string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, "/admin/users", bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	session := newSession()
	session.Put("loggedIn", true)
	session.Put("email", actor)
	request = request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, session))
	response := httptest.NewRecorder()
	s.adminUsers(response, request)
	return response
}

func TestAccountMigrationUsesLatestPublicationInsteadOfDraft(t *testing.T) {
	s := accountRegressionState(t)
	path := filepath.Join(s.config.NetspocData, "policyweb.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE policy_draft (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			document TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
		CREATE TABLE policy_publication (
			version TEXT PRIMARY KEY,
			document TEXT NOT NULL,
			published_at TEXT NOT NULL
		);`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	draft := legacyAccountPolicyJSON(t, "draft", []editableUser{
		{Email: "admin@example.net", Role: "admin"},
		{Email: "reviewer@example.net", Role: policyDeveloperRole},
		{Email: "draft-only@example.net", Role: "admin"},
	})
	oldPublication := legacyAccountPolicyJSON(t, "old", []editableUser{{Email: "old@example.net", Role: "admin"}})
	latestPublication := legacyAccountPolicyJSON(t, "latest", []editableUser{
		{Email: "admin@example.net", Role: "admin"},
		{Email: "reviewer@example.net", Role: "reviewer"},
	})
	if _, err := db.Exec(`INSERT INTO policy_draft(id, document, updated_at) VALUES(1, ?, '2026-08-30T18:00:00Z')`, draft); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy_publication(version, document, published_at) VALUES
		('p-old', ?, '2026-08-29T18:00:00Z'),
		('p-latest', ?, '2026-08-30T18:00:00Z')`, oldPublication, latestPublication); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	users, version, err := s.accountCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("migrated users_version = %d, want 1", version)
	}
	if len(users) != 2 {
		t.Fatalf("migrated accounts = %#v, want exactly latest publication users", users)
	}
	if got := regressionAccount(t, users, "reviewer@example.net"); got.Role != "reviewer" || got.Source != "local" || !got.Active {
		t.Fatalf("latest published reviewer was not normalized and migrated: %#v", got)
	}
	for _, forbidden := range []string{"old@example.net", "draft-only@example.net"} {
		for _, user := range users {
			if user.Email == forbidden {
				t.Fatalf("account %q was migrated from a non-authoritative document", forbidden)
			}
		}
	}
}

func TestAccountMigrationIgnoresDraftAndFileWithoutPublication(t *testing.T) {
	s := accountRegressionState(t)
	path := filepath.Join(s.config.NetspocData, "policyweb.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE policy_draft (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			document TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
		CREATE TABLE policy_publication (
			version TEXT PRIMARY KEY,
			document TEXT NOT NULL,
			published_at TEXT NOT NULL
		);`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	draft := legacyAccountPolicyJSON(t, "draft", []editableUser{{Email: "draft-admin@example.net", Role: policyDeveloperRole}})
	if _, err := db.Exec(`INSERT INTO policy_draft(id, document, updated_at) VALUES(1, ?, '2026-08-30T18:00:00Z')`, draft); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	fileDraft := legacyAccountPolicyJSON(t, "file-draft", []editableUser{{Email: "file-admin@example.net", Role: "admin"}})
	if err := os.WriteFile(s.draftPath(), []byte(fileDraft), 0o640); err != nil {
		t.Fatal(err)
	}

	users, version, err := s.accountCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if version != 0 || len(users) != 0 {
		t.Fatalf("mutable policy data initialized accounts: users_version=%d users=%#v", version, users)
	}
}

func TestPolicyPublicationCannotInitializeAccounts(t *testing.T) {
	s := accountRegressionState(t)
	p := validEditablePolicy()
	p.Users = append(p.Users, editableUser{Email: "publication-developer@example.net", Role: policyDeveloperRole})

	if err := s.storePublication("p-must-not-seed-accounts", p); err != nil {
		t.Fatal(err)
	}
	users, version, err := s.accountCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if version != 0 || len(users) != 0 {
		t.Fatalf("ordinary publication initialized accounts: users_version=%d users=%#v", version, users)
	}
}

func TestPolicyPersistenceExcludesAccounts(t *testing.T) {
	s := accountRegressionState(t)
	seedRegressionAccounts(t, s, editableUser{Email: "admin@example.net", Role: "admin", Source: "local", Active: true})
	p := validEditablePolicy()
	p.Users = append(p.Users, editableUser{Email: "must-not-persist@example.net", Role: "reviewer", Source: "local", Active: true})

	if _, err := s.saveDraftAs(p, "admin@example.net", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.storeRevision("p-account-document-test", "", p, []policyChange{}); err != nil {
		t.Fatal(err)
	}
	if err := s.storePublication("p-account-publication-test", p); err != nil {
		t.Fatal(err)
	}

	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	queries := map[string]string{
		"draft":       `SELECT document FROM policy_draft WHERE id=1`,
		"revision":    `SELECT document FROM policy_revision WHERE version='p-account-document-test'`,
		"publication": `SELECT document FROM policy_publication WHERE version='p-account-publication-test'`,
	}
	for name, query := range queries {
		var raw string
		if err := db.QueryRow(query).Scan(&raw); err != nil {
			t.Fatalf("read %s document: %v", name, err)
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &document); err != nil {
			t.Fatalf("decode %s document: %v", name, err)
		}
		if _, exists := document["users"]; exists {
			t.Fatalf("%s document persisted accounts: %s", name, raw)
		}
	}
}

func TestAdminCreatesReviewerWithoutChangingPolicyVersions(t *testing.T) {
	s := accountRegressionState(t)
	usersVersion := seedRegressionAccounts(t, s, editableUser{Email: "admin@example.net", Role: "admin", Source: "local", Active: true})
	p := validEditablePolicy()
	draftBefore, err := s.saveDraftAs(p, "admin@example.net", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.storePublication("p-account-base", p); err != nil {
		t.Fatal(err)
	}
	publicationBefore, err := s.latestPublicationVersion()
	if err != nil {
		t.Fatal(err)
	}
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	var revisionsBefore int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_revision`).Scan(&revisionsBefore); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	response := accountAdminRequest(t, s, http.MethodPost, "admin@example.net", map[string]any{
		"email": " Reviewer@Example.NET ", "role": "reviewer", "users_version": usersVersion,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("create reviewer status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Success      bool           `json:"success"`
		Users        []editableUser `json:"users"`
		UsersVersion int64          `json:"users_version"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	created := regressionAccount(t, result.Users, "reviewer@example.net")
	if !result.Success || result.UsersVersion != usersVersion+1 || created.Role != "reviewer" || created.Revision != 1 {
		t.Fatalf("unexpected create response: %#v", result)
	}
	if err := s.checkEmailAuthorization(created.Email); err != nil {
		t.Fatalf("new reviewer without owner membership is not login-authorized: %v", err)
	}
	if got := policyRole(s.authorizationPolicy(), created.Email); got != "reviewer" {
		t.Fatalf("new reviewer role was not immediately effective: %q", got)
	}

	draftAfter, err := s.draftInfo()
	if err != nil {
		t.Fatal(err)
	}
	publicationAfter, err := s.latestPublicationVersion()
	if err != nil {
		t.Fatal(err)
	}
	db, err = s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var revisionsAfter int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_revision`).Scan(&revisionsAfter); err != nil {
		t.Fatal(err)
	}
	if draftAfter.Version != draftBefore.Version || publicationAfter != publicationBefore || revisionsAfter != revisionsBefore {
		t.Fatalf("account CRUD changed policy workflow state: draft %d->%d publication %q->%q revisions %d->%d",
			draftBefore.Version, draftAfter.Version, publicationBefore, publicationAfter, revisionsBefore, revisionsAfter)
	}
}

func TestAccountRoleChangeIsImmediatelyEffective(t *testing.T) {
	s := accountRegressionState(t)
	version := seedRegressionAccounts(t, s,
		editableUser{Email: "admin@example.net", Role: "admin", Source: "local", Active: true},
		editableUser{Email: "operator@example.net", Role: "reviewer", Source: "local", Active: true},
	)
	if err := s.storePublication("p-role-base", validEditablePolicy()); err != nil {
		t.Fatal(err)
	}
	users, _, err := s.accountCatalog()
	if err != nil {
		t.Fatal(err)
	}
	operator := regressionAccount(t, users, "operator@example.net")
	if got := policyRole(s.authorizationPolicy(), operator.Email); got != "reviewer" {
		t.Fatalf("initial role = %q, want reviewer", got)
	}
	users, nextVersion, err := s.updateAccount("admin@example.net", accountMutationRequest{
		Email: operator.Email, Role: "deployer", Revision: operator.Revision, UsersVersion: &version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if nextVersion != version+1 || regressionAccount(t, users, operator.Email).Role != "deployer" {
		t.Fatalf("unexpected updated catalog version=%d users=%#v", nextVersion, users)
	}
	if got := policyRole(s.authorizationPolicy(), operator.Email); got != "deployer" {
		t.Fatalf("updated account role was not immediately effective: %q", got)
	}
}

func TestLastAdministratorOrDeveloperCannotBeRemoved(t *testing.T) {
	t.Run("sole administrator", func(t *testing.T) {
		s := accountRegressionState(t)
		version := seedRegressionAccounts(t, s, editableUser{Email: "admin@example.net", Role: "admin", Source: "local", Active: true})
		users, _, err := s.accountCatalog()
		if err != nil {
			t.Fatal(err)
		}
		admin := regressionAccount(t, users, "admin@example.net")
		if _, _, err := s.updateAccount(admin.Email, accountMutationRequest{Email: admin.Email, Role: "viewer", Revision: admin.Revision, UsersVersion: &version}); !errors.Is(err, errLastAccountAdmin) {
			t.Fatalf("sole administrator degradation error=%v, want %v", err, errLastAccountAdmin)
		}
		if _, _, err := s.deleteAccount(admin.Email, accountMutationRequest{Email: admin.Email, Revision: admin.Revision, UsersVersion: &version}); !errors.Is(err, errLastAccountAdmin) {
			t.Fatalf("sole administrator deletion error=%v, want %v", err, errLastAccountAdmin)
		}
	})

	t.Run("developer is final privileged account", func(t *testing.T) {
		s := accountRegressionState(t)
		version := seedRegressionAccounts(t, s,
			editableUser{Email: "admin@example.net", Role: "admin", Source: "local", Active: true},
			editableUser{Email: "developer@example.net", Role: policyDeveloperRole, Source: "local", Active: true},
		)
		users, _, err := s.accountCatalog()
		if err != nil {
			t.Fatal(err)
		}
		admin := regressionAccount(t, users, "admin@example.net")
		users, version, err = s.updateAccount(admin.Email, accountMutationRequest{Email: admin.Email, Role: "viewer", Revision: admin.Revision, UsersVersion: &version})
		if err != nil {
			t.Fatalf("administrator could not be degraded while a developer remains: %v", err)
		}
		developer := regressionAccount(t, users, "developer@example.net")
		if _, _, err := s.updateAccount(developer.Email, accountMutationRequest{Email: developer.Email, Role: "reviewer", Revision: developer.Revision, UsersVersion: &version}); !errors.Is(err, errLastAccountAdmin) {
			t.Fatalf("last developer degradation error=%v, want %v", err, errLastAccountAdmin)
		}
		if _, _, err := s.deleteAccount(developer.Email, accountMutationRequest{Email: developer.Email, Revision: developer.Revision, UsersVersion: &version}); !errors.Is(err, errLastAccountAdmin) {
			t.Fatalf("last developer deletion error=%v, want %v", err, errLastAccountAdmin)
		}
	})
}

func TestReferencedAccountCannotBeDeleted(t *testing.T) {
	s := accountRegressionState(t)
	version := seedRegressionAccounts(t, s,
		editableUser{Email: "admin@example.net", Role: "admin", Source: "local", Active: true},
		editableUser{Email: "reviewer@example.net", Role: "reviewer", Source: "local", Active: true},
	)
	p := validEditablePolicy()
	p.Owners[0].Users = append(p.Owners[0].Users, "reviewer@example.net")
	if _, err := s.saveDraftAs(p, "admin@example.net", nil); err != nil {
		t.Fatal(err)
	}
	users, _, err := s.accountCatalog()
	if err != nil {
		t.Fatal(err)
	}
	reviewer := regressionAccount(t, users, "reviewer@example.net")
	_, _, err = s.deleteAccount("admin@example.net", accountMutationRequest{Email: reviewer.Email, Revision: reviewer.Revision, UsersVersion: &version})
	if !errors.Is(err, errAccountReferenced) {
		t.Fatalf("referenced account deletion error=%v, want %v", err, errAccountReferenced)
	}
	if _, active := s.activeAccount(reviewer.Email); !active {
		t.Fatal("failed referenced-account deletion removed the account")
	}
	_, afterVersion, err := s.accountCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if afterVersion != version {
		t.Fatalf("failed referenced-account deletion changed users_version %d -> %d", version, afterVersion)
	}
}

func TestCredentialWithoutAccountCannotUseLocalAuthentication(t *testing.T) {
	s := accountRegressionState(t)
	if _, _, err := s.accountCatalog(); err != nil {
		t.Fatal(err)
	}
	const email = "credential-only@example.net"
	if err := SetUserPassword(s.config.UserDir, email, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if s.localPasswordIdentityAllowed(email) {
		t.Fatal("credential file without an account enabled local authentication")
	}
	if err := s.checkEmailAuthorization(email); err == nil {
		t.Fatal("credential file without an account passed email authorization")
	}
}

func TestAccountMutationRejectsStaleGlobalCAS(t *testing.T) {
	s := accountRegressionState(t)
	version := seedRegressionAccounts(t, s,
		editableUser{Email: "admin@example.net", Role: "admin", Source: "local", Active: true},
		editableUser{Email: "operator@example.net", Role: "viewer", Source: "local", Active: true},
	)
	users, _, err := s.accountCatalog()
	if err != nil {
		t.Fatal(err)
	}
	operator := regressionAccount(t, users, "operator@example.net")
	if _, _, err := s.updateAccount("admin@example.net", accountMutationRequest{
		Email: operator.Email, Role: "reviewer", Revision: operator.Revision, UsersVersion: &version,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.updateAccount("admin@example.net", accountMutationRequest{
		Email: operator.Email, Role: "deployer", Revision: operator.Revision, UsersVersion: &version,
	}); !errors.Is(err, errAccountConflict) {
		t.Fatalf("stale users_version error=%v, want %v", err, errAccountConflict)
	}
	users, afterVersion, err := s.accountCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if afterVersion != version+1 || regressionAccount(t, users, operator.Email).Role != "reviewer" {
		t.Fatalf("stale mutation changed catalog version=%d users=%#v", afterVersion, users)
	}
}

func TestAdminCanPromoteOwnAccountToDeveloperImmediately(t *testing.T) {
	s := accountRegressionState(t)
	version := seedRegressionAccounts(t, s,
		editableUser{Email: "admin@example.net", Role: "admin", Source: "local", Active: true},
	)
	users, _, err := s.accountCatalog()
	if err != nil {
		t.Fatal(err)
	}
	admin := regressionAccount(t, users, "admin@example.net")
	users, nextVersion, err := s.updateAccount(admin.Email, accountMutationRequest{
		Email: admin.Email, Role: policyDeveloperRole, Revision: admin.Revision, UsersVersion: &version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if nextVersion != version+1 || regressionAccount(t, users, admin.Email).Role != policyDeveloperRole {
		t.Fatalf("self promotion was not immediately effective: version=%d users=%#v", nextVersion, users)
	}
	if !bypassesFourEyes(s.authorizationPolicy(), admin.Email) {
		t.Fatal("promoted developer did not receive the four-eyes exemption")
	}

	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var result string
	if err := db.QueryRow(`SELECT result FROM policy_audit WHERE action='account.update' ORDER BY id DESC LIMIT 1`).Scan(&result); err != nil {
		t.Fatalf("read atomic account audit: %v", err)
	}
	if result != "success" {
		t.Fatalf("account audit result=%q, want success", result)
	}
}

func TestPolicyWritesRejectStaleAccountSnapshot(t *testing.T) {
	s := accountRegressionState(t)
	version := seedRegressionAccounts(t, s,
		editableUser{Email: "admin@example.net", Role: "admin", Source: "local", Active: true},
		editableUser{Email: "operator@example.net", Role: "viewer", Source: "local", Active: true},
	)
	p := validEditablePolicy()
	if err := s.attachPolicyAccounts(p); err != nil {
		t.Fatal(err)
	}
	operator := regressionAccount(t, p.Users, "operator@example.net")
	if _, _, err := s.updateAccount("admin@example.net", accountMutationRequest{
		Email: operator.Email, Role: "reviewer", Revision: operator.Revision, UsersVersion: &version,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.saveDraftAs(p, "admin@example.net", nil); !errors.Is(err, errAccountConflict) {
		t.Fatalf("stale draft write error=%v, want %v", err, errAccountConflict)
	}
	if err := s.storeRevision("p-stale-account-revision", "", p, []policyChange{}); !errors.Is(err, errAccountConflict) {
		t.Fatalf("stale revision write error=%v, want %v", err, errAccountConflict)
	}
	if err := s.storePublication("p-stale-account-publication", p); !errors.Is(err, errAccountConflict) {
		t.Fatalf("stale publication write error=%v, want %v", err, errAccountConflict)
	}

	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for name, query := range map[string]string{
		"draft":       `SELECT COUNT(*) FROM policy_draft`,
		"revision":    `SELECT COUNT(*) FROM policy_revision WHERE version='p-stale-account-revision'`,
		"publication": `SELECT COUNT(*) FROM policy_publication WHERE version='p-stale-account-publication'`,
	} {
		var count int
		if err := db.QueryRow(query).Scan(&count); err != nil {
			t.Fatalf("count %s writes: %v", name, err)
		}
		if count != 0 {
			t.Fatalf("stale account snapshot persisted %s", name)
		}
	}
}
