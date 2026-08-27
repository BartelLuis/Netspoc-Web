package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFindLDAPPolicyUserUsesOnlyStableDirectoryID(t *testing.T) {
	p := &editablePolicy{Users: []editableUser{{Source: "ldap", DirectoryID: "id-1", Username: "alice", Email: "custom@example.org", Active: true}}}
	if got := findLDAPPolicyUser(p, ldapIdentity{DirectoryID: "id-1", Username: "renamed"}); got == nil {
		t.Fatal("stable directory ID did not match")
	}
	if got := findLDAPPolicyUser(p, ldapIdentity{DirectoryID: "new-id", Username: "ALICE"}); got != nil {
		t.Fatal("username fallback authorized a different directory identity")
	}
	if got := findLDAPPolicyUser(p, ldapIdentity{Username: "alice"}); got != nil {
		t.Fatal("empty directory identity was authorized")
	}
}

func TestLDAPLoginPolicyRecheckUsesCurrentIdentityAndMaintenanceRole(t *testing.T) {
	identity := ldapIdentity{DirectoryID: "id-1", Username: "alice", Email: "directory@example.test"}
	activeAdmin := &editablePolicy{Users: []editableUser{{
		Source: "ldap", DirectoryID: identity.DirectoryID, Username: identity.Username,
		Email: identity.Email, Role: "admin", Active: true,
	}}}
	if _, err := ldapPolicyLoginUser(activeAdmin, identity, true); err != nil {
		t.Fatalf("active LDAP administrator was rejected during maintenance: %v", err)
	}

	tests := []struct {
		name        string
		user        editableUser
		maintenance bool
		want        error
	}{
		{name: "disabled", user: editableUser{Source: "ldap", DirectoryID: "id-1", Email: identity.Email, Role: "admin", Active: false}},
		{name: "source changed", user: editableUser{Source: "local", DirectoryID: "id-1", Email: identity.Email, Role: "admin", Active: true}},
		{name: "identity changed", user: editableUser{Source: "ldap", DirectoryID: "id-2", Email: identity.Email, Role: "admin", Active: true}},
		{name: "maintenance role changed", user: editableUser{Source: "ldap", DirectoryID: "id-1", Email: identity.Email, Role: "viewer", Active: true}, maintenance: true, want: errLDAPMaintenanceLogin},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ldapPolicyLoginUser(&editablePolicy{Users: []editableUser{test.user}}, identity, test.maintenance)
			if err == nil {
				t.Fatal("changed authorization snapshot was accepted")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestLDAPSettingsRequireTLSAndSingleTemplates(t *testing.T) {
	valid := &config{LdapURI: "ldaps://ldap.example.test:636", LdapDNTemplate: "uid=%s,ou=people", LdapBaseDN: "dc=example,dc=test", LdapFilterTemplate: "uid=%s"}
	if err := validateLDAPSettings(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*config){
		func(c *config) { c.LdapURI = "ldap://ldap.example.test" },
		func(c *config) { c.LdapDNTemplate = "uid=user,ou=people" },
		func(c *config) { c.LdapDNTemplate = "uid=%s,cn=%s" },
		func(c *config) { c.LdapDNTemplate = "uid=%q" },
	} {
		c := *valid
		mutate(&c)
		if err := validateLDAPSettings(&c); err == nil {
			t.Fatalf("invalid LDAP settings accepted: %#v", c)
		}
	}
}

func TestLDAPBindDNEscapesUsername(t *testing.T) {
	username := "alice,ou=admins"
	got, err := ldapBindDN("uid=%s,ou=people", username)
	if err != nil {
		t.Fatal(err)
	}
	want := "uid=" + ldap.EscapeDN(username) + ",ou=people"
	if got != want {
		t.Fatalf("bind DN = %q, want %q", got, want)
	}
}

func TestLDAPEntryRequiresConfiguredImmutableID(t *testing.T) {
	entry := ldap.NewEntry("uid=alice,dc=example,dc=test", map[string][]string{"uid": {"alice"}})
	if id := ldapEntryID(entry, "entryUUID"); id != "" {
		t.Fatalf("DN was used as mutable identity: %q", id)
	}
}

func TestLDAPSyncDoesNotMigrateIdentityByUsername(t *testing.T) {
	p := &editablePolicy{Users: []editableUser{{Source: "ldap", DirectoryID: "", Username: "alice", Email: "alice@example.test", Role: "viewer", Active: true}}}
	_, err := calculateLDAPSyncPreview(p, []ldapIdentity{{DirectoryID: "immutable-id", Username: "alice", Email: "alice@example.test"}})
	if err == nil {
		t.Fatal("sync silently migrated an account using its mutable username")
	}
}

func TestProtectDirectoryUsersOnlyAllowsEmailAndRoleChanges(t *testing.T) {
	current := &editablePolicy{Users: []editableUser{{Source: "ldap", DirectoryID: "id-1", Username: "alice", Email: "old@example.org", Role: "viewer", Active: true}}}
	next := &editablePolicy{Users: []editableUser{{Source: "ldap", DirectoryID: "id-1", Username: "forged", Email: "new@example.org", Role: "admin", Active: false, Password: "forged"}}}
	if err := protectDirectoryUsers(current, next); err != nil {
		t.Fatal(err)
	}
	got := next.Users[0]
	if got.Email != "new@example.org" || got.Role != "admin" {
		t.Fatalf("editable fields were lost: %#v", got)
	}
	if got.Username != "alice" || !got.Active || got.Password != "" {
		t.Fatalf("directory fields were modified: %#v", got)
	}
}

func TestProtectDirectoryUsersPreventsManualCreationAndDeletion(t *testing.T) {
	current := &editablePolicy{Users: []editableUser{{Source: "ldap", DirectoryID: "id-1", Username: "alice", Email: "alice@example.org", Role: "viewer", Active: true}}}
	next := &editablePolicy{}
	if err := protectDirectoryUsers(current, next); err != nil {
		t.Fatal(err)
	}
	if len(next.Users) != 1 || next.Users[0].DirectoryID != "id-1" {
		t.Fatal("LDAP user was deleted")
	}
	forged := &editablePolicy{Users: []editableUser{{Source: "ldap", DirectoryID: "id-2", Email: "x@example.org"}}}
	if err := protectDirectoryUsers(current, forged); err == nil {
		t.Fatal("manual LDAP user creation was accepted")
	}
}

func TestProtectDirectoryUsersRejectsDuplicateDirectoryID(t *testing.T) {
	current := &editablePolicy{Users: []editableUser{{
		Source: "ldap", DirectoryID: "id-1", Username: "alice",
		Email: "alice@example.org", Role: "viewer", Active: true,
	}}}
	next := &editablePolicy{Users: []editableUser{
		{Source: "ldap", DirectoryID: "id-1", Email: "alice@example.org", Role: "viewer"},
		{Source: "ldap", DirectoryID: "id-1", Email: "alias@example.org", Role: "admin"},
	}}
	if err := protectDirectoryUsers(current, next); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate LDAP directory ID was accepted: %v", err)
	}
}

func TestLDAPSyncPreviewTokenIsActorBoundAndConfirmedOnce(t *testing.T) {
	s := workflowTestState(t)
	p := validEditablePolicy()
	meta, err := s.saveDraftAs(p, "admin@example.net", nil)
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.loadPolicyDraft()
	if err != nil {
		t.Fatal(err)
	}
	preview, err := calculateLDAPSyncPreview(current, []ldapIdentity{{DirectoryID: "directory-1", Username: "alice", Email: "alice@example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := s.storeLDAPSyncPreview("admin@example.net", meta.Version, preview)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.loadLDAPSyncPreview("other@example.net", stored.Token); !errors.Is(err, errLDAPPreviewInvalid) {
		t.Fatalf("preview was not actor-bound: %v", err)
	}

	body, _ := json.Marshal(map[string]any{"confirm": true, "preview_token": stored.Token})
	request := httptest.NewRequest(http.MethodPost, "/admin/ldap-sync", bytes.NewReader(body))
	session := newSession()
	session.Put("email", "admin@example.net")
	request = request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, session))
	response := httptest.NewRecorder()
	s.adminLDAPSync(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("confirm status = %d; body=%s", response.Code, response.Body.String())
	}
	updated, err := s.loadPolicyDraft()
	if err != nil {
		t.Fatal(err)
	}
	if user := findLDAPPolicyUser(updated, ldapIdentity{DirectoryID: "directory-1"}); user == nil || user.Email != "alice@example.net" {
		t.Fatalf("LDAP preview was not applied: %#v", updated.Users)
	}
	if _, err := s.loadLDAPSyncPreview("admin@example.net", stored.Token); !errors.Is(err, errLDAPPreviewInvalid) {
		t.Fatalf("consumed preview remained usable: %v", err)
	}
}

func TestLDAPSyncPreviewBecomesStaleAfterDraftChange(t *testing.T) {
	s := workflowTestState(t)
	p := validEditablePolicy()
	meta, err := s.saveDraftAs(p, "admin@example.net", nil)
	if err != nil {
		t.Fatal(err)
	}
	preview := ldapSyncPreview{Users: append([]editableUser(nil), p.Users...)}
	stored, err := s.storeLDAPSyncPreview("admin@example.net", meta.Version, preview)
	if err != nil {
		t.Fatal(err)
	}
	expected := meta.Version
	if _, err := s.saveDraftAs(p, "admin@example.net", &expected); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]any{"confirm": true, "preview_token": stored.Token})
	request := httptest.NewRequest(http.MethodPost, "/admin/ldap-sync", bytes.NewReader(body))
	session := newSession()
	session.Put("email", "admin@example.net")
	request = request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, session))
	response := httptest.NewRecorder()
	s.adminLDAPSync(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale confirm status = %d; body=%s", response.Code, response.Body.String())
	}
}
