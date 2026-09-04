package backend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPolicyPasswordIsRejectedAndNeverPersisted(t *testing.T) {
	raw := []byte(`{"name":"policy","users":[{"email":"admin@example.net","role":"admin","password":"plain-secret"}]}`)
	if _, err := decodeStagePolicy(raw); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("staging accepted policy password field: %v", err)
	}
	request := httptest.NewRequest("POST", "/admin/bootstrap", strings.NewReader(string(raw)))
	if _, err := decodePolicy(request); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("policy endpoint accepted password field: %v", err)
	}

	s := workflowTestState(t)
	p := validEditablePolicy()
	p.Users[0].Password = "plain-secret"
	if _, err := s.saveDraftAs(p, "admin@example.net", nil); err != nil {
		t.Fatal(err)
	}
	p.Users[0].Password = "plain-secret"
	if err := s.storeRevision("p-password-test", "", p, []map[string]string{}); err != nil {
		t.Fatal(err)
	}
	p.Users[0].Password = "plain-secret"
	if err := s.storePublication("p-password-publication", p); err != nil {
		t.Fatal(err)
	}

	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	queries := map[string]string{
		"draft":       `SELECT document FROM policy_draft WHERE id=1`,
		"revision":    `SELECT document FROM policy_revision WHERE version='p-password-test'`,
		"publication": `SELECT document FROM policy_publication WHERE version='p-password-publication'`,
	}
	for name, query := range queries {
		var document string
		if err := db.QueryRow(query).Scan(&document); err != nil {
			t.Fatalf("read %s document: %v", name, err)
		}
		if strings.Contains(document, "plain-secret") || strings.Contains(document, `"password"`) {
			t.Fatalf("%s persisted credential material: %s", name, document)
		}
	}
}

func workflowTestState(t *testing.T, additionalUsers ...editableUser) *state {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "policies"), 0750); err != nil {
		t.Fatal(err)
	}
	s := &state{config: &config{NetspocData: filepath.Join(root, "policies"), UserDir: filepath.Join(root, "users")}, cache: newCache(filepath.Join(root, "policies"), 8)}
	users := append([]editableUser(nil), validEditablePolicy().Users...)
	users = append(users, additionalUsers...)
	seedPolicyTestAccounts(t, s, users...)
	return s
}

func TestLegacyCompiledPolicyDoesNotBlockAdministrativeBootstrap(t *testing.T) {
	s := workflowTestState(t)
	legacyCurrent := filepath.Join(s.config.NetspocData, "current")
	if err := os.MkdirAll(legacyCurrent, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyCurrent, "email"), []byte("legacy@example.net\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if s.policyInitialized() {
		t.Fatal("legacy current/email incorrectly disabled the explicit bootstrap migration")
	}
	if err := s.storePublication("p-migrated", validEditablePolicy()); err != nil {
		t.Fatal(err)
	}
	if !s.policyInitialized() {
		t.Fatal("an immutable policy publication did not mark administration initialized")
	}
}

func TestRulesWithoutLegacyTargetContextRemainPublishableButNotDeployable(t *testing.T) {
	s := workflowTestState(t)
	p := validEditablePolicy()
	p.Tenants = nil
	p.TargetContexts = nil
	rule := &p.Services[0].Rules[0]
	rule.TargetContext, rule.RuleGroup = "", ""
	rule.StableRuleID, rule.ShortID, rule.PolicyName, rule.PolicyComment, rule.NamingVersion = "", "", "MANUAL_WEB", "", ""

	if _, err := s.createPendingRevision(p, "editor@example.net", "migration", "CHG-1", nil, nil); err != nil {
		t.Fatalf("manual rule without legacy target context was not staged: %v", err)
	}
	plan := generateDeploymentPlan(p, nil)
	if plan.Ready || len(plan.Commands) != 0 || len(plan.Warnings) == 0 {
		t.Fatalf("unbound rule unexpectedly produced an executable deployment plan: %#v", plan)
	}
	if err := s.publishPolicy(p); err != nil {
		t.Fatalf("manual rule without legacy target context was not published: %v", err)
	}
	if version, err := s.latestPublicationVersion(); err != nil || version == "" {
		t.Fatalf("publication was not recorded: version=%q err=%v", version, err)
	}
}

func TestLegacyDeploymentBaselineWithoutRuleIDsLoadsDeterministically(t *testing.T) {
	s := workflowTestState(t)
	p := validEditablePolicy()
	p.Tenants = nil
	p.TargetContexts = nil
	rule := &p.Services[0].Rules[0]
	rule.TargetContext, rule.StableRuleID, rule.ShortID = "", "", ""
	rule.PolicyName, rule.PolicyComment, rule.NamingVersion = "", "", ""

	const version = "p-legacy-without-rule-identities"
	if err := s.storeRevision(version, "", p, []policyChange{}); err != nil {
		t.Fatal(err)
	}
	if err := s.finalizePublication(version, p, "reviewer@example.net", true); err != nil {
		t.Fatal(err)
	}

	publication, loadedVersion, err := s.latestPublicationSnapshot()
	if err != nil || loadedVersion != version {
		t.Fatalf("legacy publication=%q err=%v", loadedVersion, err)
	}
	if got := publication.Services[0].Rules[0].StableRuleID; got != "" {
		t.Fatalf("immutable legacy publication gained a random rule ID while loading: %q", got)
	}
	record, err := s.loadRevisionRecord(version, false)
	if err != nil {
		t.Fatal(err)
	}
	if !samePolicyDocument(publication, record.Policy) {
		t.Fatal("byte-identical legacy publication and revision normalized differently")
	}
	base, plan, err := s.deploymentPlanBase(publication, version)
	if err != nil || base != nil || plan != nil {
		t.Fatalf("legacy baseline should safely trigger a full plan: base=%#v plan=%#v err=%v", base, plan, err)
	}
}

func TestEditorScopeIgnoresDetachedAccountsButProtectsOwnerAccess(t *testing.T) {
	current := validEditablePolicy()
	next := *current
	next.Users = append([]editableUser(nil), current.Users...)
	next.Owners = append([]editableOwner(nil), current.Owners...)
	if err := enforceEditorPolicyScope(current, &next); err != nil {
		t.Fatal(err)
	}
	next.Users[0].Role = "viewer"
	if err := enforceEditorPolicyScope(current, &next); err != nil {
		t.Fatalf("detached account catalog affected editor policy scope: %v", err)
	}
	next.Users = append([]editableUser(nil), current.Users...)
	next.Owners[0].ReadAll = true
	if err := enforceEditorPolicyScope(current, &next); err == nil {
		t.Fatal("editor changed owner access")
	}
}

func TestPolicyRolesIncludeReviewerAndDeployer(t *testing.T) {
	p := validEditablePolicy()
	p.Users = append(p.Users, editableUser{Email: "review@example.net", Role: "reviewer"}, editableUser{Email: "deploy@example.net", Role: "deployer"})
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}
	if !hasPolicyRole(p, "review@example.net", "reviewer") || !hasPolicyRole(p, "deploy@example.net", "deployer") {
		t.Fatal("workflow roles were not recognized")
	}
}

func TestAuthorizationPolicyIgnoresDraftRoleElevation(t *testing.T) {
	s := workflowTestState(t, editableUser{Email: "editor@example.net", Role: "editor"})
	published := validEditablePolicy()
	published.Users = append(published.Users, editableUser{Email: "editor@example.net", Role: "editor"})
	if err := s.storePublication("published-auth", published); err != nil {
		t.Fatal(err)
	}

	draft := validEditablePolicy()
	draft.Users = append(draft.Users, editableUser{Email: "editor@example.net", Role: "admin"})
	if _, err := s.saveDraftAs(draft, "admin@example.net", nil); err != nil {
		t.Fatal(err)
	}

	if got := policyRole(s.authorizationPolicy(), "editor@example.net"); got != "editor" {
		t.Fatalf("mutable draft changed authorization role: got %q, want editor", got)
	}
}

func TestInactiveLDAPUserHasNoPolicyRole(t *testing.T) {
	p := validEditablePolicy()
	p.Users = append(p.Users, editableUser{
		Email:       "directory-admin@example.net",
		Role:        "admin",
		Source:      "ldap",
		DirectoryID: "directory-1",
		Active:      false,
	})
	if got := policyRole(p, "directory-admin@example.net"); got != "" {
		t.Fatalf("inactive LDAP user retained role %q", got)
	}
	p.Users[len(p.Users)-1].Active = true
	if got := policyRole(p, "directory-admin@example.net"); got != "admin" {
		t.Fatalf("active LDAP user role = %q, want admin", got)
	}
}

func TestValidationRequiresEffectivePolicyAdministrator(t *testing.T) {
	p := validEditablePolicy()
	p.Users[0].Role = "viewer"
	p.Users = append(p.Users, editableUser{
		Email:       "directory-admin@example.net",
		Role:        "admin",
		Source:      "ldap",
		DirectoryID: "directory-1",
		Username:    "directory-admin",
		Active:      false,
	})
	if err := validateEditablePolicy(p); err == nil || !strings.Contains(err.Error(), "policy administrator") {
		t.Fatalf("inactive LDAP administrator satisfied policy-admin requirement: %v", err)
	}
	p.Users[1].Active = true
	p.Owners[0].Users = append(p.Owners[0].Users, "directory-admin@example.net")
	if err := validateEditablePolicy(p); err != nil {
		t.Fatalf("active LDAP policy administrator was rejected: %v", err)
	}
}

func TestValidationRequiresPolicyAdministratorWithOwnerLoginAccess(t *testing.T) {
	p := validEditablePolicy()
	p.Users = append(p.Users, editableUser{Email: "owner-user@example.net", Role: "viewer"})
	p.Owners[0].Admins = []string{"owner-user@example.net"}
	if err := validateEditablePolicy(p); err == nil || !strings.Contains(err.Error(), "assigned to an owner") {
		t.Fatalf("unassigned policy administrator did not trigger lockout protection: %v", err)
	}
	p.Owners[0].Users = append(p.Owners[0].Users, "admin@example.net")
	if err := validateEditablePolicy(p); err != nil {
		t.Fatalf("owner-authorized policy administrator was rejected: %v", err)
	}
}

func TestValidationRequiresEffectiveOwnerAdministrator(t *testing.T) {
	p := validEditablePolicy()
	p.Users = append(p.Users, editableUser{
		Email:       "directory-owner@example.net",
		Role:        "viewer",
		Source:      "ldap",
		DirectoryID: "directory-1",
		Username:    "directory-owner",
		Active:      false,
	})
	p.Owners[0].Admins = []string{"directory-owner@example.net"}
	p.Owners[0].Users = []string{"admin@example.net"}
	if err := validateEditablePolicy(p); err == nil || !strings.Contains(err.Error(), "owner administrator") {
		t.Fatalf("inactive LDAP administrator satisfied owner-admin requirement: %v", err)
	}
	p.Users[1].Active = true
	if err := validateEditablePolicy(p); err != nil {
		t.Fatalf("active LDAP owner administrator was rejected: %v", err)
	}
}

func TestValidateStagedRevisionRejectsLegacyDiff(t *testing.T) {
	legacy := &policyRevisionRecord{CreatedBy: "editor@example.net", Policy: validEditablePolicy()}
	if err := validateStagedRevision(legacy); err == nil {
		t.Fatal("legacy revision without staging metadata was accepted")
	}

	plan := generateDeploymentPlan(validEditablePolicy(), nil)
	staged := &policyRevisionRecord{
		CreatedBy: "editor@example.net", Comment: "review this change", ChangeReference: "CHG-42",
		DeploymentPlan: plan,
		Validation:     map[string]any{"valid": true, "errors": []string{}, "warnings": plan.Warnings, "deployment_ready": plan.Ready, "plan_hash": plan.Hash},
	}
	if err := validateStagedRevision(staged); err != nil {
		t.Fatalf("complete staging metadata was rejected: %v", err)
	}
	staged.Validation.(map[string]any)["plan_hash"] = "tampered"
	if err := validateStagedRevision(staged); err == nil {
		t.Fatal("validation for a different deployment plan was accepted")
	}
}

func TestPolicyRejectsUnsafeAccountEmail(t *testing.T) {
	p := validEditablePolicy()
	p.Users[0].Email = "../admin@example.net"
	if err := validateEditablePolicy(p); err == nil {
		t.Fatal("unsafe account email was accepted")
	}
}

func TestRuleLifecycleValidation(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	rule := editableRule{RuleGroup: "TMP", ExpiresAt: "2026-09-01", RollbackOwner: "ops", Purpose: "migration", ChangeReference: "CHG-1"}
	if err := validateRuleLifecycle(rule, now); err != nil {
		t.Fatal(err)
	}
	rule.ExpiresAt = "2026-01-01"
	if err := validateRuleLifecycle(rule, now); err == nil {
		t.Fatal("expired temporary rule was accepted")
	}
	rule.ExpiresAt = "2026-09-01"
	rule.ChangeReference = ""
	if err := validateRuleLifecycle(rule, now); err == nil {
		t.Fatal("temporary rule without change reference was accepted")
	}
	nonTemporary := editableRule{RuleGroup: "SRV", ExpiresAt: "2026-09-01"}
	if err := validateRuleLifecycle(nonTemporary, now); err == nil || !strings.Contains(err.Error(), "only allowed for TMP") {
		t.Fatalf("expires_at on a non-TMP rule was accepted: %v", err)
	}
}

func TestApprovalHashIncludesDeploymentAndValidation(t *testing.T) {
	p := validEditablePolicy()
	a, err := revisionApprovalHash("p1", nil, p, map[string]any{"device": "a"}, map[string]any{"valid": true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := revisionApprovalHash("p1", nil, p, map[string]any{"device": "b"}, map[string]any{"valid": true})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("deployment plan is not bound to approval")
	}
	c, err := revisionApprovalHash("p1", nil, p, map[string]any{"device": "a"}, map[string]any{"valid": false})
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Fatal("validation result is not bound to approval")
	}
	if !revisionValidationHasErrors(map[string]any{"valid": false, "errors": []any{"missing target"}}) {
		t.Fatal("blocking validation was not recognized")
	}
	type plan struct {
		Target   string   `json:"target"`
		Commands []string `json:"commands"`
	}
	original := plan{Target: "fw", Commands: []string{"set x"}}
	roundTripped := map[string]any{"target": "fw", "commands": []any{"set x"}}
	d, err := revisionApprovalHash("p1", nil, p, original, map[string]any{"valid": true})
	if err != nil {
		t.Fatal(err)
	}
	e, err := revisionApprovalHash("p1", nil, p, roundTripped, map[string]any{"valid": true})
	if err != nil {
		t.Fatal(err)
	}
	if d != e {
		t.Fatal("approval hash changed after JSON persistence")
	}
}

func TestDraftOptimisticLockAndMetadata(t *testing.T) {
	s := workflowTestState(t)
	p := validEditablePolicy()
	meta, err := s.saveDraftAs(p, "first@example.net", nil)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Version != 1 || meta.UpdatedBy != "first@example.net" {
		t.Fatalf("unexpected metadata: %#v", meta)
	}
	expected := meta.Version
	meta, err = s.saveDraftAs(p, "second@example.net", &expected)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Version != 2 {
		t.Fatalf("draft version = %d", meta.Version)
	}
	if _, err := s.saveDraftAs(p, "stale@example.net", &expected); !errors.Is(err, errDraftConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestRevisionWorkflowMetadataAndRejection(t *testing.T) {
	s := workflowTestState(t)
	p := validEditablePolicy()
	findings := []policyFinding{{Severity: "high", Code: "test", Message: "risk"}}
	meta := revisionMetadata{CreatedBy: "editor@example.net", Comment: "why", ChangeReference: "CHG-7", Findings: findings, DeploymentPlan: map[string]any{"target": "fw"}, Validation: map[string]any{"valid": true}}
	if err := s.storeRevisionWithMetadata("p-test", "", p, []map[string]string{}, meta); err != nil {
		t.Fatal(err)
	}
	record, err := s.loadRevisionRecord("p-test", true)
	if err != nil {
		t.Fatal(err)
	}
	if record.CreatedBy != meta.CreatedBy || record.Comment != meta.Comment || !reflect.DeepEqual(record.Findings, findings) {
		t.Fatalf("metadata mismatch: %#v", record)
	}
	if err := s.rejectRevision("p-test", "reviewer@example.net", "needs work"); err != nil {
		t.Fatal(err)
	}
	record, err = s.loadRevisionRecord("p-test", false)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "rejected" || record.RejectedBy != "reviewer@example.net" || record.RejectionComment != "needs work" {
		t.Fatalf("rejection mismatch: %#v", record)
	}
}

func TestStructuredReviewerDiffSurvivesRevisionPersistence(t *testing.T) {
	s := workflowTestState(t)
	previous := validEditablePolicy()
	if err := validateEditablePolicy(previous); err != nil {
		t.Fatal(err)
	}
	next := cloneEditablePolicy(t, previous)
	next.Services[0].Rules[0].PolicyComment = "reviewer-visible derived change"
	changes := diffPolicies(previous, next)
	if err := s.storeRevision("p-structured-diff", "", next, changes); err != nil {
		t.Fatal(err)
	}
	record, err := s.loadRevisionRecord("p-structured-diff", false)
	if err != nil {
		t.Fatal(err)
	}
	serviceIndex := slices.IndexFunc(record.Changes, func(change policyChange) bool { return change.Type == "service" })
	if serviceIndex < 0 {
		t.Fatalf("stored service diff missing: %#v", record.Changes)
	}
	serviceChange := record.Changes[serviceIndex]
	if _, ok := serviceChange.Before.(map[string]any); !ok {
		t.Fatalf("stored before value is not structured: %#v", serviceChange.Before)
	}
	if !slices.ContainsFunc(serviceChange.FieldChanges, func(field policyFieldChange) bool {
		return field.Path == "/services/web/rules/0/policy_comment"
	}) {
		t.Fatalf("stored field-level rule diff missing: %#v", serviceChange.FieldChanges)
	}
	data, err := json.Marshal(record.Changes)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"before":"{`) || !strings.Contains(string(data), `"before":{`) {
		t.Fatalf("reviewer diff was encoded as an opaque JSON string: %s", data)
	}
}

func TestPublishedRevisionKeepsApproverAndCommands(t *testing.T) {
	s := workflowTestState(t)
	p := validEditablePolicy()
	meta := revisionMetadata{CreatedBy: "editor@example.net", DeploymentPlan: map[string]any{"commands": []string{"set policy"}}, Validation: map[string]any{"valid": true}}
	if err := s.storeRevisionWithMetadata("p-published", "", p, []map[string]string{}, meta); err != nil {
		t.Fatal(err)
	}
	if err := s.markRevisionPublishedBy("p-published", "reviewer@example.net"); err != nil {
		t.Fatal(err)
	}
	record, err := s.loadRevisionRecord("p-published", false)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "published" || record.ApprovedBy != "reviewer@example.net" {
		t.Fatalf("unexpected published metadata: %#v", record)
	}
	commands, ok := revisionCommands(record.DeploymentPlan).([]any)
	if !ok || len(commands) != 1 || commands[0] != "set policy" {
		t.Fatalf("unexpected commands: %#v", revisionCommands(record.DeploymentPlan))
	}
}

func TestFinalizePublicationUpdatesRevisionAtomically(t *testing.T) {
	s := workflowTestState(t)
	p := validEditablePolicy()
	if err := s.storeRevisionWithMetadata("p-atomic", "", p, []map[string]string{}, revisionMetadata{CreatedBy: "editor@example.net"}); err != nil {
		t.Fatal(err)
	}
	if err := s.finalizePublication("p-atomic", p, "reviewer@example.net", true); err != nil {
		t.Fatal(err)
	}
	record, err := s.loadRevisionRecord("p-atomic", false)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "published" || record.ApprovedBy != "reviewer@example.net" {
		t.Fatalf("unexpected record: %#v", record)
	}
	if _, err := s.loadPublication("p-atomic"); err != nil {
		t.Fatal(err)
	}
	if err := s.finalizePublication("p-no-revision", p, "reviewer@example.net", true); err == nil {
		t.Fatal("publication without pending revision succeeded")
	}
	if _, err := s.loadPublication("p-no-revision"); err == nil {
		t.Fatal("failed transaction left a publication behind")
	}
}

func TestWhereUsedReportsRuleSide(t *testing.T) {
	records := whereUsed(validEditablePolicy(), "host:server")
	if len(records) != 1 || records[0].Service != "web" || records[0].Rule != 1 || records[0].Side != "destination" {
		t.Fatalf("unexpected references: %#v", records)
	}
}

func TestAdminWhereUsedDoesNotExposeDraftToViewer(t *testing.T) {
	s := workflowTestState(t,
		editableUser{Email: "editor@example.net", Role: "editor"},
		editableUser{Email: "viewer@example.net", Role: "viewer"},
	)
	published := validEditablePolicy()
	published.Users = append(published.Users,
		editableUser{Email: "editor@example.net", Role: "editor"},
		editableUser{Email: "viewer@example.net", Role: "viewer"},
	)
	if err := s.storePublication("published-auth", published); err != nil {
		t.Fatal(err)
	}

	draft := validEditablePolicy()
	draft.Services[0].Name = "unpublished-secret-service"
	if _, err := s.saveDraftAs(draft, "admin@example.net", nil); err != nil {
		t.Fatal(err)
	}

	request := func(email string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/admin/where-used?object=host%3Aserver", nil)
		session := newSession()
		session.Put("email", email)
		return r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, session))
	}

	viewerResponse := httptest.NewRecorder()
	s.adminWhereUsed(viewerResponse, request("viewer@example.net"))
	if viewerResponse.Code != http.StatusForbidden {
		t.Fatalf("viewer status = %d, body=%s", viewerResponse.Code, viewerResponse.Body.String())
	}
	if strings.Contains(viewerResponse.Body.String(), "unpublished-secret-service") {
		t.Fatal("viewer response exposed an unpublished service")
	}

	editorResponse := httptest.NewRecorder()
	s.adminWhereUsed(editorResponse, request("editor@example.net"))
	if editorResponse.Code != http.StatusOK || !strings.Contains(editorResponse.Body.String(), "unpublished-secret-service") {
		t.Fatalf("editor response status=%d body=%s", editorResponse.Code, editorResponse.Body.String())
	}
}

func TestLDAPSyncPreviewDoesNotMutatePolicy(t *testing.T) {
	p := &editablePolicy{Users: []editableUser{{Email: "old@example.net", Role: "viewer", Source: "ldap", DirectoryID: "old", Username: "old", Active: true}}}
	before := append([]editableUser(nil), p.Users...)
	preview, err := calculateLDAPSyncPreview(p, []ldapIdentity{{DirectoryID: "new", Username: "new", Email: "new@example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Added != 1 || preview.Disabled != 1 {
		t.Fatalf("unexpected preview: %#v", preview)
	}
	if !reflect.DeepEqual(p.Users, before) {
		t.Fatal("preview mutated the draft")
	}
}
