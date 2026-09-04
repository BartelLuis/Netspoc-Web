package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func validEditablePolicy() *editablePolicy {
	return &editablePolicy{
		Name:           "office-policy",
		Tenants:        []tenant{{MKZ: "M120", Name: "Mandant 120", Active: true}},
		TargetContexts: []targetContext{{Name: "prod", ContextType: "dedicated", AssignedMKZ: "M120"}},
		Users:          []editableUser{{Email: "admin@example.net"}},
		Owners:         []editableOwner{{Name: "network-team", Admins: []string{"admin@example.net"}}},
		Networks: []editableNetwork{{
			Name: "office", CIDR: "10.20.0.0/16", Owner: "network-team", Zone: "GDMZ",
			Hosts: []editableHost{{Name: "server", IP: "10.20.0.10", Owner: "network-team", Zone: "IDMZ"}},
		}},
		Services: []editableService{{
			Name: "web", Owners: []string{"network-team"},
			Rules: []editableRule{{
				Action: "permit", Sources: []string{"network:office"}, Destinations: []string{"host:server"}, Protocols: []string{"tcp 443"},
				RuleGroup: "SRV", Owner: "network-team", ChangeReference: "CHG-1", ReviewDate: "2030-12-31", Purpose: "Web access",
				StableRuleID: "123e4567-e89b-42d3-a456-426614174000", TargetContext: "prod", PolicyName: "WEB_ALLOW",
			}},
		}},
	}
}

func TestValidateEditablePolicy(t *testing.T) {
	p := validEditablePolicy()
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}
	p.Services[0].Rules[0].Destinations = []string{"host:missing"}
	if err := validateEditablePolicy(p); err == nil {
		t.Fatal("unknown object reference was accepted")
	}
}

func TestValidateEditablePolicyRejectsInvalidDirectoryIdentityMetadata(t *testing.T) {
	tests := map[string][]editableUser{
		"LDAP without directory ID": {{Email: "ldap@example.net", Role: "viewer", Source: "ldap", Active: true}},
		"duplicate LDAP directory ID": {
			{Email: "ldap-a@example.net", Role: "viewer", Source: "ldap", DirectoryID: "directory-1", Active: true},
			{Email: "ldap-b@example.net", Role: "viewer", Source: "ldap", DirectoryID: "directory-1", Active: true},
		},
		"local user with directory ID":     {{Email: "local@example.net", Role: "viewer", Source: "local", DirectoryID: "directory-1"}},
		"directory ID without LDAP source": {{Email: "missing-source@example.net", Role: "viewer", DirectoryID: "directory-1"}},
		"unsupported source":               {{Email: "other@example.net", Role: "viewer", Source: "other"}},
	}
	for name, extraUsers := range tests {
		t.Run(name, func(t *testing.T) {
			p := validEditablePolicy()
			p.Users = append(p.Users, extraUsers...)
			if err := validateEditablePolicy(p); err == nil {
				t.Fatal("invalid directory identity metadata was accepted")
			}
		})
	}
}

func TestHostNameIsDerivedFromIPAddress(t *testing.T) {
	p := validEditablePolicy()
	p.Networks[0].Hosts[0].Name = ""
	p.Networks[0].Hosts[0].IP = "172.25.26.1"
	p.Networks[0].CIDR = "172.25.26.0/24"
	p.Services[0].Rules[0].Destinations = []string{"host:ip-172-25-26-1"}
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}
	if got := p.Networks[0].Hosts[0].Name; got != "ip-172-25-26-1" {
		t.Fatalf("generated host name = %q", got)
	}
}

func TestMissingHostIPAddressHasSpecificError(t *testing.T) {
	p := validEditablePolicy()
	p.Networks[0].Hosts[0].Name = ""
	p.Networks[0].Hosts[0].IP = ""
	err := validateEditablePolicy(p)
	if err == nil || !strings.Contains(err.Error(), "without an IP address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOwnerHierarchyAndRoles(t *testing.T) {
	p := validEditablePolicy()
	p.Users = append(p.Users, editableUser{Email: "reader@example.net", Role: "viewer"})
	p.Owners = append(p.Owners, editableOwner{Name: "branch", Parent: "network-team", Users: []string{"reader@example.net"}})
	p.Networks[0].Hosts[0].Owner = "branch"
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}
	p.Owners[0].Parent = "branch"
	if err := validateEditablePolicy(p); err == nil {
		t.Fatal("cyclic owner hierarchy was accepted")
	}
}

func TestPolicyDiffApprovalChangesWithBase(t *testing.T) {
	next := validEditablePolicy()
	first, err := approvalHash("p1", nil, next)
	if err != nil {
		t.Fatal(err)
	}
	base := validEditablePolicy()
	base.Name = "older"
	second, err := approvalHash("p1", base, next)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("approval does not include the published base policy")
	}
	third, err := approvalHash("p2", nil, next)
	if err != nil {
		t.Fatal(err)
	}
	if first == third {
		t.Fatal("approval does not include the diff policy ID")
	}
}

func TestEmptyPolicyDiffIsAnEmptyArray(t *testing.T) {
	p := validEditablePolicy()
	changes := diffPolicies(p, p)
	if changes == nil || len(changes) != 0 {
		t.Fatalf("expected empty non-nil diff, got %#v", changes)
	}
	data, err := json.Marshal(changes)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "[]" {
		t.Fatalf("empty diff encoded as %s", data)
	}
}

func TestPolicyDiffIncludesNamingConfigurationAndDerivedRuleDetails(t *testing.T) {
	old := validEditablePolicy()
	if err := validateEditablePolicy(old); err != nil {
		t.Fatal(err)
	}
	next := cloneEditablePolicy(t, old)
	next.Tenants[0].Name = "Mandant 120 neu"
	next.TargetContexts[0].AssignedMKZ = "M121"
	next.NamingCatalog.Version = "fortigate-v2"
	next.Services[0].Description = "review-visible service change"
	next.Services[0].Rules[0].PolicyName = "SRV_GDMZ_IDMZ_h_in_ABCDE"
	next.Services[0].Rules[0].PolicyComment = "review-visible derived comment"
	next.Services[0].Rules[0].NamingVersion = "fortigate-v2"

	changes := diffPolicies(old, next)
	for _, kind := range []string{"tenant", "target_context", "naming_catalog", "service"} {
		if !slices.ContainsFunc(changes, func(change policyChange) bool {
			return change.Type == kind && change.Change == "changed" && change.Before != nil && change.After != nil
		}) {
			t.Fatalf("%s before/after change missing from diff: %#v", kind, changes)
		}
	}
	serviceChangeIndex := slices.IndexFunc(changes, func(change policyChange) bool { return change.Type == "service" })
	if serviceChangeIndex < 0 {
		t.Fatal("service change missing")
	}
	serviceChange := changes[serviceChangeIndex]
	for _, path := range []string{"/services/web/rules/0/policy_name", "/services/web/rules/0/policy_comment", "/services/web/rules/0/naming_version"} {
		if !slices.ContainsFunc(serviceChange.FieldChanges, func(field policyFieldChange) bool { return field.Path == path }) {
			t.Fatalf("derived field path %q is not reviewer-visible: %#v", path, serviceChange)
		}
	}
	before, beforeOK := serviceChange.Before.(map[string]any)
	after, afterOK := serviceChange.After.(map[string]any)
	if !beforeOK || !afterOK || before["rules"] == nil || after["rules"] == nil {
		t.Fatalf("service before/after is not structured JSON: %#v", serviceChange)
	}
}

func TestPolicyRoles(t *testing.T) {
	p := &editablePolicy{Users: []editableUser{
		{Email: "admin@example.net", Role: "admin"},
		{Email: "editor@example.net", Role: "editor"},
		{Email: "developer@example.net", Role: policyDeveloperRole},
		{Email: "reader@example.net", Role: "viewer"},
	}}
	if !hasPolicyRole(p, "EDITOR@example.net", "admin", "editor") {
		t.Fatal("editor role was not recognized")
	}
	if hasPolicyRole(p, "reader@example.net", "admin", "editor") {
		t.Fatal("viewer received administration access")
	}
	for _, role := range []string{"admin", "editor", "reviewer", "deployer", "viewer"} {
		if !hasPolicyRole(p, "DEVELOPER@example.net", role) {
			t.Fatalf("developer did not inherit %q capability", role)
		}
	}
	if !bypassesFourEyes(p, "developer@example.net") || bypassesFourEyes(p, "admin@example.net") {
		t.Fatal("four-eyes bypass is not limited to the developer role")
	}
}

func TestDeveloperSatisfiesPolicyAdministratorInvariant(t *testing.T) {
	p := validEditablePolicy()
	p.Users[0].Role = policyDeveloperRole
	if err := validateEditablePolicy(p); err != nil {
		t.Fatalf("developer-only policy administration was rejected: %v", err)
	}
	if !maintenanceLoginAllowed(p, p.Users[0].Email) {
		t.Fatal("developer cannot log in during maintenance")
	}
}

func TestDeveloperCanUseDirectAdministrationGates(t *testing.T) {
	s := workflowTestState(t, editableUser{Email: "developer@example.net", Role: policyDeveloperRole})
	s.config.FortiGateReadOnly = true
	p := validEditablePolicy()
	p.Users = append(p.Users, editableUser{Email: "developer@example.net", Role: policyDeveloperRole})
	if err := s.storePublication("p-developer-admin-gates", p); err != nil {
		t.Fatal(err)
	}
	meta, err := s.saveDraftAs(p, "admin@example.net", nil)
	if err != nil {
		t.Fatal(err)
	}

	statusRequest, _ := ownerRequest(http.MethodGet, "/admin/status", "", "developer@example.net")
	statusResponse := httptest.NewRecorder()
	s.adminStatus(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"role":"developer"`) || !strings.Contains(statusResponse.Body.String(), `"maintenance"`) || !strings.Contains(statusResponse.Body.String(), `"fortigate_read_only":true`) {
		t.Fatalf("developer status = %d body=%s", statusResponse.Code, statusResponse.Body.String())
	}

	policyRequest, _ := ownerRequest(http.MethodGet, "/admin/policy", "", "developer@example.net")
	policyResponse := httptest.NewRecorder()
	s.adminPolicy(policyResponse, policyRequest)
	if policyResponse.Code != http.StatusOK {
		t.Fatalf("developer policy GET = %d body=%s", policyResponse.Code, policyResponse.Body.String())
	}

	policyJSON, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	version := meta.Version
	stageJSON, err := json.Marshal(stageRequest{
		Policy: policyJSON, DraftVersion: &version, Comment: "developer staging test", ChangeReference: "DEV-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	stageRequestHTTP, _ := ownerRequest(http.MethodPost, "/admin/stage", string(stageJSON), "developer@example.net")
	stageRequestHTTP.Header.Set("Content-Type", "application/json")
	stageResponse := httptest.NewRecorder()
	s.adminStage(stageResponse, stageRequestHTTP)
	if stageResponse.Code != http.StatusOK {
		t.Fatalf("developer stage = %d body=%s", stageResponse.Code, stageResponse.Body.String())
	}
}

func TestInactiveLDAPAccountsAreExcludedFromLegacyExports(t *testing.T) {
	p := &editablePolicy{Users: []editableUser{
		{Email: "inactive@example.net", Source: "ldap", Active: false},
		{Email: "active@example.net", Source: "ldap", Active: true},
		{Email: "local@example.net", Source: "", Active: false},
	}}
	inactive := inactiveLDAPAccountEmails(p)
	got := withoutInactiveLDAPAccounts([]string{
		"inactive@example.net", "active@example.net", "local@example.net", "guest",
	}, inactive)
	want := []string{"active@example.net", "local@example.net", "guest"}
	if !slices.Equal(got, want) {
		t.Fatalf("filtered legacy identities = %#v, want %#v", got, want)
	}
}

func TestPublishEditablePolicy(t *testing.T) {
	root := t.TempDir()
	s := &state{
		config: &config{NetspocData: filepath.Join(root, "policies"), UserDir: filepath.Join(root, "users")},
		cache:  newCache(filepath.Join(root, "policies"), 8),
	}
	seedPolicyTestAccounts(t, s, validEditablePolicy().Users...)
	if err := s.publishPolicy(validEditablePolicy()); err != nil {
		t.Fatal(err)
	}
	if userFile, err := safeUserFile(filepath.Join(root, "users"), "admin@example.net"); err != nil {
		t.Fatal(err)
	} else if _, err := os.Stat(userFile); !os.IsNotExist(err) {
		t.Fatalf("policy publication touched local credentials: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "policies", "current", "email"))
	if err != nil {
		t.Fatal(err)
	}
	var emails map[string][]string
	if err := json.Unmarshal(data, &emails); err != nil {
		t.Fatal(err)
	}
	if got := emails["admin@example.net"]; len(got) != 1 || got[0] != "network-team" {
		t.Fatalf("unexpected authorization export: %#v", emails)
	}
	if got := s.currentPolicy(); got == "" || got[0] != 'p' {
		t.Fatalf("current policy does not identify its generated directory: %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, "policies", "policyweb.sqlite")); err != nil {
		t.Fatalf("SQLite policy store was not created: %v", err)
	}
	assets := s.loadAssets(s.currentPolicy(), "network-team")
	if len(assets.networkList) != 1 || assets.networkList[0] != "network:office" {
		t.Fatalf("unexpected network assets: %#v", assets.networkList)
	}
}

func TestPublishedPoliciesAppearInHistory(t *testing.T) {
	root := t.TempDir()
	s := &state{config: &config{NetspocData: filepath.Join(root, "policies"), UserDir: filepath.Join(root, "users")}, cache: newCache(filepath.Join(root, "policies"), 8)}
	p := validEditablePolicy()
	seedPolicyTestAccounts(t, s, p.Users...)
	if err := s.publishPolicy(p); err != nil {
		t.Fatal(err)
	}
	p.Services[0].Description = "second"
	if err := s.publishPolicy(p); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/?active_owner=network-team", nil)
	history, err := s.generateHistory(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("published policy history has %d entries: %#v", len(history), history)
	}
	if history[0]["policy"] == history[1]["policy"] {
		t.Fatalf("policy IDs are not unique: %#v", history)
	}
}

func TestPublishOwnerInheritanceAndHostOwnership(t *testing.T) {
	root := t.TempDir()
	p := validEditablePolicy()
	p.Users = append(p.Users, editableUser{Email: "child@example.net", Role: "viewer"})
	p.Owners = append(p.Owners, editableOwner{Name: "child", Parent: "network-team", Users: []string{"child@example.net"}})
	p.Networks[0].Hosts[0].Owner = "child"
	s := &state{config: &config{NetspocData: filepath.Join(root, "policies"), UserDir: filepath.Join(root, "users")}, cache: newCache(filepath.Join(root, "policies"), 8)}
	seedPolicyTestAccounts(t, s, p.Users...)
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}
	if err := s.publishPolicy(p); err != nil {
		t.Fatal(err)
	}
	version := s.currentPolicy()
	data, err := os.ReadFile(filepath.Join(root, "policies", version, "email"))
	if err != nil {
		t.Fatal(err)
	}
	var access map[string][]string
	if err := json.Unmarshal(data, &access); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(access["admin@example.net"], "child") {
		t.Fatalf("parent admin lacks child access: %#v", access)
	}
	data, err = os.ReadFile(filepath.Join(root, "policies", version, "owner", "child", "assets"))
	if err != nil {
		t.Fatal(err)
	}
	var assets struct {
		Anys map[string]struct {
			Networks map[string][]string `json:"networks"`
		} `json:"anys"`
	}
	if err := json.Unmarshal(data, &assets); err != nil {
		t.Fatal(err)
	}
	if children := assets.Anys["all"].Networks["network:office"]; !slices.Contains(children, "host:server") {
		t.Fatalf("child owner cannot see its host: %#v", assets)
	}
	req := httptest.NewRequest("GET", "/?active_owner=child&history="+version, nil)
	resources := s.getNetworkResourcesForNetworks(req, "network:office")
	if len(resources) != 1 || resources[0]["child_ip"] != "10.20.0.10" {
		t.Fatalf("owned host is missing from network resources: %#v", resources)
	}
}

func TestSelectedNetworksDefaultsToAllAndNormalizesNames(t *testing.T) {
	a := &assets{networkList: []string{"network:office", "network:dmz"}}
	if got := selectedNetworks("", a); !slices.Equal(got, []string{"network:dmz", "network:office"}) {
		t.Fatalf("empty selection should include all visible networks: %#v", got)
	}
	if got := selectedNetworks("office", a); !slices.Equal(got, []string{"network:office"}) {
		t.Fatalf("unprefixed network name was not normalized: %#v", got)
	}
}

func TestMailRecipients(t *testing.T) {
	got, err := mailRecipients("To: One <one@example.net>\nCc: two@example.net, ONE@example.net\nSubject: Test\n\nBody")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"one@example.net", "two@example.net"}) {
		t.Fatalf("unexpected recipients: %#v", got)
	}
}

func TestStripBccHeader(t *testing.T) {
	message := "To: one@example.net\nBcc: hidden@example.net,\n another@example.net\nSubject: Test\n\nBody"
	got := stripMailHeader(message, "bcc")
	if strings.Contains(strings.ToLower(got), "bcc:") || strings.Contains(got, "another@example.net") {
		t.Fatalf("Bcc header was not removed: %q", got)
	}
	if !strings.Contains(got, "Subject: Test\n\nBody") {
		t.Fatalf("other message content was damaged: %q", got)
	}
}

func TestMissingOwnerServiceListsAreEmpty(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "policy", "owner", "team"), 0750); err != nil {
		t.Fatal(err)
	}
	c := newCache(root, 8)
	got := c.loadServiceLists("policy", "team")
	if got == nil || len(got.Owner) != 0 || len(got.User) != 0 || len(got.Visible) != 0 {
		t.Fatalf("expected empty service lists, got %#v", got)
	}
}
