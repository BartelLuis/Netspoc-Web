package backend

import (
	"strings"
	"testing"
)

func namingTestPolicy(contextType string) *editablePolicy {
	p := &editablePolicy{
		Tenants:        []tenant{{MKZ: "M120", Name: "Mandant 120", Active: true}},
		TargetContexts: []targetContext{{Name: "prod", ContextType: contextType, AssignedMKZ: "M120"}},
		Networks: []editableNetwork{
			{Name: "source", Zone: "GDMZ"},
			{Name: "target", Zone: "IDMZ"},
		},
		Services: []editableService{{Name: "db", Rules: []editableRule{{
			Sources: []string{"network:source"}, Destinations: []string{"network:target"}, Protocols: []string{"tcp 1433"},
			RuleGroup: "SRV", Owner: "APP", ChangeReference: "CHG-1", ReviewDate: "2027-08-31", Purpose: "Appzugriff",
			StableRuleID: "123e4567-e89b-42d3-a456-426614174000", TenantMKZ: "M120", TargetContext: "prod",
		}}}},
	}
	normalizeCatalog(&p.NamingCatalog)
	return p
}

func TestGenerateDedicatedPolicyNameIsStable(t *testing.T) {
	p := namingTestPolicy("dedicated")
	if err := derivePolicyNames(p); err != nil {
		t.Fatal(err)
	}
	rule := &p.Services[0].Rules[0]
	first := rule.PolicyName
	if strings.Contains(first, "M120") {
		t.Fatalf("dedicated name contains MKZ: %q", first)
	}
	if len(first) > 35 || !strings.HasPrefix(first, "SRV_GDMZ_IDMZ_sql_in_") {
		t.Fatalf("unexpected name %q", first)
	}
	rule.Owner, rule.ChangeReference = "NEW", "CHG-2"
	if err := derivePolicyNames(p); err != nil {
		t.Fatal(err)
	}
	if rule.PolicyName != first {
		t.Fatalf("name changed from %q to %q", first, rule.PolicyName)
	}
}

func TestGenerateSharedPolicyNameAndIgnoreClientName(t *testing.T) {
	p := namingTestPolicy("shared")
	p.Services[0].Rules[0].PolicyName = "CLIENT_CONTROLLED"
	if err := derivePolicyNames(p); err != nil {
		t.Fatal(err)
	}
	got := p.Services[0].Rules[0].PolicyName
	if !strings.HasPrefix(got, "SRV_M120_GDMZ_IDMZ_sql_in_") {
		t.Fatalf("unexpected shared name %q", got)
	}
	if got == "CLIENT_CONTROLLED" {
		t.Fatal("client policy name was accepted")
	}
}

func TestPolicyNamingValidation(t *testing.T) {
	p := namingTestPolicy("shared")
	p.Tenants[0].MKZ = "M000"
	if err := derivePolicyNames(p); err == nil {
		t.Fatal("M000 was accepted")
	}
	p = namingTestPolicy("shared")
	p.Networks[0].Zone = ""
	if err := derivePolicyNames(p); err == nil {
		t.Fatal("missing zone was accepted")
	}
}

func TestPolicyNamingRequiresTargetContextForEveryRule(t *testing.T) {
	p := namingTestPolicy("dedicated")
	p.Tenants = nil
	p.TargetContexts = nil
	rule := &p.Services[0].Rules[0]
	rule.RuleGroup, rule.TenantMKZ, rule.TargetContext = "", "", ""
	rule.StableRuleID, rule.ShortID, rule.PolicyName, rule.PolicyComment, rule.NamingVersion = "", "", "", "", ""
	if err := derivePolicyNames(p); err == nil || !strings.Contains(err.Error(), "verbindliche Policy-Naming") {
		t.Fatalf("rule without a target context was accepted: %v", err)
	}
}

func TestShortIDCollisionIsResolvedDeterministically(t *testing.T) {
	p := namingTestPolicy("dedicated")
	rule := p.Services[0].Rules[0]
	rule.ShortID = "ABCDE"
	second := rule
	second.StableRuleID = "123e4567-e89b-42d3-a456-426614174001"
	second.ShortID = "ABCDE"
	p.Services[0].Rules = []editableRule{rule, second}
	if err := derivePolicyNames(p); err != nil {
		t.Fatal(err)
	}
	a, b := p.Services[0].Rules[0], p.Services[0].Rules[1]
	if a.ShortID == b.ShortID {
		t.Fatalf("collision was not resolved: %s", a.ShortID)
	}
	if err := derivePolicyNames(p); err != nil {
		t.Fatal(err)
	}
	if p.Services[0].Rules[1].ShortID != b.ShortID {
		t.Fatal("resolved ID was not stable")
	}
}

func TestRuleIdentityFieldsAreServerOwned(t *testing.T) {
	current := namingTestPolicy("dedicated")
	if err := derivePolicyNames(current); err != nil {
		t.Fatal(err)
	}
	original := current.Services[0].Rules[0]
	next := namingTestPolicy("dedicated")
	next.Services[0].Rules[0].StableRuleID = original.StableRuleID
	next.Services[0].Rules[0].ShortID = "FFFFF"
	next.Services[0].Rules[0].PolicyName = "CLIENT_CONTROLLED"
	protectRuleIdentities(current, next)
	if got := next.Services[0].Rules[0].ShortID; got != original.ShortID {
		t.Fatalf("existing short ID = %q, want %q", got, original.ShortID)
	}
	if err := derivePolicyNames(next); err != nil {
		t.Fatal(err)
	}
	if next.Services[0].Rules[0].PolicyName == "CLIENT_CONTROLLED" {
		t.Fatal("client-controlled policy name survived derivation")
	}

	forgedID := "123e4567-e89b-42d3-a456-426614174099"
	created := namingTestPolicy("dedicated")
	created.Services[0].Rules[0].StableRuleID = forgedID
	created.Services[0].Rules[0].ShortID = "ABCDE"
	protectRuleIdentities(current, created)
	if created.Services[0].Rules[0].StableRuleID != "" || created.Services[0].Rules[0].ShortID != "" {
		t.Fatal("client-provided identity for a new rule was accepted")
	}
	if err := derivePolicyNames(created); err != nil {
		t.Fatal(err)
	}
	if created.Services[0].Rules[0].StableRuleID == forgedID {
		t.Fatal("backend reused a client-provided stable rule ID")
	}
}

func TestDuplicateStableRuleIDIsRejected(t *testing.T) {
	p := namingTestPolicy("dedicated")
	p.Services[0].Rules = append(p.Services[0].Rules, p.Services[0].Rules[0])
	if err := derivePolicyNames(p); err == nil || !strings.Contains(err.Error(), "mehrfach") {
		t.Fatalf("duplicate stable rule ID was accepted: %v", err)
	}
}

func TestNamingCatalogChangesRequireNewVersion(t *testing.T) {
	current := namingTestPolicy("dedicated")
	next := cloneEditablePolicy(t, current)
	next.NamingCatalog.ServiceCodes["tcp 1433"] = "db"
	if err := enforceNamingCatalogVersion(current, next); err == nil || !strings.Contains(err.Error(), "neue Naming-Version") {
		t.Fatalf("catalog change without version bump was accepted: %v", err)
	}
	next.NamingCatalog.Version = "fortigate-v2"
	if err := enforceNamingCatalogVersion(current, next); err != nil {
		t.Fatalf("versioned catalog change was rejected: %v", err)
	}
}

func TestVersionedCatalogDoesNotRenameExistingRules(t *testing.T) {
	current := namingTestPolicy("dedicated")
	if err := derivePolicyNames(current); err != nil {
		t.Fatal(err)
	}
	original := current.Services[0].Rules[0]
	next := cloneEditablePolicy(t, current)
	next.NamingCatalog.ServiceCodes["tcp 1433"] = "db"
	next.NamingCatalog.Version = "fortigate-v2"
	next.Services[0].Rules[0].Owner = "NEW-OWNER"
	created := original
	created.StableRuleID, created.ShortID, created.PolicyName, created.PolicyComment, created.NamingVersion = "", "", "", "", ""
	created.ChangeReference = "CHG-NEW"
	next.Services[0].Rules = append(next.Services[0].Rules, created)
	if err := enforceNamingCatalogVersion(current, next); err != nil {
		t.Fatal(err)
	}
	protectRuleIdentities(current, next)
	if err := derivePolicyNames(next); err != nil {
		t.Fatal(err)
	}
	retained := next.Services[0].Rules[0]
	if retained.PolicyName != original.PolicyName || retained.NamingVersion != original.NamingVersion {
		t.Fatalf("existing rule was renamed: %#v -> %#v", original, retained)
	}
	if !strings.Contains(retained.PolicyComment, "Owner: NEW-OWNER") {
		t.Fatalf("mutable metadata was not refreshed in retained comment: %q", retained.PolicyComment)
	}
	newRule := next.Services[0].Rules[1]
	if newRule.NamingVersion != "fortigate-v2" || !strings.Contains(newRule.PolicyName, "_db_") {
		t.Fatalf("new rule did not use versioned catalog: %#v", newRule)
	}
}

func TestNamingCatalogValidationRejectsUnsafeDefinitions(t *testing.T) {
	tests := map[string]func(*namingCatalog){
		"rank order": func(c *namingCatalog) { c.ZoneRanks["OeDMZ"] = c.ZoneRanks["EXT"] },
		"zone code":  func(c *namingCatalog) { c.ZoneShortCodes["GDMZ"] = "bad-code" },
		"service code": func(c *namingCatalog) {
			c.ServiceCodes["tcp 8443"] = "bad_code"
		},
		"shortening": func(c *namingCatalog) { c.ServiceShortCodes["sql"] = "sql" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			catalog := defaultNamingCatalog()
			mutate(&catalog)
			if err := validateNamingCatalog(&catalog); err == nil {
				t.Fatal("unsafe naming catalog was accepted")
			}
		})
	}
}

func TestEditorCannotChangeAdministrativeCatalogScope(t *testing.T) {
	current := namingTestPolicy("dedicated")
	next := cloneEditablePolicy(t, current)
	next.NamingCatalog.Version = "fortigate-v2"
	if err := enforceEditorPolicyScope(current, next); err == nil {
		t.Fatal("editor was allowed to change naming catalog")
	}
}
