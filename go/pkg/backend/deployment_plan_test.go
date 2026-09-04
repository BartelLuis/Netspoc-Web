package backend

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func deployableNamingPolicy(t *testing.T) *editablePolicy {
	t.Helper()
	p := namingTestPolicy("dedicated")
	p.Networks[0].CIDR = "10.20.0.0/24"
	p.Networks[1].CIDR = "10.30.0.0/24"
	if err := derivePolicyNames(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDeploymentPlanIsDeterministicAndReviewable(t *testing.T) {
	p := deployableNamingPolicy(t)
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod", TargetContexts: []string{"prod"}, AllowDeploy: true,
		PolicyInsertBefore: "POLICYWEB-END",
		ZoneInterfaces:     map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	first := generateDeploymentPlan(p, []FortinetTarget{target})
	second := generateDeploymentPlan(p, []FortinetTarget{target})
	if !first.Ready || len(first.Errors) != 0 {
		t.Fatalf("plan is not ready: %#v", first.Errors)
	}
	if first.Hash == "" || first.Hash != second.Hash || !reflect.DeepEqual(first.Commands, second.Commands) {
		t.Fatal("deployment plan is not deterministic")
	}
	if len(first.Commands) != 4 {
		t.Fatalf("commands = %d, want two addresses, one service and one policy", len(first.Commands))
	}
	policy := first.Commands[len(first.Commands)-1]
	if policy.Kind != "policy" || !strings.Contains(policy.Command, `set name "`+p.Services[0].Rules[0].PolicyName+`"`) {
		t.Fatalf("unexpected policy preview:\n%s", policy.Command)
	}
	if !strings.Contains(policy.Command, `set srcintf "port2"`) || !strings.Contains(policy.Command, `set dstintf "port3"`) {
		t.Fatalf("interface mapping missing:\n%s", policy.Command)
	}
	if policy.InsertBefore != "POLICYWEB-END" || policy.CreatePayload["policyid"] != 0 || policy.CreatePayload["status"] != "disable" || policy.ActivatePayload["status"] != "enable" {
		t.Fatalf("create ordering metadata missing: %#v", policy)
	}
	for _, preview := range []string{"# PREPARE branch (name is absent): create DISABLED", "# FINALIZE branch (name already exists): apply the final payload", "# ACTIVATE branch (only after a successful disabled create and positioning):"} {
		if !strings.Contains(policy.Command, preview) {
			t.Errorf("policy preview does not distinguish create/update CLI branch %q:\n%s", preview, policy.Command)
		}
	}
	for field, want := range map[string]any{
		"status": "enable", "nat": "disable", "nat46": "disable", "nat64": "disable",
		"srcaddr-negate": "disable", "dstaddr-negate": "disable", "srcaddr6-negate": "disable", "dstaddr6-negate": "disable",
		"service-negate": "disable", "internet-service": "disable", "internet-service-src": "disable",
		"internet-service6": "disable", "internet-service6-src": "disable", "policy-expiry": "disable",
		"tos": "0x00", "tos-mask": "0x00", "tos-negate": "disable", "sgt-check": "disable",
		"ztna-status": "disable", "ztna-policy-redirect": "disable", "ztna-device-ownership": "disable", "ztna-tags-match-logic": "or",
	} {
		if got := policy.Payload[field]; got != want {
			t.Errorf("policy payload %q = %#v, want %#v", field, got, want)
		}
	}
	for _, field := range []string{"users", "groups", "fsso-groups", "sgt", "ztna-ems-tag", "ztna-ems-tag-secondary", "ztna-geo-tag"} {
		if values, ok := policy.Payload[field].([]map[string]string); !ok || len(values) != 0 {
			t.Errorf("policy does not explicitly clear %q: %#v", field, policy.Payload[field])
		}
	}
	for _, field := range []string{"srcaddr6", "dstaddr6"} {
		if values, ok := policy.Payload[field].([]map[string]string); !ok || len(values) != 0 {
			t.Errorf("IPv4 policy does not explicitly clear %q: %#v", field, policy.Payload[field])
		}
		if !strings.Contains(policy.Command, "unset "+field) {
			t.Errorf("policy preview does not clear %q:\n%s", field, policy.Command)
		}
	}
	for _, line := range []string{
		"set status enable", "set nat disable", "set nat46 disable", "set nat64 disable", "set policy-expiry disable",
		"unset users", "unset groups", "unset fsso-groups", "set tos 0x00", "set tos-mask 0x00", "set tos-negate disable",
		"set sgt-check disable", "unset sgt", "set ztna-status disable", "unset ztna-ems-tag", "unset ztna-ems-tag-secondary",
		"unset ztna-geo-tag", "set ztna-policy-redirect disable", "set ztna-device-ownership disable", "set ztna-tags-match-logic or",
	} {
		if !strings.Contains(policy.Command, line) {
			t.Errorf("policy preview is missing %q:\n%s", line, policy.Command)
		}
	}
}

func TestDeploymentPlanUpdatesUnifiedPolicyAtomicallyOnAddressFamilyChange(t *testing.T) {
	previous := deployableNamingPolicy(t)
	next := *previous
	next.Networks = append([]editableNetwork(nil), previous.Networks...)
	next.Networks[0].CIDR = "2001:db8:1::/64"
	next.Networks[1].CIDR = "2001:db8:2::/64"
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod", TargetContexts: []string{"prod"}, AllowDeploy: true,
		PolicyInsertBefore: "POLICYWEB-END", ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	plan := generateDeploymentPlanWithBase(previous, &next, []FortinetTarget{target})
	if !plan.Ready || len(plan.Errors) != 0 {
		t.Fatalf("family transition plan is not ready: %#v", plan.Errors)
	}
	name := previous.Services[0].Rules[0].PolicyName
	matching := []deploymentCommand{}
	for _, command := range plan.Commands {
		if command.Kind == "policy" && scalarString(command.Payload["name"]) == name {
			matching = append(matching, command)
		}
	}
	if len(matching) != 1 || matching[0].Method != "UPSERT" {
		t.Fatalf("family transition commands = %#v, want one unified UPSERT", matching)
	}
	if values, ok := matching[0].Payload["srcaddr"].([]map[string]string); !ok || len(values) != 0 {
		t.Fatalf("unified update does not explicitly clear IPv4 source: %#v", matching[0].Payload)
	}
	if values, ok := matching[0].Payload["srcaddr6"].([]map[string]string); !ok || len(values) == 0 {
		t.Fatalf("unified update is not bound to new IPv6 source: %#v", matching[0].Payload)
	}
}

func TestDeploymentPlanRejectsInPlaceDenyMatchChangeDuringStaging(t *testing.T) {
	previous := deployableNamingPolicy(t)
	previous.Services[0].Rules[0].Action = "deny"
	next := cloneEditablePolicy(t, previous)
	next.Networks[0].CIDR = "10.99.0.0/24"
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod", TargetContexts: []string{"prod"}, AllowDeploy: true,
		PolicyInsertBefore: "POLICYWEB-END", ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	plan := generateDeploymentPlanWithBase(previous, next, []FortinetTarget{target})
	if plan.Ready || !strings.Contains(strings.Join(plan.Errors, "\n"), "DENY-Policy") || !strings.Contains(strings.Join(plan.Errors, "\n"), "in-place") {
		t.Fatalf("unsafe DENY match transition was staged as executable: %#v", plan.Errors)
	}
}

func TestLegacyPublicationUsesFullPlanWithoutDeleteAssumptions(t *testing.T) {
	s := workflowTestState(t)
	previous := deployableNamingPolicy(t)
	if err := s.storePublication("bootstrap-publication", previous); err != nil {
		t.Fatal(err)
	}
	planBase, previousPlan, err := s.deploymentPlanBase(previous, "bootstrap-publication")
	if err != nil {
		t.Fatal(err)
	}
	if planBase != nil || previousPlan != nil {
		t.Fatal("legacy/bootstrap publication was treated as a deployed baseline")
	}
	next := cloneEditablePolicy(t, previous)
	next.Services[0].Rules = append([]editableRule(nil), next.Services[0].Rules[:1]...)
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod", TargetContexts: []string{"prod"},
		PolicyInsertBefore: "POLICYWEB-END", ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	plan := generateDeploymentPlanWithBase(planBase, next, []FortinetTarget{target})
	if !plan.Ready {
		t.Fatalf("full migration plan is not ready: %#v", plan.Errors)
	}
	for _, command := range plan.Commands {
		if command.Method == "DELETE" {
			t.Fatalf("full legacy migration plan assumed an unsafe deletion: %#v", command)
		}
	}
}

func TestDeploymentPlanBlocksMissingInterfaceMapping(t *testing.T) {
	p := deployableNamingPolicy(t)
	target := FortinetTarget{Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod", TargetContexts: []string{"prod"}, AllowDeploy: true, PolicyInsertBefore: "POLICYWEB-END", ZoneInterfaces: map[string]string{"GDMZ": "port2"}}
	plan := generateDeploymentPlan(p, []FortinetTarget{target})
	if plan.Ready || len(plan.Errors) == 0 || len(plan.Commands) != 0 {
		t.Fatalf("unsafe plan was accepted: %#v", plan)
	}
}

func TestFortinetPortRangeConvertsNetspocSourcePort(t *testing.T) {
	if got, err := fortinetPortRange("69:82"); err != nil || got != "82:69" {
		t.Fatalf("fortinetPortRange = %q, %v", got, err)
	}
	for _, invalid := range []string{"0", "65536", "80:90:100", "text"} {
		if _, err := fortinetPortRange(invalid); err == nil {
			t.Errorf("invalid range %q was accepted", invalid)
		}
	}
}

func TestFortiOSObjectsBindTypeAndUnusedServiceRanges(t *testing.T) {
	v4, err := subnetDeploymentObject("network:v4", "10.20.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	v6, err := hostDeploymentObject("host:v6", "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if v4.payload["type"] != "ipmask" || v6.payload["type"] != "ipprefix" {
		t.Fatalf("address types are not bound: v4=%#v v6=%#v", v4.payload, v6.payload)
	}
	_, service, cli, err := deploymentService([]string{"tcp 443"}, "ipv4")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"tcp-portrange", "udp-portrange", "sctp-portrange"} {
		if _, exists := service[field]; !exists {
			t.Fatalf("service payload does not bind %q: %#v", field, service)
		}
	}
	preview := strings.Join(cli, "\n")
	for _, line := range []string{"set tcp-portrange 443", "unset udp-portrange", "unset sctp-portrange"} {
		if !strings.Contains(preview, line) {
			t.Errorf("service preview is missing %q:\n%s", line, preview)
		}
	}
	if !decimalProtocol("254") || decimalProtocol("255") {
		t.Fatal("FortiOS protocol-number boundary is not enforced")
	}
}

func TestLegacyPolicyStagesWithoutDeploymentCommands(t *testing.T) {
	p := validEditablePolicy()
	p.Tenants = nil
	p.TargetContexts = nil
	p.NamingCatalog = namingCatalog{}
	for networkIndex := range p.Networks {
		p.Networks[networkIndex].Zone = ""
		for hostIndex := range p.Networks[networkIndex].Hosts {
			p.Networks[networkIndex].Hosts[hostIndex].Zone = ""
		}
	}
	for serviceIndex := range p.Services {
		for ruleIndex := range p.Services[serviceIndex].Rules {
			rule := &p.Services[serviceIndex].Rules[ruleIndex]
			rule.RuleGroup, rule.StableRuleID, rule.ShortID = "", "", ""
			rule.TenantMKZ, rule.TargetContext = "", ""
			rule.PolicyName, rule.PolicyComment, rule.NamingVersion = "", "", ""
		}
	}
	plan := generateDeploymentPlan(p, nil)
	if plan.Ready || len(plan.Commands) != 0 || len(plan.Warnings) == 0 {
		t.Fatalf("unexpected legacy plan: %#v", plan)
	}
}

func TestDeploymentPlanDeletesOnlyPoliciesRemovedFromApprovedBase(t *testing.T) {
	previous := deployableNamingPolicy(t)
	next := *previous
	next.Services = []editableService{}
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod", TargetContexts: []string{"prod"}, AllowDeploy: true,
		PolicyInsertBefore: "POLICYWEB-END",
		ZoneInterfaces:     map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	plan := generateDeploymentPlanWithBase(previous, &next, []FortinetTarget{target})
	if !plan.Ready || len(plan.Errors) != 0 {
		t.Fatalf("delete plan is not ready: %#v", plan.Errors)
	}
	if len(plan.Commands) != 1 || plan.Commands[0].Method != "DELETE" || plan.Commands[0].Kind != "policy" {
		t.Fatalf("unexpected delete commands: %#v", plan.Commands)
	}
	if got := plan.Commands[0].Payload["name"]; got != previous.Services[0].Rules[0].PolicyName {
		t.Fatalf("deleted policy = %v", got)
	}
	for _, field := range []string{"srcintf", "dstintf", "srcaddr", "dstaddr", "action", "service", "schedule", "logtraffic", "comments"} {
		if _, ok := plan.Commands[0].Payload[field]; !ok {
			t.Fatalf("delete safety payload is missing %q: %#v", field, plan.Commands[0].Payload)
		}
	}
	if plan.Targets[0].RequiredVersion != supportedFortiOSRelease {
		t.Fatalf("required version = %q", plan.Targets[0].RequiredVersion)
	}
}

func TestPolicyDeleteUsesImmutablePreviousInterfaceMapping(t *testing.T) {
	previous := deployableNamingPolicy(t)
	oldTarget := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod", TargetContexts: []string{"prod"},
		PolicyInsertBefore: "POLICYWEB-END", ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	previousPlan := generateDeploymentPlan(previous, []FortinetTarget{oldTarget})
	if !previousPlan.Ready {
		t.Fatalf("previous plan is not ready: %#v", previousPlan.Errors)
	}
	next := cloneEditablePolicy(t, previous)
	next.Services = []editableService{}
	newTarget := oldTarget
	newTarget.ZoneInterfaces = map[string]string{"GDMZ": "port9", "IDMZ": "port10"}
	plan := generateDeploymentPlanWithBase(previous, next, []FortinetTarget{newTarget})
	if !plan.Ready || len(plan.Commands) != 1 {
		t.Fatalf("delete plan is not ready: %#v", plan.Errors)
	}
	if got := scalarString(plan.Commands[0].Payload["srcintf"].([]map[string]string)[0]["name"]); got != "port9" {
		t.Fatalf("test setup did not reconstruct current mapping: %q", got)
	}
	if err := bindPolicyDeletePayloadsToPreviousPlan(&plan, &previousPlan); err != nil {
		t.Fatal(err)
	}
	if got := plan.Commands[0].Payload["srcintf"].([]any)[0].(map[string]any)["name"]; got != "port2" {
		t.Fatalf("DELETE was not rebound to immutable previous mapping: %#v", plan.Commands[0].Payload)
	}
}

func TestDeploymentTopologyPersistsAfterLastPolicyDelete(t *testing.T) {
	previous := deployableNamingPolicy(t)
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod", TargetContexts: []string{"prod"}, AllowDeploy: true,
		PolicyInsertBefore: "POLICYWEB-END", ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	previousPlan := generateDeploymentPlan(previous, []FortinetTarget{target})
	next := cloneEditablePolicy(t, previous)
	next.Services = []editableService{}
	deletePlan := generateDeploymentPlanWithBase(previous, next, []FortinetTarget{target})
	if !deletePlan.Ready || len(deletePlan.Targets) == 0 {
		t.Fatalf("last-policy delete lost target topology: %#v", deletePlan)
	}
	if err := validateDeploymentTopologyTransition(previousPlan, deletePlan); err != nil {
		t.Fatalf("ordinary last-policy delete was treated as target migration: %v", err)
	}
	afterDelete := generateDeploymentPlanWithBase(next, next, []FortinetTarget{target})
	if err := validateDeploymentTopologyTransition(deletePlan, afterDelete); err != nil {
		t.Fatalf("target topology disappeared after cleanup: %v", err)
	}
}

func TestFortiOS74IPv6UsesUnifiedPolicyTable(t *testing.T) {
	p := deployableNamingPolicy(t)
	p.Networks[0].CIDR = "2001:db8:1::/64"
	p.Networks[1].CIDR = "2001:db8:2::/64"
	p.Services[0].Rules[0].Protocols = []string{"icmp 128"}
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod", TargetContexts: []string{"prod"},
		ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	plan := generateDeploymentPlan(p, []FortinetTarget{target})
	if !plan.Ready || len(plan.Errors) != 0 {
		t.Fatalf("IPv6 plan is not ready: %#v", plan.Errors)
	}
	policy := plan.Commands[len(plan.Commands)-1]
	if policy.Path != "/api/v2/cmdb/firewall/policy" || policy.Kind != "policy" {
		t.Fatalf("IPv6 policy used legacy table: %#v", policy)
	}
	if _, ok := policy.Payload["srcaddr6"]; !ok {
		t.Fatalf("IPv6 source field missing: %#v", policy.Payload)
	}
	if _, ok := policy.Payload["dstaddr6"]; !ok {
		t.Fatalf("IPv6 destination field missing: %#v", policy.Payload)
	}
	for _, field := range []string{"srcaddr", "dstaddr"} {
		if values, ok := policy.Payload[field].([]map[string]string); !ok || len(values) != 0 {
			t.Fatalf("IPv6 policy does not explicitly clear %q: %#v", field, policy.Payload[field])
		}
	}
	service := plan.Commands[len(plan.Commands)-2]
	if service.Payload["protocol"] != "ICMP6" {
		t.Fatalf("IPv6 ICMP service = %#v", service.Payload)
	}
}

func TestDeploymentPolicyCreateOrderUsesReviewedSourceOrderNotManualNames(t *testing.T) {
	p := deployableNamingPolicy(t)
	base := p.Services[0].Rules[0]
	a, b, c := base, base, base
	a.PolicyName, b.PolicyName, c.PolicyName = "POLICY_A", "POLICY_B", "POLICY_C"
	p.Services[0].Rules = []editableRule{c, a, b}
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod",
		TargetContexts: []string{"prod"}, AllowDeploy: true, PolicyInsertBefore: "POLICYWEB-END",
		ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	plan := generateDeploymentPlan(p, []FortinetTarget{target})
	if !plan.Ready || len(plan.Errors) != 0 {
		t.Fatalf("plan is not ready: %#v", plan.Errors)
	}
	policies := []deploymentCommand{}
	for _, command := range plan.Commands {
		if command.Kind == "policy" && command.Method == "UPSERT" {
			policies = append(policies, command)
		}
	}
	if len(policies) != 3 {
		t.Fatalf("policy commands = %d, want 3", len(policies))
	}
	// The reviewed source order is C, A, B. Creation runs bottom-up while the
	// insertion anchors recreate exactly that order on the appliance.
	wantNames := []string{"POLICY_B", "POLICY_A", "POLICY_C"}
	wantAnchors := []string{"POLICYWEB-END", "POLICY_B", "POLICY_A"}
	for i, command := range policies {
		if got := scalarString(command.Payload["name"]); got != wantNames[i] || command.InsertBefore != wantAnchors[i] {
			t.Fatalf("policy command %d = %q before %q, want %q before %q", i, got, command.InsertBefore, wantNames[i], wantAnchors[i])
		}
		if !strings.Contains(command.Command, "filter=name=="+wantAnchors[i]) {
			t.Fatalf("review preview lacks insertion successor %q:\n%s", wantAnchors[i], command.Command)
		}
	}
}

func TestManualPolicyNameCannotCollideWithInsertionAnchor(t *testing.T) {
	p := deployableNamingPolicy(t)
	p.Services[0].Rules[0].PolicyName = "POLICYWEB-END"
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod",
		TargetContexts: []string{"prod"}, AllowDeploy: true, PolicyInsertBefore: "policyweb-end",
		ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	plan := generateDeploymentPlan(p, []FortinetTarget{target})
	if plan.Ready || !slices.ContainsFunc(plan.Errors, func(message string) bool { return strings.Contains(message, "Policy-Anker") }) {
		t.Fatalf("anchor collision produced an executable plan: %#v", plan)
	}
}

func TestDeploymentEndpointIdentityIsCanonical(t *testing.T) {
	first := deploymentEndpointID(" HTTPS://FGT.EXAMPLE.TEST:443/api/../proxy/ ")
	second := deploymentEndpointID("https://fgt.example.test/proxy")
	if first != second {
		t.Fatalf("equivalent endpoints produced different identities: %s != %s", first, second)
	}
	if first == deploymentEndpointID("https://fgt.example.test:8443/proxy") {
		t.Fatal("different endpoint ports produced the same identity")
	}
}

func TestDeploymentTargetSummaryShowsNormalizedEndpointAndExactVDOMWithoutSecrets(t *testing.T) {
	p := deployableNamingPolicy(t)
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: " HTTPS://FGT.EXAMPLE.TEST:443/api/../proxy/ ", TokenEnv: "FORTIGATE_SUPER_SECRET_TOKEN", VDOM: "Prod-Exact", TargetContexts: []string{"prod"},
		PolicyInsertBefore: "POLICYWEB-END", ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	plan := generateDeploymentPlan(p, []FortinetTarget{target})
	if !plan.Ready || len(plan.Targets) != 1 {
		t.Fatalf("target summary plan = %#v", plan)
	}
	summary := plan.Targets[0]
	if summary.Endpoint != "https://fgt.example.test/proxy" || summary.Scope != "Prod-Exact" || summary.Context != "prod" {
		t.Fatalf("target summary is not exact/reviewable: %#v", summary)
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), target.TokenEnv) || strings.Contains(string(encoded), "secret") {
		t.Fatalf("target summary leaked credential metadata: %s", encoded)
	}
}

func TestDeploymentTargetIdentityBindsPrincipalAndTrust(t *testing.T) {
	base := FortinetTarget{Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN"}
	first, err := deploymentTargetEndpointID(base)
	if err != nil {
		t.Fatal(err)
	}
	changedPrincipal := base
	changedPrincipal.TokenEnv = "OTHER_TOKEN"
	second, err := deploymentTargetEndpointID(changedPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different API principals produced the same target identity")
	}
	caFile := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(caFile, []byte("reviewed CA bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	changedTrust := base
	changedTrust.CAFile = caFile
	third, err := deploymentTargetEndpointID(changedTrust)
	if err != nil {
		t.Fatal(err)
	}
	if first == third {
		t.Fatal("custom CA contents were not bound into the target identity")
	}
	changedScope := base
	changedScope.VDOM = "other-vdom"
	fourth, err := deploymentTargetEndpointID(changedScope)
	if err != nil {
		t.Fatal(err)
	}
	if first == fourth {
		t.Fatal("different FortiGate VDOMs produced the same target identity")
	}
}

func TestDeploymentPlanEnforcesFortiOS74FieldLimits(t *testing.T) {
	p := deployableNamingPolicy(t)
	p.Services[0].Rules[0].PolicyComment = strings.Repeat("x", 1024)
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "prod",
		TargetContexts: []string{"prod"}, PolicyInsertBefore: "POLICYWEB-END",
		ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	plan := generateDeploymentPlan(p, []FortinetTarget{target})
	if plan.Ready || !strings.Contains(strings.Join(plan.Errors, "\n"), "1023") {
		t.Fatalf("overlong FortiOS comment was accepted: %#v", plan.Errors)
	}

	p = deployableNamingPolicy(t)
	longName := strings.Repeat("a", 72)
	p.Networks = append(p.Networks, editableNetwork{Name: longName, CIDR: "10.40.0.0/24", Zone: "GDMZ"})
	p.Services[0].Rules[0].Sources = []string{"network:" + longName}
	plan = generateDeploymentPlan(p, []FortinetTarget{target})
	if plan.Ready || !strings.Contains(strings.Join(plan.Errors, "\n"), "79") {
		t.Fatalf("overlong FortiOS object name was accepted: %#v", plan.Errors)
	}
}

func TestICMPServicesAreSeparatedByAddressFamilyInSharedVDOM(t *testing.T) {
	p := deployableNamingPolicy(t)
	p.TargetContexts = append(p.TargetContexts, targetContext{Name: "prod6", ContextType: "dedicated", AssignedMKZ: "M120"})
	p.Networks = append(p.Networks,
		editableNetwork{Name: "source6", CIDR: "2001:db8:1::/64", Zone: "GDMZ"},
		editableNetwork{Name: "target6", CIDR: "2001:db8:2::/64", Zone: "IDMZ"},
	)
	v4 := p.Services[0].Rules[0]
	v4.Protocols, v4.PolicyName = []string{"icmp 8"}, "POLICY_V4"
	v6 := v4
	v6.Sources, v6.Destinations = []string{"network:source6"}, []string{"network:target6"}
	v6.TargetContext, v6.PolicyName = "prod6", "POLICY_V6"
	p.Services[0].Rules = []editableRule{v4, v6}
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", TokenEnv: "FORTIGATE_TOKEN", VDOM: "root",
		TargetContexts: []string{"prod", "prod6"}, ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
	}
	plan := generateDeploymentPlan(p, []FortinetTarget{target})
	if !plan.Ready || len(plan.Errors) != 0 {
		t.Fatalf("mixed-family plan is not ready: %#v", plan.Errors)
	}
	services := map[string]string{}
	for _, command := range plan.Commands {
		if command.Kind == "service" {
			services[command.Payload["name"].(string)] = command.Payload["protocol"].(string)
		}
	}
	if len(services) != 2 {
		t.Fatalf("ICMP/ICMP6 services were incorrectly deduplicated: %#v", services)
	}
	seen := map[string]bool{}
	for _, protocol := range services {
		seen[protocol] = true
	}
	if !seen["ICMP"] || !seen["ICMP6"] {
		t.Fatalf("unexpected service protocols: %#v", services)
	}
}

func TestDenyPolicyExplicitlyDisablesVIPMatching(t *testing.T) {
	rule := editableRule{
		Action: "deny", PolicyName: "deny-vip-safe", PolicyComment: "deny without implicit VIP matching",
		Sources: []string{"source"}, Destinations: []string{"destination"},
	}
	command := deploymentPolicyCommand(FortinetTarget{Name: "edge", Type: "fortigate"}, "prod", 1, "ipv4", rule, "PW_SVC_TEST", "port1", "port2")
	if scalarString(command.Payload["match-vip"]) != "disable" || scalarString(command.Payload["match-vip-only"]) != "disable" {
		t.Fatalf("deny policy VIP modes are not bound: %#v", command.Payload)
	}
	for _, expected := range []string{"set match-vip disable", "set match-vip-only disable"} {
		if !strings.Contains(command.Command, expected) {
			t.Fatalf("deny policy preview lacks %q:\n%s", expected, command.Command)
		}
	}
}
