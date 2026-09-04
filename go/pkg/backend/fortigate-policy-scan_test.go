package backend

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fortiGatePolicyScanFixture struct {
	mu       sync.Mutex
	policies []map[string]any
	fail     bool
	truncate bool
	methods  []string
	starts   []int
}

func (fixture *fortiGatePolicyScanFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.methods = append(fixture.methods, r.Method)

	if fixture.fail {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	start, _ := strconv.Atoi(r.URL.Query().Get("start"))
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if start < 0 || start > len(fixture.policies) || count < 1 {
		http.Error(w, "invalid pagination", http.StatusBadRequest)
		return
	}
	fixture.starts = append(fixture.starts, start)
	end := start + count
	if end > len(fixture.policies) {
		end = len(fixture.policies)
	}
	results := fixture.policies[start:end]
	if fixture.truncate && start == 0 && len(results) > 1 {
		results = results[:1]
	}
	writeFakeFortiGate(w, map[string]any{
		"status":        "success",
		"http_status":   http.StatusOK,
		"revision":      "fixture-revision",
		"size":          len(fixture.policies),
		"matched_count": len(fixture.policies),
		"results":       results,
	})
}

func (fixture *fortiGatePolicyScanFixture) update(mutator func([]map[string]any)) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	mutator(fixture.policies)
}

func (fixture *fortiGatePolicyScanFixture) setFailure(fail bool) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.fail = fail
}

func (fixture *fortiGatePolicyScanFixture) setTruncated(truncate bool) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.truncate = truncate
}

func (fixture *fortiGatePolicyScanFixture) requestMethods() []string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return append([]string(nil), fixture.methods...)
}

func (fixture *fortiGatePolicyScanFixture) requestStarts() []int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return append([]int(nil), fixture.starts...)
}

func TestFortiGatePolicyScanReconcilesInventoryReadOnly(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "scanner-test-token")
	t.Setenv(fortiGateReadOnlyEnv, "true")

	fixture := &fortiGatePolicyScanFixture{policies: []map[string]any{
		{
			"policyid": 1, "uuid": "11111111-1111-1111-1111-111111111111", "name": "WEB_ALLOW",
			"action": "accept", "status": "enable", "srcintf": []map[string]string{{"name": "port2"}},
			"dstintf": []map[string]string{{"name": "port3"}}, "srcaddr": []map[string]string{{"name": "all"}},
			"dstaddr": []map[string]string{{"name": "web-server"}}, "service": []map[string]string{{"name": "HTTPS"}},
			"schedule": "always", "comments": "managed rule",
		},
		{
			"policyid": 2, "uuid": "22222222-2222-2222-2222-222222222222", "name": "OUT_OF_BAND",
			"action": "accept", "status": "enable", "srcintf": []map[string]string{{"name": "port1"}},
			"dstintf": []map[string]string{{"name": "port4"}}, "srcaddr": []map[string]string{{"name": "all"}},
			"dstaddr": []map[string]string{{"name": "all"}}, "service": []map[string]string{{"name": "PING"}},
			"schedule": "always", "comments": "local exception",
		},
	}}
	server := httptest.NewTLSServer(fixture)
	defer server.Close()

	s := workflowTestState(t)
	s.config.FortiGateReadOnly = true
	s.config.FortinetTargets = []FortinetTarget{runtimeTestTarget(t, server)}
	if err := s.storePublication("p-scanner-base", validEditablePolicy()); err != nil {
		t.Fatal(err)
	}

	first, err := s.runFortiGatePolicyScan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Targets != 1 || first.Succeeded != 1 || first.Failed != 0 || first.Observed != 2 || first.NewPolicies != 2 || first.NewUnknown != 1 {
		t.Fatalf("first scan summary = %#v", first)
	}
	records, scans, services, err := s.listFortiGatePolicyInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || len(scans) != 1 || len(services) != 1 || services[0] != "web" {
		t.Fatalf("inventory sizes records=%d scans=%d services=%#v", len(records), len(scans), services)
	}
	byName := map[string]fortiGatePolicyObservationView{}
	for _, record := range records {
		byName[record.PolicyName] = record
	}
	managed := byName["WEB_ALLOW"]
	if managed.AssignedService != "web" || managed.AssignmentSource != "automatic" || managed.Action != "accept" || managed.Revision != 1 {
		t.Fatalf("automatically matched record = %#v", managed)
	}
	unknown := byName["OUT_OF_BAND"]
	if unknown.AssignedService != "" || unknown.AssignmentSource != "unknown" || unknown.Revision != 1 {
		t.Fatalf("unknown record = %#v", unknown)
	}

	second, err := s.runFortiGatePolicyScan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.Observed != 2 || second.NewPolicies != 0 || second.NewUnknown != 0 {
		t.Fatalf("repeat scan summary = %#v", second)
	}
	records, _, _, err = s.listFortiGatePolicyInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("repeat scan created duplicate observations: %#v", records)
	}
	for _, record := range records {
		if record.Revision != 1 {
			t.Fatalf("unchanged record revision = %d, want 1: %#v", record.Revision, record)
		}
	}
	previous, pinnedRevision, err := s.assignFortiGatePolicy(managed.ID, managed.Revision, "")
	if err != nil {
		t.Fatal(err)
	}
	if previous != "web" || pinnedRevision != 2 {
		t.Fatalf("manual unknown assignment result previous=%q revision=%d", previous, pinnedRevision)
	}

	previous, revision, err := s.assignFortiGatePolicy(unknown.ID, unknown.Revision, "web")
	if err != nil {
		t.Fatal(err)
	}
	if previous != unknownFortiGateService || revision != 2 {
		t.Fatalf("manual assignment result previous=%q revision=%d", previous, revision)
	}
	fixture.update(func(policies []map[string]any) {
		policies[1]["comments"] = "local exception, revised on device"
	})
	third, err := s.runFortiGatePolicyScan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if third.Observed != 2 || third.NewPolicies != 0 || third.NewUnknown != 0 {
		t.Fatalf("post-assignment scan summary = %#v", third)
	}
	records, _, _, err = s.listFortiGatePolicyInventory()
	if err != nil {
		t.Fatal(err)
	}
	byName = map[string]fortiGatePolicyObservationView{}
	for _, record := range records {
		byName[record.PolicyName] = record
	}
	assigned := byName["OUT_OF_BAND"]
	if assigned.AssignedService != "web" || assigned.AssignmentSource != "manual" || assigned.Revision != 3 || assigned.Comments != "local exception, revised on device" {
		t.Fatalf("manual assignment was not preserved: %#v", assigned)
	}
	pinnedUnknown := byName["WEB_ALLOW"]
	if pinnedUnknown.AssignedService != "" || pinnedUnknown.AssignmentSource != "manual" || pinnedUnknown.Revision != 2 {
		t.Fatalf("manual unknown assignment was not preserved: %#v", pinnedUnknown)
	}

	fixture.setTruncated(true)
	incomplete, err := s.runFortiGatePolicyScan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if incomplete.Targets != 1 || incomplete.Succeeded != 0 || incomplete.Failed != 1 {
		t.Fatalf("incomplete scan summary = %#v", incomplete)
	}
	records, scans, _, err = s.listFortiGatePolicyInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || len(scans) != 1 || !strings.Contains(scans[0].LastError, "incomplete") {
		t.Fatalf("incomplete scan changed inventory: records=%#v scans=%#v", records, scans)
	}
	fixture.setTruncated(false)

	fixture.setFailure(true)
	failed, err := s.runFortiGatePolicyScan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if failed.Targets != 1 || failed.Succeeded != 0 || failed.Failed != 1 {
		t.Fatalf("failed scan summary = %#v", failed)
	}
	records, scans, _, err = s.listFortiGatePolicyInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("failed scan erased existing observations: %#v", records)
	}
	if len(scans) != 1 || scans[0].LastError == "" || scans[0].ObservedCount != 2 {
		t.Fatalf("failed scan state = %#v", scans)
	}
	for _, method := range fixture.requestMethods() {
		if method != http.MethodGet {
			t.Fatalf("policy scanner sent mutating method %q", method)
		}
	}

	fixture.setFailure(false)
	s.config.FortinetTargets = nil
	removed, err := s.runFortiGatePolicyScan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if removed.Targets != 0 {
		t.Fatalf("removed target scan summary = %#v", removed)
	}
	records, scans, _, err = s.listFortiGatePolicyInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 || len(scans) != 0 {
		t.Fatalf("removed target remained visible: records=%#v scans=%#v", records, scans)
	}

	s.config.FortinetTargets = []FortinetTarget{runtimeTestTarget(t, server)}
	restored, err := s.runFortiGatePolicyScan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if restored.Observed != 2 || restored.NewPolicies != 0 {
		t.Fatalf("restored target scan summary = %#v", restored)
	}
	records, _, _, err = s.listFortiGatePolicyInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("restored target inventory = %#v", records)
	}
	foundRestoredManualAssignment := false
	for _, record := range records {
		if record.PolicyName == "OUT_OF_BAND" {
			foundRestoredManualAssignment = true
			if record.AssignedService != "web" || record.AssignmentSource != "manual" {
				t.Fatalf("restored target lost manual assignment: %#v", record)
			}
		}
	}
	if !foundRestoredManualAssignment {
		t.Fatal("restored target has no OUT_OF_BAND observation")
	}
}

func TestFortiGatePolicyCompleteSnapshotPaginatesBeyondOneHundred(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "scanner-test-token")
	policies := make([]map[string]any, 0, 101)
	for index := 0; index < 101; index++ {
		policies = append(policies, map[string]any{"policyid": index + 1, "name": fmt.Sprintf("POLICY_%03d", index)})
	}
	fixture := &fortiGatePolicyScanFixture{policies: policies}
	server := httptest.NewTLSServer(fixture)
	defer server.Close()
	target := runtimeTestTarget(t, server)
	client, err := target.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	objects, err := listFortiGateObjectsCompleteSnapshot(context.Background(), client, target, "/api/v2/cmdb/firewall/policy", nil, fortiGatePolicyScanPageSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != len(policies) {
		t.Fatalf("complete policy snapshot returned %d objects, want %d", len(objects), len(policies))
	}
	starts := fixture.requestStarts()
	if len(starts) != 2 || starts[0] != 0 || starts[1] != 100 {
		t.Fatalf("complete policy snapshot starts = %#v", starts)
	}
}

func TestFortiGatePolicySnapshotUsesOnlyTopLevelIdentity(t *testing.T) {
	target := fortiGatePolicyScanTarget{ID: "target", Config: FortinetTarget{Name: "edge", VDOM: "root"}}
	snapshot, err := makeFortiGatePolicySnapshot(target, fortiGateObject{MKey: "7", Data: map[string]any{
		"policyid": 7,
		"srcaddr":  []any{map[string]any{"name": "nested-name", "uuid": "11111111-1111-1111-1111-111111111111"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.PolicyName != "" || !snapshot.IdentityWeak || snapshot.RemoteIdentity != "policyid:7\x00name:" {
		t.Fatalf("nested identity leaked into policy snapshot: %#v", snapshot)
	}
	_, err = makeFortiGatePolicySnapshot(target, fortiGateObject{MKey: "8", Data: map[string]any{
		"policyid": 8, "name": "INVALID_UUID", "uuid": "not-a-policy-uuid",
	}})
	if err == nil {
		t.Fatal("invalid top-level policy UUID was accepted")
	}
}

func TestFortiGatePolicyHandlersRequireAdministrator(t *testing.T) {
	viewer := editableUser{Email: "viewer@example.net", Role: "viewer", Source: "local", Active: true}
	developer := editableUser{Email: "developer@example.net", Role: policyDeveloperRole, Source: "local", Active: true}
	s := workflowTestState(t, viewer, developer)
	policy := validEditablePolicy()
	policy.Users[0].Role = "admin"
	policy.Users = append(policy.Users, viewer, developer)
	if err := s.storePublication("p-policy-handler-roles", policy); err != nil {
		t.Fatal(err)
	}

	for name, test := range map[string]struct {
		method  string
		path    string
		body    string
		handler http.HandlerFunc
	}{
		"list":   {method: http.MethodGet, path: "/admin/fortigate-policies", handler: s.adminFortiGatePolicies},
		"scan":   {method: http.MethodPost, path: "/admin/fortigate-policies/scan", body: `{}`, handler: s.adminScanFortiGatePolicies},
		"assign": {method: http.MethodPost, path: "/admin/fortigate-policies/assign", body: `{}`, handler: s.adminAssignFortiGatePolicy},
	} {
		t.Run(name+" rejects viewer", func(t *testing.T) {
			request, _ := ownerRequest(test.method, test.path, test.body, viewer.Email)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			test.handler(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("viewer response = %d, body=%s", response.Code, response.Body.String())
			}
		})
	}

	request, _ := ownerRequest(http.MethodGet, "/admin/fortigate-policies", "", developer.Email)
	response := httptest.NewRecorder()
	s.adminFortiGatePolicies(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"scanner_enabled":false`) {
		t.Fatalf("developer inventory response = %d, body=%s", response.Code, response.Body.String())
	}
}

func TestFortiGatePolicyScanLeasePreventsOverlap(t *testing.T) {
	s := workflowTestState(t)
	acquired, err := s.acquireFortiGatePolicyScanLease("first")
	if err != nil || !acquired {
		t.Fatalf("first lease = %v, %v", acquired, err)
	}
	defer s.releaseFortiGatePolicyScanLease("first")
	acquired, err = s.acquireFortiGatePolicyScanLease("second")
	if err != nil {
		t.Fatal(err)
	}
	if acquired {
		t.Fatal("overlapping policy scan acquired the active lease")
	}
	s.releaseFortiGatePolicyScanLease("first")
	acquired, err = s.acquireFortiGatePolicyScanLease("second")
	if err != nil || !acquired {
		t.Fatalf("released lease was not reacquired: %v, %v", acquired, err)
	}
	s.releaseFortiGatePolicyScanLease("second")
}
