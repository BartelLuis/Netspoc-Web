package backend

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func policyRequestTestState(t *testing.T, customize func(*editablePolicy)) (*state, string) {
	t.Helper()
	additionalUsers := []editableUser{
		{Email: "viewer@example.net", Role: "viewer"},
		{Email: "editor@example.net", Role: "editor"},
		{Email: "reviewer@example.net", Role: "reviewer"},
		{Email: "deployer@example.net", Role: "deployer"},
		{Email: "developer@example.net", Role: policyDeveloperRole},
	}
	s := workflowTestState(t, additionalUsers...)
	p := validEditablePolicy()
	p.Users = append(p.Users, additionalUsers...)
	p.Owners[0].Users = append(p.Owners[0].Users,
		"viewer@example.net", "editor@example.net", "reviewer@example.net", "deployer@example.net", "developer@example.net",
	)
	p.Networks[0].Hosts = append(p.Networks[0].Hosts, editableHost{Name: "spare", IP: "10.20.0.11", Owner: "network-team", Zone: "IDMZ"})
	if customize != nil {
		customize(p)
	}
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}
	if err := s.storePublication("p-request-base", p); err != nil {
		t.Fatal(err)
	}
	// Owner authorization normally resolves the immutable policy behind the
	// current symlink. Keep this fixture portable on Windows hosts without the
	// symlink privilege by using the legacy history/current lookup shape.
	if err := os.MkdirAll(filepath.Join(s.config.NetspocData, "current"), 0o750); err != nil {
		t.Fatal(err)
	}
	authorizationDir := filepath.Join(s.config.NetspocData, "history", "current")
	if err := os.MkdirAll(authorizationDir, 0o750); err != nil {
		t.Fatal(err)
	}
	ownerAccess := map[string][]string{
		"admin@example.net":     {"network-team"},
		"viewer@example.net":    {"network-team"},
		"editor@example.net":    {"network-team"},
		"reviewer@example.net":  {"network-team"},
		"deployer@example.net":  {"network-team"},
		"developer@example.net": {"network-team"},
	}
	encodedAccess, err := json.Marshal(ownerAccess)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authorizationDir, "email"), encodedAccess, 0o640); err != nil {
		t.Fatal(err)
	}
	ownerDir := filepath.Join(s.config.NetspocData, "p-request-base", "owner", "network-team")
	if err := os.MkdirAll(ownerDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ownerDir, "service_lists"), []byte(`{"Owner":["web"],"User":[],"Visible":[]}`), 0o640); err != nil {
		t.Fatal(err)
	}
	return s, "p-request-base"
}

func policyRequestCall(t *testing.T, actor, method, target string, payload any, handler func(http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	body := ""
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = string(data)
	}
	request, _ := ownerRequest(method, target, body, actor)
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

func submitRuleChangeForTest(t *testing.T, s *state, actor, base, operation, field string, values ...string) *policyRequestRecord {
	t.Helper()
	payload := map[string]any{
		"request_type": "rule_change", "active_owner": "network-team", "base_version": base,
		"reason": "required by an automated request workflow test",
		"rule_change": map[string]any{
			"service": "web", "stable_rule_id": "123e4567-e89b-42d3-a456-426614174000",
			"operation": operation, "field": field, "values": values,
		},
	}
	recorder := policyRequestCall(t, actor, http.MethodPost, "/requests", payload, s.policyRequests)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("submit status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Request policyRequestRecord `json:"request"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return &response.Request
}

func stageRequestForTest(t *testing.T, s *state, id string, revision int64) *requestStageResult {
	return stageRequestAsForTest(t, s, "editor@example.net", id, revision)
}

func stageRequestAsForTest(t *testing.T, s *state, actor, id string, revision int64) *requestStageResult {
	t.Helper()
	recorder := policyRequestCall(t, actor, http.MethodPost, "/admin/requests/stage", map[string]any{"id": id, "revision": revision}, s.adminStagePolicyRequest)
	if recorder.Code != http.StatusOK {
		t.Fatalf("stage status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		PolicyID        string          `json:"policy_id"`
		Approval        string          `json:"approval"`
		Policy          *editablePolicy `json:"policy"`
		RequestRevision int64           `json:"revision"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return &requestStageResult{PolicyID: response.PolicyID, Approval: response.Approval, Policy: response.Policy, RequestRevision: response.RequestRevision}
}

func loadRequestForTest(t *testing.T, s *state, id string) *policyRequestRecord {
	t.Helper()
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	record, err := loadPolicyRequestDB(db, id)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestPolicyActorOwnerMemberships(t *testing.T) {
	owners := map[string]editableOwner{
		"root":         {Name: "root", Admins: []string{"Reviewer@Example.Net"}},
		"child":        {Name: "child", Parent: "root"},
		"leaf":         {Name: "leaf", Parent: "child"},
		"unrelated":    {Name: "unrelated"},
		"cycle-a":      {Name: "cycle-a", Parent: "cycle-b"},
		"cycle-b":      {Name: "cycle-b", Parent: "cycle-a", Users: []string{"reviewer@example.net"}},
		"missing-root": {Name: "missing-root", Parent: "unknown"},
	}
	memberships := policyActorOwnerMemberships(owners, " reviewer@example.net ")
	for _, name := range []string{"root", "child", "leaf", "cycle-a", "cycle-b"} {
		if !memberships[name] {
			t.Errorf("expected membership for %q", name)
		}
	}
	for _, name := range []string{"unrelated", "missing-root"} {
		if memberships[name] {
			t.Errorf("unexpected membership for %q", name)
		}
	}
}

func TestDeveloperHasEveryPolicyRequestOwnerMembership(t *testing.T) {
	p := validEditablePolicy()
	p.Users = append(p.Users, editableUser{Email: "developer@example.net", Role: policyDeveloperRole})
	p.Owners = append(p.Owners, editableOwner{Name: "unassigned"})
	memberships := policyActorOwnerMembershipsForPolicy(p, " DEVELOPER@example.net ")
	for _, owner := range p.Owners {
		if !memberships[owner.Name] {
			t.Errorf("developer lacks request membership for owner %q", owner.Name)
		}
	}
}

func TestPolicyRequestSubmissionAuthorizationAndStrictValidation(t *testing.T) {
	s, base := policyRequestTestState(t, nil)
	record := submitRuleChangeForTest(t, s, "viewer@example.net", base, "add", "destinations", "host:spare")
	if record.Status != "submitted" || record.Revision != 1 || record.BaseVersion != base {
		t.Fatalf("submitted request=%#v", record)
	}

	guest := policyRequestCall(t, "guest", http.MethodPost, "/requests", map[string]any{"request_type": "rule_change"}, s.policyRequests)
	if guest.Code != http.StatusForbidden {
		t.Fatalf("guest status=%d body=%s", guest.Code, guest.Body.String())
	}
	stale := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
		"request_type": "rule_change", "active_owner": "network-team", "base_version": "p-stale", "reason": "stale",
		"rule_change": map[string]any{"service": "web", "stable_rule_id": "123e4567-e89b-42d3-a456-426614174000", "operation": "add", "field": "protocols", "value": "tcp 9443"},
	}, s.policyRequests)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale base status=%d body=%s", stale.Code, stale.Body.String())
	}
	unknownRule := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
		"request_type": "rule_change", "active_owner": "network-team", "base_version": base, "reason": "unknown rule",
		"rule_change": map[string]any{"service": "web", "stable_rule_id": "223e4567-e89b-42d3-a456-426614174000", "operation": "add", "field": "protocols", "value": "tcp 9443"},
	}, s.policyRequests)
	if unknownRule.Code != http.StatusBadRequest || !strings.Contains(unknownRule.Body.String(), "stable_rule_id") {
		t.Fatalf("unknown rule status=%d body=%s", unknownRule.Code, unknownRule.Body.String())
	}
	unknownField := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
		"request_type": "rule_change", "active_owner": "network-team", "base_version": base, "reason": "strict", "unexpected": true,
		"rule_change": map[string]any{"service": "web", "stable_rule_id": "123e4567-e89b-42d3-a456-426614174000", "operation": "add", "field": "protocols", "value": "tcp 9443"},
	}, s.policyRequests)
	if unknownField.Code != http.StatusBadRequest || !strings.Contains(unknownField.Body.String(), "unknown field") {
		t.Fatalf("unknown field status=%d body=%s", unknownField.Code, unknownField.Body.String())
	}
}

func TestPolicyRequestStoreRechecksPublicationAtomically(t *testing.T) {
	s, base := policyRequestTestState(t, nil)
	p, version, err := s.latestPublicationSnapshot()
	if err != nil || p == nil || version != base {
		t.Fatalf("load request base: policy=%v version=%q err=%v", p != nil, version, err)
	}
	payload := storedRuleChangePayload{
		StableRuleID: "123e4567-e89b-42d3-a456-426614174000",
		Service:      "web",
		Field:        "destinations",
		Operation:    "add",
		Values:       []string{"host:spare"},
	}
	if _, err := s.validateRuleChangeSubmission(p, "network-team", payload); err != nil {
		t.Fatal(err)
	}
	if err := s.storePublication("p-request-race-winner", p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.storeSubmittedPolicyRequest("viewer@example.net", "rule_change", "network-team", base, "race regression", payload); !errors.Is(err, errPolicyRequestConflict) {
		t.Fatalf("stale request store error=%v", err)
	}
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var requests, events int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_request`).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_request_event`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if requests != 0 || events != 0 {
		t.Fatalf("stale request was partly stored: requests=%d events=%d", requests, events)
	}
}

func TestPolicyRequestSubmissionQuotaIsAtomic(t *testing.T) {
	s, base := policyRequestTestState(t, nil)
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	payloadJSON := `{"stable_rule_id":"123e4567-e89b-42d3-a456-426614174000","service":"web","field":"protocols","operation":"add","values":["tcp 9443"]}`
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i := 0; i < policyRequestSubmitLimit; i++ {
		id := fmt.Sprintf("r-quota-%03d", i)
		if _, err := tx.Exec(`INSERT INTO policy_request(id,type,requester,active_owner,base_version,payload,reason,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'submitted',1,?,?)`, id, "rule_change", "viewer@example.net", "network-team", base, payloadJSON, "quota test", now, now); err != nil {
			tx.Rollback()
			db.Close()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	payload := storedRuleChangePayload{StableRuleID: "123e4567-e89b-42d3-a456-426614174000", Service: "web", Field: "protocols", Operation: "add", Values: []string{"tcp 9555"}}
	if _, err := s.storeSubmittedPolicyRequest("viewer@example.net", "rule_change", "network-team", base, "quota regression", payload); !errors.Is(err, errPolicyRequestRateLimited) {
		t.Fatalf("quota store error=%v", err)
	}
	response := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
		"request_type": "rule_change", "active_owner": "network-team", "base_version": base, "reason": "quota response regression",
		"rule_change": map[string]any{"service": "web", "stable_rule_id": payload.StableRuleID, "operation": "add", "field": "protocols", "value": "tcp 9666"},
	}, s.policyRequests)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("quota response status=%d retry-after=%q body=%s", response.Code, response.Header().Get("Retry-After"), response.Body.String())
	}
}

func TestPolicyRequestComplexityAndPayloadLimits(t *testing.T) {
	s, base := policyRequestTestState(t, nil)
	tooManyRules := make([]map[string]any, policyRequestRuleLimit+1)
	for i := range tooManyRules {
		tooManyRules[i] = map[string]any{}
	}
	response := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
		"request_type": "new_service", "active_owner": "network-team", "base_version": base, "reason": "complexity regression",
		"new_service": map[string]any{"name": "too-complex", "owners": []string{"network-team"}, "rules": tooManyRules},
	}, s.policyRequests)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "at most") {
		t.Fatalf("complex service status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := normalizeRequestValues(make([]string, policyRequestValueLimit+1), false); err == nil {
		t.Fatal("oversized rule-change value list was accepted")
	}
	oversized := strings.Repeat("x", policyRequestPayloadLimit+1)
	if _, err := s.storeSubmittedPolicyRequest("viewer@example.net", "new_service", "network-team", base, "payload regression", oversized); !errors.Is(err, errPolicyRequestPayloadTooLarge) {
		t.Fatalf("oversized stored payload error=%v", err)
	}
	transient := httptest.NewRecorder()
	writePolicyRequestSubmissionError(transient, wrapPolicyRequestStoreError(errors.New("database is locked (SQLITE_BUSY)")))
	if transient.Code != http.StatusServiceUnavailable || transient.Header().Get("Retry-After") != "1" || strings.Contains(strings.ToLower(transient.Body.String()), "sqlite") {
		t.Fatalf("busy response status=%d retry-after=%q body=%s", transient.Code, transient.Header().Get("Retry-After"), transient.Body.String())
	}
}

func TestPolicyRequestTimestampAndCursorSortChronologically(t *testing.T) {
	second := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	values := []string{
		policyRequestTimestamp(second),
		policyRequestTimestamp(second.Add(120 * time.Millisecond)),
		policyRequestTimestamp(second.Add(120*time.Millisecond + 100*time.Microsecond)),
	}
	if !(values[0] < values[1] && values[1] < values[2]) {
		t.Fatalf("fixed request timestamps do not sort chronologically: %#v", values)
	}
	record := &policyRequestRecord{ID: "r-cursor", CreatedAt: values[2]}
	encoded, err := encodePolicyRequestCursor(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePolicyRequestCursor(encoded)
	if err != nil || decoded.CreatedAt != record.CreatedAt || decoded.ID != record.ID {
		t.Fatalf("cursor round trip=%#v err=%v", decoded, err)
	}
}

func TestPolicyRequestObjectScopeRemoveAndServiceOwnerBinding(t *testing.T) {
	s, base := policyRequestTestState(t, func(p *editablePolicy) {
		p.Owners = append(p.Owners, editableOwner{Name: "foreign"})
		p.Networks = append(p.Networks,
			editableNetwork{Name: "foreign-used", CIDR: "10.30.0.0/24", Owner: "foreign", Zone: "GDMZ"},
			editableNetwork{Name: "foreign-hidden", CIDR: "10.31.0.0/24", Owner: "foreign", Zone: "GDMZ"},
		)
		p.FQDNs = append(p.FQDNs,
			editableFQDN{Name: "visible-api", FQDN: "visible.example.net", Owner: "network-team", Zone: "IDMZ"},
			editableFQDN{Name: "foreign-api", FQDN: "foreign.example.net", Owner: "foreign", Zone: "IDMZ"},
		)
		p.Services[0].Rules[0].Sources = append(p.Services[0].Rules[0].Sources, "network:foreign-used")
	})

	submitRuleChangeForTest(t, s, "viewer@example.net", base, "remove", "sources", "network:foreign-used")
	removeErrors := []string{}
	for _, value := range []string{"network:foreign-hidden", "network:not-real"} {
		recorder := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
			"request_type": "rule_change", "active_owner": "network-team", "base_version": base, "reason": "remove missing",
			"rule_change": map[string]any{"service": "web", "stable_rule_id": "123e4567-e89b-42d3-a456-426614174000", "operation": "remove", "field": "sources", "value": value},
		}, s.policyRequests)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "is not present") {
			t.Fatalf("remove %q status=%d body=%s", value, recorder.Code, recorder.Body.String())
		}
		removeErrors = append(removeErrors, strings.ReplaceAll(recorder.Body.String(), value, "VALUE"))
	}
	if removeErrors[0] != removeErrors[1] {
		t.Fatalf("remove errors disclose object membership: %q != %q", removeErrors[0], removeErrors[1])
	}
	objectErrors := map[string]string{}
	for _, value := range []string{"network:foreign-hidden", "network:not-real"} {
		recorder := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
			"request_type": "rule_change", "active_owner": "network-team", "base_version": base, "reason": "object oracle regression",
			"rule_change": map[string]any{"service": "web", "stable_rule_id": "123e4567-e89b-42d3-a456-426614174000", "operation": "add", "field": "sources", "value": value},
		}, s.policyRequests)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("add %q status=%d body=%s", value, recorder.Code, recorder.Body.String())
		}
		objectErrors[value] = recorder.Body.String()
	}
	if objectErrors["network:foreign-hidden"] != objectErrors["network:not-real"] {
		t.Fatalf("unknown and foreign objects have distinguishable errors: %q != %q", objectErrors["network:not-real"], objectErrors["network:foreign-hidden"])
	}
	for _, forbiddenDetail := range []string{"unknown", "outside", "foreign-hidden", "not-real", "network-team"} {
		if strings.Contains(strings.ToLower(objectErrors["network:not-real"]), forbiddenDetail) {
			t.Fatalf("generic object error leaked %q: %s", forbiddenDetail, objectErrors["network:not-real"])
		}
	}

	fqdnSourceErrors := []string{}
	for _, value := range []string{"fqdn:visible-api", "fqdn:foreign-api", "fqdn:not-real"} {
		recorder := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
			"request_type": "rule_change", "active_owner": "network-team", "base_version": base, "reason": "FQDN source regression",
			"rule_change": map[string]any{"service": "web", "stable_rule_id": "123e4567-e89b-42d3-a456-426614174000", "operation": "add", "field": "sources", "value": value},
		}, s.policyRequests)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("FQDN source %q status=%d body=%s", value, recorder.Code, recorder.Body.String())
		}
		fqdnSourceErrors = append(fqdnSourceErrors, recorder.Body.String())
	}
	if fqdnSourceErrors[0] != fqdnSourceErrors[1] || fqdnSourceErrors[1] != fqdnSourceErrors[2] {
		t.Fatalf("FQDN source errors disclose existence or scope: %#v", fqdnSourceErrors)
	}

	service := map[string]any{
		"name": "requested-service", "description": "requested", "owners": []string{"network-team"},
		"rules": []map[string]any{{
			"action": "permit", "has_user": "none", "policy_name": "REQUESTED_WEB", "sources": []string{"network:office"}, "destinations": []string{"host:server"}, "protocols": []string{"tcp 9443"},
			"rule_group": "SRV", "owner": "foreign", "change_reference": "CHG-REQ", "review_date": "2030-12-31", "purpose": "requested", "target_context": "prod",
		}},
	}
	wrongOwner := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
		"request_type": "new_service", "active_owner": "network-team", "base_version": base, "reason": "wrong owner", "new_service": service,
	}, s.policyRequests)
	if wrongOwner.Code != http.StatusBadRequest || !strings.Contains(wrongOwner.Body.String(), "requested service owners") {
		t.Fatalf("wrong rule owner status=%d body=%s", wrongOwner.Code, wrongOwner.Body.String())
	}

	service["rules"].([]map[string]any)[0]["owner"] = "network-team"
	newServiceErrors := []string{}
	for _, destination := range []string{"network:foreign-hidden", "network:not-real"} {
		service["rules"].([]map[string]any)[0]["destinations"] = []string{destination}
		recorder := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
			"request_type": "new_service", "active_owner": "network-team", "base_version": base, "reason": "new service oracle regression", "new_service": service,
		}, s.policyRequests)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("new service destination %q status=%d body=%s", destination, recorder.Code, recorder.Body.String())
		}
		newServiceErrors = append(newServiceErrors, recorder.Body.String())
	}
	if newServiceErrors[0] != newServiceErrors[1] {
		t.Fatalf("new service object errors disclose existence or scope: %#v", newServiceErrors)
	}
}

func TestNewServiceRequestUsesManualRuleNameWithoutLegacyContextFields(t *testing.T) {
	s, base := policyRequestTestState(t, nil)
	service := func(name string) map[string]any {
		return map[string]any{
			"name": "requested-service", "description": "requested", "owners": []string{"network-team"},
			"rules": []map[string]any{{
				"action": "permit", "has_user": "none", "policy_name": name, "owner": "network-team",
				"sources": []string{"network:office"}, "destinations": []string{"host:server"}, "protocols": []string{"tcp 9443"},
			}},
		}
	}

	response := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
		"request_type": "new_service", "active_owner": "network-team", "base_version": base,
		"reason": "manual name regression", "new_service": service("  REQUESTED-WEB  "),
	}, s.policyRequests)
	if response.Code != http.StatusCreated {
		t.Fatalf("manual-name request status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Request policyRequestRecord `json:"request"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result.Request.Payload)
	if err != nil {
		t.Fatal(err)
	}
	stored := string(encoded)
	if !strings.Contains(stored, `"policy_name":"REQUESTED-WEB"`) || strings.Contains(stored, "target_context") || strings.Contains(stored, "naming_version") {
		t.Fatalf("stored request did not preserve the minimal manual-name payload: %s", stored)
	}

	for _, invalid := range []string{"", "web allow", strings.Repeat("A", 36), "web_allow"} {
		invalidResponse := policyRequestCall(t, "viewer@example.net", http.MethodPost, "/requests", map[string]any{
			"request_type": "new_service", "active_owner": "network-team", "base_version": base,
			"reason": "invalid manual name regression", "new_service": service(invalid),
		}, s.policyRequests)
		if invalidResponse.Code != http.StatusBadRequest {
			t.Fatalf("invalid or duplicate name %q status=%d body=%s", invalid, invalidResponse.Code, invalidResponse.Body.String())
		}
	}
}

func TestPolicyRequestStageIsAtomicAndOptimistic(t *testing.T) {
	s, base := policyRequestTestState(t, nil)
	record := submitRuleChangeForTest(t, s, "viewer@example.net", base, "add", "destinations", "host:spare")
	staged := stageRequestForTest(t, s, record.ID, record.Revision)
	if staged.PolicyID == "" || staged.Approval == "" || staged.RequestRevision != 3 {
		t.Fatalf("stage result=%#v", staged)
	}
	stored := loadRequestForTest(t, s, record.ID)
	if stored.Status != "staged" || stored.Revision != 3 || stored.RevisionVersion != staged.PolicyID {
		t.Fatalf("stored request=%#v", stored)
	}

	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var revisionStatus string
	if err := db.QueryRow(`SELECT status FROM policy_revision WHERE version=?`, staged.PolicyID).Scan(&revisionStatus); err != nil || revisionStatus != "pending" {
		t.Fatalf("revision status=%q err=%v", revisionStatus, err)
	}
	var eventCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_request_event WHERE request_id=?`, record.ID).Scan(&eventCount); err != nil || eventCount != 3 {
		t.Fatalf("event count=%d err=%v", eventCount, err)
	}
	retry := policyRequestCall(t, "editor@example.net", http.MethodPost, "/admin/requests/stage", map[string]any{"id": record.ID, "revision": record.Revision}, s.adminStagePolicyRequest)
	if retry.Code != http.StatusConflict {
		t.Fatalf("stale stage status=%d body=%s", retry.Code, retry.Body.String())
	}
	var links int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_request_revision WHERE request_id=?`, record.ID).Scan(&links); err != nil || links != 1 {
		t.Fatalf("links=%d err=%v", links, err)
	}
}

func TestPolicyRequestFourEyesAndRejectHook(t *testing.T) {
	t.Run("requester cannot approve", func(t *testing.T) {
		s, base := policyRequestTestState(t, nil)
		record := submitRuleChangeForTest(t, s, "reviewer@example.net", base, "add", "destinations", "host:spare")
		staged := stageRequestForTest(t, s, record.ID, record.Revision)
		details := policyRequestCall(t, "reviewer@example.net", http.MethodGet, "/admin/revision?policy_id="+staged.PolicyID, nil, s.adminRevision)
		if details.Code != http.StatusOK {
			t.Fatalf("revision details status=%d body=%s", details.Code, details.Body.String())
		}
		var identity struct {
			RequestID string `json:"request_id"`
			Requester string `json:"requester"`
		}
		if err := json.Unmarshal(details.Body.Bytes(), &identity); err != nil {
			t.Fatal(err)
		}
		if identity.RequestID != record.ID || identity.Requester != record.Requester {
			t.Fatalf("linked request identity=%#v", identity)
		}
		recorder := policyRequestCall(t, "reviewer@example.net", http.MethodPost, "/admin/publish", map[string]any{"policy_id": staged.PolicyID, "approval": staged.Approval}, s.adminPublish)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "requester may not approve") {
			t.Fatalf("self approval status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		if stored := loadRequestForTest(t, s, record.ID); stored.Status != "staged" || stored.Revision != 3 {
			t.Fatalf("failed approval changed request=%#v", stored)
		}
	})

	t.Run("requester cannot reject through revision endpoint", func(t *testing.T) {
		s, base := policyRequestTestState(t, nil)
		record := submitRuleChangeForTest(t, s, "reviewer@example.net", base, "add", "destinations", "host:spare")
		staged := stageRequestForTest(t, s, record.ID, record.Revision)
		recorder := policyRequestCall(t, "reviewer@example.net", http.MethodPost, "/admin/reject", map[string]any{"policy_id": staged.PolicyID, "comment": "reject my own request"}, s.adminReject)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "requester may not reject") {
			t.Fatalf("self rejection status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		if stored := loadRequestForTest(t, s, record.ID); stored.Status != "staged" || stored.Revision != 3 {
			t.Fatalf("failed rejection changed request=%#v", stored)
		}
		revision, err := s.loadRevisionRecord(staged.PolicyID, true)
		if err != nil {
			t.Fatal(err)
		}
		if revision.Status != "pending" || revision.RejectedBy != "" {
			t.Fatalf("failed rejection changed revision=%#v", revision)
		}
	})

	t.Run("revision rejection is atomic", func(t *testing.T) {
		s, base := policyRequestTestState(t, nil)
		record := submitRuleChangeForTest(t, s, "viewer@example.net", base, "add", "destinations", "host:spare")
		staged := stageRequestForTest(t, s, record.ID, record.Revision)
		if err := s.rejectRevision(staged.PolicyID, "reviewer@example.net", "not approved"); err != nil {
			t.Fatal(err)
		}
		stored := loadRequestForTest(t, s, record.ID)
		if stored.Status != "rejected" || stored.Revision != 4 || stored.RejectionComment != "not approved" {
			t.Fatalf("rejected request=%#v", stored)
		}
		db, err := s.policyDB()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var status, rejectedBy string
		if err := db.QueryRow(`SELECT status,rejected_by FROM policy_revision WHERE version=?`, staged.PolicyID).Scan(&status, &rejectedBy); err != nil || status != "rejected" || rejectedBy != "reviewer@example.net" {
			t.Fatalf("revision status=%q rejected_by=%q err=%v", status, rejectedBy, err)
		}
	})
}

func TestDeveloperMayCompleteOwnPolicyRequest(t *testing.T) {
	t.Run("approve", func(t *testing.T) {
		s, base := policyRequestTestState(t, func(p *editablePolicy) {
			p.Tenants = nil
			p.TargetContexts = nil
			p.Services[0].Rules[0].TargetContext = ""
			p.Services[0].Rules[0].RuleGroup = ""
		})
		record := submitRuleChangeForTest(t, s, "developer@example.net", base, "add", "destinations", "host:spare")
		staged := stageRequestAsForTest(t, s, "developer@example.net", record.ID, record.Revision)
		if err := s.ensurePolicyRequestApproverIsIndependent(staged.PolicyID, "developer@example.net"); err != nil {
			t.Fatalf("developer was blocked by request four-eyes check: %v", err)
		}
		// The request fixture uses a portable non-symlink current directory.
		// Exercise the same atomic publication transition without rebuilding the
		// filesystem artifacts, which are covered by publication workflow tests.
		if err := s.finalizePublication(staged.PolicyID, staged.Policy, "developer@example.net", true); err != nil {
			t.Fatalf("developer self-approval failed: %v", err)
		}
		if stored := loadRequestForTest(t, s, record.ID); stored.Status != "approved" || stored.Revision != 4 {
			t.Fatalf("self-approved request=%#v", stored)
		}
		revision, err := s.loadRevisionRecord(staged.PolicyID, false)
		if err != nil {
			t.Fatal(err)
		}
		if revision.Status != "published" || revision.ApprovedBy != "developer@example.net" {
			t.Fatalf("self-approved revision=%#v", revision)
		}
	})

	t.Run("reject staged revision", func(t *testing.T) {
		s, base := policyRequestTestState(t, nil)
		record := submitRuleChangeForTest(t, s, "developer@example.net", base, "add", "destinations", "host:spare")
		staged := stageRequestAsForTest(t, s, "developer@example.net", record.ID, record.Revision)
		response := policyRequestCall(t, "developer@example.net", http.MethodPost, "/admin/reject", map[string]any{
			"policy_id": staged.PolicyID,
			"comment":   "developer test rejection",
		}, s.adminReject)
		if response.Code != http.StatusOK {
			t.Fatalf("developer self-rejection status=%d body=%s", response.Code, response.Body.String())
		}
		if stored := loadRequestForTest(t, s, record.ID); stored.Status != "rejected" || stored.Revision != 4 {
			t.Fatalf("self-rejected request=%#v", stored)
		}
	})

	t.Run("reject submitted request", func(t *testing.T) {
		s, base := policyRequestTestState(t, nil)
		record := submitRuleChangeForTest(t, s, "developer@example.net", base, "add", "destinations", "host:spare")
		response := policyRequestCall(t, "developer@example.net", http.MethodPost, "/admin/requests/reject", map[string]any{
			"id": record.ID, "revision": record.Revision, "comment": "developer withdrew request",
		}, s.adminRejectPolicyRequest)
		if response.Code != http.StatusOK {
			t.Fatalf("developer request rejection status=%d body=%s", response.Code, response.Body.String())
		}
		if stored := loadRequestForTest(t, s, record.ID); stored.Status != "rejected" || stored.Revision != 2 {
			t.Fatalf("self-rejected submitted request=%#v", stored)
		}
	})
}

func TestPublishingRequestConflictsOtherOldBaseRequests(t *testing.T) {
	s, base := policyRequestTestState(t, nil)
	approvedRequest := submitRuleChangeForTest(t, s, "viewer@example.net", base, "add", "destinations", "host:spare")
	stagedConflict := submitRuleChangeForTest(t, s, "viewer@example.net", base, "add", "destinations", "host:spare")
	submittedConflict := submitRuleChangeForTest(t, s, "viewer@example.net", base, "add", "destinations", "host:spare")
	approvedStage := stageRequestForTest(t, s, approvedRequest.ID, approvedRequest.Revision)
	conflictingStage := stageRequestForTest(t, s, stagedConflict.ID, stagedConflict.Revision)

	if err := s.finalizePublication(approvedStage.PolicyID, approvedStage.Policy, "reviewer@example.net", true); err != nil {
		t.Fatal(err)
	}
	if record := loadRequestForTest(t, s, approvedRequest.ID); record.Status != "approved" || record.Revision != 4 {
		t.Fatalf("published request=%#v", record)
	}
	if record := loadRequestForTest(t, s, stagedConflict.ID); record.Status != "conflict" || record.Revision != 4 {
		t.Fatalf("staged conflict=%#v", record)
	}
	if record := loadRequestForTest(t, s, submittedConflict.ID); record.Status != "conflict" || record.Revision != 2 {
		t.Fatalf("submitted conflict=%#v", record)
	}
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	var revisionStatus string
	if err := db.QueryRow(`SELECT status FROM policy_revision WHERE version=?`, conflictingStage.PolicyID).Scan(&revisionStatus); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	if revisionStatus != "rejected" {
		t.Fatalf("obsolete linked revision status=%q", revisionStatus)
	}

	conflict := loadRequestForTest(t, s, stagedConflict.ID)
	rejected := policyRequestCall(t, "reviewer@example.net", http.MethodPost, "/admin/requests/reject", map[string]any{"id": conflict.ID, "revision": conflict.Revision, "comment": "superseded"}, s.adminRejectPolicyRequest)
	if rejected.Code != http.StatusOK {
		t.Fatalf("reject conflict status=%d body=%s", rejected.Code, rejected.Body.String())
	}
	if record := loadRequestForTest(t, s, conflict.ID); record.Status != "rejected" || record.Revision != 5 {
		t.Fatalf("acknowledged conflict=%#v", record)
	}
}

func TestPolicyRequestOwnListHidesEventsAndAdminListIsComplete(t *testing.T) {
	s, base := policyRequestTestState(t, nil)
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	payload := `{"stable_rule_id":"123e4567-e89b-42d3-a456-426614174000","service":"web","field":"destinations","operation":"add","values":["host:spare"]}`
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i := 0; i < 205; i++ {
		id := fmt.Sprintf("r-list-%03d", i)
		_, err = tx.Exec(`INSERT INTO policy_request(id,type,requester,active_owner,base_version,payload,reason,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'submitted',1,?,?)`, id, "rule_change", "viewer@example.net", "network-team", base, payload, "list test", now, now)
		if err != nil {
			tx.Rollback()
			db.Close()
			t.Fatal(err)
		}
		if i == 0 {
			for eventIndex := 0; eventIndex < policyRequestEventLimit+5; eventIndex++ {
				metadata := map[string]any{"sequence": eventIndex}
				if eventIndex == policyRequestEventLimit+4 {
					metadata["deployment_id"] = "secret-internal-id"
					metadata["targets"] = []string{"edge"}
				}
				err = insertPolicyRequestEventTx(tx, id, "internal@example.net", "request.internal", "submitted", "submitted", "", metadata, now)
				if err != nil {
					tx.Rollback()
					db.Close()
					t.Fatal(err)
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	own := policyRequestCall(t, "viewer@example.net", http.MethodGet, "/requests", nil, s.policyRequests)
	if own.Code != http.StatusOK || strings.Contains(own.Body.String(), `"events"`) || strings.Contains(own.Body.String(), "secret-internal-id") {
		t.Fatalf("own list leaked events or failed: status=%d body=%s", own.Code, own.Body.String())
	}
	seen := map[string]bool{}
	cursor := ""
	foundInternalEvent := false
	eventLimitChecked := false
	pages := 0
	for {
		target := "/admin/requests?limit=50"
		if pages == 0 {
			target = "/admin/requests"
		}
		if cursor != "" {
			target = "/admin/requests?limit=50&cursor=" + cursor
		}
		admin := policyRequestCall(t, "reviewer@example.net", http.MethodGet, target, nil, s.adminPolicyRequests)
		if admin.Code != http.StatusOK {
			t.Fatalf("admin list status=%d body=%s", admin.Code, admin.Body.String())
		}
		var response struct {
			Records    []policyRequestRecord `json:"records"`
			Pagination struct {
				HasMore    bool   `json:"has_more"`
				NextCursor string `json:"next_cursor"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(admin.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if len(response.Records) > 50 {
			t.Fatalf("admin page is unbounded: %d records", len(response.Records))
		}
		for _, record := range response.Records {
			if seen[record.ID] {
				t.Fatalf("request %q occurred on multiple pages", record.ID)
			}
			seen[record.ID] = true
			if record.ID == "r-list-000" {
				if len(record.Events) != policyRequestEventLimit || !record.EventsTruncated {
					t.Fatalf("event history is not bounded: events=%d truncated=%t", len(record.Events), record.EventsTruncated)
				}
				eventLimitChecked = true
			}
		}
		foundInternalEvent = foundInternalEvent || strings.Contains(admin.Body.String(), "secret-internal-id")
		pages++
		if !response.Pagination.HasMore {
			break
		}
		if response.Pagination.NextCursor == "" || response.Pagination.NextCursor == cursor {
			t.Fatalf("invalid pagination cursor after page %d: %q", pages, response.Pagination.NextCursor)
		}
		cursor = response.Pagination.NextCursor
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 205 || !foundInternalEvent || !eventLimitChecked || pages != 5 {
		t.Fatalf("admin pagination count=%d pages=%d event metadata present=%t event limit checked=%t", len(seen), pages, foundInternalEvent, eventLimitChecked)
	}
	for _, target := range []string{"/admin/requests?limit=0", "/admin/requests?limit=101", "/admin/requests?cursor=not-a-cursor"} {
		invalid := policyRequestCall(t, "reviewer@example.net", http.MethodGet, target, nil, s.adminPolicyRequests)
		if invalid.Code != http.StatusBadRequest {
			t.Fatalf("invalid pagination %q status=%d body=%s", target, invalid.Code, invalid.Body.String())
		}
	}
}

func TestPolicyRequestRecordsAndEventsUseOneReadSnapshot(t *testing.T) {
	s, base := policyRequestTestState(t, nil)
	record := submitRuleChangeForTest(t, s, "viewer@example.net", base, "add", "destinations", "host:spare")
	readDB, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer readDB.Close()
	writeDB, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer writeDB.Close()
	readTx, err := readDB.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer readTx.Rollback()
	snapshot, err := scanPolicyRequest(readTx.QueryRow(policyRequestSelect+` WHERE id=?`, record.ID))
	if err != nil {
		t.Fatal(err)
	}
	writeTx, err := writeDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	now := policyRequestTimestamp(time.Now())
	if _, err := writeTx.Exec(`UPDATE policy_request SET status='processing',revision=revision+1,updated_at=? WHERE id=?`, now, record.ID); err != nil {
		writeTx.Rollback()
		t.Fatal(err)
	}
	if err := insertPolicyRequestEventTx(writeTx, record.ID, "editor@example.net", "request.processing", "submitted", "processing", "", nil, now); err != nil {
		writeTx.Rollback()
		t.Fatal(err)
	}
	if err := writeTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := loadPolicyRequestEvents(readTx, []*policyRequestRecord{snapshot}); err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != "submitted" || len(snapshot.Events) != 1 || snapshot.Events[0].Action != "request.submitted" {
		t.Fatalf("mixed read snapshot: status=%q events=%#v", snapshot.Status, snapshot.Events)
	}
	if err := readTx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRequestDeploymentHookTracksFailurePartialAndSuccess(t *testing.T) {
	s, base := policyRequestTestState(t, nil)
	s.config.FortinetTargets = []FortinetTarget{
		{Name: "edge-a", Type: "fortigate", URL: "https://edge-a.example.net", VDOM: "root", TokenEnv: "EDGE_A_TOKEN", TargetContexts: []string{"prod"}, ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"}, AllowDeploy: true},
		{Name: "edge-b", Type: "fortigate", URL: "https://edge-b.example.net", VDOM: "root", TokenEnv: "EDGE_B_TOKEN", TargetContexts: []string{"prod"}, ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"}, AllowDeploy: true},
	}
	record := submitRuleChangeForTest(t, s, "viewer@example.net", base, "add", "destinations", "host:spare")
	staged := stageRequestForTest(t, s, record.ID, record.Revision)
	revision, err := s.loadRevisionRecord(staged.PolicyID, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := decodeStoredDeploymentPlan(revision.DeploymentPlan)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Commands) == 0 {
		t.Fatal("test setup produced no deployment commands")
	}
	if err := s.finalizePublication(staged.PolicyID, staged.Policy, "reviewer@example.net", true); err != nil {
		t.Fatal(err)
	}

	run := func(id, target, status, message string, offset time.Duration) {
		t.Helper()
		started := time.Now().UTC().Add(offset).Format(time.RFC3339Nano)
		result := &deploymentRunResult{DeploymentID: id, PolicyID: staged.PolicyID, PlanHash: plan.Hash, Actor: "deployer@example.net", Targets: []string{target}, Status: "running", StartedAt: started}
		if err := s.startDeploymentLog(result, target); err != nil {
			t.Fatal(err)
		}
		result.Status, result.Error = status, message
		result.FinishedAt = time.Now().UTC().Add(offset + time.Millisecond).Format(time.RFC3339Nano)
		if err := s.finishDeploymentLog(result); err != nil {
			s.releaseDeploymentLock(id)
			t.Fatal(err)
		}
		s.releaseDeploymentLock(id)
	}

	run("d-request-failed", "edge-a", "failed", "device unavailable", 0)
	if stored := loadRequestForTest(t, s, record.ID); stored.Status != "approved" {
		t.Fatalf("failed deployment request=%#v", stored)
	}
	run("d-request-partial", "edge-a", "succeeded", "", time.Second)
	if stored := loadRequestForTest(t, s, record.ID); stored.Status != "approved" {
		t.Fatalf("partial deployment request=%#v", stored)
	}
	run("d-request-complete", "edge-b", "succeeded", "", 2*time.Second)
	if stored := loadRequestForTest(t, s, record.ID); stored.Status != "deployed" || stored.Revision != 5 {
		t.Fatalf("complete deployment request=%#v", stored)
	}

	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, action := range []string{"request.deployment_failed", "request.deployment_partial", "request.deployed"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM policy_request_event WHERE request_id=? AND action=?`, record.ID, action).Scan(&count); err != nil || count != 1 {
			t.Fatalf("event %s count=%d err=%v", action, count, err)
		}
	}
}
