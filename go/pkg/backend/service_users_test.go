package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
)

func publishServiceUserFixture(t *testing.T, p *editablePolicy) *state {
	t.Helper()
	root := t.TempDir()
	s := &state{
		config: &config{
			NetspocData: filepath.Join(root, "policies"),
			UserDir:     filepath.Join(root, "users"),
		},
		cache: newCache(filepath.Join(root, "policies"), 8),
	}
	seedPolicyTestAccounts(t, s, p.Users...)
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}
	if err := s.publishPolicy(p); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRuleUserSideDefaultsToSourceAndIsValidated(t *testing.T) {
	p := validEditablePolicy()
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}
	if got := p.Services[0].Rules[0].HasUser; got != "src" {
		t.Fatalf("default user side = %q, want src", got)
	}

	for _, value := range []string{"src", "dst", "both", "none"} {
		p := validEditablePolicy()
		p.Services[0].Rules[0].HasUser = value
		if err := validateEditablePolicy(p); err != nil {
			t.Errorf("valid user side %q was rejected: %v", value, err)
		}
	}

	p = validEditablePolicy()
	p.Services[0].Rules[0].HasUser = "somewhere"
	if err := validateEditablePolicy(p); err == nil {
		t.Fatal("invalid user side was accepted")
	}
}

func TestLegacyRuleGetsAVisibleServiceDiff(t *testing.T) {
	previous := validEditablePolicy()
	next := validEditablePolicy()
	normalizeEditablePolicy(next)
	changes := diffPolicies(previous, next)
	if !slices.ContainsFunc(changes, func(change policyChange) bool {
		return change.Type == "service" && change.Name == "web" && change.Change == "changed"
	}) {
		t.Fatalf("service-user migration is missing from diff: %#v", changes)
	}
}

func TestPublishedServiceUsersReachTheUserTab(t *testing.T) {
	s := publishServiceUserFixture(t, validEditablePolicy())
	version := s.currentPolicy()

	users := s.loadUsers(version, "network-team")
	if got := users["web"]; !slices.Equal(got, []string{"network:office"}) {
		t.Fatalf("published service users = %#v", got)
	}
	if !slices.Contains(s.loadServiceLists(version, "network-team").User, "web") {
		t.Fatalf("web is missing from used services: %#v", s.loadServiceLists(version, "network-team").User)
	}

	req, _ := ownerRequest(http.MethodGet, "/?active_owner=network-team&history="+version+"&service=web", "", "admin@example.net")
	recorder := httptest.NewRecorder()
	s.getUsers(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("get_users status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Records []object `json:"records"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Records) != 1 || response.Records[0].Name != "network:office" || response.Records[0].IP != "10.20.0.0/16" {
		t.Fatalf("unexpected service user records: %#v", response.Records)
	}
}

func TestRuleUserSideControlsPublishedObjects(t *testing.T) {
	tests := []struct {
		side string
		want []string
	}{
		{side: "src", want: []string{"network:office"}},
		{side: "dst", want: []string{"host:server"}},
		{side: "both", want: []string{"host:server", "network:office"}},
		{side: "none", want: nil},
	}
	for _, test := range tests {
		t.Run(test.side, func(t *testing.T) {
			p := validEditablePolicy()
			p.Services[0].Rules[0].HasUser = test.side
			s := publishServiceUserFixture(t, p)
			version := s.currentPolicy()
			got := s.loadUsers(version, "network-team")["web"]
			if !slices.Equal(got, test.want) {
				t.Fatalf("service users = %#v, want %#v", got, test.want)
			}
			isUsed := slices.Contains(s.loadServiceLists(version, "network-team").User, "web")
			if isUsed != (test.side != "none") {
				t.Fatalf("used service membership = %v for side %q", isUsed, test.side)
			}
		})
	}
}

func TestRuleOverviewShowsExplicitObjectsForBothUserSides(t *testing.T) {
	p := validEditablePolicy()
	p.Services[0].Rules[0].HasUser = "both"
	s := publishServiceUserFixture(t, p)

	req, _ := ownerRequest(http.MethodGet, "/?active_owner=network-team&history="+s.currentPolicy()+"&relation=owner", "", "admin@example.net")
	recorder := httptest.NewRecorder()
	s.getServicesAndRules(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("get_services_and_rules status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Records []struct {
			Src []string `json:"src"`
			Dst []string `json:"dst"`
		} `json:"records"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Records) != 1 || !slices.Equal(response.Records[0].Src, []string{"10.20.0.0/16"}) || !slices.Equal(response.Records[0].Dst, []string{"10.20.0.10"}) {
		t.Fatalf("rule overview did not retain explicit objects: %#v", response.Records)
	}
}

func TestFQDNCanBeAServiceUserDestination(t *testing.T) {
	p := policyWithFQDN()
	p.Services[0].Rules[0].HasUser = "dst"
	s := publishServiceUserFixture(t, p)
	version := s.currentPolicy()

	if got := s.loadUsers(version, "network-team")["web"]; !slices.Equal(got, []string{"fqdn:customer-api"}) {
		t.Fatalf("FQDN service users = %#v", got)
	}
	req, _ := ownerRequest(http.MethodGet, "/?active_owner=network-team&history="+version+"&service=web", "", "admin@example.net")
	recorder := httptest.NewRecorder()
	s.getUsers(recorder, req)
	var response struct {
		Records []object `json:"records"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Records) != 1 || response.Records[0].FQDN != "api.example.com" || response.Records[0].Owner != "network-team" {
		t.Fatalf("unexpected FQDN service user record: %#v", response.Records)
	}
}
