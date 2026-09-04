package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func collectorPolicy() *editablePolicy {
	return &editablePolicy{
		Name:           "collector-policy",
		Tenants:        []tenant{{MKZ: "M120", Name: "Mandant 120", Active: true}},
		TargetContexts: []targetContext{{Name: "prod", ContextType: "dedicated", AssignedMKZ: "M120"}},
		Users: []editableUser{
			{Email: "root@example.net", Role: "admin"},
			{Email: "developer@example.net", Role: policyDeveloperRole},
			{Email: "noc@example.net", Role: "viewer"},
			{Email: "multi@example.net", Role: "viewer"},
			{Email: "scope@example.net", Role: "viewer"},
			{Email: "fb1@example.net", Role: "viewer"},
			{Email: "foreign@example.net", Role: "viewer"},
		},
		Owners: []editableOwner{
			{Name: "ROOT", Admins: []string{"root@example.net"}},
			{Name: "NOC", Parent: "ROOT", ReadAll: true, Users: []string{"noc@example.net", "multi@example.net"}},
			{Name: "SCOPE", Parent: "ROOT", ReadOwners: []string{"FB1"}, Users: []string{"scope@example.net"}},
			{Name: "REGION", Parent: "ROOT"},
			{Name: "FB1", Parent: "REGION", ReadOwners: []string{"FOREIGN"}, Users: []string{"fb1@example.net"}},
			{Name: "BRANCH", Parent: "FB1"},
			{Name: "FB2", Parent: "REGION", Users: []string{"multi@example.net"}},
			{Name: "FOREIGN", Parent: "ROOT", Users: []string{"foreign@example.net"}},
		},
		Networks: []editableNetwork{
			{
				Name: "alpha", CIDR: "10.10.0.0/24", Owner: "FB1", Zone: "GDMZ",
				Hosts: []editableHost{{Name: "alpha-host", IP: "10.10.0.10", Owner: "FB1", Zone: "IDMZ"}},
			},
			{
				Name: "branch", CIDR: "10.20.0.0/24", Owner: "BRANCH", Zone: "GDMZ",
				Hosts: []editableHost{{Name: "branch-host", IP: "10.20.0.10", Owner: "BRANCH", Zone: "IDMZ"}},
			},
			{
				Name: "sibling", CIDR: "10.30.0.0/24", Owner: "FB2", Zone: "GDMZ",
				Hosts: []editableHost{{Name: "sibling-host", IP: "10.30.0.10", Owner: "FB2", Zone: "IDMZ"}},
			},
			{
				Name: "foreign", CIDR: "10.40.0.0/24", Owner: "FOREIGN", Zone: "GDMZ",
				Hosts: []editableHost{{Name: "foreign-host", IP: "10.40.0.10", Owner: "FOREIGN", Zone: "IDMZ"}},
			},
		},
		Services: []editableService{
			collectorService("alpha-service", "FB1", "alpha", "alpha-host", "tcp 443"),
			collectorService("branch-service", "BRANCH", "branch", "branch-host", "tcp 443"),
			collectorService("sibling-service", "FB2", "sibling", "sibling-host", "tcp 443"),
			collectorService("foreign-service", "FOREIGN", "foreign", "foreign-host", "tcp 443"),
		},
	}
}

func collectorService(name, owner, network, host, protocol string) editableService {
	return editableService{
		Name: name, Owners: []string{owner},
		Rules: []editableRule{{
			Action:          "permit",
			PolicyName:      strings.ToUpper(strings.ReplaceAll(name, "-", "_")),
			Sources:         []string{"network:" + network},
			Destinations:    []string{"host:" + host},
			Protocols:       []string{protocol},
			RuleGroup:       "SRV",
			Owner:           owner,
			ChangeReference: "CHG-1",
			ReviewDate:      "2030-12-31",
			Purpose:         "Collector access",
			TargetContext:   "prod",
		}},
	}
}

func ownerAccessFixture(t *testing.T) *state {
	t.Helper()
	root := t.TempDir()
	p := collectorPolicy()
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

func ownerRequest(method, target, body, email string) (*http.Request, *GoSession) {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	session := newSession()
	session.Put("loggedIn", true)
	session.Put("email", email)
	req = req.WithContext(context.WithValue(req.Context(), sessionContextKey{}, session))
	return req, session
}

func TestReadAllCollectorAggregatesEveryOwner(t *testing.T) {
	s := ownerAccessFixture(t)
	assertCollectorData(t, s, "noc@example.net", "NOC",
		[]string{"network:alpha", "network:branch", "network:foreign", "network:sibling"},
		[]string{"alpha-service", "branch-service", "foreign-service", "sibling-service"},
	)
}

func TestReadOwnersCollectorAggregatesTargetAndDescendantsOnly(t *testing.T) {
	s := ownerAccessFixture(t)
	assertCollectorData(t, s, "scope@example.net", "SCOPE",
		[]string{"network:alpha", "network:branch"},
		[]string{"alpha-service", "branch-service"},
	)
}

func TestReadOwnersDoesNotFollowNestedReadGrants(t *testing.T) {
	s := ownerAccessFixture(t)
	version := s.currentPolicy()

	directTargetNetworks := slices.Clone(s.loadAssets(version, "FB1").networkList)
	slices.Sort(directTargetNetworks)
	if !slices.Equal(directTargetNetworks, []string{"network:alpha", "network:branch", "network:foreign"}) {
		t.Fatalf("FB1 read grant was not applied: %#v", directTargetNetworks)
	}

	collectorNetworks := slices.Clone(s.loadAssets(version, "SCOPE").networkList)
	slices.Sort(collectorNetworks)
	if !slices.Equal(collectorNetworks, []string{"network:alpha", "network:branch"}) {
		t.Fatalf("SCOPE followed FB1's nested read grant: %#v", collectorNetworks)
	}
}

func assertCollectorData(t *testing.T, s *state, email, owner string, wantNetworks, wantServices []string) {
	t.Helper()

	req, _ := ownerRequest(http.MethodGet, "/?active_owner="+owner, "", email)
	recorder := httptest.NewRecorder()
	s.getNetworksAndResources(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("network status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	var networkResponse struct {
		Records []struct {
			Name     string `json:"name"`
			Children []struct {
				Name string `json:"name"`
				IP   string `json:"ip"`
			} `json:"children"`
		} `json:"records"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &networkResponse); err != nil {
		t.Fatal(err)
	}
	gotNetworks := make([]string, 0, len(networkResponse.Records))
	for _, network := range networkResponse.Records {
		gotNetworks = append(gotNetworks, network.Name)
		if len(network.Children) != 1 || network.Children[0].Name == "" || network.Children[0].IP == "" {
			t.Errorf("contained IP resource missing for %s: %#v", network.Name, network.Children)
		}
	}
	slices.Sort(gotNetworks)
	if !slices.Equal(gotNetworks, wantNetworks) {
		t.Errorf("networks for %s = %#v, want %#v", owner, gotNetworks, wantNetworks)
	}

	req, _ = ownerRequest(http.MethodGet, "/?active_owner="+owner+"&relation=owner", "", email)
	recorder = httptest.NewRecorder()
	s.serviceList(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("service status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	var serviceResponse struct {
		Records []struct {
			Name string `json:"name"`
		} `json:"records"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &serviceResponse); err != nil {
		t.Fatal(err)
	}
	gotServices := make([]string, 0, len(serviceResponse.Records))
	for _, service := range serviceResponse.Records {
		gotServices = append(gotServices, service.Name)
	}
	slices.Sort(gotServices)
	if !slices.Equal(gotServices, wantServices) {
		t.Errorf("services for %s = %#v, want %#v", owner, gotServices, wantServices)
	}

	req, _ = ownerRequest(http.MethodGet, "/?active_owner="+owner+"&relation=owner", "", email)
	recorder = httptest.NewRecorder()
	s.getServicesAndRules(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("rule status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	var ruleResponse struct {
		Records []struct {
			Service string   `json:"service"`
			Action  string   `json:"action"`
			Src     []string `json:"src"`
			Dst     []string `json:"dst"`
			Prt     []string `json:"prt"`
		} `json:"records"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &ruleResponse); err != nil {
		t.Fatal(err)
	}
	gotRuleServices := make([]string, 0, len(ruleResponse.Records))
	for _, rule := range ruleResponse.Records {
		gotRuleServices = append(gotRuleServices, rule.Service)
		if rule.Action != "permit" || len(rule.Src) == 0 || len(rule.Dst) == 0 || len(rule.Prt) == 0 {
			t.Errorf("incomplete rule for %s: %#v", rule.Service, rule)
		}
	}
	slices.Sort(gotRuleServices)
	if !slices.Equal(gotRuleServices, wantServices) {
		t.Errorf("rules for %s = %#v, want services %#v", owner, gotRuleServices, wantServices)
	}
}

func TestCollectorsRemainSelectableAndSettable(t *testing.T) {
	s := ownerAccessFixture(t)
	tests := []struct {
		email string
		owner string
	}{
		{email: "noc@example.net", owner: "NOC"},
		{email: "scope@example.net", owner: "SCOPE"},
	}

	for _, tt := range tests {
		t.Run(tt.owner, func(t *testing.T) {
			req, _ := ownerRequest(http.MethodGet, "/get_owners", "", tt.email)
			recorder := httptest.NewRecorder()
			s.getOwners(recorder, req)
			if recorder.Code != http.StatusOK {
				t.Fatalf("get_owners status = %d; body=%s", recorder.Code, recorder.Body.String())
			}
			var response struct {
				Records []struct {
					Name string `json:"name"`
				} `json:"records"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if len(response.Records) != 1 || response.Records[0].Name != tt.owner {
				t.Fatalf("owner selection = %#v, want only %s", response.Records, tt.owner)
			}

			req, session := ownerRequest(http.MethodPost, "/set", "owner="+tt.owner, tt.email)
			recorder = httptest.NewRecorder()
			s.setSessionData(recorder, req)
			if recorder.Code != http.StatusOK || session.Get("owner") != tt.owner {
				t.Fatalf("collector was not stored: status=%d owner=%v body=%s",
					recorder.Code, session.Get("owner"), recorder.Body.String())
			}
		})
	}
}

func TestReadAllCollectorIsDefaultForUserWithMultipleOwners(t *testing.T) {
	s := ownerAccessFixture(t)
	if got := s.findAuthorizedOwners("multi@example.net"); !slices.Equal(got, []string{"FB2", "NOC"}) {
		t.Fatalf("multi-owner authorization = %#v", got)
	}

	req, session := ownerRequest(http.MethodGet, "/get_owner", "", "multi@example.net")
	recorder := httptest.NewRecorder()
	s.getOwner(recorder, req)
	if recorder.Code != http.StatusOK || session.Get("owner") != "NOC" {
		t.Fatalf("default owner = %v, want NOC; status=%d body=%s",
			session.Get("owner"), recorder.Code, recorder.Body.String())
	}
}

func TestDeveloperCanAccessEveryOwnerWithoutMembership(t *testing.T) {
	s := ownerAccessFixture(t)
	want := []string{"BRANCH", "FB1", "FB2", "FOREIGN", "NOC", "REGION", "ROOT", "SCOPE"}
	if got := s.findAuthorizedOwners(" DEVELOPER@example.net "); !slices.Equal(got, want) {
		t.Fatalf("developer owner authorization = %#v, want %#v", got, want)
	}
	if err := s.checkEmailAuthorization("developer@example.net"); err != nil {
		t.Fatalf("unassigned developer cannot log in: %v", err)
	}
}

func TestReadScopeDoesNotGrantDirectOwnerAccess(t *testing.T) {
	s := ownerAccessFixture(t)
	tests := []struct {
		name        string
		email       string
		activeOwner string
	}{
		{name: "read-all target", email: "noc@example.net", activeOwner: "FB1"},
		{name: "read-owners target", email: "scope@example.net", activeOwner: "FB1"},
		{name: "unrelated collector", email: "fb1@example.net", activeOwner: "NOC"},
		{name: "foreign owner", email: "foreign@example.net", activeOwner: "SCOPE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := ownerRequest(http.MethodGet, "/?active_owner="+tt.activeOwner, "", tt.email)
			recorder := httptest.NewRecorder()
			s.serviceList(recorder, req)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestInvalidReadOwnersAreRejected(t *testing.T) {
	tests := []struct {
		name       string
		readOwners []string
	}{
		{name: "empty", readOwners: []string{""}},
		{name: "unknown", readOwners: []string{"MISSING"}},
		{name: "self", readOwners: []string{"SCOPE"}},
		{name: "duplicate", readOwners: []string{"FB1", "FB1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := collectorPolicy()
			p.Owners[2].ReadOwners = tt.readOwners
			if err := validateEditablePolicy(p); err == nil {
				t.Fatalf("invalid read_owners %#v was accepted", tt.readOwners)
			}
		})
	}
}

func TestReadOwnersAreTrimmedBeforeValidation(t *testing.T) {
	p := collectorPolicy()
	p.Owners[2].ReadOwners = []string{" FB1 "}
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Owners[2].ReadOwners, []string{"FB1"}) {
		t.Fatalf("normalized read_owners = %#v", p.Owners[2].ReadOwners)
	}
}
