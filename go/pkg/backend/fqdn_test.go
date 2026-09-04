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

func policyWithFQDN() *editablePolicy {
	p := validEditablePolicy()
	p.FQDNs = []editableFQDN{{Name: "customer-api", FQDN: " API.Example.COM. ", Owner: "network-team", Zone: "IDMZ"}}
	p.Services[0].Rules[0].Destinations = []string{"fqdn:customer-api"}
	return p
}

func TestValidateEditableFQDN(t *testing.T) {
	p := policyWithFQDN()
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}
	if got := p.FQDNs[0].FQDN; got != "api.example.com" {
		t.Fatalf("canonical FQDN = %q", got)
	}
}

func TestRejectInvalidEditableFQDN(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*editablePolicy)
		want   string
	}{
		{name: "not fully qualified", mutate: func(p *editablePolicy) { p.FQDNs[0].FQDN = "intranet" }, want: "invalid FQDN"},
		{name: "wildcard", mutate: func(p *editablePolicy) { p.FQDNs[0].FQDN = "*.example.com" }, want: "invalid FQDN"},
		{name: "unknown owner", mutate: func(p *editablePolicy) { p.FQDNs[0].Owner = "missing" }, want: "unknown owner"},
		{name: "duplicate name", mutate: func(p *editablePolicy) {
			p.FQDNs = append(p.FQDNs, editableFQDN{Name: "customer-api", FQDN: "other.example.com", Owner: "network-team", Zone: "IDMZ"})
		}, want: "duplicate FQDN object"},
		{name: "duplicate value", mutate: func(p *editablePolicy) {
			p.FQDNs = append(p.FQDNs, editableFQDN{Name: "other", FQDN: "api.example.com", Owner: "network-team", Zone: "IDMZ"})
		}, want: "duplicate FQDN"},
		{name: "source reference", mutate: func(p *editablePolicy) {
			p.Services[0].Rules[0].Sources = []string{"fqdn:customer-api"}
		}, want: "only use FQDN object"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := policyWithFQDN()
			test.mutate(p)
			err := validateEditablePolicy(p)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestFQDNIsIncludedInEditableDiff(t *testing.T) {
	old := validEditablePolicy()
	next := policyWithFQDN()
	changes := diffPolicies(old, next)
	if !slices.ContainsFunc(changes, func(change policyChange) bool {
		return change.Type == "fqdn" && change.Name == "customer-api" && change.Change == "added"
	}) {
		t.Fatalf("FQDN change missing from diff: %#v", changes)
	}
}

func TestPublishFQDNForOwnerAndRuleView(t *testing.T) {
	root := t.TempDir()
	p := policyWithFQDN()
	p.Users = append(p.Users, editableUser{Email: "child@example.net", Role: "viewer"})
	p.Users = append(p.Users, editableUser{Email: "foreign@example.net", Role: "viewer"})
	p.Owners = append(p.Owners, editableOwner{Name: "child", Parent: "network-team", Users: []string{"child@example.net"}})
	p.Owners = append(p.Owners, editableOwner{Name: "foreign", Users: []string{"foreign@example.net"}})
	p.FQDNs[0].Owner = "child"
	p.FQDNs = append(p.FQDNs, editableFQDN{Name: "foreign-api", FQDN: "foreign.example.com", Owner: "foreign", Zone: "IDMZ"})
	p.Services[0].Owners = []string{"child"}
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}

	s := &state{
		config: &config{NetspocData: filepath.Join(root, "policies"), UserDir: filepath.Join(root, "users")},
		cache:  newCache(filepath.Join(root, "policies"), 8),
	}
	seedPolicyTestAccounts(t, s, p.Users...)
	if err := s.publishPolicy(p); err != nil {
		t.Fatal(err)
	}
	version := s.currentPolicy()

	obj := s.loadObjects(version)["fqdn:customer-api"]
	if obj == nil || obj.FQDN != "api.example.com" || obj.Owner != "child" || obj.IP != "" {
		t.Fatalf("unexpected exported FQDN object: %#v", obj)
	}
	for _, owner := range []string{"network-team", "child"} {
		if got := s.loadAssets(version, owner).fqdnList; !slices.Equal(got, []string{"fqdn:customer-api"}) {
			t.Errorf("FQDN assets for %s = %#v", owner, got)
		}
	}
	if got := s.loadAssets(version, "foreign").fqdnList; !slices.Equal(got, []string{"fqdn:foreign-api"}) {
		t.Errorf("FQDN assets for foreign = %#v", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/?active_owner=network-team&history="+version+"&display_property=ip", nil)
	rules := s.expandRules(req, "web")
	if len(rules) != 1 || !slices.Equal(rules[0]["dst"].([]string), []string{"api.example.com"}) {
		t.Fatalf("FQDN destination not rendered in rule view: %#v", rules)
	}

	session := newSession()
	session.Put("email", "admin@example.net")
	req = httptest.NewRequest(http.MethodGet, "/get_fqdns?active_owner=network-team&history="+version, nil)
	req = req.WithContext(context.WithValue(req.Context(), sessionContextKey{}, session))
	recorder := httptest.NewRecorder()
	s.getFQDNs(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("get_fqdns status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Records []object `json:"records"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Records) != 1 || response.Records[0].Name != "fqdn:customer-api" || response.Records[0].FQDN != "api.example.com" {
		t.Fatalf("unexpected get_fqdns response: %#v", response.Records)
	}

	draft := s.readDraft()
	publication, err := s.latestPublication()
	if err != nil {
		t.Fatal(err)
	}
	if len(draft.FQDNs) != 2 || len(publication.FQDNs) != 2 || publication.FQDNs[0].Owner != "child" {
		t.Fatalf("FQDN was not retained in SQLite: draft=%#v publication=%#v", draft.FQDNs, publication.FQDNs)
	}
}

func TestFQDNValueCanBeSearched(t *testing.T) {
	root := t.TempDir()
	s := &state{
		config: &config{NetspocData: filepath.Join(root, "policies"), UserDir: filepath.Join(root, "users")},
		cache:  newCache(filepath.Join(root, "policies"), 8),
	}
	p := policyWithFQDN()
	seedPolicyTestAccounts(t, s, p.Users...)
	if err := validateEditablePolicy(p); err != nil {
		t.Fatal(err)
	}
	if err := s.publishPolicy(p); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/?history="+s.currentPolicy()+"&search_case_sensitive=1", nil)
	if got := s.buildTextSearchMap(req, "api.example.com"); !got["fqdn:customer-api"] {
		t.Fatalf("FQDN value did not resolve to its policy object: %#v", got)
	}
}
