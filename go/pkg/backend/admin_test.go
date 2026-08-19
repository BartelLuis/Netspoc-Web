package backend

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func validEditablePolicy() *editablePolicy {
	return &editablePolicy{
		Name:   "office-policy",
		Users:  []editableUser{{Email: "admin@example.net", Password: "secret"}},
		Owners: []editableOwner{{Name: "network-team", Admins: []string{"admin@example.net"}}},
		Networks: []editableNetwork{{
			Name: "office", CIDR: "10.20.0.0/16", Owner: "network-team",
			Hosts: []editableHost{{Name: "server", IP: "10.20.0.10", Owner: "network-team"}},
		}},
		Services: []editableService{{
			Name: "web", Owners: []string{"network-team"},
			Rules: []editableRule{{Action: "permit", Sources: []string{"network:office"}, Destinations: []string{"host:server"}, Protocols: []string{"tcp 443"}}},
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

func TestHostNameIsDerivedFromIPAddress(t *testing.T) {
	p := validEditablePolicy()
	p.Networks[0].Hosts[0].Name = ""
	p.Networks[0].Hosts[0].IP = "172.25.26.1"
	p.Networks[0].CIDR = "172.25.26.0/24"
	if err := validateEditablePolicy(p); err != nil { t.Fatal(err) }
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
	if err := validateEditablePolicy(p); err != nil { t.Fatal(err) }
	p.Owners[0].Parent = "branch"
	if err := validateEditablePolicy(p); err == nil { t.Fatal("cyclic owner hierarchy was accepted") }
}

func TestPolicyDiffApprovalChangesWithBase(t *testing.T) {
	next := validEditablePolicy()
	first, err := approvalHash("p1", nil, next)
	if err != nil { t.Fatal(err) }
	base := validEditablePolicy()
	base.Name = "older"
	second, err := approvalHash("p1", base, next)
	if err != nil { t.Fatal(err) }
	if first == second { t.Fatal("approval does not include the published base policy") }
	third, err := approvalHash("p2", nil, next)
	if err != nil { t.Fatal(err) }
	if first == third { t.Fatal("approval does not include the diff policy ID") }
}

func TestEmptyPolicyDiffIsAnEmptyArray(t *testing.T) {
	p := validEditablePolicy()
	changes := diffPolicies(p, p)
	if changes == nil || len(changes) != 0 { t.Fatalf("expected empty non-nil diff, got %#v", changes) }
	data, err := json.Marshal(changes); if err != nil { t.Fatal(err) }
	if string(data) != "[]" { t.Fatalf("empty diff encoded as %s", data) }
}

func TestPolicyRoles(t *testing.T) {
	p := &editablePolicy{Users: []editableUser{
		{Email: "admin@example.net", Role: "admin"},
		{Email: "editor@example.net", Role: "editor"},
		{Email: "reader@example.net", Role: "viewer"},
	}}
	if !hasPolicyRole(p, "EDITOR@example.net", "admin", "editor") {
		t.Fatal("editor role was not recognized")
	}
	if hasPolicyRole(p, "reader@example.net", "admin", "editor") {
		t.Fatal("viewer received administration access")
	}
}

func TestPublishEditablePolicy(t *testing.T) {
	root := t.TempDir()
	s := &state{
		config: &config{NetspocData: filepath.Join(root, "policies"), UserDir: filepath.Join(root, "users")},
		cache:  newCache(filepath.Join(root, "policies"), 8),
	}
	if err := s.publishPolicy(validEditablePolicy()); err != nil {
		t.Fatal(err)
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
	if err := s.publishPolicy(p); err != nil { t.Fatal(err) }
	p.Services[0].Description = "second"
	if err := s.publishPolicy(p); err != nil { t.Fatal(err) }
	req := httptest.NewRequest("GET", "/?active_owner=network-team", nil)
	history, err := s.generateHistory(req); if err != nil { t.Fatal(err) }
	if len(history) != 2 { t.Fatalf("published policy history has %d entries: %#v", len(history), history) }
	if history[0]["policy"] == history[1]["policy"] { t.Fatalf("policy IDs are not unique: %#v", history) }
}

func TestPublishOwnerInheritanceAndHostOwnership(t *testing.T) {
	root := t.TempDir()
	p := validEditablePolicy()
	p.Users = append(p.Users, editableUser{Email: "child@example.net", Password: "secret", Role: "viewer"})
	p.Owners = append(p.Owners, editableOwner{Name: "child", Parent: "network-team", Users: []string{"child@example.net"}})
	p.Networks[0].Hosts[0].Owner = "child"
	s := &state{config: &config{NetspocData: filepath.Join(root, "policies"), UserDir: filepath.Join(root, "users")}, cache: newCache(filepath.Join(root, "policies"), 8)}
	if err := validateEditablePolicy(p); err != nil { t.Fatal(err) }
	if err := s.publishPolicy(p); err != nil { t.Fatal(err) }
	version := s.currentPolicy()
	data, err := os.ReadFile(filepath.Join(root, "policies", version, "email")); if err != nil { t.Fatal(err) }
	var access map[string][]string; if err := json.Unmarshal(data, &access); err != nil { t.Fatal(err) }
	if !slices.Contains(access["admin@example.net"], "child") { t.Fatalf("parent admin lacks child access: %#v", access) }
	data, err = os.ReadFile(filepath.Join(root, "policies", version, "owner", "child", "assets")); if err != nil { t.Fatal(err) }
	var assets struct { Anys map[string]struct { Networks map[string][]string `json:"networks"` } `json:"anys"` }
	if err := json.Unmarshal(data, &assets); err != nil { t.Fatal(err) }
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
