package backend

import (
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
)

func TestGetProtoMatcherIgnoresEmptySearch(t *testing.T) {
	for _, target := range []string{"/", "/?search_proto=+++"} {
		req := httptest.NewRequest("GET", target, nil)
		if matcher := getProtoMatcher(req); matcher != nil {
			t.Fatalf("getProtoMatcher(%q) returned a matcher for an empty search", target)
		}
	}
}

func TestSelectServicesMatchesExplicitRuleEndpoints(t *testing.T) {
	root := t.TempDir()
	s := &state{
		config: &config{
			NetspocData: filepath.Join(root, "policies"),
			UserDir:     filepath.Join(root, "users"),
		},
		cache: newCache(filepath.Join(root, "policies"), 8),
	}
	if err := s.publishPolicy(validEditablePolicy()); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		"GET",
		"/?active_owner=network-team&history="+s.currentPolicy(),
		nil,
	)
	services := []string{"web"}
	source := map[string]bool{"network:office": true}
	destination := map[string]bool{"host:server": true}

	for name, test := range map[string]struct {
		first  map[string]bool
		second map[string]bool
	}{
		"source":                  {first: source},
		"destination":             {first: destination},
		"both endpoints":          {first: source, second: destination},
		"both endpoints reversed": {first: destination, second: source},
	} {
		t.Run(name, func(t *testing.T) {
			got := s.selectServices(services, req, test.first, test.second, nil)
			if !slices.Equal(got, services) {
				t.Fatalf("selectServices() = %#v, want %#v", got, services)
			}
		})
	}

	got := s.selectServices(
		services,
		req,
		map[string]bool{"network:missing": true},
		nil,
		nil,
	)
	if len(got) != 0 {
		t.Fatalf("unrelated endpoint matched services: %#v", got)
	}
}
