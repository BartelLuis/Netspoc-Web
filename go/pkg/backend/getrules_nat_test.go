package backend

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAdaptNameIPIncludesPolicyName(t *testing.T) {
	dataDir := t.TempDir()
	currentDir := filepath.Join(dataDir, "current")
	if err := os.MkdirAll(currentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(currentDir, "POLICY"), []byte("# p-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := newCache(dataDir, 8)
	c.getOwnerEntry("p-test", "network-team").natSet = map[string]bool{}
	s := &state{cache: c, config: &config{NetspocData: dataDir}}
	request := httptest.NewRequest(http.MethodGet,
		"/?active_owner=network-team&display_property=name", nil)

	records := s.adaptNameIP(request, "web", []*rule{{
		Action: "permit", PolicyName: "ALLOW_WEB",
		Src: []string{"network:clients"}, Dst: []string{"host:web"},
		Prt: []string{"tcp 443"},
	}})
	if len(records) != 1 {
		t.Fatalf("rule records = %d, want 1", len(records))
	}
	if got := records[0]["policy_name"]; got != "ALLOW_WEB" {
		t.Fatalf("policy_name = %#v, want %q", got, "ALLOW_WEB")
	}
}

func TestName2IPDoesNotMutateCachedObjectForNAT(t *testing.T) {
	const (
		version    = "p-test"
		objectName = "host:server"
		original   = "10.106.166.10"
		natIP      = "192.0.2.10"
	)

	c := newCache(t.TempDir(), 8)
	entry := c.getCacheEntry(version)
	entry.objects = map[string]*object{
		objectName: {
			IP:  original,
			NAT: map[string]string{"internet": natIP},
		},
	}
	s := &state{cache: c}

	if got := s.name2IP(version, objectName, map[string]bool{"internet": true}); got != natIP {
		t.Fatalf("NAT address = %q, want %q", got, natIP)
	}
	if got := s.name2IP(version, objectName, nil); got != original {
		t.Fatalf("cached address changed to %q after NAT lookup, want %q", got, original)
	}

	// Concurrent calls exercise the shared cache under the race detector. NAT
	// selection is request-local and must never write to the cached object.
	const workers = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(useNAT bool) {
			defer wg.Done()
			<-start
			if useNAT {
				results <- s.name2IP(version, objectName, map[string]bool{"internet": true})
				return
			}
			results <- s.name2IP(version, objectName, nil)
		}(i%2 == 0)
	}
	close(start)
	wg.Wait()
	close(results)

	for got := range results {
		if got != original && got != natIP {
			t.Fatalf("unexpected address from concurrent lookup: %q", got)
		}
	}
	if got := entry.objects[objectName].IP; got != original {
		t.Fatalf("cached object was mutated to %q, want %q", got, original)
	}
}

func TestGetNatObjSelectsTagWithoutMutatingCachedObject(t *testing.T) {
	const (
		version    = "p-test"
		objectName = "host:server"
		original   = "10.106.166.10"
		natIP      = "192.0.2.10"
	)
	c := newCache(t.TempDir(), 8)
	entry := c.getCacheEntry(version)
	entry.objects = map[string]*object{
		objectName: {IP: original, NAT: map[string]string{"internet": natIP}},
	}
	s := &state{cache: c}

	const workers = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(useNAT bool) {
			defer wg.Done()
			<-start
			selected := map[string]bool(nil)
			if useNAT {
				selected = map[string]bool{"internet": true}
			}
			results <- s.getNatObj(objectName, selected, version).IP
		}(i%2 == 0)
	}
	close(start)
	wg.Wait()
	close(results)

	seenOriginal, seenNAT := false, false
	for got := range results {
		switch got {
		case original:
			seenOriginal = true
		case natIP:
			seenNAT = true
		default:
			t.Fatalf("unexpected address from concurrent object lookup: %q", got)
		}
	}
	if !seenOriginal || !seenNAT {
		t.Fatalf("NAT selection results: original=%v NAT=%v", seenOriginal, seenNAT)
	}
	if got := entry.objects[objectName].IP; got != original {
		t.Fatalf("cached object was mutated to %q, want %q", got, original)
	}
}
