package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeFortiGateRequest struct {
	Method  string
	Path    string
	Query   url.Values
	Wrapped bool
	Payload map[string]any
}

type fakeFortiGate struct {
	mu                   sync.Mutex
	version              string
	build                int
	objects              map[string][]map[string]any
	requests             []fakeFortiGateRequest
	tamperName           string
	nextPolicy           int
	postedPolicyID       int
	cancelOnce           context.CancelFunc
	limitReached         bool
	pageSize             int
	revision             string
	revisionAfterFirst   string
	repeatFirstPage      bool
	replaceAfterMutation string
	replaceName          string
	replacement          map[string]any
}

func newFakeFortiGate(version string) *fakeFortiGate {
	return &fakeFortiGate{
		version: version, build: 2902, nextPolicy: 100, revision: "fake-revision-1",
		objects: map[string][]map[string]any{
			"/api/v2/cmdb/firewall/address":        {},
			"/api/v2/cmdb/firewall/address6":       {},
			"/api/v2/cmdb/firewall.service/custom": {},
			"/api/v2/cmdb/firewall/policy":         {},
			"/api/v2/cmdb/firewall/policy6":        {},
		},
	}
}

func (f *fakeFortiGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer runtime-secret" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	if r.URL.Query().Get("access_token") != "" {
		http.Error(w, "token leaked into URL", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("vdom") != "root" {
		http.Error(w, "missing vdom", http.StatusBadRequest)
		return
	}
	if r.URL.Path == "/api/v2/monitor/system/status" {
		f.requests = append(f.requests, fakeFortiGateRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()})
		writeFakeFortiGate(w, map[string]any{"status": "success", "results": map[string]any{"version": f.version, "build": f.build}})
		return
	}
	collection, mkey := f.collectionAndMKey(r.URL.Path)
	if collection == "" {
		http.NotFound(w, r)
		return
	}
	wrapped, payload, err := decodeFakeMutation(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.requests = append(f.requests, fakeFortiGateRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Wrapped: wrapped, Payload: cloneAnyMap(payload)})
	switch r.Method {
	case http.MethodGet:
		results := f.filteredObjects(collection, mkey, r.URL.Query().Get("filter"))
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		limitReached := f.limitReached
		nextIndex := -1
		if f.pageSize > 0 && start < len(results) {
			end := start + f.pageSize
			if end > len(results) {
				end = len(results)
			}
			limitReached = end < len(results)
			nextIndex = end - 1
			results = results[start:end]
		} else if f.pageSize > 0 {
			results = []map[string]any{}
			limitReached = false
		}
		if f.repeatFirstPage && start > 0 && f.pageSize > 0 {
			first := f.filteredObjects(collection, "", r.URL.Query().Get("filter"))
			end := f.pageSize
			if end > len(first) {
				end = len(first)
			}
			results = first[:end]
			limitReached = false
		}
		revision := f.revision
		if start > 0 && f.revisionAfterFirst != "" {
			revision = f.revisionAfterFirst
		}
		response := map[string]any{"status": "success", "http_status": 200, "results": results, "limit_reached": limitReached, "revision": revision}
		if limitReached && nextIndex >= 0 {
			response["next_idx"] = nextIndex
		}
		writeFakeFortiGate(w, response)
	case http.MethodPost:
		if !wrapped {
			http.Error(w, "mutation payload is not a raw CMDB object", http.StatusBadRequest)
			return
		}
		item := cloneAnyMap(payload)
		if strings.HasSuffix(collection, "/policy") || strings.HasSuffix(collection, "/policy6") {
			if scalarString(item["policyid"]) == "" || scalarString(item["policyid"]) == "0" {
				item["policyid"] = f.nextPolicy
				f.nextPolicy++
			}
			if f.postedPolicyID != 0 {
				item["policyid"] = f.postedPolicyID
			}
		}
		if item["name"] == f.tamperName {
			item["subnet"] = "203.0.113.0 255.255.255.0"
		}
		f.objects[collection] = append(f.objects[collection], item)
		f.replaceObjectOnce(scalarString(item["name"]))
		f.cancelRequestOnce()
		writeFakeFortiGate(w, map[string]any{"status": "success", "http_status": 200})
	case http.MethodPut:
		if r.URL.Query().Get("action") == "move" {
			if err := f.moveObject(collection, mkey, r.URL.Query()); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeFakeFortiGate(w, map[string]any{"status": "success", "http_status": 200})
			return
		}
		if !wrapped {
			http.Error(w, "mutation payload is not a raw CMDB object", http.StatusBadRequest)
			return
		}
		index := f.objectIndex(collection, mkey)
		if index < 0 {
			http.NotFound(w, r)
			return
		}
		item := cloneAnyMap(f.objects[collection][index])
		for key, value := range payload {
			item[key] = value
		}
		if item["name"] == f.tamperName {
			item["subnet"] = "203.0.113.0 255.255.255.0"
		}
		f.objects[collection][index] = item
		f.replaceObjectOnce(scalarString(item["name"]))
		f.cancelRequestOnce()
		writeFakeFortiGate(w, map[string]any{"status": "success", "http_status": 200})
	case http.MethodDelete:
		index := f.objectIndex(collection, mkey)
		if index >= 0 {
			f.objects[collection] = append(f.objects[collection][:index], f.objects[collection][index+1:]...)
		}
		f.cancelRequestOnce()
		writeFakeFortiGate(w, map[string]any{"status": "success", "http_status": 200})
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func (f *fakeFortiGate) replaceObjectOnce(trigger string) {
	if trigger != f.replaceAfterMutation || f.replaceName == "" {
		return
	}
	f.replaceAfterMutation = ""
	for collection := range f.objects {
		for index, item := range f.objects[collection] {
			if scalarString(item["name"]) == f.replaceName {
				replacement := cloneAnyMap(f.replacement)
				if _, exists := replacement["name"]; !exists {
					replacement["name"] = f.replaceName
				}
				f.objects[collection][index] = replacement
				return
			}
		}
	}
}

func (f *fakeFortiGate) cancelRequestOnce() {
	if f.cancelOnce != nil {
		cancel := f.cancelOnce
		f.cancelOnce = nil
		cancel()
	}
}

func (f *fakeFortiGate) collectionAndMKey(path string) (string, string) {
	collections := make([]string, 0, len(f.objects))
	for collection := range f.objects {
		collections = append(collections, collection)
	}
	// firewall.service/custom must be tested before any shorter prefix.
	for i := 0; i < len(collections); i++ {
		for j := i + 1; j < len(collections); j++ {
			if len(collections[j]) > len(collections[i]) {
				collections[i], collections[j] = collections[j], collections[i]
			}
		}
	}
	for _, collection := range collections {
		if path == collection {
			return collection, ""
		}
		if strings.HasPrefix(path, collection+"/") {
			mkey, _ := url.PathUnescape(strings.TrimPrefix(path, collection+"/"))
			return collection, mkey
		}
	}
	return "", ""
}

func decodeFakeMutation(r *http.Request) (bool, map[string]any, error) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut || r.URL.Query().Get("action") == "move" {
		return false, nil, nil
	}
	var body map[string]any
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		return false, nil, err
	}
	if _, hasEnvelope := body["data"]; hasEnvelope {
		return false, nil, errors.New("CMDB mutation must not use a data envelope")
	}
	return true, body, nil
}

func (f *fakeFortiGate) filteredObjects(collection, mkey, filter string) []map[string]any {
	result := []map[string]any{}
	name := strings.TrimPrefix(filter, "name==")
	for _, item := range f.objects[collection] {
		if mkey != "" && fakeMKey(collection, item) != mkey {
			continue
		}
		if filter != "" && scalarString(item["name"]) != name {
			continue
		}
		result = append(result, cloneAnyMap(item))
	}
	return result
}

func fakeMKey(collection string, item map[string]any) string {
	if strings.HasSuffix(collection, "/policy") || strings.HasSuffix(collection, "/policy6") {
		return scalarString(item["policyid"])
	}
	return scalarString(item["name"])
}

func (f *fakeFortiGate) objectIndex(collection, mkey string) int {
	for i, item := range f.objects[collection] {
		if fakeMKey(collection, item) == mkey {
			return i
		}
	}
	return -1
}

func (f *fakeFortiGate) moveObject(collection, mkey string, query url.Values) error {
	index := f.objectIndex(collection, mkey)
	if index < 0 {
		return fmt.Errorf("mkey %s missing", mkey)
	}
	item := f.objects[collection][index]
	f.objects[collection] = append(f.objects[collection][:index], f.objects[collection][index+1:]...)
	reference, before := query.Get("before"), true
	if reference == "" {
		reference, before = query.Get("after"), false
	}
	referenceIndex := f.objectIndex(collection, reference)
	if referenceIndex < 0 {
		return fmt.Errorf("reference %s missing", reference)
	}
	insert := referenceIndex
	if !before {
		insert++
	}
	f.objects[collection] = append(f.objects[collection], nil)
	copy(f.objects[collection][insert+1:], f.objects[collection][insert:])
	f.objects[collection][insert] = item
	return nil
}

func cloneAnyMap(value map[string]any) map[string]any {
	data, _ := json.Marshal(value)
	result := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	_ = decoder.Decode(&result)
	return result
}

func writeFakeFortiGate(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func runtimeTestTarget(t testing.TB, server *httptest.Server) FortinetTarget {
	t.Helper()
	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("test FortiGate has no TLS certificate")
	}
	caFile := filepath.Join(t.TempDir(), "fortigate-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return FortinetTarget{
		Name: "edge", Type: "fortigate", URL: server.URL, VDOM: "root", TokenEnv: "FGT_RUNTIME_TOKEN",
		TargetContexts: []string{"prod"}, ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
		PolicyInsertBefore: "policyweb-anchor", AllowDeploy: true, CAFile: caFile,
	}
}

func TestFortiOS74PreflightAndBearerHeader(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	for _, version := range []string{"v7.4.12", " FortiOS v7.4.9 ", "v7.4.12,build2902,230", "FortiOS v7.4.12,build2902,230"} {
		t.Run(version, func(t *testing.T) {
			fake := newFakeFortiGate(version)
			server := httptest.NewTLSServer(fake)
			defer server.Close()
			target := &runtimeTarget{Config: runtimeTestTarget(t, server)}
			if err := preflightFortiGateTargets(context.Background(), []*runtimeTarget{target}); err != nil {
				t.Fatal(err)
			}
			if target.System.Version != version || target.System.Build != "2902" {
				t.Fatalf("system info = %#v", target.System)
			}
		})
	}
}

func TestFortiOSPreflightBlocksOtherMinorVersionsBeforeMutation(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	for _, version := range []string{"v7.2.10", "v7.6.2", "v7.4", "v7.4-beta", "v7.40.1", "garbage7.4.12", "v7.4.12-beta", "v7.4.12-rc1", "v7.4.12 beta", "beta v7.4.12", "garbage FortiOS v7.4.12", "FortiOS v7.4.12,build2902,beta"} {
		t.Run(version, func(t *testing.T) {
			fake := newFakeFortiGate(version)
			server := httptest.NewTLSServer(fake)
			defer server.Close()
			target := &runtimeTarget{Config: runtimeTestTarget(t, server)}
			err := preflightFortiGateTargets(context.Background(), []*runtimeTarget{target})
			if err == nil || !strings.Contains(err.Error(), "requires FortiOS 7.4.x") {
				t.Fatalf("preflight error = %v", err)
			}
			for _, request := range fake.requests {
				if request.Method != http.MethodGet {
					t.Fatalf("mutation happened before version rejection: %#v", request)
				}
			}
		})
	}
}

func TestDeploymentPreflightRequiresVerifiedTLS(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	config := runtimeTestTarget(t, server)
	config.CAFile, config.InsecureSkipVerify = "", true
	target := &runtimeTarget{Config: config}
	err := preflightFortiGateTargets(context.Background(), []*runtimeTarget{target})
	if err == nil || !strings.Contains(err.Error(), "requires verified TLS") {
		t.Fatalf("insecure deployment preflight error = %v", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("insecure deployment contacted target: %#v", fake.requests)
	}

	// Preview/status also transmits the bearer token and must therefore use a
	// verified TLS peer.
	config.AllowDeploy = false
	target = &runtimeTarget{Config: config}
	if err := preflightFortiGateTargets(context.Background(), []*runtimeTarget{target}); err == nil || !strings.Contains(err.Error(), "requires verified TLS") {
		t.Fatalf("preview-only insecure preflight error = %v", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("insecure preview contacted target: %#v", fake.requests)
	}
}

func TestFortiGateObjectListingPaginatesWithNextIndexPlusOne(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/address"
	fake.objects[path] = []map[string]any{{"name": "one"}, {"name": "two"}, {"name": "three"}}
	fake.pageSize = 2
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := runtimeTestTarget(t, server)
	objects, err := listFortiGateObjects(context.Background(), server.Client(), target, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 || objects[0].MKey != "one" || objects[1].MKey != "two" || objects[2].MKey != "three" {
		t.Fatalf("paginated objects lost order: %#v", objects)
	}
	starts := []string{}
	for _, request := range fake.requests {
		starts = append(starts, request.Query.Get("start"))
	}
	if strings.Join(starts, ",") != "0,2" {
		t.Fatalf("pagination starts = %v, want next_idx+1 => [0 2]", starts)
	}
}

func TestFortiGateObjectListingFailsClosedOnUnstableOrMalformedPages(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	for _, test := range []struct {
		name, want string
		configure  func(*fakeFortiGate)
	}{
		{name: "revision changes", want: "changed while", configure: func(fake *fakeFortiGate) { fake.revisionAfterFirst = "fake-revision-2" }},
		{name: "duplicate mkey", want: "repeats mkey", configure: func(fake *fakeFortiGate) { fake.repeatFirstPage = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeFortiGate("v7.4.12")
			path := "/api/v2/cmdb/firewall/address"
			fake.objects[path] = []map[string]any{{"name": "one"}, {"name": "two"}, {"name": "three"}}
			fake.pageSize = 2
			test.configure(fake)
			server := httptest.NewTLSServer(fake)
			defer server.Close()
			_, err := listFortiGateObjects(context.Background(), server.Client(), runtimeTestTarget(t, server), path, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("pagination error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFortiGateObjectListingRejectsMalformedResults(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	tests := []struct {
		name     string
		path     string
		response map[string]any
	}{
		{
			name: "policy array contains null",
			path: "/api/v2/cmdb/firewall/policy",
			response: map[string]any{
				"status": "success", "http_status": 200, "revision": "stable", "limit_reached": false,
				"results": []any{map[string]any{"policyid": 1, "name": "valid"}, nil},
			},
		},
		{
			name: "object container has non-object child",
			path: "/api/v2/cmdb/firewall/address",
			response: map[string]any{
				"status": "success", "http_status": 200, "revision": "stable", "limit_reached": false,
				"results": map[string]any{"valid": map[string]any{"name": "valid"}, "invalid": "not-an-object"},
			},
		},
		{
			name: "missing results",
			path: "/api/v2/cmdb/firewall/address",
			response: map[string]any{
				"status": "success", "http_status": 200, "revision": "stable", "limit_reached": false,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeFakeFortiGate(w, test.response)
			}))
			defer server.Close()
			_, err := listFortiGateObjects(context.Background(), server.Client(), runtimeTestTarget(t, server), test.path, nil)
			if err == nil || !strings.Contains(err.Error(), "results") {
				t.Fatalf("malformed results error = %v", err)
			}
		})
	}
}

func TestFortiGateFailureRestoresSnapshots(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	addressPath := "/api/v2/cmdb/firewall/address"
	fake.objects[addressPath] = []map[string]any{{"name": "first", "subnet": "10.0.0.1 255.255.255.255", "comment": "keep me"}}
	fake.tamperName = "second"
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true, ExpectedBefore: map[string]map[string]any{
		addressPath + "\x00first": {"name": "first", "subnet": "10.0.0.1 255.255.255.255", "comment": "keep me"},
	}, Commands: []deploymentCommand{
		{Target: "edge", Context: "prod", Sequence: 1, Kind: "address", Method: "UPSERT", Path: addressPath, Payload: map[string]any{"name": "first", "subnet": "10.0.0.2 255.255.255.255"}},
		{Target: "edge", Context: "prod", Sequence: 2, Kind: "address", Method: "UPSERT", Path: addressPath, Payload: map[string]any{"name": "second", "subnet": "10.0.0.3 255.255.255.255"}},
	}}
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	err = executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result)
	if err == nil {
		t.Fatal("tampered verification unexpectedly succeeded")
	}
	if !result.RollbackAttempted || !result.RollbackSucceeded || len(result.RollbackErrors) != 0 {
		t.Fatalf("rollback result = %#v", result)
	}
	first := fake.filteredObjects(addressPath, "", "name==first")
	second := fake.filteredObjects(addressPath, "", "name==second")
	if len(first) != 1 || scalarString(first[0]["subnet"]) != "10.0.0.1 255.255.255.255" || scalarString(first[0]["comment"]) != "keep me" {
		t.Fatalf("first object was not fully restored: %#v", first)
	}
	if len(second) != 0 {
		t.Fatalf("new object survived rollback: %#v", second)
	}
	for _, request := range fake.requests {
		if (request.Method == http.MethodPost || request.Method == http.MethodPut) && request.Query.Get("action") != "move" && !request.Wrapped {
			t.Fatalf("mutation did not use a raw CMDB object: %#v", request)
		}
	}
}

func TestRollbackRefusesToClobberReplacementObject(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/address"
	base := map[string]any{"name": "first", "subnet": "10.0.0.1 255.255.255.255", "uuid": "owned-object"}
	desired := map[string]any{"name": "first", "subnet": "10.0.0.2 255.255.255.255"}
	fake.objects[path] = []map[string]any{cloneAnyMap(base)}
	fake.tamperName = "second"
	fake.replaceAfterMutation = "second"
	fake.replaceName = "first"
	fake.replacement = map[string]any{"name": "first", "subnet": desired["subnet"], "uuid": "administrator-replacement"}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{
		Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true,
		ExpectedBefore: map[string]map[string]any{path + "\x00first": {"name": "first", "subnet": base["subnet"]}},
		Commands: []deploymentCommand{
			{Target: "edge", Context: "prod", Sequence: 1, Kind: "address", Method: "UPSERT", Path: path, Payload: desired},
			{Target: "edge", Context: "prod", Sequence: 2, Kind: "address", Method: "UPSERT", Path: path, Payload: map[string]any{"name": "second", "subnet": "10.0.0.3 255.255.255.255"}},
		},
	}
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	if err := executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result); err == nil {
		t.Fatal("deployment unexpectedly succeeded")
	}
	if !result.RollbackAttempted || result.RollbackSucceeded || len(result.RollbackErrors) == 0 || !strings.Contains(strings.Join(result.RollbackErrors, " "), "identity changed") {
		t.Fatalf("replacement rollback result = %#v", result)
	}
	current := fake.filteredObjects(path, "", "name==first")
	if len(current) != 1 || scalarString(current[0]["uuid"]) != "administrator-replacement" {
		t.Fatalf("administrator replacement was clobbered: %#v", current)
	}
}

func TestDeploymentPerformsFinalFullDriftPass(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/address"
	base := map[string]any{"name": "first", "subnet": "10.0.0.1 255.255.255.255", "uuid": "owned-object"}
	fake.objects[path] = []map[string]any{cloneAnyMap(base)}
	fake.replaceAfterMutation = "second"
	fake.replaceName = "first"
	fake.replacement = map[string]any{"name": "first", "subnet": "192.0.2.0 255.255.255.0", "uuid": "administrator-change"}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{
		Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true,
		ExpectedBefore: map[string]map[string]any{path + "\x00first": {"name": "first", "subnet": base["subnet"]}},
		Commands: []deploymentCommand{
			{Target: "edge", Context: "prod", Sequence: 1, Kind: "address", Method: "UPSERT", Path: path, Payload: map[string]any{"name": "first", "subnet": "10.0.0.2 255.255.255.255"}},
			{Target: "edge", Context: "prod", Sequence: 2, Kind: "address", Method: "UPSERT", Path: path, Payload: map[string]any{"name": "second", "subnet": "10.0.0.3 255.255.255.255"}},
		},
	}
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	err = executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result)
	if err == nil || !strings.Contains(err.Error(), "final deployment verification failed") {
		t.Fatalf("final verification error = %v", err)
	}
	if !result.RollbackAttempted || result.RollbackSucceeded {
		t.Fatalf("final verification did not trigger safe compensation: %#v", result)
	}
	if second := fake.filteredObjects(path, "", "name==second"); len(second) != 0 {
		t.Fatalf("owned second mutation was not compensated: %#v", second)
	}
}

func TestFortiGateAddressFamilyTransitionUsesUnifiedAtomicPut(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/policy"
	old := map[string]any{
		"policyid": 10, "name": "stable-policy", "srcaddr": []any{map[string]any{"name": "old-v4"}}, "dstaddr": []any{map[string]any{"name": "old-v4-dst"}},
		"srcaddr6": []any{}, "dstaddr6": []any{}, "srcaddr-negate": "disable", "dstaddr-negate": "disable", "srcaddr6-negate": "disable", "dstaddr6-negate": "disable", "action": "accept",
	}
	fake.objects[path] = []map[string]any{cloneAnyMap(old), {"policyid": 999, "name": "policyweb-anchor", "action": "deny"}}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	newPayload := map[string]any{
		"name": "stable-policy", "srcaddr": []any{}, "dstaddr": []any{}, "srcaddr6": []any{map[string]any{"name": "new-v6"}}, "dstaddr6": []any{map[string]any{"name": "new-v6-dst"}},
		"srcaddr-negate": "disable", "dstaddr-negate": "disable", "srcaddr6-negate": "disable", "dstaddr6-negate": "disable", "action": "accept",
	}
	createPayload := cloneAnyMap(newPayload)
	createPayload["policyid"] = 0
	commands := []deploymentCommand{{Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: "UPSERT", Path: path, InsertBefore: "policyweb-anchor", Payload: newPayload, CreatePayload: createPayload}}
	target := &runtimeTarget{
		Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true,
		ExpectedBefore: map[string]map[string]any{path + "\x00stable-policy": cloneAnyMap(old)}, Commands: commands,
	}
	delete(target.ExpectedBefore[path+"\x00stable-policy"], "policyid")
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	if err := executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result); err != nil {
		t.Fatal(err)
	}
	policies := fake.objects[path]
	if len(policies) != 2 || scalarString(policies[0]["name"]) != "stable-policy" || scalarString(policies[1]["name"]) != "policyweb-anchor" {
		t.Fatalf("transition policy order = %#v", policies)
	}
	if values, ok := policies[0]["srcaddr"].([]any); !ok || len(values) != 0 || scalarString(policies[0]["policyid"]) != "10" {
		t.Fatalf("transition did not atomically clear IPv4 while retaining policy identity: %#v", policies[0])
	}
	if values, ok := policies[0]["srcaddr6"].([]any); !ok || len(values) != 1 {
		t.Fatalf("transition did not set IPv6 match in the same PUT: %#v", policies[0])
	}
}

func TestDriftTreatsAddressFamilyTransitionAsFinalUpsertState(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/policy"
	newPayload := map[string]any{
		"name": "stable-policy", "srcaddr": []any{}, "dstaddr": []any{},
		"srcaddr6": []any{map[string]any{"name": "new-v6"}}, "dstaddr6": []any{map[string]any{"name": "new-v6-dst"}}, "action": "accept",
	}
	actual := cloneAnyMap(newPayload)
	actual["policyid"] = 100
	fake.objects[path] = []map[string]any{actual, {"policyid": 999, "name": "policyweb-anchor", "action": "deny"}}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	createPayload := cloneAnyMap(newPayload)
	createPayload["policyid"] = 0
	commands := []deploymentCommand{
		{Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: "DELETE", Path: path, Payload: map[string]any{"name": "stable-policy", "srcaddr": []any{map[string]any{"name": "old-v4"}}, "dstaddr": []any{map[string]any{"name": "old-v4-dst"}}, "action": "accept"}},
		{Target: "edge", Context: "prod", Sequence: 2, Kind: "policy", Method: "UPSERT", Path: path, InsertBefore: "policyweb-anchor", Payload: newPayload, CreatePayload: createPayload},
	}
	final, err := finalDeploymentCommands(commands)
	if err != nil {
		t.Fatal(err)
	}
	if len(final) != 1 || !strings.EqualFold(final[0].Method, "UPSERT") {
		t.Fatalf("family transition final commands = %#v", final)
	}
	target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client(), Commands: commands}
	record := inspectDrift(context.Background(), target, final[0])
	if record.Status != "in_sync" {
		t.Fatalf("deployed family transition reported as drift: %#v", record)
	}
}

func TestFortiGateDeleteRollbackRestoresPolicyOrderAndContent(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	policyPath, addressPath := "/api/v2/cmdb/firewall/policy", "/api/v2/cmdb/firewall/address"
	expectedPolicy := map[string]any{
		"name": "old-policy", "srcintf": []any{map[string]any{"name": "port2"}}, "dstintf": []any{map[string]any{"name": "port3"}},
		"srcaddr": []any{map[string]any{"name": "network:source"}}, "dstaddr": []any{map[string]any{"name": "network:target"}},
		"action": "accept", "service": []any{map[string]any{"name": "HTTPS"}}, "schedule": "always", "logtraffic": "all", "comments": "must survive",
	}
	oldPolicy := cloneAnyMap(expectedPolicy)
	oldPolicy["policyid"] = 10
	fake.objects[policyPath] = []map[string]any{
		oldPolicy,
		{"policyid": 20, "name": "following-policy", "action": "deny"},
	}
	fake.tamperName = "bad-address"
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true, ExpectedBefore: map[string]map[string]any{}, Commands: []deploymentCommand{
		{Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: "DELETE", Path: policyPath, Payload: expectedPolicy},
		{Target: "edge", Context: "prod", Sequence: 2, Kind: "address", Method: "UPSERT", Path: addressPath, Payload: map[string]any{"name": "bad-address", "subnet": "10.1.1.1 255.255.255.255"}},
	}}
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	if err := executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result); err == nil {
		t.Fatal("deployment unexpectedly succeeded")
	}
	if !result.RollbackSucceeded {
		t.Fatalf("policy rollback failed: %#v", result.RollbackErrors)
	}
	policies := fake.objects[policyPath]
	if len(policies) != 2 || scalarString(policies[0]["name"]) != "old-policy" || scalarString(policies[1]["name"]) != "following-policy" {
		t.Fatalf("policy order was not restored: %#v", policies)
	}
	if scalarString(policies[0]["comments"]) != "must survive" || scalarString(policies[0]["policyid"]) != "10" {
		t.Fatalf("policy content/mkey was not restored: %#v", policies[0])
	}
}

func TestRollbackRepositionsSeveralAdjacentDeletedPolicies(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	policyPath, addressPath := "/api/v2/cmdb/firewall/policy", "/api/v2/cmdb/firewall/address"
	fake.objects[policyPath] = []map[string]any{
		{"policyid": 1, "name": "unmanaged-before", "action": "deny"},
		{"policyid": 10, "name": "A", "action": "accept"},
		{"policyid": 20, "name": "B", "action": "accept"},
		{"policyid": 30, "name": "C", "action": "accept"},
		{"policyid": 999, "name": "policyweb-anchor", "action": "deny"},
	}
	fake.tamperName = "bad-address"
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	deleteCommand := func(sequence int, name string) deploymentCommand {
		return deploymentCommand{Target: "edge", Context: "prod", Sequence: sequence, Kind: "policy", Method: "DELETE", Path: policyPath, Payload: map[string]any{"name": name, "action": "accept"}}
	}
	// This order makes B the first policy recreated during compensation, while
	// both of its original neighbours A and C are still absent.
	commands := []deploymentCommand{
		deleteCommand(1, "C"), deleteCommand(2, "A"), deleteCommand(3, "B"),
		{Target: "edge", Context: "prod", Sequence: 4, Kind: "address", Method: "UPSERT", Path: addressPath, Payload: map[string]any{"name": "bad-address", "subnet": "10.0.0.1 255.255.255.255"}},
	}
	target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true, ExpectedBefore: map[string]map[string]any{}, Commands: commands}
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	if err := executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result); err == nil {
		t.Fatal("deployment unexpectedly succeeded")
	}
	if !result.RollbackSucceeded {
		t.Fatalf("multi-policy rollback failed: %#v", result.RollbackErrors)
	}
	names := []string{}
	for _, policy := range fake.objects[policyPath] {
		names = append(names, scalarString(policy["name"]))
	}
	want := []string{"unmanaged-before", "A", "B", "C", "policyweb-anchor"}
	if !sameJSONValue(names, want) {
		t.Fatalf("restored policy order = %#v; want %#v", names, want)
	}
}

func TestFortiGateDeleteBlocksOnApprovedBaseDrift(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/policy"
	expected := map[string]any{
		"name": "old-policy", "srcintf": []any{map[string]any{"name": "port2"}}, "dstintf": []any{map[string]any{"name": "port3"}},
		"srcaddr": []any{map[string]any{"name": "network:source"}}, "dstaddr": []any{map[string]any{"name": "network:target"}},
		"action": "accept", "service": []any{map[string]any{"name": "HTTPS"}}, "schedule": "always", "logtraffic": "all", "comments": "approved",
	}
	actual := cloneAnyMap(expected)
	actual["policyid"], actual["action"] = 10, "deny"
	fake.objects[path] = []map[string]any{actual}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true, ExpectedBefore: map[string]map[string]any{}, Commands: []deploymentCommand{{
		Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: "DELETE", Path: path, Payload: expected,
	}}}
	_, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err == nil || !strings.Contains(err.Error(), "refuse DELETE of drifted policy") {
		t.Fatalf("drifted delete precondition error = %v", err)
	}
	for _, request := range fake.requests {
		if request.Method != http.MethodGet {
			t.Fatalf("mutation occurred despite DELETE precondition drift: %#v", request)
		}
	}
}

func TestFortiGateUpsertBlocksUnownedCollisionAndApprovedBaseDrift(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	path := "/api/v2/cmdb/firewall/address"
	tests := []struct {
		name           string
		actual         map[string]any
		expectedBefore map[string]map[string]any
		want           string
	}{
		{
			name: "unowned name collision", actual: map[string]any{"name": "managed", "subnet": "192.0.2.1 255.255.255.255"},
			expectedBefore: map[string]map[string]any{}, want: "name collision",
		},
		{
			name: "approved object drifted", actual: map[string]any{"name": "managed", "subnet": "192.0.2.1 255.255.255.255"},
			expectedBefore: map[string]map[string]any{path + "\x00managed": {"name": "managed", "subnet": "10.0.0.1 255.255.255.255"}}, want: "drifted address",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeFortiGate("v7.4.12")
			fake.objects[path] = []map[string]any{cloneAnyMap(test.actual)}
			server := httptest.NewTLSServer(fake)
			defer server.Close()
			target := &runtimeTarget{
				Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true, ExpectedBefore: test.expectedBefore,
				Commands: []deploymentCommand{{Target: "edge", Context: "prod", Sequence: 1, Kind: "address", Method: "UPSERT", Path: path, Payload: map[string]any{"name": "managed", "subnet": "10.0.0.2 255.255.255.255"}}},
			}
			_, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("snapshot error = %v; want %q", err, test.want)
			}
			for _, request := range fake.requests {
				if request.Method != http.MethodGet {
					t.Fatalf("mutation occurred despite failed UPSERT precondition: %#v", request)
				}
			}
		})
	}
}

func TestFortiGateRefusesInPlaceMutationOfVersionedContentObjects(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	tests := []struct {
		kind, path string
		before     map[string]any
		desired    map[string]any
	}{
		{kind: "address", path: "/api/v2/cmdb/firewall/address", before: map[string]any{"name": "PW_A4_FIXED", "type": "ipmask", "subnet": "10.0.0.0 255.255.255.0"}, desired: map[string]any{"name": "PW_A4_FIXED", "type": "ipmask", "subnet": "10.1.0.0 255.255.255.0"}},
		{kind: "service", path: "/api/v2/cmdb/firewall.service/custom", before: map[string]any{"name": "PW_SVC_FIXED", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "80"}, desired: map[string]any{"name": "PW_SVC_FIXED", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			fake := newFakeFortiGate("v7.4.12")
			fake.objects[test.path] = []map[string]any{cloneAnyMap(test.before)}
			server := httptest.NewTLSServer(fake)
			defer server.Close()
			command := deploymentCommand{Target: "edge", Context: "prod", Sequence: 1, Kind: test.kind, Method: "UPSERT", Path: test.path, Payload: test.desired, SemanticsVersion: fortiOSObjectSemanticsVersion}
			target := &runtimeTarget{
				Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true,
				ExpectedBefore: map[string]map[string]any{test.path + "\x00" + scalarString(test.before["name"]): test.before}, Commands: []deploymentCommand{command},
			}
			if _, err := snapshotDeployment(context.Background(), []*runtimeTarget{target}); err == nil || !strings.Contains(err.Error(), "immutable/content-addressed") {
				t.Fatalf("same-name semantic mutation was not blocked: %v", err)
			}
			for _, request := range fake.requests {
				if request.Method != http.MethodGet {
					t.Fatalf("immutable collision caused a live mutation: %#v", request)
				}
			}
		})
	}
}

func TestFortiGateUpsertBlocksNonDefaultNewlyManagedMatchFieldFromLegacyBase(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	rule := editableRule{
		Action: "accept", PolicyName: "legacy-managed", PolicyComment: "legacy base ownership upgrade",
		Sources: []string{"source"}, Destinations: []string{"destination"},
	}
	command := deploymentPolicyCommand(FortinetTarget{Name: "edge", Type: "fortigate", VDOM: "prod"}, "prod", 1, "ipv4", rule, "PW_SVC_TEST", "port1", "port2")
	legacyBase := cloneAnyMap(command.Payload)
	delete(legacyBase, "groups")
	actual := cloneAnyMap(legacyBase)
	actual["groups"] = []any{map[string]any{"name": "Contractors"}}
	actual["policyid"] = 10

	fake := newFakeFortiGate("v7.4.12")
	fake.objects[command.Path] = []map[string]any{actual}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	identity, err := deploymentCommandIdentity(command)
	if err != nil {
		t.Fatal(err)
	}
	target := &runtimeTarget{
		Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true,
		ExpectedBefore: map[string]map[string]any{identity: legacyBase}, Commands: []deploymentCommand{command},
	}
	_, err = snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err == nil || !strings.Contains(err.Error(), "newly managed policy match state") || !strings.Contains(err.Error(), "groups") {
		t.Fatalf("legacy base silently adopted non-default group selector: %v", err)
	}
	for _, request := range fake.requests {
		if request.Method != http.MethodGet {
			t.Fatalf("mutation occurred despite unsafe legacy ownership adoption: %#v", request)
		}
	}
}

func TestFortiOS74PolicyProjectionAcceptsBroadDefaultGETAndBlocksExtraSemantics(t *testing.T) {
	rule := editableRule{
		Action: "accept", PolicyName: "projection-policy", PolicyComment: "broad FortiOS GET fixture",
		Sources: []string{"source"}, Destinations: []string{"destination"},
	}
	command := deploymentPolicyCommand(FortinetTarget{Name: "edge", Type: "fortigate", VDOM: "root"}, "prod", 1, "ipv4", rule, "PW_SVC_TEST", "port1", "port2")
	actual := fortiOS74PolicySemanticDefaults()
	for key, value := range command.Payload {
		actual[key] = value
	}
	actual["policyid"], actual["uuid"], actual["q_origin_key"] = 17, "device-assigned-uuid", 17
	wireJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	actual = map[string]any{}
	if err := json.Unmarshal(wireJSON, &actual); err != nil {
		t.Fatal(err)
	}
	if differences := fortiGateCommandDifferences(command, command.Payload, actual); len(differences) != 0 {
		t.Fatalf("realistic broad default policy GET was rejected: %v", differences)
	}
	tests := map[string]any{
		"src-vendor-mac":        []any{map[string]any{"name": "vendor-selector"}},
		"reputation-minimum":    3,
		"reputation-minimum6":   4,
		"http-policy-redirect":  "enable",
		"ssh-policy-redirect":   "enable",
		"vlan-filter":           "100",
		"geoip-anycast":         "enable",
		"internet-service":      "enable",
		"internet-service-name": []any{map[string]any{"name": "Fortinet-Web"}},
		"ippool":                "enable",
		"poolname":              []any{map[string]any{"name": "operator-pool"}},
		"permit-any-host":       "enable",
		"future-match-selector": "non-default",
	}
	for field, value := range tests {
		t.Run(field, func(t *testing.T) {
			changed := cloneAnyMap(actual)
			changed[field] = value
			differences := fortiGateCommandDifferences(command, command.Payload, changed)
			if len(differences) == 0 || !strings.Contains(strings.Join(differences, " "), field) {
				t.Fatalf("non-default/unreviewed %s was ignored: %v", field, differences)
			}
		})
	}
}

func TestFortiOS74AddressAndServiceProjectionHandlesUnionGETsFailClosed(t *testing.T) {
	address := deploymentCommand{Kind: "address", Payload: map[string]any{"name": "PW_A4_TEST", "type": "ipmask", "subnet": "10.0.0.0 255.255.255.0"}}
	addressGET := fortiOS74AddressSemanticDefaults("address")
	for key, value := range address.Payload {
		addressGET[key] = value
	}
	// FortiOS full GETs populate inactive union/helper branches for ipmask.
	addressGET["start-ip"], addressGET["end-ip"], addressGET["wildcard"] = "10.100.77.240", "255.255.255.255", "10.0.0.0 0.0.0.255"
	addressGET["uuid"], addressGET["q_origin_key"] = "uuid", "PW_A4_TEST"
	if differences := fortiGateCommandDifferences(address, address.Payload, addressGET); len(differences) != 0 {
		t.Fatalf("realistic ipmask union GET was rejected: %v", differences)
	}
	for field, value := range map[string]any{"associated-interface": "port9", "unknown-address-matcher": "enabled"} {
		changed := cloneAnyMap(addressGET)
		changed[field] = value
		if differences := fortiGateCommandDifferences(address, address.Payload, changed); len(differences) == 0 {
			t.Fatalf("address semantic field %q was ignored", field)
		}
	}

	address6 := deploymentCommand{Kind: "address6", Payload: map[string]any{"name": "PW_A6_TEST", "type": "ipprefix", "ip6": "2001:db8::/64"}}
	address6GET := fortiOS74AddressSemanticDefaults("address6")
	for key, value := range address6.Payload {
		address6GET[key] = value
	}
	address6GET["start-ip"], address6GET["end-ip"], address6GET["host"] = "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::2"
	address6GET["uuid"] = "uuid6"
	if differences := fortiGateCommandDifferences(address6, address6.Payload, address6GET); len(differences) != 0 {
		t.Fatalf("realistic ipprefix union GET was rejected: %v", differences)
	}

	service := deploymentCommand{Kind: "service", Payload: map[string]any{"name": "PW_SVC_TEST", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443", "udp-portrange": "", "sctp-portrange": ""}}
	serviceGET := fortiOS74ServiceSemanticDefaults()
	for key, value := range service.Payload {
		serviceGET[key] = value
	}
	serviceGET["uuid"], serviceGET["q_origin_key"] = "service-uuid", "PW_SVC_TEST"
	if differences := fortiGateCommandDifferences(service, service.Payload, serviceGET); len(differences) != 0 {
		t.Fatalf("realistic TCP service GET was rejected: %v", differences)
	}
	for field, value := range map[string]any{"iprange": "192.0.2.1-192.0.2.2", "fqdn": "operator.example", "helper": "ftp", "proxy": "enable", "application": []any{1234}, "unknown-service-matcher": "enabled"} {
		changed := cloneAnyMap(serviceGET)
		changed[field] = value
		if differences := fortiGateCommandDifferences(service, service.Payload, changed); len(differences) == 0 {
			t.Fatalf("service semantic field %q was ignored", field)
		}
	}
}

func TestFortiGatePolicyExtrasBlockUnownedDeleteAndDrift(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	path := "/api/v2/cmdb/firewall/policy"
	desired := map[string]any{"name": "managed", "action": "accept", "src-vendor-mac": []any{}}
	actual := cloneAnyMap(desired)
	actual["policyid"] = 10
	actual["src-vendor-mac"] = []any{map[string]any{"name": "operator-selector"}}
	for _, test := range []struct {
		name, method, want string
		expected           map[string]map[string]any
	}{
		{name: "unowned", method: "UPSERT", want: "name collision", expected: map[string]map[string]any{}},
		{name: "delete", method: "DELETE", want: "refuse DELETE", expected: map[string]map[string]any{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeFortiGate("v7.4.12")
			fake.objects[path] = []map[string]any{cloneAnyMap(actual)}
			server := httptest.NewTLSServer(fake)
			defer server.Close()
			command := deploymentCommand{Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: test.method, Path: path, Payload: desired}
			target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true, ExpectedBefore: test.expected, Commands: []deploymentCommand{command}}
			if _, err := snapshotDeployment(context.Background(), []*runtimeTarget{target}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("policy extra snapshot error = %v, want %q", err, test.want)
			}
		})
	}
	fake := newFakeFortiGate("v7.4.12")
	fake.objects[path] = []map[string]any{actual}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	command := deploymentCommand{Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: "UPSERT", Path: path, Payload: desired}
	record := inspectDrift(context.Background(), &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client()}, command)
	if record.Status != "changed" || !strings.Contains(strings.Join(record.Differences, " "), "src-vendor-mac") {
		t.Fatalf("policy extra was not reported as drift: %#v", record)
	}
}

func TestFortiGateAlreadyDesiredUpsertSkipsMutation(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/address"
	desired := map[string]any{"name": "managed", "subnet": "10.0.0.1 255.255.255.255"}
	actual := cloneAnyMap(desired)
	actual["q_origin_key"] = "read-only-helper"
	fake.objects[path] = []map[string]any{actual}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{
		Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true, ExpectedBefore: map[string]map[string]any{},
		Commands: []deploymentCommand{{Target: "edge", Context: "prod", Sequence: 1, Kind: "address", Method: "UPSERT", Path: path, Payload: desired}},
	}
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 || !snapshots[0].AlreadyDesired {
		t.Fatalf("snapshot was not marked already desired: %#v", snapshots)
	}
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	if err := executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 1 || result.Results[0].Status != "already_in_sync" || result.CommandsApplied != 0 {
		t.Fatalf("deployment result = %#v", result)
	}
	for _, request := range fake.requests {
		if request.Method != http.MethodGet {
			t.Fatalf("already desired object was mutated: %#v", request)
		}
	}
}

func TestFortiGateRevalidatesSnapshotImmediatelyBeforeMutation(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/address"
	base := map[string]any{"name": "managed", "subnet": "10.0.0.1 255.255.255.255"}
	fake.objects[path] = []map[string]any{cloneAnyMap(base)}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{
		Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true,
		ExpectedBefore: map[string]map[string]any{path + "\x00managed": base},
		Commands:       []deploymentCommand{{Target: "edge", Context: "prod", Sequence: 1, Kind: "address", Method: "UPSERT", Path: path, Payload: map[string]any{"name": "managed", "subnet": "10.0.0.2 255.255.255.255"}}},
	}
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an independent administrator changing the object after the
	// all-target snapshot but before this command reaches its mutation.
	fake.objects[path][0]["subnet"] = "192.0.2.0 255.255.255.0"
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	err = executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result)
	if err == nil || !strings.Contains(err.Error(), "precondition changed after snapshot") {
		t.Fatalf("TOCTOU precondition error = %v", err)
	}
	if result.RollbackAttempted || len(result.Results) != 1 || result.Results[0].Status != "precondition_failed" {
		t.Fatalf("TOCTOU deployment result = %#v", result)
	}
	for _, request := range fake.requests {
		if request.Method != http.MethodGet {
			t.Fatalf("mutation occurred after snapshot became stale: %#v", request)
		}
	}
}

func TestFortiGateRevalidationRejectsSameMKeyReplacementIdentity(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/address"
	base := map[string]any{"name": "managed", "subnet": "10.0.0.1 255.255.255.255", "uuid": "snapshot-identity"}
	desired := map[string]any{"name": "managed", "subnet": "10.0.0.2 255.255.255.255"}
	fake.objects[path] = []map[string]any{cloneAnyMap(base)}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{
		Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true,
		ExpectedBefore: map[string]map[string]any{path + "\x00managed": {"name": "managed", "subnet": base["subnet"]}},
		Commands:       []deploymentCommand{{Target: "edge", Context: "prod", Sequence: 1, Kind: "address", Method: "UPSERT", Path: path, Payload: desired}},
	}
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	// Same name/mkey and even exact desired content must not silently adopt a
	// replacement object with a different FortiOS UUID.
	fake.objects[path][0] = map[string]any{"name": "managed", "subnet": desired["subnet"], "uuid": "replacement-identity"}
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	err = executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result)
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("replacement identity precondition error = %v", err)
	}
	if result.RollbackAttempted || result.CommandsApplied != 0 {
		t.Fatalf("replacement object was touched: %#v", result)
	}
}

func TestRollbackPayloadUsesOnlyApprovedWritableFields(t *testing.T) {
	update := deploymentCommand{Kind: "address", Method: "UPSERT", Payload: map[string]any{"name": "managed", "subnet": "new"}}
	actual := map[string]any{"name": "managed", "subnet": "old", "q_origin_key": "helper", "uuid": "helper", "read_only": "helper"}
	approved := map[string]any{"name": "managed", "subnet": "old"}
	if payload := rollbackPayload(update, actual, approved); !sameJSONValue(payload, approved) {
		t.Fatalf("update rollback payload = %#v; want %#v", payload, approved)
	}

	deleteCommand := deploymentCommand{Kind: "policy", Method: "DELETE", Payload: map[string]any{"name": "old-policy", "action": "accept"}}
	deleted := map[string]any{"policyid": json.Number("42"), "name": "old-policy", "action": "accept", "q_origin_key": "helper", "uuid": "helper"}
	payload := rollbackPayload(deleteCommand, deleted, deleteCommand.Payload)
	if scalarString(payload["policyid"]) != "42" || scalarString(payload["name"]) != "old-policy" || len(payload) != 3 {
		t.Fatalf("delete rollback payload was not sanitized: %#v", payload)
	}

	legacyUpdate := deploymentCommand{Kind: "policy", Method: "UPSERT", Payload: map[string]any{"name": "legacy-policy", "action": "accept", "match-vip": "disable"}}
	legacyActual := map[string]any{"policyid": 7, "uuid": "read-only", "name": "legacy-policy", "action": "accept"}
	legacyApproved := map[string]any{"name": "legacy-policy", "action": "accept"}
	legacyRestore := rollbackPayload(legacyUpdate, legacyActual, legacyApproved)
	if scalarString(legacyRestore["match-vip"]) != "enable" {
		t.Fatalf("legacy omitted default was not materialized for partial-PUT rollback: %#v", legacyRestore)
	}
	if _, exists := legacyRestore["policyid"]; exists || legacyRestore["uuid"] != nil {
		t.Fatalf("legacy restore leaked read-only identity fields: %#v", legacyRestore)
	}
}

func TestFortiGatePolicyInsertionChainCreatesExactApprovedOrder(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/policy"
	fake.objects[path] = []map[string]any{{"policyid": 999, "name": "policyweb-anchor", "action": "deny"}}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	policyCommand := func(sequence int, name, successor string) deploymentCommand {
		payload := map[string]any{"name": name, "action": "accept"}
		create := cloneAnyMap(payload)
		create["policyid"] = 0
		return deploymentCommand{Target: "edge", Context: "prod", Sequence: sequence, Kind: "policy", Method: "UPSERT", Path: path, InsertBefore: successor, Payload: payload, CreatePayload: create}
	}
	// Execution is deliberately bottom-up: B is placed at the terminal anchor,
	// then A is placed immediately before B.
	commands := []deploymentCommand{policyCommand(1, "B", "policyweb-anchor"), policyCommand(2, "A", "B")}
	config := runtimeTestTarget(t, server)
	if err := validateRuntimePolicyChain(config, commands); err != nil {
		t.Fatal(err)
	}
	target := &runtimeTarget{Config: config, Client: server.Client(), PreconditionsBound: true, ExpectedBefore: map[string]map[string]any{}, Commands: commands}
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	if err := executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result); err != nil {
		t.Fatal(err)
	}
	policies := fake.objects[path]
	if len(policies) != 3 || scalarString(policies[0]["name"]) != "A" || scalarString(policies[1]["name"]) != "B" || scalarString(policies[2]["name"]) != "policyweb-anchor" {
		t.Fatalf("policy order = %#v", policies)
	}
}

func TestFortiGateExistingPolicyRevalidatesAgainstReviewedPreparedNeighbour(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/policy"
	baseE := map[string]any{"policyid": 10, "name": "E", "status": "enable", "action": "accept", "comments": "before"}
	fake.objects[path] = []map[string]any{cloneAnyMap(baseE), {"policyid": 999, "name": "policyweb-anchor", "action": "deny"}}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	newPolicy := map[string]any{"name": "N", "status": "enable", "action": "accept", "comments": "new"}
	newCreate := cloneAnyMap(newPolicy)
	newCreate["status"], newCreate["policyid"] = "disable", 0
	desiredE := map[string]any{"name": "E", "status": "enable", "action": "accept", "comments": "after"}
	commands := []deploymentCommand{
		{Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: "UPSERT", Path: path, InsertBefore: "policyweb-anchor", Payload: newPolicy, CreatePayload: newCreate, ActivatePayload: map[string]any{"status": "enable"}},
		{Target: "edge", Context: "prod", Sequence: 2, Kind: "policy", Method: "UPSERT", Path: path, InsertBefore: "N", Payload: desiredE, CreatePayload: map[string]any{"policyid": 0, "name": "E", "status": "disable", "action": "accept", "comments": "after"}, ActivatePayload: map[string]any{"status": "enable"}},
	}
	baseWithoutID := cloneAnyMap(baseE)
	delete(baseWithoutID, "policyid")
	target := &runtimeTarget{
		Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true,
		ExpectedBefore: map[string]map[string]any{path + "\x00E": baseWithoutID}, Commands: commands,
	}
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	if err := executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result); err != nil {
		t.Fatalf("reviewed E -> N -> anchor PREPARE chain failed: %v", err)
	}
	policies := fake.objects[path]
	if len(policies) != 3 || scalarString(policies[0]["name"]) != "E" || scalarString(policies[1]["name"]) != "N" || scalarString(policies[2]["name"]) != "policyweb-anchor" || scalarString(policies[0]["comments"]) != "after" {
		t.Fatalf("reviewed prepared-neighbour order/content = %#v", policies)
	}
}

func TestRollbackRecreatesPoliciesDisabledAndRestoresDenyBeforeAccept(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/policy"
	fake.objects[path] = []map[string]any{
		{"policyid": 101, "name": "new-deny", "status": "enable", "action": "deny"},
		{"policyid": 100, "name": "new-accept", "status": "enable", "action": "accept"},
		{"policyid": 999, "name": "policyweb-anchor", "status": "enable", "action": "deny"},
	}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client()}
	postOrder := []string{"101", "100", "999"}
	deleted := func(sequence, policyID int, name, action, before, after, status string) deploymentSnapshot {
		payload := map[string]any{"name": name, "status": status, "action": action}
		data := cloneAnyMap(payload)
		data["policyid"] = policyID
		return deploymentSnapshot{
			Target: target, Command: deploymentCommand{Target: "edge", Context: "prod", Sequence: sequence, Kind: "policy", Method: "DELETE", Path: path, Payload: payload},
			Existed: true, MKey: strconv.Itoa(policyID), Data: data, Restore: cloneAnyMap(payload), BeforeMKey: before, AfterMKey: after,
			PostObserved: true, PostAbsent: true, PostOrder: append([]string(nil), postOrder...),
		}
	}
	created := func(sequence, policyID int, name, action string) deploymentSnapshot {
		payload := map[string]any{"name": name, "status": "enable", "action": action}
		return deploymentSnapshot{
			Target: target, Command: deploymentCommand{Target: "edge", Context: "prod", Sequence: sequence, Kind: "policy", Method: "UPSERT", Path: path, Payload: payload, CreatePayload: map[string]any{"policyid": 0, "name": name, "status": "disable", "action": action}, ActivatePayload: map[string]any{"status": "enable"}},
			PostObserved: true, PostMKey: strconv.Itoa(policyID), PostState: cloneAnyMap(payload), PostOrder: append([]string(nil), postOrder...),
		}
	}
	snapshots := []deploymentSnapshot{
		deleted(1, 10, "old-deny", "deny", "20", "", "enable"),
		deleted(2, 20, "old-accept", "accept", "30", "10", "enable"),
		deleted(3, 30, "old-disabled-deny", "deny", "999", "20", "disable"),
		created(4, 100, "new-accept", "accept"),
		created(5, 101, "new-deny", "deny"),
	}
	applied := make([]appliedDeploymentStep, len(snapshots))
	for index := range snapshots {
		applied[index] = appliedDeploymentStep{Snapshot: snapshots[index]}
	}
	if errorsFound := rollbackDeployment(context.Background(), applied); len(errorsFound) != 0 {
		t.Fatalf("phased rollback failed: %v", errorsFound)
	}
	names := []string{}
	for _, policy := range fake.objects[path] {
		names = append(names, scalarString(policy["name"]))
	}
	if !sameJSONValue(names, []string{"old-deny", "old-accept", "old-disabled-deny", "policyweb-anchor"}) {
		t.Fatalf("baseline policy order was not restored: %v", names)
	}
	if scalarString(fake.objects[path][2]["status"]) != "disable" {
		t.Fatalf("originally disabled policy was activated: %#v", fake.objects[path][2])
	}
	mutationIndex := func(method, name, status string) int {
		for index, request := range fake.requests {
			if request.Method != method {
				continue
			}
			requestName := scalarString(request.Payload["name"])
			if requestName == "" {
				for _, policy := range snapshots {
					if policy.MKey != "" && strings.HasSuffix(request.Path, "/"+policy.MKey) || policy.PostMKey != "" && strings.HasSuffix(request.Path, "/"+policy.PostMKey) {
						requestName = scalarString(policy.Command.Payload["name"])
					}
				}
			}
			if requestName == name && (status == "" || scalarString(request.Payload["status"]) == status) {
				return index
			}
		}
		return -1
	}
	for _, name := range []string{"old-deny", "old-accept", "old-disabled-deny"} {
		if index := mutationIndex(http.MethodPost, name, "disable"); index < 0 {
			t.Fatalf("%s was not recreated disabled; requests=%#v", name, fake.requests)
		}
	}
	denyEnable := mutationIndex(http.MethodPut, "old-deny", "enable")
	newAcceptDelete := mutationIndex(http.MethodDelete, "new-accept", "")
	acceptEnable := mutationIndex(http.MethodPut, "old-accept", "enable")
	newDenyDelete := mutationIndex(http.MethodDelete, "new-deny", "")
	if denyEnable < 0 || newAcceptDelete < denyEnable || acceptEnable < newAcceptDelete || newDenyDelete < acceptEnable {
		t.Fatalf("unsafe rollback mutation order deny=%d newAcceptDelete=%d accept=%d newDenyDelete=%d requests=%#v", denyEnable, newAcceptDelete, acceptEnable, newDenyDelete, fake.requests)
	}
	if mutationIndex(http.MethodPut, "old-disabled-deny", "enable") >= 0 {
		t.Fatalf("originally disabled baseline DENY was activated: %#v", fake.requests)
	}
}

func TestRollbackReconciliationFailurePreventsAllCompensationWrites(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/address"
	desiredA := map[string]any{"name": "A", "subnet": "10.0.0.2 255.255.255.255"}
	desiredB := map[string]any{"name": "B", "subnet": "10.0.1.2 255.255.255.255"}
	fake.objects[path] = []map[string]any{
		cloneAnyMap(desiredA),
		{"name": "B", "subnet": "203.0.113.1 255.255.255.255"},
	}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client()}
	snapshot := func(sequence int, name string, desired map[string]any, originalSubnet string) deploymentSnapshot {
		original := map[string]any{"name": name, "subnet": originalSubnet}
		return deploymentSnapshot{
			Target: target,
			Command: deploymentCommand{
				Target: "edge", Context: "prod", Sequence: sequence, Kind: "address", Method: "UPSERT", Path: path,
				Payload: cloneAnyMap(desired),
			},
			Existed: true, MKey: name, Data: cloneAnyMap(original), Restore: cloneAnyMap(original),
		}
	}
	applied := []appliedDeploymentStep{
		{Snapshot: snapshot(1, "A", desiredA, "10.0.0.1 255.255.255.255")},
		{Snapshot: snapshot(2, "B", desiredB, "10.0.1.1 255.255.255.255")},
	}
	if errorsFound := rollbackDeployment(context.Background(), applied); len(errorsFound) == 0 {
		t.Fatal("rollback reconciliation conflict was not reported")
	}
	if subnet := scalarString(fake.objects[path][0]["subnet"]); subnet != scalarString(desiredA["subnet"]) {
		t.Fatalf("successfully reconciled object was nevertheless compensated: subnet=%q", subnet)
	}
	for _, request := range fake.requests {
		if request.Method != http.MethodGet {
			t.Fatalf("rollback wrote after incomplete reconciliation: %#v", fake.requests)
		}
	}
}

func TestRollbackRejectsRecreatedPolicyWithDifferentPolicyID(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	fake.postedPolicyID = 77
	path := "/api/v2/cmdb/firewall/policy"
	fake.objects[path] = []map[string]any{{"policyid": 999, "name": "policyweb-anchor", "status": "enable", "action": "deny"}}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client()}
	original := map[string]any{"policyid": 10, "name": "old-accept", "status": "enable", "action": "accept"}
	restore := map[string]any{"name": "old-accept", "status": "enable", "action": "accept"}
	snapshot := deploymentSnapshot{
		Target: target,
		Command: deploymentCommand{
			Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: "DELETE", Path: path,
			Payload: cloneAnyMap(restore),
		},
		Existed: true, MKey: "10", Data: cloneAnyMap(original), Restore: cloneAnyMap(restore), BeforeMKey: "999",
		PostObserved: true, PostAbsent: true, PostOrder: []string{"999"},
	}
	errorsFound := rollbackDeployment(context.Background(), []appliedDeploymentStep{{Snapshot: snapshot}})
	if len(errorsFound) == 0 || !strings.Contains(strings.Join(errorsFound, " "), "policyid") {
		t.Fatalf("reassigned rollback policyid was not rejected: %v", errorsFound)
	}
	for _, request := range fake.requests {
		if request.Method == http.MethodPut && strings.HasSuffix(request.Path, "/77") {
			t.Fatalf("policy with reassigned identity was activated or positioned: %#v", fake.requests)
		}
	}
	for _, policy := range fake.objects[path] {
		if scalarString(policy["name"]) == "old-accept" && scalarString(policy["status"]) != "disable" {
			t.Fatalf("recreated policy with wrong identity is not inert: %#v", policy)
		}
	}
}

func TestFortiGatePolicyOrderAllowsApprovedDeletionBetweenSuccessors(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/policy"
	managed := map[string]any{"policyid": 10, "name": "managed", "action": "accept"}
	removed := map[string]any{"policyid": 20, "name": "removed", "action": "deny"}
	anchor := map[string]any{"policyid": 999, "name": "policyweb-anchor", "action": "deny"}
	fake.objects[path] = []map[string]any{managed, removed, anchor}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	managedPayload := map[string]any{"name": "managed", "action": "accept"}
	createPayload := cloneAnyMap(managedPayload)
	createPayload["policyid"] = 0
	commands := []deploymentCommand{
		{Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: "DELETE", Path: path, Payload: map[string]any{"name": "removed", "action": "deny"}},
		{Target: "edge", Context: "prod", Sequence: 2, Kind: "policy", Method: "UPSERT", Path: path, InsertBefore: "policyweb-anchor", Payload: managedPayload, CreatePayload: createPayload},
	}
	target := &runtimeTarget{
		Config: runtimeTestTarget(t, server), Client: server.Client(), PreconditionsBound: true,
		ExpectedBefore: map[string]map[string]any{path + "\x00managed": managedPayload}, Commands: commands,
	}
	snapshots, err := snapshotDeployment(context.Background(), []*runtimeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	if err := executeDeployment(context.Background(), []*runtimeTarget{target}, snapshots, &result); err != nil {
		t.Fatal(err)
	}
	policies := fake.objects[path]
	if len(policies) != 2 || scalarString(policies[0]["name"]) != "managed" || scalarString(policies[1]["name"]) != "policyweb-anchor" {
		t.Fatalf("policy order after approved deletion = %#v", policies)
	}
}

func TestRollbackUsesServerContextAfterRequestCancellation(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/address"
	original := map[string]any{"name": "first", "subnet": "10.0.0.1 255.255.255.255"}
	fake.objects[path] = []map[string]any{cloneAnyMap(original)}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client()}
	command := deploymentCommand{Target: "edge", Context: "prod", Sequence: 1, Kind: "address", Method: "UPSERT", Path: path, Payload: map[string]any{"name": "first", "subnet": "10.0.0.2 255.255.255.255"}}
	snapshot := deploymentSnapshot{Target: target, Command: command, Existed: true, MKey: "first", Data: cloneAnyMap(original), Restore: cloneAnyMap(original)}
	requestContext, cancel := context.WithCancel(context.Background())
	fake.cancelOnce = cancel
	defer cancel()
	result := deploymentRunResult{Results: []deploymentCommandResult{}, RollbackErrors: []string{}}
	if err := executeDeployment(requestContext, []*runtimeTarget{target}, []deploymentSnapshot{snapshot}, &result); err == nil {
		t.Fatal("canceled deployment unexpectedly succeeded")
	}
	if !result.RollbackAttempted || !result.RollbackSucceeded {
		t.Fatalf("fresh rollback context was not used: %#v", result)
	}
}

func TestDriftDetectsPolicyBehindApprovedAnchor(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	fake := newFakeFortiGate("v7.4.12")
	path := "/api/v2/cmdb/firewall/policy"
	fake.objects[path] = []map[string]any{
		{"policyid": 10, "name": "policyweb-anchor", "action": "deny"},
		{"policyid": 20, "name": "managed-policy", "action": "accept"},
	}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client()}
	command := deploymentCommand{
		Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: "UPSERT", Path: path,
		InsertBefore: "policyweb-anchor", Payload: map[string]any{"name": "managed-policy", "action": "accept"},
		CreatePayload: map[string]any{"policyid": 0, "name": "managed-policy", "action": "accept"},
	}
	record := inspectDrift(context.Background(), target, command)
	if record.Status != "changed" || len(record.Differences) == 0 || !strings.Contains(record.Differences[0], "approved successor") {
		t.Fatalf("policy-order drift was not reported: %#v", record)
	}
	fake.objects[path][0], fake.objects[path][1] = fake.objects[path][1], fake.objects[path][0]
	record = inspectDrift(context.Background(), target, command)
	if record.Status != "in_sync" {
		t.Fatalf("correct policy order reported as drift: %#v", record)
	}
}

func TestDriftDetectsDenyPolicyIdentityAndAdvancedMatchRestrictions(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	rule := editableRule{
		Action: "deny", PolicyName: "deny-unqualified", PolicyComment: "deny all approved L3/L4 matches",
		Sources: []string{"source"}, Destinations: []string{"destination"},
	}
	command := deploymentPolicyCommand(FortinetTarget{Name: "edge", Type: "fortigate", VDOM: "prod"}, "prod", 1, "ipv4", rule, "PW_SVC_TEST", "port1", "port2")

	tests := []struct {
		name  string
		field string
		value any
	}{
		{name: "stale user group", field: "groups", value: []any{map[string]any{"name": "old-ldap-group"}}},
		{name: "stale FSSO group", field: "fsso-groups", value: []any{map[string]any{"name": "old-fsso-group"}}},
		{name: "TOS mask", field: "tos-mask", value: "0xff"},
		{name: "SGT selector", field: "sgt-check", value: "enable"},
		{name: "ZTNA selector", field: "ztna-status", value: "enable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeFortiGate("v7.4.12")
			actual := cloneAnyMap(command.Payload)
			actual[tt.field] = tt.value
			actual["policyid"] = 10
			fake.objects[command.Path] = []map[string]any{actual}
			server := httptest.NewTLSServer(fake)
			defer server.Close()
			target := &runtimeTarget{Config: runtimeTestTarget(t, server), Client: server.Client()}
			record := inspectDrift(context.Background(), target, command)
			if record.Status != "changed" || !strings.Contains(strings.Join(record.Differences, " "), tt.field) {
				t.Fatalf("%s was not reported as policy drift: %#v", tt.field, record)
			}
		})
	}
}

func TestFortiGateDifferencesTreatsMissingEmptyOppositeFamilyAsEmpty(t *testing.T) {
	expected := map[string]any{
		"name": "managed-v4", "srcaddr": []any{map[string]any{"name": "v4-source"}},
		"srcaddr6": []any{}, "dstaddr6": []any{},
	}
	actual := map[string]any{"name": "managed-v4", "srcaddr": []any{map[string]any{"name": "v4-source"}}}
	if differences := fortiGateDifferences(expected, actual); len(differences) != 0 {
		t.Fatalf("absent empty opposite-family fields reported as drift: %#v", differences)
	}
	actual["srcaddr6"], actual["dstaddr6"] = nil, nil
	if differences := fortiGateDifferences(expected, actual); len(differences) != 0 {
		t.Fatalf("null empty opposite-family fields reported as drift: %#v", differences)
	}
	actual["srcaddr6"] = []any{map[string]any{"name": "stale-v6-source"}}
	if differences := fortiGateDifferences(expected, actual); len(differences) == 0 || !strings.Contains(strings.Join(differences, " "), "srcaddr6") {
		t.Fatalf("stale opposite-family match was not reported: %#v", differences)
	}
}

func TestEndpointIdentityChangeInvalidatesApprovedPlan(t *testing.T) {
	p := deployableNamingPolicy(t)
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge-one.example", VDOM: "root", TokenEnv: "FGT_RUNTIME_TOKEN",
		TargetContexts: []string{"prod"}, ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
		PolicyInsertBefore: "policyweb-anchor", AllowDeploy: true,
	}
	plan := generateDeploymentPlanWithBase(nil, p, []FortinetTarget{target})
	if !plan.Ready {
		t.Fatalf("test plan is not ready: %#v", plan.Errors)
	}
	changed := target
	changed.URL = "https://edge-two.example"
	s := &state{config: &config{FortinetTargets: []FortinetTarget{changed}}}
	_, err := s.recomputePublishedDeploymentPlan(&publishedDeployment{Policy: p, Plan: plan})
	if err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("endpoint change did not invalidate plan: %v", err)
	}
}

func TestDeploymentTopologyTransitionRequiresExplicitMigration(t *testing.T) {
	base := deploymentPlan{Targets: []deploymentTargetSummary{{Name: "edge", Type: "fortigate", Context: "prod", Scope: "root", EndpointID: "endpoint-a", Executable: true}}}
	if err := validateDeploymentTopologyTransition(base, base); err != nil {
		t.Fatal(err)
	}
	tests := map[string]deploymentPlan{
		"target removed":  {Targets: []deploymentTargetSummary{}},
		"preview change":  {Targets: []deploymentTargetSummary{{Name: "edge", Type: "fortigate", Context: "prod", Scope: "root", EndpointID: "endpoint-a", Executable: false}}},
		"scope change":    {Targets: []deploymentTargetSummary{{Name: "edge", Type: "fortigate", Context: "prod", Scope: "other", EndpointID: "endpoint-a", Executable: true}}},
		"endpoint change": {Targets: []deploymentTargetSummary{{Name: "edge", Type: "fortigate", Context: "prod", Scope: "root", EndpointID: "endpoint-b", Executable: true}}},
		"target added": {Targets: []deploymentTargetSummary{
			{Name: "edge", Type: "fortigate", Context: "prod", Scope: "root", EndpointID: "endpoint-a", Executable: true},
			{Name: "edge-2", Type: "fortigate", Context: "prod", Scope: "root", EndpointID: "endpoint-c", Executable: true},
		}},
	}
	for name, next := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateDeploymentTopologyTransition(base, next); err == nil || !strings.Contains(err.Error(), "migration") {
				t.Fatalf("topology transition error = %v", err)
			}
		})
	}
}

func TestDeploymentTopologyBlocksContextMoveBetweenExistingTargets(t *testing.T) {
	summary := func(name, context, endpoint string) deploymentTargetSummary {
		return deploymentTargetSummary{Name: name, Type: "fortigate", Context: context, Scope: "root", EndpointID: endpoint, Executable: true}
	}
	previous := deploymentPlan{Targets: []deploymentTargetSummary{
		summary("A", "prod", "endpoint-a"), summary("A", "x", "endpoint-a"), summary("B", "y", "endpoint-b"),
	}}
	next := deploymentPlan{Targets: []deploymentTargetSummary{
		summary("A", "x", "endpoint-a"), summary("B", "prod", "endpoint-b"), summary("B", "y", "endpoint-b"),
	}}
	if err := validateDeploymentTopologyTransition(previous, next); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("context move topology error = %v", err)
	}
}

func TestRuntimePreconditionsUseImmutableBasePlan(t *testing.T) {
	path := "/api/v2/cmdb/firewall/policy"
	basePayload := map[string]any{"name": "managed", "srcintf": []any{map[string]any{"name": "old-port"}}, "action": "accept"}
	basePlan := deploymentPlan{
		Targets:  []deploymentTargetSummary{{Name: "edge", Type: "fortigate", Context: "prod", Scope: "root", EndpointID: "bound", Executable: true}},
		Commands: []deploymentCommand{{Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: "UPSERT", Path: path, Payload: basePayload}},
	}
	nextPlan := deploymentPlan{
		Targets:  []deploymentTargetSummary{{Name: "edge", Type: "fortigate", Context: "prod", Scope: "root", EndpointID: "bound", Executable: true}},
		Commands: []deploymentCommand{{Target: "edge", Context: "prod", Sequence: 1, Kind: "policy", Method: "UPSERT", Path: path, Payload: map[string]any{"name": "managed", "srcintf": []any{map[string]any{"name": "new-port"}}, "action": "accept"}}},
	}
	target := &runtimeTarget{Config: FortinetTarget{Name: "edge"}}
	s := &state{config: &config{FortinetTargets: []FortinetTarget{{Name: "edge", ZoneInterfaces: map[string]string{"zone": "new-port"}}}}}
	published := &publishedDeployment{Previous: &editablePolicy{}, PreviousPlan: &basePlan, Plan: nextPlan}
	if err := s.bindRuntimePreconditions([]*runtimeTarget{target}, published); err != nil {
		t.Fatal(err)
	}
	got := target.ExpectedBefore[path+"\x00managed"]
	if !sameJSONValue(got, basePayload) {
		t.Fatalf("runtime baseline = %#v; want immutable stored payload %#v", got, basePayload)
	}
}

func TestLegacyFullReconciliationUsesEmptyRuntimeBaseline(t *testing.T) {
	path := "/api/v2/cmdb/firewall/address"
	plan := deploymentPlan{Commands: []deploymentCommand{{Target: "edge", Context: "prod", Sequence: 1, Kind: "address", Method: "UPSERT", Path: path, Payload: map[string]any{"name": "new", "subnet": "10.0.0.1 255.255.255.255"}}}}
	target := &runtimeTarget{Config: FortinetTarget{Name: "edge"}}
	s := &state{}
	published := &publishedDeployment{Previous: &editablePolicy{}, PreviousPlan: nil, Plan: plan}
	if err := s.bindRuntimePreconditions([]*runtimeTarget{target}, published); err != nil {
		t.Fatal(err)
	}
	if !target.PreconditionsBound || len(target.ExpectedBefore) != 0 {
		t.Fatalf("legacy full reconciliation baseline = %#v", target)
	}
	published.Plan.Commands = append(published.Plan.Commands, deploymentCommand{Target: "edge", Context: "prod", Sequence: 2, Kind: "policy", Method: "DELETE", Path: "/api/v2/cmdb/firewall/policy", Payload: map[string]any{"name": "old"}})
	if err := s.bindRuntimePreconditions([]*runtimeTarget{{Config: FortinetTarget{Name: "edge"}}}, published); err == nil || !strings.Contains(err.Error(), "must not contain DELETE") {
		t.Fatalf("legacy DELETE baseline error = %v", err)
	}
}

func TestAdminDeployPublishedRevisionAndProtocol(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "runtime-secret")
	t.Setenv(fortiGateReadOnlyEnv, "false")
	fake := newFakeFortiGate("v7.4.12")
	fake.objects["/api/v2/cmdb/firewall/policy"] = []map[string]any{{"policyid": 999, "name": "policyweb-anchor", "action": "deny"}}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	target := runtimeTestTarget(t, server)
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	s := &state{config: &config{NetspocData: dataDir, UserDir: filepath.Join(root, "users"), FortinetTargets: []FortinetTarget{target}}, cache: newCache(dataDir, 8)}
	p := deployableNamingPolicy(t)
	p.Users = []editableUser{{Email: "admin@example.net", Role: "admin", Active: true}}
	seedPolicyTestAccounts(t, s, p.Users...)
	plan := generateDeploymentPlanWithBase(nil, p, s.config.FortinetTargets)
	if !plan.Ready {
		t.Fatalf("test plan is not ready: %#v", plan.Errors)
	}
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.storePolicyDraft(db, p); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	version := "p-runtime-test"
	validation := map[string]any{"valid": true, "plan_hash": plan.Hash}
	if err := s.storeRevisionWithMetadata(version, "", p, []map[string]string{}, revisionMetadata{CreatedBy: "editor@example.net", DeploymentPlan: plan, Validation: validation}); err != nil {
		t.Fatal(err)
	}
	if err := s.storePublicationBy(version, p, "reviewer@example.net", version); err != nil {
		t.Fatal(err)
	}
	if err := s.markRevisionPublishedBy(version, "reviewer@example.net"); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(deployRequest{PolicyID: version, PlanHash: plan.Hash, Confirm: true})
	request := httptest.NewRequest(http.MethodPost, "/admin/deploy", bytes.NewReader(body))
	session := newSession()
	session.Put("email", "admin@example.net")
	request = request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, session))
	response := httptest.NewRecorder()
	s.adminDeploy(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("deploy status = %d; body=%s", response.Code, response.Body.String())
	}
	var decoded struct {
		Success    bool                `json:"success"`
		Deployment deploymentRunResult `json:"deployment"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Success || decoded.Deployment.Status != "succeeded" || len(decoded.Deployment.Systems) != 1 || decoded.Deployment.Systems[0].Build != strconv.Itoa(fake.build) {
		t.Fatalf("deployment response = %#v", decoded)
	}
	db, err = s.deploymentDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var status, systems string
	if err := db.QueryRow(`SELECT status, systems FROM policy_deployment_log WHERE deployment_id=?`, decoded.Deployment.DeploymentID).Scan(&status, &systems); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" || !strings.Contains(systems, `"build":"2902"`) {
		t.Fatalf("deployment protocol status=%q systems=%s", status, systems)
	}
	policies := fake.objects["/api/v2/cmdb/firewall/policy"]
	if len(policies) != 2 || scalarString(policies[1]["name"]) != "policyweb-anchor" || scalarString(policies[0]["policyid"]) == "0" {
		t.Fatalf("new policy was not allocated and placed before anchor: %#v", policies)
	}

	// The operational kill switch blocks before a second protocol or any
	// device request is started, without changing the approved plan hash.
	requestsBefore := len(fake.requests)
	s.config.FortiGateReadOnly = true
	body, _ = json.Marshal(deployRequest{PolicyID: version, PlanHash: plan.Hash, Confirm: true})
	request = httptest.NewRequest(http.MethodPost, "/admin/deploy", bytes.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, session))
	response = httptest.NewRecorder()
	s.adminDeploy(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), errFortiGateReadOnly.Error()) {
		t.Fatalf("read-only deploy status=%d body=%s", response.Code, response.Body.String())
	}
	if len(fake.requests) != requestsBefore {
		t.Fatalf("read-only deployment contacted FortiGate: before=%d after=%d", requestsBefore, len(fake.requests))
	}
	var deploymentCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_deployment_log`).Scan(&deploymentCount); err != nil {
		t.Fatal(err)
	}
	if deploymentCount != 1 {
		t.Fatalf("deployment protocols after read-only block = %d, want 1", deploymentCount)
	}
	s.config.FortiGateReadOnly = false

	// A historical delta is never a rollback mechanism. Once another revision
	// is published, the old revision must be rejected before any device call.
	newVersion := "p-runtime-test-newer"
	newPlan := generateDeploymentPlanWithBase(p, p, s.config.FortinetTargets)
	if err := s.storeRevisionWithMetadata(newVersion, version, p, []map[string]string{}, revisionMetadata{CreatedBy: "editor@example.net", DeploymentPlan: newPlan, Validation: map[string]any{"valid": true, "plan_hash": newPlan.Hash}}); err != nil {
		t.Fatal(err)
	}
	if err := s.storePublicationBy(newVersion, p, "reviewer@example.net", newVersion); err != nil {
		t.Fatal(err)
	}
	if err := s.markRevisionPublishedBy(newVersion, "reviewer@example.net"); err != nil {
		t.Fatal(err)
	}
	requestsBefore = len(fake.requests)
	body, _ = json.Marshal(deployRequest{PolicyID: version, PlanHash: plan.Hash, Confirm: true})
	request = httptest.NewRequest(http.MethodPost, "/admin/deploy", bytes.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, session))
	response = httptest.NewRecorder()
	s.adminDeploy(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "latest published revision") {
		t.Fatalf("historical deploy status=%d body=%s", response.Code, response.Body.String())
	}
	if len(fake.requests) != requestsBefore {
		t.Fatalf("historical deployment contacted FortiGate: before=%d after=%d", requestsBefore, len(fake.requests))
	}
}

func TestPublicationBlockedWhileDeploymentLockIsActive(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	s := &state{config: &config{NetspocData: dataDir}, cache: newCache(dataDir, 2)}
	db, err := s.deploymentDB()
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO policy_deployment_lock(id, deployment_id, acquired_at) VALUES(1, ?, ?)`, "d-active", time.Now().UTC().Format(time.RFC3339Nano))
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	p := deployableNamingPolicy(t)
	err = s.storePublicationBy("p-blocked", p, "reviewer@example.net", "p-blocked")
	if !errors.Is(err, errDeploymentRunning) {
		t.Fatalf("publication lock error = %v", err)
	}
	if _, err := s.acquirePublicationLock("p-blocked"); !errors.Is(err, errDeploymentRunning) {
		t.Fatalf("publication pre-mutation lock error = %v", err)
	}
	db, err = s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_publication WHERE version='p-blocked'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("publication was committed during an active deployment")
	}

	// The inverse direction uses the same row: a publication owns the lock
	// across all filesystem work, may finalize its own database row, and blocks
	// deployment start until it releases the operation lock.
	s.releaseDeploymentLock("d-active")
	publicationLock, err := s.acquirePublicationLock("p-owned")
	if err != nil {
		t.Fatal(err)
	}
	defer s.releaseDeploymentLock(publicationLock)
	if err := s.storePublicationBy("p-owned", p, "reviewer@example.net", "p-owned"); err != nil {
		t.Fatalf("publication could not finalize under its own lock: %v", err)
	}
	run := deploymentRunResult{
		DeploymentID: "d-blocked", PolicyID: "p-owned", PlanHash: "reviewed", Actor: "admin@example.net",
		Targets: []string{"edge"}, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := s.startDeploymentLog(&run, "edge"); !errors.Is(err, errDeploymentRunning) {
		t.Fatalf("deployment start during publication error = %v", err)
	}
}

func TestPolicyDBCreatesConfiguredDataDirectory(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "missing", "policy-data")
	s := &state{config: &config{NetspocData: dataDir}}
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("configured policy data path is not a directory: %v", info.Mode())
	}
}

func TestNextPublicationRequiresSuccessfulDeploymentOfCurrentRevision(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	target := FortinetTarget{
		Name: "edge", Type: "fortigate", URL: "https://edge.example.test", VDOM: "root", TokenEnv: "FGT_TOKEN",
		TargetContexts: []string{"prod"}, ZoneInterfaces: map[string]string{"GDMZ": "port2", "IDMZ": "port3"},
		PolicyInsertBefore: "policyweb-anchor", AllowDeploy: true,
	}
	s := &state{config: &config{NetspocData: dataDir, FortinetTargets: []FortinetTarget{target}}}
	p := deployableNamingPolicy(t)
	plan := generateDeploymentPlanWithBase(nil, p, s.config.FortinetTargets)
	if !plan.Ready {
		t.Fatalf("test deployment plan is not ready: %#v", plan.Errors)
	}
	version := "p-must-deploy"
	if err := s.storeRevisionWithMetadata(version, "", p, nil, revisionMetadata{DeploymentPlan: plan}); err != nil {
		t.Fatal(err)
	}
	if err := s.finalizePublication(version, p, "reviewer@example.net", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.acquirePublicationLock("p-next"); !errors.Is(err, errPublicationRequiresDeployment) {
		t.Fatalf("undeployed publication gate error = %v", err)
	}
	db, err := s.deploymentDB()
	if err != nil {
		t.Fatal(err)
	}
	targetsJSON, _ := json.Marshal([]string{"edge"})
	baseTime := time.Now().UTC()
	_, err = db.Exec(`INSERT INTO policy_deployment_log(deployment_id, revision, plan_hash, actor, requested_target, targets, status, commands_total, started_at, finished_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, "d-success", version, plan.Hash, "deployer@example.net", "edge", string(targetsJSON), "succeeded", len(plan.Commands), baseTime.Format(time.RFC3339Nano), baseTime.Format(time.RFC3339Nano))
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	lock, err := s.acquirePublicationLock("p-next")
	if err != nil {
		t.Fatalf("publication remained blocked after complete deployment: %v", err)
	}
	s.releaseDeploymentLock(lock)

	// A later failed attempt invalidates the earlier success as a trustworthy
	// baseline until the same target completes another successful run.
	db, err = s.deploymentDB()
	if err != nil {
		t.Fatal(err)
	}
	later := baseTime.Add(time.Second)
	_, err = db.Exec(`INSERT INTO policy_deployment_log(deployment_id, revision, plan_hash, actor, requested_target, targets, status, commands_total, started_at, finished_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, "d-later-failed", version, plan.Hash, "deployer@example.net", "edge", string(targetsJSON), "failed", len(plan.Commands), later.Format(time.RFC3339Nano), later.Format(time.RFC3339Nano))
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.acquirePublicationLock("p-after-failure"); !errors.Is(err, errPublicationRequiresDeployment) {
		t.Fatalf("later failed deployment did not invalidate baseline: %v", err)
	}
}

func TestPublishFinalizeFailureRestoresDraftCurrentAndLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows test runners require elevated symlink privileges")
	}
	root := t.TempDir()
	dataDir := filepath.Join(root, "policies")
	if err := os.MkdirAll(filepath.Join(dataDir, "p-old"), 0o750); err != nil {
		t.Fatal(err)
	}
	s := &state{config: &config{NetspocData: dataDir, UserDir: filepath.Join(root, "users")}, cache: newCache(dataDir, 2)}
	oldPolicy := deployableNamingPolicy(t)
	if err := s.saveDraft(oldPolicy); err != nil {
		t.Fatal(err)
	}
	expectedDraft := cloneEditablePolicy(t, oldPolicy)
	normalizeEditablePolicy(expectedDraft)
	if err := os.Symlink("p-old", filepath.Join(dataDir, "current")); err != nil {
		t.Fatal(err)
	}
	newPolicy := cloneEditablePolicy(t, oldPolicy)
	newPolicy.Name = "changed-policy"

	// A reviewer actor requires a matching pending revision. Deliberately omit
	// it so finalizePublication fails after draft/current were switched.
	err := s.publishPolicyVersionBy(newPolicy, "p-finalize-fails", "reviewer@example.net")
	if err == nil || !strings.Contains(err.Error(), "revision is not pending") {
		t.Fatalf("publish finalization error = %v", err)
	}
	currentTarget, err := os.Readlink(filepath.Join(dataDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if currentTarget != "p-old" {
		t.Fatalf("current target = %q, want p-old", currentTarget)
	}
	restoredDraft, err := s.loadPolicyDraft()
	if err != nil {
		t.Fatal(err)
	}
	if !samePolicyDocument(restoredDraft, expectedDraft) {
		t.Fatal("draft was not restored after publication finalization failure")
	}
	if _, err := s.loadPublication("p-finalize-fails"); err == nil {
		t.Fatal("failed publication was committed")
	}
	db, err := s.deploymentDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var locks int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_deployment_lock`).Scan(&locks); err != nil {
		t.Fatal(err)
	}
	if locks != 0 {
		t.Fatalf("publication lock was not released: %d rows", locks)
	}
}

func cloneEditablePolicy(t testing.TB, policy *editablePolicy) *editablePolicy {
	t.Helper()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var result editablePolicy
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return &result
}
