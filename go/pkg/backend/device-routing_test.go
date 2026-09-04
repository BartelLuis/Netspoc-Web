package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func routeForTest(network, gateway, iface string, vrf int) deviceRoute {
	prefix := netip.MustParsePrefix(network)
	return deviceRoute{Network: prefix.String(), Gateway: gateway, Interface: iface, VRF: &vrf, prefix: prefix}
}

func TestParseRoutingNetwork(t *testing.T) {
	tests := map[string]string{
		"10.1.2.3":               "10.1.2.3/32",
		"10.1.2.99/24":           "10.1.2.0/24",
		"10.1.2.0/255.255.255.0": "10.1.2.0/24",
		"10.1.2.0 255.255.255.0": "10.1.2.0/24",
		"2001:db8::10":           "2001:db8::10/128",
		"2001:db8::1234/64":      "2001:db8::/64",
	}
	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			actual, err := parseRoutingNetwork(input)
			if err != nil || actual.String() != expected {
				t.Fatalf("parseRoutingNetwork(%q) = %q, %v; want %q", input, actual, err, expected)
			}
		})
	}
	for _, input := range []string{"", "host.example", "10.1.2.0/255.0.255.0", "10.1.2.999/24", "::ffff:192.0.2.0/80"} {
		if _, err := parseRoutingNetwork(input); err == nil {
			t.Fatalf("parseRoutingNetwork(%q) succeeded", input)
		}
	}
	mapped, err := parseRoutingNetwork("::ffff:192.0.2.0/120")
	if err != nil || mapped.String() != "192.0.2.0/24" {
		t.Fatalf("mapped IPv4 prefix = %q, %v", mapped, err)
	}
}

func TestParseRequestedVRF(t *testing.T) {
	for input, expected := range map[string]int{"": 0, "0": 0, "7": 7, "251": 251} {
		var values []string
		if input != "" {
			values = []string{input}
		}
		actual, err := parseRequestedVRF(values)
		if err != nil || actual != expected {
			t.Fatalf("parseRequestedVRF(%q) = %d, %v; want %d", input, actual, err, expected)
		}
	}
	for _, values := range [][]string{{""}, {"-1"}, {"1", "2"}, {"252"}, {"2147483648"}, {"vrf"}} {
		if _, err := parseRequestedVRF(values); err == nil {
			t.Fatalf("parseRequestedVRF(%q) succeeded", values)
		}
	}
}

func TestDecodeDeviceRouteKeepsFortiOSRoutingFieldsSeparate(t *testing.T) {
	route, err := decodeDeviceRoute(map[string]any{
		"ip_mask": "10.0.0.0/8", "gateway": "192.0.2.1", "interface": "port2",
		"type": "static", "distance": json.Number("10"), "metric": json.Number("20"),
		"priority": json.Number("30"), "vrf": json.Number("4"),
	})
	if err != nil || route.Network != "10.0.0.0/8" || route.Gateway != "192.0.2.1" || route.Interface != "port2" || route.Protocol != "static" {
		t.Fatalf("decoded route = %#v, err=%v", route, err)
	}
	if route.Distance == nil || *route.Distance != 10 || route.Metric == nil || *route.Metric != 20 || route.Priority == nil || *route.Priority != 30 || route.VRF == nil || *route.VRF != 4 {
		t.Fatalf("numeric route fields were lost or conflated: %#v", route)
	}
}

func TestDecodeDeviceRouteRequiresUsableForwardingData(t *testing.T) {
	for name, row := range map[string]map[string]any{
		"missing forwarding": {"ip_mask": "10.0.0.0/8", "type": "static"},
		"invalid gateway":    {"ip_mask": "10.0.0.0/8", "gateway": "router.example", "interface": "port1"},
		"gateway family":     {"ip_mask": "10.0.0.0/8", "gateway": "2001:db8::1", "interface": "port1"},
		"version mismatch":   {"ip_mask": "10.0.0.0/8", "interface": "port1", "ip_version": 6},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeDeviceRoute(row); err == nil {
				t.Fatalf("route %#v was accepted", row)
			}
		})
	}
	connected, err := decodeDeviceRoute(map[string]any{"ip_mask": "10.0.0.0/8", "interface": "port1", "type": "connected", "ip_version": 4})
	if err != nil || connected.Interface != "port1" || connected.Blackhole {
		t.Fatalf("connected route = %#v, %v", connected, err)
	}
	blackhole, err := decodeDeviceRoute(map[string]any{"ip_mask": "203.0.113.0/24", "blackhole": true, "type": "static"})
	if err != nil || !blackhole.Blackhole {
		t.Fatalf("blackhole route = %#v, %v", blackhole, err)
	}
}

func TestEffectiveDeviceRoutesUsesLPMPartitionsAndPreservesECMP(t *testing.T) {
	routes := []deviceRoute{
		routeForTest("0.0.0.0/0", "192.0.2.1", "wan", 0),
		routeForTest("10.0.0.0/8", "192.0.2.2", "core", 0),
		routeForTest("10.1.0.0/25", "192.0.2.3", "left-a", 0),
		routeForTest("10.1.0.0/25", "192.0.2.4", "left-b", 0),
		routeForTest("10.1.0.128/25", "192.0.2.5", "right", 0),
		routeForTest("10.1.0.0/24", "192.0.2.6", "other-vrf", 7),
	}
	matches := effectiveDeviceRoutes(routes, netip.MustParsePrefix("10.1.0.0/24"), 0)
	got := make([]string, 0, len(matches))
	for _, route := range matches {
		got = append(got, route.Network+"@"+route.Interface+"#"+string(rune(deviceRouteVRF(route)+'0')))
	}
	want := []string{
		"10.1.0.0/25@left-a#0", "10.1.0.0/25@left-b#0", "10.1.0.128/25@right#0",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("effective routes = %v, want %v", got, want)
	}
	if !hasMultipathRoutes(matches) {
		t.Fatal("multipath alternatives were not detected")
	}
	if hasECMPRoutes(matches) {
		t.Fatal("multipath without cost evidence was incorrectly called ECMP")
	}
	distance, metric, priority := 10, 20, 30
	ecmp := []deviceRoute{
		routeForTest("10.1.0.0/24", "192.0.2.1", "port1", 0),
		routeForTest("10.1.0.0/24", "192.0.2.2", "port2", 0),
	}
	for index := range ecmp {
		ecmp[index].Protocol, ecmp[index].Distance, ecmp[index].Metric, ecmp[index].Priority = "static", &distance, &metric, &priority
	}
	if !hasECMPRoutes(ecmp) {
		t.Fatal("equal-cost installed alternatives were not recognized as ECMP")
	}

	vrfSeven := effectiveDeviceRoutes(routes, netip.MustParsePrefix("10.1.0.0/24"), 7)
	if len(vrfSeven) != 1 || vrfSeven[0].Interface != "other-vrf" {
		t.Fatalf("VRF filter returned %#v", vrfSeven)
	}

	partial := effectiveDeviceRoutes(routes[:3], netip.MustParsePrefix("10.1.0.0/24"), 0)
	if len(partial) != 2 || partial[0].Network != "10.1.0.0/25" || partial[1].Network != "10.0.0.0/8" {
		t.Fatalf("partial partition routes = %#v", partial)
	}
}

func TestEffectiveDeviceRoutesCoversIPv6AndLargeTables(t *testing.T) {
	ipv6 := []deviceRoute{
		routeForTest("::/0", "2001:db8::1", "fallback", 0),
		routeForTest("2001:db8:1::/65", "2001:db8::2", "left", 0),
		routeForTest("2001:db8:1:0:8000::/65", "2001:db8::3", "right", 0),
	}
	matches := effectiveDeviceRoutes(ipv6, netip.MustParsePrefix("2001:db8:1::/64"), 0)
	interfaces := map[string]bool{}
	for _, route := range matches {
		interfaces[route.Interface] = true
	}
	if len(matches) != 2 || !interfaces["left"] || !interfaces["right"] {
		t.Fatalf("IPv6 coverage routes = %#v", matches)
	}

	large := make([]deviceRoute, 0, 10001)
	large = append(large, routeForTest("0.0.0.0/0", "192.0.2.1", "fallback", 0))
	for index := 0; index < 10000; index++ {
		address := netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 1})
		prefix := netip.PrefixFrom(address, 32)
		large = append(large, deviceRoute{Network: prefix.String(), Interface: "host", prefix: prefix})
	}
	matches = effectiveDeviceRoutes(large, netip.MustParsePrefix("10.0.0.0/8"), 0)
	if len(matches) != 10001 || matches[len(matches)-1].Interface != "fallback" {
		t.Fatalf("large-table selection returned %d routes", len(matches))
	}
}

func TestDuplicateRoutesAreNotMultipath(t *testing.T) {
	distance := 10
	route := routeForTest("10.0.0.0/8", "192.0.2.1", "port1", 0)
	route.Protocol, route.Distance = "static", &distance
	duplicates := []deviceRoute{route, route}
	if hasMultipathRoutes(duplicates) || hasECMPRoutes(duplicates) {
		t.Fatal("duplicate route rows were reported as multipath")
	}
}

func TestRouteCandidateRequiresOneVRFAndDifferentForwarding(t *testing.T) {
	source, destination := netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("172.16.0.0/24")
	sourceRoute := routeForTest("10.0.0.0/8", "", "inside", 0)
	destinationRoute := routeForTest("172.16.0.0/16", "192.0.2.1", "outside", 0)
	if !routeCandidate([]deviceRoute{sourceRoute}, []deviceRoute{destinationRoute}, source, destination) {
		t.Fatal("different routes in one VRF were not considered a candidate")
	}
	destinationRoute.VRF = new(int)
	*destinationRoute.VRF = 2
	if routeCandidate([]deviceRoute{sourceRoute}, []deviceRoute{destinationRoute}, source, destination) {
		t.Fatal("routes from different VRFs were combined")
	}
	if routeCandidate([]deviceRoute{sourceRoute}, []deviceRoute{sourceRoute}, source, destination) {
		t.Fatal("identical forwarding on both sides was considered a firewall hop")
	}
	blackhole := sourceRoute
	blackhole.Blackhole = true
	blackhole.Interface = ""
	*destinationRoute.VRF = 0
	affected, assessment := assessRouteCandidate([]deviceRoute{blackhole}, []deviceRoute{destinationRoute})
	if !affected || assessment != "drop_candidate" {
		t.Fatalf("blackhole return route = affected %t, assessment %q", affected, assessment)
	}
}

func TestReadFortiGateRoutesUsesBearerVDOMAndExactMonitorEndpoint(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "routing-secret")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v2/monitor/router/ipv4" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("vdom") != "root" || r.Header.Get("Authorization") != "Bearer routing-secret" {
			t.Errorf("query/header = %q %q", r.URL.RawQuery, r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("count") != "-1" {
			t.Errorf("routing table was not requested completely: %q", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "results": []any{
			map[string]any{"ip_mask": "0.0.0.0/0", "gateway": "192.0.2.1", "interface": "wan1", "type": "static"},
			map[string]any{"ip_mask": "10.0.0.0/8", "interface": "port2", "type": "connected"},
		}})
	}))
	defer server.Close()
	target := runtimeTestTarget(t, server)
	routes, err := readFortiGateRoutes(context.Background(), target, 32)
	if err != nil || len(routes) != 2 {
		t.Fatalf("readFortiGateRoutes() = %#v, %v", routes, err)
	}
}

func TestReadFortiGateRoutesUsesIPv6MonitorEndpoint(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "routing-secret")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v2/monitor/router/ipv6" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "results": []any{
			map[string]any{"ip_mask": "::/0", "gateway": "2001:db8::1", "interface": "wan1", "type": "static"},
			map[string]any{"ip_mask": "2001:db8:100::/48", "interface": "port2", "type": "connected"},
		}})
	}))
	defer server.Close()

	routes, err := readFortiGateRoutes(context.Background(), runtimeTestTarget(t, server), 128)
	if err != nil || len(routes) != 2 || !routes[0].prefix.Addr().Is6() || !routes[1].prefix.Addr().Is6() {
		t.Fatalf("readFortiGateRoutes() = %#v, %v", routes, err)
	}
}

func TestFortiGateRoutingMonitorEndpointRejectsNonGETBeforeRequest(t *testing.T) {
	contacted := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacted = true }))
	defer server.Close()
	target := runtimeTestTarget(t, server)
	client, err := target.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fortiGateCall(context.Background(), client, target, http.MethodPost, "/api/v2/monitor/router/ipv4", nil, nil); err == nil {
		t.Fatal("POST to routing monitor endpoint was accepted")
	}
	if contacted {
		t.Fatal("rejected monitor mutation contacted the FortiGate")
	}
}

func TestReadFortiGateRoutesRejectsUnreliableTables(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "routing-secret")
	tests := []any{
		map[string]any{"ip_mask": "10.0.0.0/8"},
		[]any{"not-an-object"},
		[]any{map[string]any{"gateway": "192.0.2.1"}},
		[]any{map[string]any{"ip_mask": "not-a-prefix"}},
		[]any{map[string]any{"ip_mask": "10.0.0.0/8", "distance": "ten"}},
		[]any{map[string]any{"ip_mask": "10.0.0.0/8"}},
		[]any{
			map[string]any{"ip_mask": "0.0.0.0/0", "gateway": "192.0.2.1", "interface": "wan1"},
			map[string]any{"ip_mask": "10.0.0.0/8"},
		},
	}
	for index, results := range tests {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "results": results})
			}))
			defer server.Close()
			if _, err := readFortiGateRoutes(context.Background(), runtimeTestTarget(t, server), 32); err == nil {
				t.Fatal("malformed routing table was accepted")
			}
		})
	}
}

func TestDeviceRoutesHandlerEnforcesRoleBeforeContactingDevices(t *testing.T) {
	s := workflowTestState(t, editableUser{Email: "viewer@example.net", Role: "viewer"})
	policy := validEditablePolicy()
	policy.Users = append(policy.Users, editableUser{Email: "viewer@example.net", Role: "viewer"})
	if err := s.publishPolicy(policy); err != nil {
		t.Fatal(err)
	}
	contacted := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		contacted = true
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "results": []any{}})
	}))
	defer server.Close()
	s.config.FortinetTargets = []FortinetTarget{runtimeTestTarget(t, server)}

	request, _ := ownerRequest(http.MethodGet, "/devices/routes?source=10.0.0.0%2F8&destination=172.16.0.0%2F16", "", "viewer@example.net")
	recorder := httptest.NewRecorder()
	s.getDeviceRoutes(recorder, request)
	if recorder.Code != http.StatusForbidden || contacted {
		t.Fatalf("viewer response=%d contacted=%v body=%s", recorder.Code, contacted, recorder.Body.String())
	}
}

func TestDeviceRoutesHandlerReturnsEffectiveCandidate(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "routing-secret")
	s := workflowTestState(t)
	if err := s.publishPolicy(validEditablePolicy()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "results": []any{
			map[string]any{"ip_mask": "0.0.0.0/0", "gateway": "192.0.2.1", "interface": "wan", "type": "static", "vrf": 0},
			map[string]any{"ip_mask": "10.0.0.0/8", "interface": "inside", "type": "connected", "vrf": 0},
			map[string]any{"ip_mask": "172.16.0.0/16", "gateway": "192.0.2.2", "interface": "outside", "type": "static", "vrf": 0},
			map[string]any{"ip_mask": "10.0.0.0/8", "interface": "vrf7-inside", "type": "connected", "vrf": 7},
			map[string]any{"ip_mask": "172.16.0.0/16", "blackhole": true, "type": "blackhole", "vrf": 7},
		}})
	}))
	defer server.Close()
	s.config.FortinetTargets = []FortinetTarget{runtimeTestTarget(t, server)}

	request, _ := ownerRequest(http.MethodGet, "/devices/routes?source=10.1.0.0%2F16&destination=172.16.1.0%2F24", "", "admin@example.net")
	recorder := httptest.NewRecorder()
	s.getDeviceRoutes(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response=%d cache=%q body=%s", recorder.Code, recorder.Header().Get("Cache-Control"), recorder.Body.String())
	}
	var analysis deviceRouteAnalysis
	if err := json.NewDecoder(recorder.Body).Decode(&analysis); err != nil {
		t.Fatal(err)
	}
	if !analysis.Success || analysis.Status != "complete" || analysis.VRF != 0 || !analysis.Complete || analysis.Partial || len(analysis.AffectedFirewalls) != 1 || analysis.AffectedFirewalls[0] != "edge" {
		t.Fatalf("analysis summary = %#v", analysis)
	}
	if len(analysis.Devices) != 1 || analysis.Devices[0].Assessment != "endpoint_candidate" || !analysis.Devices[0].Affected {
		t.Fatalf("device analysis = %#v", analysis.Devices)
	}
	if len(analysis.Devices[0].SourceRoutes) != 1 || analysis.Devices[0].SourceRoutes[0].Network != "10.0.0.0/8" ||
		len(analysis.Devices[0].DestinationRoutes) != 1 || analysis.Devices[0].DestinationRoutes[0].Network != "172.16.0.0/16" {
		t.Fatalf("effective routes = %#v / %#v", analysis.Devices[0].SourceRoutes, analysis.Devices[0].DestinationRoutes)
	}

	request, _ = ownerRequest(http.MethodGet, "/devices/routes?source=10.1.0.0%2F16&destination=172.16.1.0%2F24&vrf=7", "", "admin@example.net")
	recorder = httptest.NewRecorder()
	s.getDeviceRoutes(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("VRF 7 response=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := json.NewDecoder(recorder.Body).Decode(&analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.VRF != 7 || len(analysis.Devices) != 1 || analysis.Devices[0].Assessment != "drop_candidate" || !analysis.Devices[0].Affected {
		t.Fatalf("VRF 7 analysis = %#v", analysis)
	}
}

func TestDeviceRoutesHandlerRejectsMixedFamiliesBeforeContactingDevices(t *testing.T) {
	s := workflowTestState(t)
	if err := s.publishPolicy(validEditablePolicy()); err != nil {
		t.Fatal(err)
	}
	contacted := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacted = true }))
	defer server.Close()
	s.config.FortinetTargets = []FortinetTarget{runtimeTestTarget(t, server)}
	request, _ := ownerRequest(http.MethodGet, "/devices/routes?source=10.0.0.0%2F8&destination=2001%3Adb8%3A%3A%2F32", "", "admin@example.net")
	recorder := httptest.NewRecorder()
	s.getDeviceRoutes(recorder, request)
	if recorder.Code != http.StatusBadRequest || contacted {
		t.Fatalf("response=%d contacted=%v body=%s", recorder.Code, contacted, recorder.Body.String())
	}
	request, _ = ownerRequest(http.MethodGet, "/devices/routes?source=10.0.0.0%2F8&destination=172.16.0.0%2F16&vrf=-1", "", "admin@example.net")
	recorder = httptest.NewRecorder()
	s.getDeviceRoutes(recorder, request)
	if recorder.Code != http.StatusBadRequest || contacted {
		t.Fatalf("invalid VRF response=%d contacted=%v body=%s", recorder.Code, contacted, recorder.Body.String())
	}
}

func TestDeviceRoutesHandlerFailsWhenAllFortiGatesFail(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "routing-secret")
	s := workflowTestState(t)
	if err := s.publishPolicy(validEditablePolicy()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "device unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	s.config.FortinetTargets = []FortinetTarget{runtimeTestTarget(t, server)}

	request, _ := ownerRequest(http.MethodGet, "/devices/routes?source=10.0.0.0%2F8&destination=172.16.0.0%2F16", "", "admin@example.net")
	recorder := httptest.NewRecorder()
	s.getDeviceRoutes(recorder, request)
	if recorder.Code != http.StatusBadGateway || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response=%d cache=%q body=%s", recorder.Code, recorder.Header().Get("Cache-Control"), recorder.Body.String())
	}
	var analysis deviceRouteAnalysis
	if err := json.NewDecoder(recorder.Body).Decode(&analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.Success || analysis.Status != "failed" || analysis.Message == "" || len(analysis.Devices) != 1 || analysis.Devices[0].Error == "" {
		t.Fatalf("failed analysis = %#v", analysis)
	}
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var auditResult string
	if err := db.QueryRow(`SELECT result FROM policy_audit WHERE action = 'device.routing.read' ORDER BY id DESC LIMIT 1`).Scan(&auditResult); err != nil {
		t.Fatal(err)
	}
	if auditResult != "failed" {
		t.Fatalf("audit result = %q", auditResult)
	}
}

func TestRouteReadsShareGlobalConcurrencyLimit(t *testing.T) {
	t.Setenv("FGT_RUNTIME_TOKEN", "routing-secret")
	var active atomic.Int32
	var maximum atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "results": []any{
			map[string]any{"ip_mask": "0.0.0.0/0", "gateway": "192.0.2.1", "interface": "wan1", "type": "static"},
		}})
	}))
	defer server.Close()
	targets := make([]FortinetTarget, 8)
	for index := range targets {
		targets[index] = runtimeTestTarget(t, server)
	}
	source := netip.MustParsePrefix("10.0.0.0/8")
	destination := netip.MustParsePrefix("172.16.0.0/16")
	var group sync.WaitGroup
	for request := 0; request < 2; request++ {
		group.Add(1)
		go func() {
			defer group.Done()
			analysis := analyzeDeviceRoutes(context.Background(), targets, source, destination, 0)
			if !analysis.Success {
				t.Errorf("analysis failed: %#v", analysis)
			}
		}()
	}
	group.Wait()
	if got := maximum.Load(); got == 0 || got > maxParallelRouteReads {
		t.Fatalf("maximum concurrent route reads = %d", got)
	}
}
