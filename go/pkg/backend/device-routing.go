package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxDeviceRouteRows    = 100000
	maxDeviceRouteMatches = 256
	maxParallelRouteReads = 4
	maxFortiGateVRF       = 251
	deviceRouteTimeout    = 30 * time.Second
)

var deviceRouteReadSemaphore = make(chan struct{}, maxParallelRouteReads)

type deviceRoute struct {
	Network   string `json:"network"`
	Gateway   string `json:"gateway,omitempty"`
	Interface string `json:"interface,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Distance  *int   `json:"distance,omitempty"`
	Metric    *int   `json:"metric,omitempty"`
	Priority  *int   `json:"priority,omitempty"`
	VRF       *int   `json:"vrf,omitempty"`
	Blackhole bool   `json:"blackhole,omitempty"`
	prefix    netip.Prefix
}

type deviceRouteResult struct {
	Name                  string        `json:"name"`
	VDOM                  string        `json:"vdom,omitempty"`
	Online                bool          `json:"online"`
	Affected              bool          `json:"affected"`
	Assessment            string        `json:"assessment"`
	RouteCount            int           `json:"route_count,omitempty"`
	SourceRoutes          []deviceRoute `json:"source_routes"`
	DestinationRoutes     []deviceRoute `json:"destination_routes"`
	SourceRoutesTruncated bool          `json:"source_routes_truncated,omitempty"`
	DestRoutesTruncated   bool          `json:"destination_routes_truncated,omitempty"`
	SourceMultipath       bool          `json:"source_multipath,omitempty"`
	DestinationMultipath  bool          `json:"destination_multipath,omitempty"`
	SourceECMP            bool          `json:"source_ecmp,omitempty"`
	DestinationECMP       bool          `json:"destination_ecmp,omitempty"`
	Error                 string        `json:"error,omitempty"`
}

type deviceRouteAnalysis struct {
	Success               bool                `json:"success"`
	Status                string              `json:"status"`
	Message               string              `json:"msg,omitempty"`
	Source                string              `json:"source"`
	Destination           string              `json:"destination"`
	AddressFamily         string              `json:"address_family"`
	VRF                   int                 `json:"vrf"`
	AnalyzedAt            string              `json:"analyzed_at"`
	AffectedFirewalls     []string            `json:"affected_firewalls"`
	Devices               []deviceRouteResult `json:"devices"`
	Complete              bool                `json:"complete"`
	Partial               bool                `json:"partial"`
	PathOrderingAvailable bool                `json:"path_ordering_available"`
	Notice                string              `json:"notice"`
}

func (s *state) getDeviceRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin", "editor", "reviewer", "deployer") {
		s.audit(actor, "device.routing.read", "denied", nil)
		writeError(w, "Policy operations role required", http.StatusForbidden)
		return
	}
	query := r.URL.Query()
	for key := range query {
		if key != "source" && key != "destination" && key != "vrf" {
			writeError(w, fmt.Sprintf("Unknown query parameter %q", key), http.StatusBadRequest)
			return
		}
	}
	if len(query["source"]) != 1 || len(query["destination"]) != 1 {
		writeError(w, "source and destination are required exactly once", http.StatusBadRequest)
		return
	}
	source, err := parseRoutingNetwork(query.Get("source"))
	if err != nil {
		writeError(w, "Invalid source network: "+err.Error(), http.StatusBadRequest)
		return
	}
	destination, err := parseRoutingNetwork(query.Get("destination"))
	if err != nil {
		writeError(w, "Invalid destination network: "+err.Error(), http.StatusBadRequest)
		return
	}
	if source.Addr().BitLen() != destination.Addr().BitLen() {
		writeError(w, "Source and destination must use the same address family", http.StatusBadRequest)
		return
	}
	vrf, err := parseRequestedVRF(query["vrf"])
	if err != nil {
		writeError(w, "Invalid VRF: "+err.Error(), http.StatusBadRequest)
		return
	}
	targets, err := s.routingFortinetTargets()
	if err != nil {
		s.audit(actor, "device.routing.read", "failed", map[string]any{
			"source": source.String(), "destination": destination.String(), "vrf": vrf,
			"reason": "target_store_unavailable",
		})
		writeError(w, "FortiGate target store is unavailable", http.StatusServiceUnavailable)
		return
	}

	analysisContext, cancel := context.WithTimeout(r.Context(), deviceRouteTimeout)
	defer cancel()
	result := analyzeDeviceRoutes(analysisContext, targets, source, destination, vrf)
	metadata := map[string]any{
		"source": source.String(), "destination": destination.String(), "vrf": vrf,
		"affected_firewalls": result.AffectedFirewalls,
	}
	s.audit(actor, "device.routing.read", result.Status, metadata)
	if !result.Success {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(result)
		return
	}
	writeJSON(w, result)
}

func analyzeDeviceRoutes(ctx context.Context, targets []FortinetTarget, source, destination netip.Prefix, vrf int) deviceRouteAnalysis {
	fortiGates := make([]FortinetTarget, 0, len(targets))
	for _, target := range targets {
		if target.Type == "fortigate" {
			fortiGates = append(fortiGates, target)
		}
	}
	results := make([]deviceRouteResult, len(fortiGates))
	var group sync.WaitGroup
	for index, target := range fortiGates {
		index, target := index, target
		group.Add(1)
		go func() {
			defer group.Done()
			select {
			case deviceRouteReadSemaphore <- struct{}{}:
				defer func() { <-deviceRouteReadSemaphore }()
			case <-ctx.Done():
				results[index] = deviceRouteResult{Name: target.Name, VDOM: target.VDOM, Error: ctx.Err().Error(), SourceRoutes: []deviceRoute{}, DestinationRoutes: []deviceRoute{}}
				return
			}
			results[index] = analyzeFortiGateRoutes(ctx, target, source, destination, vrf)
		}()
	}
	group.Wait()

	affected := make([]string, 0, len(results))
	for _, device := range results {
		if device.Affected {
			affected = append(affected, device.Name)
		}
	}
	available := 0
	for _, device := range results {
		if device.Online {
			available++
		}
	}
	family := "IPv4"
	if source.Addr().Is6() {
		family = "IPv6"
	}
	status := "empty"
	success := true
	message := ""
	if len(results) > 0 {
		switch {
		case available == len(results):
			status = "complete"
		case available > 0:
			status = "partial"
		default:
			status = "failed"
			success = false
			message = "Keine FortiGate-Routingtabelle konnte gelesen werden"
		}
	}
	return deviceRouteAnalysis{
		Success: success, Status: status, Message: message, Source: source.String(), Destination: destination.String(),
		AddressFamily: family, VRF: vrf, AnalyzedAt: time.Now().UTC().Format(time.RFC3339),
		AffectedFirewalls: affected, Devices: results, Complete: len(results) > 0 && available == len(results),
		Partial: available > 0 && available < len(results), PathOrderingAvailable: false,
		Notice: "Die betroffenen Firewalls sind Routing-Kandidaten. Eine belastbare Reihenfolge mehrerer Firewalls lässt sich aus Routingtabellen allein ohne Topologie- oder Nachbarschaftsdaten nicht ableiten.",
	}
}

func analyzeFortiGateRoutes(ctx context.Context, target FortinetTarget, source, destination netip.Prefix, vrf int) deviceRouteResult {
	result := deviceRouteResult{
		Name: target.Name, VDOM: target.VDOM,
		Assessment: "unavailable", SourceRoutes: []deviceRoute{}, DestinationRoutes: []deviceRoute{},
	}
	if strings.TrimSpace(target.VDOM) == "" {
		result.Error = "Für die Routinganalyse muss am FortiGate ein eindeutiges VDOM konfiguriert sein"
		return result
	}
	routes, err := readFortiGateRoutes(ctx, target, source.Addr().BitLen())
	if err != nil {
		result.Error = redactedFortinetError(target, err)
		return result
	}
	result.Online = true
	result.Assessment = "inconclusive"
	result.RouteCount = len(routes)
	sourceRoutes := effectiveDeviceRoutes(routes, source, vrf)
	destinationRoutes := effectiveDeviceRoutes(routes, destination, vrf)
	result.Affected, result.Assessment = assessRouteCandidate(sourceRoutes, destinationRoutes)
	result.SourceMultipath = hasMultipathRoutes(sourceRoutes)
	result.DestinationMultipath = hasMultipathRoutes(destinationRoutes)
	result.SourceECMP = hasECMPRoutes(sourceRoutes)
	result.DestinationECMP = hasECMPRoutes(destinationRoutes)
	result.SourceRoutes, result.SourceRoutesTruncated = limitDeviceRoutes(sourceRoutes)
	result.DestinationRoutes, result.DestRoutesTruncated = limitDeviceRoutes(destinationRoutes)
	return result
}

func readFortiGateRoutes(ctx context.Context, target FortinetTarget, bitLength int) ([]deviceRoute, error) {
	client, err := target.httpClient()
	if err != nil {
		return nil, err
	}
	path := "/api/v2/monitor/router/ipv4"
	if bitLength == 128 {
		path = "/api/v2/monitor/router/ipv6"
	}
	response, err := fortiGateCall(ctx, client, target, http.MethodGet, path, url.Values{"count": {"-1"}}, nil)
	if err != nil {
		return nil, err
	}
	raw, ok := response["results"]
	if !ok {
		return nil, errors.New("FortiGate routing response has no results field")
	}
	rows, ok := raw.([]any)
	if !ok {
		return nil, errors.New("FortiGate routing results are not an array")
	}
	if len(rows) > maxDeviceRouteRows {
		return nil, fmt.Errorf("FortiGate routing table exceeds the safety limit of %d rows", maxDeviceRouteRows)
	}
	routes := make([]deviceRoute, 0, len(rows))
	for index, rawRow := range rows {
		row, ok := rawRow.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("FortiGate route row %d is not an object", index)
		}
		route, err := decodeDeviceRoute(row)
		if err != nil {
			return nil, fmt.Errorf("FortiGate route row %d is invalid: %w", index, err)
		}
		if route.prefix.Addr().BitLen() != bitLength {
			return nil, fmt.Errorf("FortiGate route row %d has the wrong address family", index)
		}
		routes = append(routes, route)
	}
	sortDeviceRoutes(routes)
	return routes, nil
}

func decodeDeviceRoute(row map[string]any) (deviceRoute, error) {
	prefix, err := routePrefix(row)
	if err != nil {
		return deviceRoute{}, err
	}
	route := deviceRoute{
		Network: prefix.String(), prefix: prefix,
		Gateway:   firstRouteField(row, "gateway", "next_hop", "next-hop", "nexthop"),
		Interface: firstRouteField(row, "interface", "interface_name", "device", "dev", "outgoing_interface"),
		Protocol:  firstRouteField(row, "type", "protocol", "route_type"),
	}
	if route.Distance, err = firstRouteInteger(row, "distance", "admin_distance"); err != nil {
		return deviceRoute{}, err
	}
	if route.Metric, err = firstRouteInteger(row, "metric", "cost"); err != nil {
		return deviceRoute{}, err
	}
	if route.Priority, err = firstRouteInteger(row, "priority"); err != nil {
		return deviceRoute{}, err
	}
	if route.VRF, err = firstRouteInteger(row, "vrf", "vrf_id"); err != nil {
		return deviceRoute{}, err
	}
	blackhole := strings.ToLower(firstRouteField(row, "blackhole", "discard"))
	route.Blackhole = blackhole == "true" || blackhole == "1" ||
		firstRouteBoolean(row, "blackhole", "discard") ||
		strings.Contains(strings.ToLower(route.Protocol), "blackhole") ||
		strings.EqualFold(route.Interface, "blackhole")
	if route.Interface == "" && !route.Blackhole {
		return deviceRoute{}, errors.New("route has neither an outgoing interface nor a discard disposition")
	}
	if route.Gateway != "" {
		gateway, parseErr := netip.ParseAddr(route.Gateway)
		if parseErr != nil {
			return deviceRoute{}, errors.New("gateway is not an IP address")
		}
		if gateway.Unmap().BitLen() != prefix.Addr().BitLen() {
			return deviceRoute{}, errors.New("gateway has the wrong address family")
		}
		route.Gateway = gateway.Unmap().String()
	}
	if rawVersion, exists := row["ip_version"]; exists && rawVersion != nil {
		version, versionErr := firstRouteInteger(row, "ip_version")
		if versionErr != nil || version == nil || (*version != 4 && *version != 6) {
			return deviceRoute{}, errors.New("ip_version is not 4 or 6")
		}
		if (*version == 4) != prefix.Addr().Is4() {
			return deviceRoute{}, errors.New("ip_version does not match the route prefix")
		}
	}
	return route, nil
}

func routePrefix(row map[string]any) (netip.Prefix, error) {
	for _, key := range []string{"ip_mask", "ip-mask", "network", "prefix", "destination", "dst"} {
		value := strings.TrimSpace(scalarString(row[key]))
		if value == "" {
			continue
		}
		prefix, err := parseRoutePrefix(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%s is not a valid route prefix", key)
		}
		return prefix, nil
	}
	ip := firstRouteField(row, "ip", "address")
	mask := firstRouteField(row, "mask", "netmask", "prefix_length")
	if ip != "" && mask != "" {
		return parseRoutePrefix(ip + "/" + mask)
	}
	return netip.Prefix{}, errors.New("route network is missing")
}

func firstRouteField(row map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(scalarString(row[key])); value != "" {
			return value
		}
	}
	return ""
}

func firstRouteInteger(row map[string]any, keys ...string) (*int, error) {
	for _, key := range keys {
		raw, exists := row[key]
		if !exists || raw == nil {
			continue
		}
		value := strings.TrimSpace(scalarString(raw))
		if value == "" {
			return nil, fmt.Errorf("%s is not an integer", key)
		}
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("%s is not a non-negative integer", key)
		}
		return &parsed, nil
	}
	return nil, nil
}

func firstRouteBoolean(row map[string]any, keys ...string) bool {
	for _, key := range keys {
		if value, ok := row[key].(bool); ok && value {
			return true
		}
	}
	return false
}

func parseRoutingNetwork(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, errors.New("network is empty")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		address = address.Unmap()
		return netip.PrefixFrom(address, address.BitLen()), nil
	}
	prefix, err := parseRoutePrefix(value)
	if err != nil {
		return netip.Prefix{}, errors.New("expected an IP address or CIDR network")
	}
	return prefix, nil
}

func parseRequestedVRF(values []string) (int, error) {
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return 0, errors.New("expected exactly one non-negative integer")
	}
	vrf, err := strconv.ParseUint(strings.TrimSpace(values[0]), 10, 8)
	if err != nil || vrf > maxFortiGateVRF {
		return 0, fmt.Errorf("expected an integer between 0 and %d", maxFortiGateVRF)
	}
	return int(vrf), nil
}

func parseRoutePrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, errors.New("empty prefix")
	}
	if fields := strings.Fields(value); len(fields) == 2 && !strings.Contains(value, "/") {
		value = fields[0] + "/" + fields[1]
	}
	parts := strings.Split(value, "/")
	if len(parts) == 2 && strings.Contains(parts[1], ".") {
		address := net.ParseIP(strings.TrimSpace(parts[0])).To4()
		mask := net.ParseIP(strings.TrimSpace(parts[1])).To4()
		if address == nil || mask == nil {
			return netip.Prefix{}, errors.New("invalid IPv4 address or mask")
		}
		ones, bits := net.IPMask(mask).Size()
		if bits != 32 || ones < 0 {
			return netip.Prefix{}, errors.New("non-contiguous IPv4 mask")
		}
		parsed, _ := netip.AddrFromSlice(address)
		return netip.PrefixFrom(parsed.Unmap(), ones).Masked(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, errors.New("IPv4-mapped prefix is broader than the IPv4 address space")
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	if !prefix.IsValid() {
		return netip.Prefix{}, errors.New("invalid prefix length")
	}
	return prefix.Masked(), nil
}

func effectiveDeviceRoutes(routes []deviceRoute, network netip.Prefix, vrf int) []deviceRoute {
	candidates := make([]deviceRoute, 0)
	for _, route := range routes {
		if deviceRouteVRF(route) == vrf && prefixesOverlap(route.prefix, network) {
			candidates = append(candidates, route)
		}
	}
	sortDeviceRoutes(candidates)
	coverage := newPrefixCoverage()
	result := make([]deviceRoute, 0)
	for start := 0; start < len(candidates); {
		end := start + 1
		for end < len(candidates) && candidates[end].Network == candidates[start].Network {
			end++
		}
		segment := network
		if candidates[start].prefix.Bits() > network.Bits() {
			segment = candidates[start].prefix
		}
		if !coverage.contains(segment) {
			result = append(result, candidates[start:end]...)
			coverage.add(segment)
		}
		start = end
	}
	sortDeviceRoutes(result)
	return result
}

// prefixCoverage stores a canonical union of CIDR prefixes. Fully covered
// siblings are folded into their parent, so checking and adding a prefix costs
// at most one map lookup per address bit even for very large routing tables.
type prefixCoverage map[netip.Prefix]struct{}

func newPrefixCoverage() prefixCoverage {
	return make(prefixCoverage)
}

func (coverage prefixCoverage) contains(prefix netip.Prefix) bool {
	prefix = prefix.Masked()
	for bits := prefix.Bits(); bits >= 0; bits-- {
		candidate := netip.PrefixFrom(prefix.Addr(), bits).Masked()
		if _, exists := coverage[candidate]; exists {
			return true
		}
	}
	return false
}

func (coverage prefixCoverage) add(prefix netip.Prefix) {
	prefix = prefix.Masked()
	if coverage.contains(prefix) {
		return
	}
	coverage[prefix] = struct{}{}
	for prefix.Bits() > 0 {
		sibling := siblingPrefix(prefix)
		if _, exists := coverage[sibling]; !exists {
			return
		}
		delete(coverage, prefix)
		delete(coverage, sibling)
		prefix = netip.PrefixFrom(prefix.Addr(), prefix.Bits()-1).Masked()
		coverage[prefix] = struct{}{}
	}
}

func siblingPrefix(prefix netip.Prefix) netip.Prefix {
	prefix = prefix.Masked()
	bits := prefix.Bits()
	address := prefix.Addr()
	if address.Is4() {
		bytes := address.As4()
		bit := bits - 1
		bytes[bit/8] ^= byte(1 << (7 - bit%8))
		return netip.PrefixFrom(netip.AddrFrom4(bytes), bits).Masked()
	}
	bytes := address.As16()
	bit := bits - 1
	bytes[bit/8] ^= byte(1 << (7 - bit%8))
	return netip.PrefixFrom(netip.AddrFrom16(bytes), bits).Masked()
}

func prefixesOverlap(left, right netip.Prefix) bool {
	if left.Addr().BitLen() != right.Addr().BitLen() {
		return false
	}
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func assessRouteCandidate(sourceRoutes, destinationRoutes []deviceRoute) (bool, string) {
	if len(sourceRoutes) == 0 || len(destinationRoutes) == 0 {
		return false, "inconclusive"
	}
	vrf := deviceRouteVRF(sourceRoutes[0])
	for _, route := range append(append([]deviceRoute(nil), sourceRoutes...), destinationRoutes...) {
		if deviceRouteVRF(route) != vrf {
			return false, "inconclusive"
		}
	}
	for _, route := range append(append([]deviceRoute(nil), sourceRoutes...), destinationRoutes...) {
		if route.Blackhole {
			return true, "drop_candidate"
		}
	}
	if sameRouteSet(sourceRoutes, destinationRoutes) {
		return false, "not_affected"
	}
	interfacesDiffer := false
	for _, sourceRoute := range sourceRoutes {
		for _, destinationRoute := range destinationRoutes {
			if sourceRoute.Interface != "" && destinationRoute.Interface != "" && sourceRoute.Interface != destinationRoute.Interface {
				interfacesDiffer = true
			}
		}
	}
	if interfacesDiffer {
		if containsEndpointRoute(sourceRoutes) || containsEndpointRoute(destinationRoutes) {
			return true, "endpoint_candidate"
		}
		return true, "transit_candidate"
	}
	return false, "weak_candidate"
}

func routeCandidate(sourceRoutes, destinationRoutes []deviceRoute, _, _ netip.Prefix) bool {
	result, _ := assessRouteCandidate(sourceRoutes, destinationRoutes)
	return result
}

func containsEndpointRoute(routes []deviceRoute) bool {
	for _, route := range routes {
		protocol := strings.ToLower(route.Protocol)
		if protocol == "connected" || protocol == "connect" || protocol == "local" || protocol == "kernel" {
			return true
		}
	}
	return false
}

func deviceRouteVRF(route deviceRoute) int {
	if route.VRF == nil {
		return 0
	}
	return *route.VRF
}

func sameRouteSet(left, right []deviceRoute) bool {
	identities := func(routes []deviceRoute) []string {
		result := make([]string, 0, len(routes))
		seen := make(map[string]bool)
		for _, route := range routes {
			identity := routeForwardingIdentity(route)
			if !seen[identity] {
				seen[identity] = true
				result = append(result, identity)
			}
		}
		sort.Strings(result)
		return result
	}
	leftIDs, rightIDs := identities(left), identities(right)
	if len(leftIDs) != len(rightIDs) {
		return false
	}
	for index := range leftIDs {
		if leftIDs[index] != rightIDs[index] {
			return false
		}
	}
	return true
}

func hasECMPRoutes(routes []deviceRoute) bool {
	type uniqueRouteGroup struct {
		routes []deviceRoute
		paths  map[string]bool
	}
	groups := make(map[string]*uniqueRouteGroup)
	for _, route := range routes {
		key := strconv.Itoa(deviceRouteVRF(route)) + "\x00" + route.Network
		group := groups[key]
		if group == nil {
			group = &uniqueRouteGroup{paths: make(map[string]bool)}
			groups[key] = group
		}
		path := routeForwardingIdentity(route)
		if !group.paths[path] {
			group.paths[path] = true
			group.routes = append(group.routes, route)
		}
	}
	equalInteger := func(left, right *int) bool {
		return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
	}
	for _, group := range groups {
		if len(group.routes) < 2 {
			continue
		}
		reference := group.routes[0]
		hasCostEvidence := reference.Distance != nil || reference.Metric != nil || reference.Priority != nil
		verified := reference.Protocol != "" && hasCostEvidence
		for _, candidate := range group.routes[1:] {
			if candidate.Protocol != reference.Protocol || !equalInteger(candidate.Distance, reference.Distance) ||
				!equalInteger(candidate.Metric, reference.Metric) || !equalInteger(candidate.Priority, reference.Priority) {
				verified = false
			}
		}
		if verified {
			return true
		}
	}
	return false
}

func hasMultipathRoutes(routes []deviceRoute) bool {
	seen := make(map[string]map[string]bool)
	for _, route := range routes {
		key := strconv.Itoa(deviceRouteVRF(route)) + "\x00" + route.Network
		if seen[key] == nil {
			seen[key] = make(map[string]bool)
		}
		path := routeForwardingIdentity(route)
		if len(seen[key]) > 0 && !seen[key][path] {
			return true
		}
		seen[key][path] = true
	}
	return false
}

func routeForwardingIdentity(route deviceRoute) string {
	return route.Gateway + "\x00" + route.Interface + "\x00" + strconv.FormatBool(route.Blackhole)
}

func limitDeviceRoutes(routes []deviceRoute) ([]deviceRoute, bool) {
	if len(routes) <= maxDeviceRouteMatches {
		return routes, false
	}
	return routes[:maxDeviceRouteMatches], true
}

func sortDeviceRoutes(routes []deviceRoute) {
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].prefix.Bits() != routes[j].prefix.Bits() {
			return routes[i].prefix.Bits() > routes[j].prefix.Bits()
		}
		if routes[i].Network != routes[j].Network {
			return routes[i].Network < routes[j].Network
		}
		if routes[i].Interface != routes[j].Interface {
			return routes[i].Interface < routes[j].Interface
		}
		return routes[i].Gateway < routes[j].Gateway
	})
}
