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

type deviceInterfaceAddress struct {
	Interface  string
	Address    netip.Addr
	Prefix     netip.Prefix
	VRF        int
	Configured bool
}

type deviceRouteResult struct {
	TargetID              string        `json:"target_id"`
	Name                  string        `json:"name"`
	VDOM                  string        `json:"vdom,omitempty"`
	Online                bool          `json:"online"`
	Affected              bool          `json:"affected"`
	Assessment            string        `json:"assessment"`
	SourceConnected       bool          `json:"source_connected"`
	DestinationConnected  bool          `json:"destination_connected"`
	RouteCount            int           `json:"route_count,omitempty"`
	SourceRoutes          []deviceRoute `json:"source_routes"`
	DestinationRoutes     []deviceRoute `json:"destination_routes"`
	SourceRoutesTruncated bool          `json:"source_routes_truncated,omitempty"`
	DestRoutesTruncated   bool          `json:"destination_routes_truncated,omitempty"`
	SourceMultipath       bool          `json:"source_multipath,omitempty"`
	DestinationMultipath  bool          `json:"destination_multipath,omitempty"`
	SourceECMP            bool          `json:"source_ecmp,omitempty"`
	DestinationECMP       bool          `json:"destination_ecmp,omitempty"`
	TopologyError         string        `json:"topology_error,omitempty"`
	Error                 string        `json:"error,omitempty"`
	routes                []deviceRoute
	interfaceAddresses    []deviceInterfaceAddress
}

type deviceRouteEndpoint struct {
	TargetID        string        `json:"target_id"`
	Name            string        `json:"name"`
	VDOM            string        `json:"vdom,omitempty"`
	ConnectedRoutes []deviceRoute `json:"connected_routes"`
}

type deviceRoutePathHop struct {
	Sequence                int           `json:"sequence"`
	TargetID                string        `json:"target_id"`
	Name                    string        `json:"name"`
	VDOM                    string        `json:"vdom,omitempty"`
	Role                    string        `json:"role"`
	IngressInterfaces       []string      `json:"ingress_interfaces"`
	EgressInterfaces        []string      `json:"egress_interfaces"`
	NextHops                []string      `json:"next_hops"`
	SelectedRoutes          []deviceRoute `json:"selected_routes"`
	SelectedRoutesTruncated bool          `json:"selected_routes_truncated,omitempty"`
	ECMP                    bool          `json:"ecmp,omitempty"`
	Multipath               bool          `json:"multipath,omitempty"`
}

type deviceRoutePathResult struct {
	Status              string
	Message             string
	Hops                []deviceRoutePathHop
	SourceEndpoint      *deviceRouteEndpoint
	DestinationEndpoint *deviceRouteEndpoint
	Complete            bool
}

type deviceRouteAnalysis struct {
	Success               bool                 `json:"success"`
	Status                string               `json:"status"`
	Message               string               `json:"msg,omitempty"`
	Source                string               `json:"source"`
	Destination           string               `json:"destination"`
	AddressFamily         string               `json:"address_family"`
	VRF                   int                  `json:"vrf"`
	AnalyzedAt            string               `json:"analyzed_at"`
	AffectedFirewalls     []string             `json:"affected_firewalls"`
	Devices               []deviceRouteResult  `json:"devices"`
	Complete              bool                 `json:"complete"`
	Partial               bool                 `json:"partial"`
	ScanStatus            string               `json:"scan_status"`
	ScanComplete          bool                 `json:"scan_complete"`
	ScanPartial           bool                 `json:"scan_partial"`
	PathStatus            string               `json:"path_status"`
	PathMessage           string               `json:"path_message"`
	PathComplete          bool                 `json:"path_complete"`
	PathOrderingAvailable bool                 `json:"path_ordering_available"`
	SourceEndpoint        *deviceRouteEndpoint `json:"source_endpoint,omitempty"`
	DestinationEndpoint   *deviceRouteEndpoint `json:"destination_endpoint,omitempty"`
	RoutePath             []deviceRoutePathHop `json:"route_path"`
	Notice                string               `json:"notice"`
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
		"affected_firewalls": result.AffectedFirewalls, "path_status": result.PathStatus,
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
				results[index] = deviceRouteResult{TargetID: deviceRouteTargetID(target), Name: target.Name, VDOM: target.VDOM, Error: ctx.Err().Error(), SourceRoutes: []deviceRoute{}, DestinationRoutes: []deviceRoute{}}
				return
			}
			results[index] = analyzeFortiGateRoutes(ctx, target, source, destination, vrf)
		}()
	}
	group.Wait()

	path := deriveDeviceRoutePath(results, source, destination, vrf)
	pathRoles := make(map[string]string, len(path.Hops))
	affected := make([]string, 0, len(path.Hops))
	for _, hop := range path.Hops {
		affected = append(affected, hop.Name)
		pathRoles[hop.TargetID] = hop.Role
	}
	for index := range results {
		if !results[index].Online {
			continue
		}
		results[index].Affected = false
		results[index].Assessment = "not_on_path"
		if role, onPath := pathRoles[results[index].TargetID]; onPath {
			results[index].Affected = true
			results[index].Assessment = "path_" + role
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
	scanComplete := len(results) > 0 && available == len(results)
	scanPartial := available > 0 && available < len(results)
	return deviceRouteAnalysis{
		Success: success, Status: status, Message: message, Source: source.String(), Destination: destination.String(),
		AddressFamily: family, VRF: vrf, AnalyzedAt: time.Now().UTC().Format(time.RFC3339),
		AffectedFirewalls: affected, Devices: results, Complete: path.Complete,
		Partial: scanPartial || path.Status == "partial", ScanStatus: status, ScanComplete: scanComplete, ScanPartial: scanPartial,
		PathStatus: path.Status, PathMessage: path.Message,
		PathComplete: path.Complete, PathOrderingAvailable: len(path.Hops) > 0,
		SourceEndpoint: path.SourceEndpoint, DestinationEndpoint: path.DestinationEndpoint,
		RoutePath: path.Hops, Notice: path.Message,
	}
}

func analyzeFortiGateRoutes(ctx context.Context, target FortinetTarget, source, destination netip.Prefix, vrf int) deviceRouteResult {
	result := deviceRouteResult{
		TargetID: deviceRouteTargetID(target), Name: target.Name, VDOM: target.VDOM,
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
	result.routes = routes
	sourceRoutes := effectiveDeviceRoutes(routes, source, vrf)
	destinationRoutes := effectiveDeviceRoutes(routes, destination, vrf)
	result.SourceConnected = directlyConnectedNetwork(routes, source, vrf)
	result.DestinationConnected = directlyConnectedNetwork(routes, destination, vrf)
	result.Affected, result.Assessment = assessRouteCandidate(sourceRoutes, destinationRoutes)
	result.SourceMultipath = hasMultipathRoutes(sourceRoutes)
	result.DestinationMultipath = hasMultipathRoutes(destinationRoutes)
	result.SourceECMP = hasECMPRoutes(sourceRoutes)
	result.DestinationECMP = hasECMPRoutes(destinationRoutes)
	result.SourceRoutes, result.SourceRoutesTruncated = limitDeviceRoutes(sourceRoutes)
	result.DestinationRoutes, result.DestRoutesTruncated = limitDeviceRoutes(destinationRoutes)
	result.interfaceAddresses = localRouteInterfaceAddresses(routes)
	configuredAddresses, err := readFortiGateInterfaceAddresses(ctx, target, source.Addr().BitLen())
	if err != nil {
		result.TopologyError = redactedFortinetError(target, err)
	} else {
		result.interfaceAddresses = mergeDeviceInterfaceAddresses(result.interfaceAddresses, configuredAddresses)
	}
	return result
}

func deviceRouteTargetID(target FortinetTarget) string {
	if strings.TrimSpace(target.managedID) != "" {
		return target.managedID
	}
	return configuredFortiGateID(target)
}

func deriveDeviceRoutePath(results []deviceRouteResult, source, destination netip.Prefix, vrf int) deviceRoutePathResult {
	path := deviceRoutePathResult{Status: "empty", Message: "Keine FortiGate-VDOMs für die Routinganalyse konfiguriert.", Hops: []deviceRoutePathHop{}}
	if len(results) == 0 {
		return path
	}

	sourceCandidates := connectedEndpointCandidates(results, source, vrf)
	destinationCandidates := connectedEndpointCandidates(results, destination, vrf)
	routingIncomplete := routePathHasUnavailableRouting(results)
	switch {
	case len(sourceCandidates) == 0:
		path.Status = "not_found"
		path.Message = "Kein erreichbares VDOM besitzt das Quellnetz als direkt verbundenes Netz."
		if routingIncomplete {
			path.Status = "partial"
			path.Message = "Das Quell-VDOM konnte nicht sicher bestimmt werden, weil mindestens eine Routingtabelle nicht gelesen werden konnte."
		}
		return path
	case len(sourceCandidates) > 1:
		path.Status = "ambiguous"
		path.Message = "Mehrere VDOMs besitzen das Quellnetz als direkt verbundenes Netz; der Start des Pfads ist nicht eindeutig."
		return path
	case len(destinationCandidates) == 0:
		path.SourceEndpoint = endpointForDevice(results[sourceCandidates[0]], source, vrf)
		path.Status = "not_found"
		path.Message = "Keine erreichbare Ziel-Firewall besitzt das Zielnetz als direkt verbundenes Netz."
		if routingIncomplete {
			path.Status = "partial"
			path.Message = "Die Ziel-Firewall konnte nicht sicher bestimmt werden, weil mindestens eine Routingtabelle nicht gelesen werden konnte."
		}
		return path
	case len(destinationCandidates) > 1:
		path.SourceEndpoint = endpointForDevice(results[sourceCandidates[0]], source, vrf)
		path.Status = "ambiguous"
		path.Message = "Mehrere VDOMs besitzen das Zielnetz als direkt verbundenes Netz; das Ende des Pfads ist nicht eindeutig."
		return path
	}

	sourceIndex, destinationIndex := sourceCandidates[0], destinationCandidates[0]
	path.SourceEndpoint = endpointForDevice(results[sourceIndex], source, vrf)
	path.DestinationEndpoint = endpointForDevice(results[destinationIndex], destination, vrf)
	topologyIncomplete := false

	visited := make(map[int]bool, len(results))
	currentIndex := sourceIndex
	ingressInterfaces := []string{}
	for len(path.Hops) <= len(results) {
		if visited[currentIndex] {
			path.Status = "unreachable"
			path.Message = "Der ermittelte Next-Hop-Verlauf enthält eine Schleife und erreicht die Ziel-Firewall nicht."
			return path
		}
		visited[currentIndex] = true
		current := results[currentIndex]
		selectedRoutes := effectiveDeviceRoutes(current.routes, destination, vrf)
		hop := newDeviceRoutePathHop(current, selectedRoutes, ingressInterfaces, len(path.Hops)+1)

		if currentIndex == destinationIndex {
			path.Hops = append(path.Hops, hop)
			assignDeviceRoutePathRoles(path.Hops, true)
			if routingIncomplete || topologyIncomplete {
				path.Status = "partial"
				path.Message = "Der sichtbare Routing-Pfad erreicht die Ziel-Firewall, konnte wegen unvollständiger Geräte- oder Interface-Daten aber nicht vollständig verifiziert werden."
				return path
			}
			path.Status = "complete"
			path.Message = "Eindeutiger Routing-Pfad vom Quell-VDOM bis zur Ziel-Firewall ermittelt."
			path.Complete = true
			return path
		}

		if len(selectedRoutes) == 0 {
			path.Hops = append(path.Hops, hop)
			assignDeviceRoutePathRoles(path.Hops, false)
			path.Status = "unreachable"
			path.Message = fmt.Sprintf("%s hat keine aktive Route zum Zielnetz.", deviceRouteDisplayName(current))
			return path
		}
		for _, route := range selectedRoutes {
			if route.Blackhole {
				path.Hops = append(path.Hops, hop)
				assignDeviceRoutePathRoles(path.Hops, false)
				path.Status = "unreachable"
				path.Message = fmt.Sprintf("Die Vorwärtsroute auf %s verwirft mindestens einen Teil des Zielnetzes.", deviceRouteDisplayName(current))
				return path
			}
		}

		gateways, completeGateways := routeNextHops(selectedRoutes)
		hop.NextHops = gateways
		if !completeGateways || len(gateways) == 0 {
			path.Hops = append(path.Hops, hop)
			assignDeviceRoutePathRoles(path.Hops, false)
			path.Status = "unresolved"
			path.Message = fmt.Sprintf("Der nächste VDOM-Hop hinter %s kann aus einer Route ohne eindeutige Gateway-Adresse nicht bestimmt werden.", deviceRouteDisplayName(current))
			return path
		}
		if routePathHasUnavailableTopology(results) {
			topologyIncomplete = true
		}

		nextIndices := map[int]bool{}
		nextIngress := []string{}
		for _, route := range selectedRoutes {
			gateway, err := netip.ParseAddr(strings.TrimSpace(route.Gateway))
			if err != nil {
				path.Hops = append(path.Hops, hop)
				assignDeviceRoutePathRoles(path.Hops, false)
				path.Status = "unresolved"
				path.Message = fmt.Sprintf("Die Vorwärtsroute auf %s enthält eine ungültige Gateway-Adresse.", deviceRouteDisplayName(current))
				return path
			}
			owners, directLink, ambiguousLink := deviceRouteGatewayOwners(results, currentIndex, route, gateway.Unmap(), vrf)
			if !directLink {
				path.Hops = append(path.Hops, hop)
				assignDeviceRoutePathRoles(path.Hops, false)
				path.Status = "unresolved"
				path.Message = fmt.Sprintf("Der Next Hop %s auf %s ist nicht als direkt verbundene Adjazenz über Interface %s belegt.", gateway, deviceRouteDisplayName(current), route.Interface)
				return path
			}
			if ambiguousLink {
				path.Hops = append(path.Hops, hop)
				assignDeviceRoutePathRoles(path.Hops, false)
				path.Status = "ambiguous"
				path.Message = fmt.Sprintf("Das Transitnetz des Next Hops %s wird von mehr als zwei VDOMs verwendet und ist deshalb nicht eindeutig.", gateway)
				return path
			}
			if len(owners) == 0 {
				path.Hops = append(path.Hops, hop)
				assignDeviceRoutePathRoles(path.Hops, false)
				path.Status = "unresolved"
				path.Message = fmt.Sprintf("Der Next Hop %s hinter %s gehört zu keinem bekannten FortiGate-VDOM.", gateway, deviceRouteDisplayName(current))
				if routingIncomplete || topologyIncomplete {
					path.Status = "partial"
					path.Message = fmt.Sprintf("Der Next Hop %s hinter %s konnte wegen unvollständiger Geräte- oder Interface-Daten nicht sicher zugeordnet werden.", gateway, deviceRouteDisplayName(current))
				}
				return path
			}
			if len(owners) > 1 {
				path.Hops = append(path.Hops, hop)
				assignDeviceRoutePathRoles(path.Hops, false)
				path.Status = "ambiguous"
				path.Message = fmt.Sprintf("Der Next Hop %s hinter %s ist mehreren VDOMs zugeordnet.", gateway, deviceRouteDisplayName(current))
				return path
			}
			nextIndices[owners[0].Index] = true
			nextIngress = append(nextIngress, owners[0].Interfaces...)
		}
		if len(nextIndices) != 1 {
			path.Hops = append(path.Hops, hop)
			assignDeviceRoutePathRoles(path.Hops, false)
			path.Status = "ambiguous"
			path.Message = fmt.Sprintf("Die aktiven Vorwärtsrouten auf %s führen zu unterschiedlichen VDOMs.", deviceRouteDisplayName(current))
			return path
		}

		path.Hops = append(path.Hops, hop)
		nextIndex := -1
		for index := range nextIndices {
			nextIndex = index
		}
		if visited[nextIndex] {
			assignDeviceRoutePathRoles(path.Hops, false)
			path.Status = "unreachable"
			path.Message = "Der ermittelte Next-Hop-Verlauf enthält eine Schleife und erreicht die Ziel-Firewall nicht."
			return path
		}
		currentIndex = nextIndex
		ingressInterfaces = uniqueSortedStrings(nextIngress)
	}

	assignDeviceRoutePathRoles(path.Hops, false)
	path.Status = "unreachable"
	path.Message = "Der Routing-Pfad überschreitet die Anzahl der bekannten VDOMs und wurde abgebrochen."
	return path
}

func connectedEndpointCandidates(results []deviceRouteResult, network netip.Prefix, vrf int) []int {
	result := []int{}
	for index, device := range results {
		if device.Online && directlyConnectedNetwork(device.routes, network, vrf) {
			result = append(result, index)
		}
	}
	return result
}

func endpointForDevice(device deviceRouteResult, network netip.Prefix, vrf int) *deviceRouteEndpoint {
	routes, _ := directlyConnectedRoutes(device.routes, network, vrf)
	limited, _ := limitDeviceRoutes(routes)
	return &deviceRouteEndpoint{TargetID: device.TargetID, Name: device.Name, VDOM: device.VDOM, ConnectedRoutes: limited}
}

func newDeviceRoutePathHop(device deviceRouteResult, routes []deviceRoute, ingress []string, sequence int) deviceRoutePathHop {
	selected, truncated := limitDeviceRoutes(routes)
	return deviceRoutePathHop{
		Sequence: sequence, TargetID: device.TargetID, Name: device.Name, VDOM: device.VDOM,
		IngressInterfaces: uniqueSortedStrings(ingress), EgressInterfaces: routeInterfaces(routes),
		NextHops: []string{}, SelectedRoutes: selected, SelectedRoutesTruncated: truncated,
		ECMP: hasECMPRoutes(routes), Multipath: hasMultipathRoutes(routes),
	}
}

func assignDeviceRoutePathRoles(hops []deviceRoutePathHop, reachedDestination bool) {
	for index := range hops {
		hops[index].Role = "transit"
	}
	if len(hops) == 0 {
		return
	}
	hops[0].Role = "source"
	if reachedDestination {
		if len(hops) == 1 {
			hops[0].Role = "source_destination"
		} else {
			hops[len(hops)-1].Role = "destination"
		}
	}
}

type deviceRouteGatewayOwner struct {
	Index      int
	Interfaces []string
}

func deviceRouteGatewayOwners(results []deviceRouteResult, currentIndex int, selected deviceRoute, gateway netip.Addr, vrf int) ([]deviceRouteGatewayOwner, bool, bool) {
	currentLinks := deviceRouteGatewayLinks(results[currentIndex].routes, gateway, selected.Interface, vrf)
	if len(currentLinks) == 0 {
		return nil, false, false
	}
	owners := []deviceRouteGatewayOwner{}
	ambiguousLink := false
	for index, device := range results {
		if index == currentIndex || !device.Online {
			continue
		}
		interfaces := []string{}
		for _, address := range device.interfaceAddresses {
			if address.VRF != vrf || address.Address.Unmap() != gateway.Unmap() {
				continue
			}
			candidateLinks := deviceRouteInterfaceLinks(device, address, vrf)
			for _, currentLink := range currentLinks {
				for _, candidateLink := range candidateLinks {
					if currentLink == candidateLink {
						participants := deviceRouteLinkParticipants(results, currentLink, vrf)
						if len(participants) > 2 {
							ambiguousLink = true
							continue
						}
						if len(participants) == 2 && participants[currentIndex] && participants[index] {
							interfaces = append(interfaces, address.Interface)
						}
					}
				}
			}
		}
		if len(interfaces) > 0 {
			owners = append(owners, deviceRouteGatewayOwner{Index: index, Interfaces: uniqueSortedStrings(interfaces)})
		}
	}
	return owners, true, ambiguousLink
}

func deviceRouteLinkParticipants(results []deviceRouteResult, link netip.Prefix, vrf int) map[int]bool {
	participants := map[int]bool{}
	for index, device := range results {
		if !device.Online {
			continue
		}
		for _, route := range device.routes {
			protocol := strings.ToLower(strings.TrimSpace(route.Protocol))
			if deviceRouteVRF(route) == vrf && !route.Blackhole && protocol != "local" && protocol != "l" && isDirectDeviceRoute(route) && route.prefix.Masked() == link.Masked() {
				participants[index] = true
				break
			}
		}
		if participants[index] {
			continue
		}
		for _, address := range device.interfaceAddresses {
			if address.VRF == vrf && address.Prefix.IsValid() && address.Prefix.Masked() == link.Masked() {
				participants[index] = true
				break
			}
		}
	}
	return participants
}

func deviceRouteGatewayLinks(routes []deviceRoute, gateway netip.Addr, iface string, vrf int) []netip.Prefix {
	links := []netip.Prefix{}
	seen := map[netip.Prefix]bool{}
	for _, route := range routes {
		protocol := strings.ToLower(strings.TrimSpace(route.Protocol))
		if deviceRouteVRF(route) != vrf || route.Blackhole || route.Interface != iface || !route.prefix.Contains(gateway) || protocol == "local" || protocol == "l" || !isDirectDeviceRoute(route) {
			continue
		}
		prefix := route.prefix.Masked()
		if !seen[prefix] {
			seen[prefix] = true
			links = append(links, prefix)
		}
	}
	sort.Slice(links, func(left, right int) bool {
		if links[left].Bits() != links[right].Bits() {
			return links[left].Bits() > links[right].Bits()
		}
		return links[left].Addr().Less(links[right].Addr())
	})
	return links
}

func deviceRouteInterfaceLinks(device deviceRouteResult, address deviceInterfaceAddress, vrf int) []netip.Prefix {
	links := []netip.Prefix{}
	if address.Prefix.IsValid() && address.Prefix.Contains(address.Address) {
		links = append(links, address.Prefix.Masked())
	}
	links = append(links, deviceRouteGatewayLinks(device.routes, address.Address, address.Interface, vrf)...)
	seen := map[netip.Prefix]bool{}
	result := []netip.Prefix{}
	for _, link := range links {
		if !seen[link] {
			seen[link] = true
			result = append(result, link)
		}
	}
	return result
}

func routeNextHops(routes []deviceRoute) ([]string, bool) {
	gateways := []string{}
	for _, route := range routes {
		gateway := strings.TrimSpace(route.Gateway)
		if gateway == "" {
			return uniqueSortedStrings(gateways), false
		}
		address, err := netip.ParseAddr(gateway)
		if err != nil || address.IsUnspecified() {
			return uniqueSortedStrings(gateways), false
		}
		gateways = append(gateways, address.Unmap().String())
	}
	return uniqueSortedStrings(gateways), true
}

func routeInterfaces(routes []deviceRoute) []string {
	interfaces := []string{}
	for _, route := range routes {
		if strings.TrimSpace(route.Interface) != "" {
			interfaces = append(interfaces, route.Interface)
		}
	}
	return uniqueSortedStrings(interfaces)
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func routePathHasUnavailableRouting(results []deviceRouteResult) bool {
	for _, result := range results {
		if !result.Online {
			return true
		}
	}
	return false
}

func routePathHasUnavailableTopology(results []deviceRouteResult) bool {
	for _, result := range results {
		if result.Online && result.TopologyError != "" {
			return true
		}
	}
	return false
}

func deviceRouteDisplayName(device deviceRouteResult) string {
	if strings.TrimSpace(device.VDOM) == "" {
		return device.Name
	}
	return device.Name + " (VDOM " + device.VDOM + ")"
}

func readFortiGateInterfaceAddresses(ctx context.Context, target FortinetTarget, bitLength int) ([]deviceInterfaceAddress, error) {
	client, err := target.httpClient()
	if err != nil {
		return nil, err
	}
	objects, err := listFortiGateObjectsCompleteSnapshot(ctx, client, target, "/api/v2/cmdb/system/interface", nil, 500)
	if err != nil {
		return nil, err
	}
	addresses := []deviceInterfaceAddress{}
	for index, object := range objects {
		name := strings.TrimSpace(scalarString(object.Data["name"]))
		if name == "" {
			name = strings.TrimSpace(object.MKey)
		}
		if name == "" {
			return nil, fmt.Errorf("FortiGate interface row %d has no name", index)
		}
		vrf := 0
		if configuredVRF, parseErr := firstRouteInteger(object.Data, "vrf"); parseErr != nil {
			return nil, fmt.Errorf("FortiGate interface %q has an invalid VRF", name)
		} else if configuredVRF != nil {
			if *configuredVRF > maxFortiGateVRF {
				return nil, fmt.Errorf("FortiGate interface %q has a VRF outside the supported range", name)
			}
			vrf = *configuredVRF
		}

		if bitLength == 32 {
			if raw, exists := deviceRouteObjectField(object.Data, "ip"); exists {
				if err := appendConfiguredInterfaceAddress(&addresses, name, vrf, raw, bitLength); err != nil {
					return nil, fmt.Errorf("FortiGate interface %q has an invalid IP address: %w", name, err)
				}
			}
			for _, tableName := range []string{"secondaryip", "secondary-ip-list"} {
				raw, exists := deviceRouteObjectField(object.Data, tableName)
				if !exists {
					continue
				}
				if err := appendConfiguredInterfaceAddressRows(&addresses, name, vrf, raw, bitLength, "ip"); err != nil {
					return nil, fmt.Errorf("FortiGate interface %q has invalid secondary IP data: %w", name, err)
				}
			}
		} else {
			if raw, exists := deviceRouteObjectField(object.Data, "ip6-address"); exists {
				if err := appendConfiguredInterfaceAddress(&addresses, name, vrf, raw, bitLength); err != nil {
					return nil, fmt.Errorf("FortiGate interface %q has an invalid IPv6 address: %w", name, err)
				}
			}
			if rawIPv6, exists := deviceRouteObjectField(object.Data, "ipv6"); exists && rawIPv6 != nil {
				ipv6, ok := rawIPv6.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("FortiGate interface %q has malformed IPv6 settings", name)
				}
				if raw, exists := deviceRouteObjectField(ipv6, "ip6-address"); exists {
					if err := appendConfiguredInterfaceAddress(&addresses, name, vrf, raw, bitLength); err != nil {
						return nil, fmt.Errorf("FortiGate interface %q has an invalid primary IPv6 address: %w", name, err)
					}
				}
				if raw, exists := deviceRouteObjectField(ipv6, "ip6-extra-addr"); exists {
					if err := appendConfiguredInterfaceAddressRows(&addresses, name, vrf, raw, bitLength, "prefix"); err != nil {
						return nil, fmt.Errorf("FortiGate interface %q has invalid extra IPv6 address data: %w", name, err)
					}
				}
			}
			if raw, exists := deviceRouteObjectField(object.Data, "ip6-extra-addr"); exists {
				if err := appendConfiguredInterfaceAddressRows(&addresses, name, vrf, raw, bitLength, "prefix"); err != nil {
					return nil, fmt.Errorf("FortiGate interface %q has invalid extra IPv6 address data: %w", name, err)
				}
			}
		}
	}
	return mergeDeviceInterfaceAddresses(nil, addresses), nil
}

func deviceRouteObjectField(object map[string]any, wanted string) (any, bool) {
	for key, value := range object {
		if strings.EqualFold(key, wanted) {
			return value, true
		}
	}
	return nil, false
}

func appendConfiguredInterfaceAddressRows(result *[]deviceInterfaceAddress, iface string, vrf int, value any, bitLength int, field string) error {
	rows := []map[string]any{}
	if row, ok := value.(map[string]any); ok {
		if _, directRow := deviceRouteObjectField(row, field); directRow {
			rows = append(rows, row)
		}
	}
	if len(rows) == 0 {
		var err error
		rows, err = deviceRouteObjectRows(value, field)
		if err != nil {
			return err
		}
	}
	for index, row := range rows {
		raw, exists := deviceRouteObjectField(row, field)
		if !exists {
			return fmt.Errorf("row %d has no %s field", index, field)
		}
		if err := appendConfiguredInterfaceAddress(result, iface, vrf, raw, bitLength); err != nil {
			return fmt.Errorf("row %d: %w", index, err)
		}
	}
	return nil
}

func deviceRouteObjectRows(value any, mkeyField string) ([]map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	result := []map[string]any{}
	switch item := value.(type) {
	case []any:
		for index, child := range item {
			row, ok := child.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("row %d is not an object", index)
			}
			result = append(result, row)
		}
	case map[string]any:
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			row, ok := item[key].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("entry %q is not an object", key)
			}
			if _, exists := deviceRouteObjectField(row, mkeyField); !exists && mkeyField == "prefix" {
				copy := make(map[string]any, len(row)+1)
				for field, value := range row {
					copy[field] = value
				}
				copy[mkeyField] = key
				row = copy
			}
			result = append(result, row)
		}
	default:
		return nil, fmt.Errorf("expected an array or object, got %T", value)
	}
	return result, nil
}

func appendConfiguredInterfaceAddress(result *[]deviceInterfaceAddress, iface string, vrf int, value any, bitLength int) error {
	address, prefix, present, err := parseConfiguredInterfaceAddress(value, bitLength)
	if err != nil || !present {
		return err
	}
	*result = append(*result, deviceInterfaceAddress{Interface: iface, Address: address, Prefix: prefix, VRF: vrf, Configured: true})
	return nil
}

func parseConfiguredInterfaceAddress(value any, bitLength int) (netip.Addr, netip.Prefix, bool, error) {
	fields := []string{}
	switch item := value.(type) {
	case nil:
		return netip.Addr{}, netip.Prefix{}, false, nil
	case string:
		fields = strings.Fields(strings.TrimSpace(item))
	case []any:
		for _, child := range item {
			field := strings.TrimSpace(scalarString(child))
			if field == "" {
				return netip.Addr{}, netip.Prefix{}, false, errors.New("address array contains a non-scalar value")
			}
			fields = append(fields, field)
		}
	default:
		return netip.Addr{}, netip.Prefix{}, false, fmt.Errorf("unsupported address value %T", value)
	}
	if len(fields) == 0 {
		return netip.Addr{}, netip.Prefix{}, false, nil
	}
	if len(fields) > 2 {
		return netip.Addr{}, netip.Prefix{}, false, errors.New("address has too many fields")
	}
	candidate := strings.Trim(strings.TrimSpace(fields[0]), "[](),")
	var address netip.Addr
	var prefix netip.Prefix
	if parsed, parseErr := netip.ParsePrefix(candidate); parseErr == nil {
		address = parsed.Addr().Unmap()
		bits := parsed.Bits()
		if parsed.Addr().Is4In6() {
			bits -= 96
		}
		prefix = netip.PrefixFrom(address, bits).Masked()
	} else {
		parsed, parseErr := netip.ParseAddr(candidate)
		if parseErr != nil {
			return netip.Addr{}, netip.Prefix{}, false, errors.New("address is not an IP address or prefix")
		}
		address = parsed.Unmap()
		prefix = netip.PrefixFrom(address, address.BitLen()).Masked()
		if len(fields) == 2 {
			bits, maskErr := deviceRouteInterfaceMaskBits(fields[1], address.BitLen())
			if maskErr != nil {
				return netip.Addr{}, netip.Prefix{}, false, maskErr
			}
			prefix = netip.PrefixFrom(address, bits).Masked()
		}
	}
	if len(fields) == 2 && strings.Contains(candidate, "/") {
		return netip.Addr{}, netip.Prefix{}, false, errors.New("prefixed address also contains a separate mask")
	}
	if address.BitLen() != bitLength {
		return netip.Addr{}, netip.Prefix{}, false, errors.New("address has the wrong address family")
	}
	if address.IsUnspecified() || address.IsLinkLocalUnicast() {
		return netip.Addr{}, netip.Prefix{}, false, nil
	}
	return address, prefix, true, nil
}

func deviceRouteInterfaceMaskBits(raw string, bitLength int) (int, error) {
	raw = strings.TrimSpace(raw)
	if bitLength == 32 {
		mask := net.ParseIP(raw).To4()
		if mask == nil {
			return 0, errors.New("IPv4 netmask is invalid")
		}
		ones, bits := net.IPMask(mask).Size()
		if bits != 32 || ones < 0 {
			return 0, errors.New("IPv4 netmask is non-contiguous")
		}
		return ones, nil
	}
	bits, err := strconv.Atoi(raw)
	if err != nil || bits < 0 || bits > bitLength {
		return 0, errors.New("IPv6 prefix length is invalid")
	}
	return bits, nil
}

func localRouteInterfaceAddresses(routes []deviceRoute) []deviceInterfaceAddress {
	result := []deviceInterfaceAddress{}
	for _, route := range routes {
		if !isDirectDeviceRoute(route) || !route.prefix.IsValid() || route.prefix.Bits() != route.prefix.Addr().BitLen() || route.prefix.Addr().IsUnspecified() || route.prefix.Addr().IsLinkLocalUnicast() {
			continue
		}
		result = append(result, deviceInterfaceAddress{Interface: route.Interface, Address: route.prefix.Addr().Unmap(), Prefix: route.prefix, VRF: deviceRouteVRF(route)})
	}
	return mergeDeviceInterfaceAddresses(nil, result)
}

func mergeDeviceInterfaceAddresses(groups ...[]deviceInterfaceAddress) []deviceInterfaceAddress {
	seen := map[string]bool{}
	result := []deviceInterfaceAddress{}
	for _, group := range groups {
		for _, address := range group {
			if !address.Address.IsValid() {
				continue
			}
			address.Address = address.Address.Unmap()
			key := strconv.Itoa(address.VRF) + "\x00" + address.Address.String() + "\x00" + address.Prefix.String() + "\x00" + address.Interface + "\x00" + strconv.FormatBool(address.Configured)
			if !seen[key] {
				seen[key] = true
				result = append(result, address)
			}
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].VRF != result[right].VRF {
			return result[left].VRF < result[right].VRF
		}
		if result[left].Address != result[right].Address {
			return result[left].Address.Less(result[right].Address)
		}
		return result[left].Interface < result[right].Interface
	})
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

func directlyConnectedNetwork(routes []deviceRoute, network netip.Prefix, vrf int) bool {
	_, complete := directlyConnectedRoutes(routes, network, vrf)
	return complete
}

func directlyConnectedRoutes(routes []deviceRoute, network netip.Prefix, vrf int) ([]deviceRoute, bool) {
	candidates := make([]deviceRoute, 0)
	for _, route := range routes {
		if deviceRouteVRF(route) == vrf && prefixesOverlap(route.prefix, network) {
			candidates = append(candidates, route)
		}
	}
	sortDeviceRoutes(candidates)
	direct := []deviceRoute{}
	coverage := newPrefixCoverage()
	for start := 0; start < len(candidates); {
		end := start + 1
		for end < len(candidates) && candidates[end].Network == candidates[start].Network {
			end++
		}
		segment := network
		if candidates[start].prefix.Bits() > network.Bits() {
			segment = candidates[start].prefix
		}
		if coverage.contains(segment) {
			start = end
			continue
		}
		for _, route := range candidates[start:end] {
			if route.Blackhole || !isDirectDeviceRoute(route) {
				return direct, false
			}
		}
		direct = append(direct, candidates[start:end]...)
		coverage.add(segment)
		start = end
	}
	return direct, coverage.contains(network)
}

func isDirectDeviceRoute(route deviceRoute) bool {
	switch strings.ToLower(strings.TrimSpace(route.Protocol)) {
	case "connected", "connect", "local", "kernel", "direct", "c", "l":
		return true
	default:
		return false
	}
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
		if isDirectDeviceRoute(route) {
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
