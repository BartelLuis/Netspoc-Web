package backend

import (
	"maps"
	"net/http"
	"slices"
	"strings"
)

func (s *state) getNetworks(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwnerAccess(w, r, requestedActiveOwner(r)) {
		return
	}
	networks := s.generateNetworks(r)
	writeRecords(w, networks)
}

func (s *state) generateNetworks(r *http.Request) []*object {
	owner := r.FormValue("active_owner")
	if owner == "" {
		owner = getOwnerFromSession(r)
	}
	chosen := r.FormValue("chosen_networks")
	history := s.getHistoryParamOrCurrentPolicy(r)
	assets := s.loadAssets(history, owner)
	networkSet := make(map[string]bool, len(assets.networkList))
	for _, name := range assets.networkList {
		networkSet[name] = true
	}
	// The object table is authoritative. Merge it with the legacy assets index
	// so owned networks remain visible even when that index is stale.
	for name, object := range s.loadObjects(history) {
		if object.Owner == owner && strings.HasPrefix(name, "network:") {
			networkSet[name] = true
		}
	}
	networkNames := slices.Sorted(maps.Keys(networkSet))
	if chosen != "" {
		networkNames = untaintNetworks(chosen, assets)
	}
	return s.getCombinedObjList(networkNames, owner, history)
}

func (s *state) getNetworkResourcesForNetworks(r *http.Request, selected string) []jsonMap {
	var data []jsonMap
	owner := r.FormValue("active_owner")
	if owner == "" {
		owner = getOwnerFromSession(r)
	}
	history := s.getHistoryParamOrCurrentPolicy(r)
	assets := s.loadAssets(history, owner)
	networkNames := selectedNetworks(selected, assets)
	natSet := s.loadNATSet(history, owner)
	objects := s.loadObjects(history)
	for _, networkName := range networkNames {
		childNames := assets.net2childs[networkName]
		for _, childName := range childNames {
			obj, found := objects[childName]
			if !found {
				continue
			}
			entry := jsonMap{
				"name":       networkName,
				"child_ip":   s.name2IP(history, childName, natSet),
				"child_name": childName,
				"child_owner": map[string]string{
					"owner": obj.Owner,
				},
			}
			data = append(data, entry)
			ip6 := s.name2IP6(history, childName)
			if ip6 != "" {
				entry := jsonMap{
					"name":       networkName,
					"child_ip":   ip6,
					"child_name": childName,
					"child_owner": map[string]string{
						"owner": obj.Owner,
					},
				}
				data = append(data, entry)
			}
		}
	}
	return data
}

// selectedNetworks accepts values with or without the legacy "network:"
// prefix. On initial page load an empty selection means all visible networks.
func selectedNetworks(selected string, a *assets) []string {
	if strings.TrimSpace(selected) == "" {
		result := slices.Clone(a.networkList)
		slices.Sort(result)
		return result
	}
	parts := strings.Split(selected, ",")
	for i, name := range parts {
		name = strings.TrimSpace(name)
		if name != "" && !strings.HasPrefix(name, "network:") {
			name = "network:" + name
		}
		parts[i] = name
	}
	return intersect(parts, a.networkList)
}

func (s *state) getNetworkResources(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwnerAccess(w, r, requestedActiveOwner(r)) {
		return
	}
	selected := r.FormValue("selected_networks")
	result := s.getNetworkResourcesForNetworks(r, selected)
	writeRecords(w, result)
}

func (s *state) getNetworksAndResources(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwnerAccess(w, r, requestedActiveOwner(r)) {
		return
	}
	var result []jsonMap
	networks := s.generateNetworks(r)
	netsAsCSV := ""
	for _, network := range networks {
		netsAsCSV += network.Name + ","
	}
	type Network struct {
		Name     string    `json:"name"`
		IP       string    `json:"ip"`
		Owner    string    `json:"owner"`
		Children []jsonMap `json:"children"`
	}
	networkResources := s.getNetworkResourcesForNetworks(r, netsAsCSV)
	net2data := make(map[string]Network)
	for _, network := range networks {
		net2data[network.Name] = Network{
			Name:     network.Name,
			IP:       network.IP,
			Owner:    network.Owner,
			Children: []jsonMap{},
		}
	}
	for _, resource := range networkResources {
		child := jsonMap{
			"ip":    resource["child_ip"],
			"name":  resource["child_name"],
			"owner": resource["child_owner"].(map[string]string)["owner"],
		}
		name := resource["name"].(string)
		network := net2data[name]
		network.Children = append(network.Children, child)
		net2data[name] = network
	}
	keys := slices.Sorted(maps.Keys(net2data))
	for _, netName := range keys {
		result = append(result, jsonMap{
			"name":     netName,
			"ip":       net2data[netName].IP,
			"owner":    net2data[netName].Owner,
			"children": net2data[netName].Children,
		})
	}
	writeRecords(w, result)
}
