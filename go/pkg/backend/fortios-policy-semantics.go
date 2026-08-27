package backend

import (
	"fmt"
	"sort"
	"strings"
)

// fortiOS74PolicySemanticDefaults is the versioned, fail-closed projection of
// FortiOS 7.4 firewall-policy state that can affect matching, forwarding,
// authentication, NAT or the effective allow/deny action. An omitted CMDB
// field is normalized to its documented default. Fields returned by FortiOS
// outside this projection are not silently discarded: only the explicit
// read-only/helper allowlist below is excluded.
func fortiOS74PolicySemanticDefaults() map[string]any {
	empty := func() any { return []any{} }
	return map[string]any{
		"name": "", "status": "enable", "action": "deny",
		"srcintf": empty(), "dstintf": empty(), "srcaddr": empty(), "dstaddr": empty(), "srcaddr6": empty(), "dstaddr6": empty(),
		"srcaddr-negate": "disable", "dstaddr-negate": "disable", "srcaddr6-negate": "disable", "dstaddr6-negate": "disable",
		"service": empty(), "service-negate": "disable", "schedule": "always", "comments": "", "logtraffic": "utm",
		"match-vip": "enable", "match-vip-only": "disable",
		"users": empty(), "groups": empty(), "fsso-groups": empty(), "src-vendor-mac": empty(),
		"reputation-minimum": 0, "reputation-direction": "destination", "reputation-minimum6": 0, "reputation-direction6": "destination",
		"vlan-filter": "", "tos": "0x00", "tos-mask": "0x00", "tos-negate": "disable",
		"sgt-check": "disable", "sgt": empty(),
		"ztna-status": "disable", "ztna-ems-tag": empty(), "ztna-ems-tag-secondary": empty(), "ztna-geo-tag": empty(),
		"ztna-policy-redirect": "disable", "ztna-device-ownership": "disable", "ztna-tags-match-logic": "or",
		"internet-service": "disable", "internet-service-src": "disable", "internet-service6": "disable", "internet-service6-src": "disable",
		"internet-service-negate": "disable", "internet-service-src-negate": "disable", "internet-service6-negate": "disable", "internet-service6-src-negate": "disable",
		"internet-service-name": empty(), "internet-service-custom": empty(), "internet-service-src-name": empty(), "internet-service-src-custom": empty(),
		"internet-service6-name": empty(), "internet-service6-custom": empty(), "internet-service6-src-name": empty(), "internet-service6-src-custom": empty(),
		"http-policy-redirect": "disable", "ssh-policy-redirect": "disable",
		"utm-status": "disable", "wccp": "disable", "webcache": "disable", "webcache-https": "disable", "wanopt": "disable",
		"identity-based-route": "", "rtp-nat": "disable",
		"nat": "disable", "nat46": "disable", "nat64": "disable", "ippool": "disable", "poolname": empty(), "poolname6": empty(), "fixedport": "disable", "port-preserve": "enable",
		"radius-mac-auth-bypass": "disable", "auth-path": "disable", "captive-portal-exempt": "disable",
		"permit-any-host": "disable", "permit-stun-host": "disable", "tcp-session-without-syn": "disable", "anti-replay": "enable",
		"geoip-anycast": "disable", "geoip-match": "physical-location", "policy-expiry": "disable",

		// Remaining configurable FortiOS 7.4 firewall-policy fields. Keeping
		// them in the projection prevents ordinary full CMDB GET responses from
		// being mistaken for schema drift, while a non-default value is still a
		// blocking semantic difference.
		"application-list": "", "auth-cert": "", "auth-redirect-addr": "", "auto-asic-offload": "enable", "av-profile": "",
		"block-notification": "disable", "capture-packet": "disable", "casb-profile": "", "cifs-profile": "", "custom-log-fields": empty(),
		"decrypted-traffic-mirror": "", "delay-tcp-npu-session": "disable", "diameter-filter-profile": "",
		"diffserv-copy": "disable", "diffserv-forward": "disable", "diffserv-reverse": "disable", "diffservcode-forward": "000000", "diffservcode-rev": "000000",
		"disclaimer": "disable", "dlp-profile": "", "dnsfilter-profile": "", "dsri": "disable", "dynamic-shaping": "disable",
		"email-collect": "disable", "emailfilter-profile": "", "fec": "disable", "file-filter-profile": "", "firewall-session-dirty": "check-all",
		"fsso-agent-for-ntlm": "", "icap-profile": "", "inbound": "disable", "inspection-mode": "flow",
		"internet-service-custom-group": empty(), "internet-service-group": empty(), "internet-service-src-custom-group": empty(), "internet-service-src-group": empty(),
		"internet-service6-custom-group": empty(), "internet-service6-group": empty(), "internet-service6-src-custom-group": empty(), "internet-service6-src-group": empty(),
		"ips-sensor": "", "ips-voip-filter": "", "logtraffic-start": "disable",
		"natinbound": "disable", "natip": "0.0.0.0 0.0.0.0", "natoutbound": "disable",
		"network-service-dynamic": empty(), "network-service-src-dynamic": empty(), "np-acceleration": "enable",
		"ntlm": "disable", "ntlm-enabled-browsers": empty(), "ntlm-guest": "disable", "outbound": "enable",
		"pcp-inbound": "disable", "pcp-outbound": "disable", "pcp-poolname": empty(), "per-ip-shaper": "",
		"policy-expiry-date": "0000-00-00 00:00:00", "policy-expiry-date-utc": "", "profile-group": "",
		"profile-protocol-options": "default", "profile-type": "single", "redirect-url": "", "replacemsg-override-group": "",
		"rtp-addr": empty(), "schedule-timeout": "disable", "sctp-filter-profile": "", "send-deny-packet": "disable", "session-ttl": 0,
		"ssh-filter-profile": "", "ssl-ssh-profile": "no-inspection", "tcp-mss-receiver": 0, "tcp-mss-sender": 0,
		"timeout-send-rst": "disable", "traffic-shaper": "", "traffic-shaper-reverse": "", "videofilter-profile": "", "virtual-patch-profile": "",
		"vlan-cos-fwd": 255, "vlan-cos-rev": 255, "voip-profile": "", "vpntunnel": "", "waf-profile": "",
		"wanopt-detection": "active", "wanopt-passive-opt": "default", "wanopt-peer": "", "wanopt-profile": "",
		"webfilter-profile": "", "webproxy-forward-server": "", "webproxy-profile": "",
		"passive-wan-health-measurement": "disable", "global-label": "", "label": "",
	}
}

var fortiOSPolicyReadOnlyFields = map[string]bool{
	"policyid":     true,
	"uuid":         true,
	"q_origin_key": true,
}

func fortiGateCommandDifferences(command deploymentCommand, expected, actual map[string]any) []string {
	switch command.Kind {
	case "policy":
		return fortiGatePolicySemanticDifferences(expected, actual)
	case "address", "address6":
		projection, known := fortiOS74AddressSemanticProjection(command.Kind, expected)
		return fortiGateProjectedObjectDifferences(projection, known, expected, actual)
	case "service":
		defaults := fortiOS74ServiceSemanticDefaults()
		return fortiGateProjectedObjectDifferences(defaults, defaults, expected, actual)
	default:
		return fortiGateDifferences(expected, actual)
	}
}

func fortiOS74AddressSemanticDefaults(kind string) map[string]any {
	if kind == "address6" {
		return map[string]any{
			"name": "", "type": "ipprefix", "ip6": "::/0", "start-ip": "::", "end-ip": "::", "fqdn": "", "country": "",
			"host": "::", "host-type": "any", "template": "", "macaddr": []any{}, "interface": "", "associated-interface": "",
			"cache-ttl": 0, "route-tag": 0, "sdn": "", "tenant": "", "epg-name": "", "sdn-tag": "", "filter": "",
			"sdn-addr-type": "private", "obj-id": "", "list": []any{}, "subnet-segment": []any{}, "tagging": []any{},
			"color": 0, "comment": "", "visibility": "enable", "allow-routing": "disable", "fabric-object": "disable",
		}
	}
	return map[string]any{
		"name": "", "type": "ipmask", "subnet": "0.0.0.0 0.0.0.0", "start-ip": "0.0.0.0", "end-ip": "0.0.0.0",
		"fqdn": "", "country": "", "wildcard": "0.0.0.0 0.0.0.0", "wildcard-fqdn": "", "macaddr": []any{},
		"start-mac": "00:00:00:00:00:00", "end-mac": "00:00:00:00:00:00", "interface": "", "associated-interface": "",
		"cache-ttl": 0, "route-tag": 0, "sub-type": "sdn", "clearpass-spt": "unknown", "sdn": "", "tenant": "",
		"organization": "", "epg-name": "", "subnet-name": "", "sdn-tag": "", "policy-group": "", "filter": "",
		"sdn-addr-type": "private", "obj-id": "", "obj-tag": "", "obj-type": "ip", "tag-detection-level": "", "tag-type": "",
		"hw-model": "", "hw-vendor": "", "os": "", "sw-version": "", "node-ip-only": "disable", "fsso-group": []any{},
		"list": []any{}, "tagging": []any{}, "color": 0, "comment": "", "visibility": "enable", "allow-routing": "disable", "fabric-object": "disable",
	}
}

// FortiOS returns values for inactive branches of its address type union. In
// the official full-GET example an ipmask object even carries non-default
// start-ip/end-ip/wildcard helper values. Compare universal fields plus only
// the active type branch; every documented inactive field remains known, so a
// truly unknown device/model field still fails closed.
func fortiOS74AddressSemanticProjection(kind string, expected map[string]any) (map[string]any, map[string]any) {
	known := fortiOS74AddressSemanticDefaults(kind)
	projection := map[string]any{}
	for _, field := range []string{"name", "type", "associated-interface", "color", "comment", "visibility", "allow-routing", "fabric-object", "tagging"} {
		if value, exists := known[field]; exists {
			projection[field] = value
		}
	}
	typeName := scalarString(expected["type"])
	if typeName == "" {
		typeName = scalarString(known["type"])
	}
	active := []string{}
	if kind == "address6" {
		switch typeName {
		case "ipprefix":
			active = []string{"ip6"}
		case "iprange":
			active = []string{"start-ip", "end-ip"}
		case "fqdn":
			active = []string{"fqdn", "cache-ttl"}
		case "geography":
			active = []string{"country"}
		case "dynamic":
			active = []string{"sdn", "tenant", "epg-name", "sdn-tag", "filter", "sdn-addr-type", "obj-id", "list"}
		case "template":
			active = []string{"template", "host", "host-type", "subnet-segment"}
		case "mac":
			active = []string{"macaddr"}
		case "route-tag":
			active = []string{"route-tag"}
		default:
			// Unknown discriminator values are already a type difference. Do not
			// guess which union branch could affect matching.
		}
	} else {
		switch typeName {
		case "ipmask":
			active = []string{"subnet"}
		case "iprange":
			active = []string{"start-ip", "end-ip"}
		case "fqdn":
			active = []string{"fqdn", "wildcard-fqdn", "cache-ttl"}
		case "geography":
			active = []string{"country"}
		case "wildcard":
			active = []string{"wildcard"}
		case "dynamic":
			active = []string{"sub-type", "clearpass-spt", "sdn", "fsso-group", "interface", "tenant", "organization", "epg-name", "subnet-name", "sdn-tag", "policy-group", "obj-tag", "obj-type", "filter", "sdn-addr-type", "obj-id", "node-ip-only", "hw-model", "hw-vendor", "os", "sw-version", "tag-detection-level", "tag-type", "list"}
		case "interface-subnet":
			active = []string{"interface"}
		case "mac":
			active = []string{"macaddr", "start-mac", "end-mac"}
		case "route-tag":
			active = []string{"route-tag"}
		}
	}
	for _, field := range active {
		projection[field] = known[field]
	}
	return projection, known
}

func fortiOS74ServiceSemanticDefaults() map[string]any {
	return map[string]any{
		"name": "", "protocol": "TCP/UDP/SCTP", "protocol-number": 0, "icmptype": 0, "icmpcode": 0,
		"tcp-portrange": "", "udp-portrange": "", "sctp-portrange": "", "iprange": "", "fqdn": "", "helper": "auto",
		"tcp-halfclose-timer": 0, "tcp-halfopen-timer": 0, "tcp-timewait-timer": 0, "tcp-rst-timer": 0, "udp-idle-timer": 0, "session-ttl": 0,
		"check-reset-range": "default", "proxy": "disable", "category": "", "color": 0, "comment": "", "visibility": "enable", "fabric-object": "disable",
		"app-service-type": "disable", "app-category": []any{}, "application": []any{},
	}
}

func fortiGateProjectedObjectDifferences(defaults, known, expected, actual map[string]any) []string {
	projection := make(map[string]any, len(defaults)+len(expected))
	for key, value := range defaults {
		projection[key] = value
	}
	for key, value := range expected {
		if !fortiOSPolicyReadOnlyFields[key] {
			if _, exists := projection[key]; !exists {
				projection[key] = value
			}
			if _, exists := known[key]; !exists {
				known[key] = value
			}
		}
	}
	wanted, observed := map[string]any{}, map[string]any{}
	for key, defaultValue := range projection {
		wanted[key], observed[key] = defaultValue, defaultValue
		if value, exists := expected[key]; exists {
			wanted[key] = value
		}
		if value, exists := actual[key]; exists {
			observed[key] = value
		}
	}
	differences := fortiGateDifferences(wanted, observed)
	for key := range actual {
		if fortiOSPolicyReadOnlyFields[key] {
			continue
		}
		if _, exists := known[key]; !exists {
			differences = append(differences, fmt.Sprintf("%s is an unreviewed FortiOS object field", key))
		}
	}
	sort.Strings(differences)
	if len(differences) > 20 {
		return append(differences[:20], "additional differences omitted")
	}
	return differences
}

func fortiGatePolicySemanticDifferences(expected, actual map[string]any) []string {
	defaults := fortiOS74PolicySemanticDefaults()
	// A field already present in an immutable legacy plan remains owned even if
	// it is not part of this release's projection. This preserves compatibility
	// without letting a new live-only field escape review.
	for key := range expected {
		if !fortiOSPolicyReadOnlyFields[key] {
			if _, known := defaults[key]; !known {
				defaults[key] = nil
			}
		}
	}
	wanted := make(map[string]any, len(defaults))
	observed := make(map[string]any, len(defaults))
	keys := make([]string, 0, len(defaults))
	for key := range defaults {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		defaultValue := defaults[key]
		wanted[key] = defaultValue
		if value, exists := expected[key]; exists {
			wanted[key] = value
		}
		observed[key] = defaultValue
		if value, exists := actual[key]; exists {
			observed[key] = value
		}
	}
	differences := fortiGateDifferences(wanted, observed)
	actualKeys := make([]string, 0, len(actual))
	for key := range actual {
		actualKeys = append(actualKeys, key)
	}
	sort.Strings(actualKeys)
	for _, key := range actualKeys {
		if fortiOSPolicyReadOnlyFields[key] {
			continue
		}
		if _, reviewed := defaults[key]; reviewed {
			continue
		}
		differences = append(differences, fmt.Sprintf("%s is an unreviewed FortiOS policy field", key))
	}
	if len(differences) > 20 {
		return append(differences[:20], "additional differences omitted")
	}
	return differences
}

func observedDeploymentState(command deploymentCommand, actual map[string]any) map[string]any {
	if command.Kind == "address" || command.Kind == "address6" || command.Kind == "service" {
		defaults := fortiOS74ServiceSemanticDefaults()
		if command.Kind != "service" {
			defaults, _ = fortiOS74AddressSemanticProjection(command.Kind, command.Payload)
		}
		for key, value := range command.Payload {
			if _, exists := defaults[key]; !exists {
				defaults[key] = value
			}
		}
		for key := range defaults {
			if value, exists := actual[key]; exists {
				defaults[key] = value
			}
		}
		return defaults
	}
	if command.Kind != "policy" {
		managed := make(map[string]any, len(command.Payload))
		for key, expected := range command.Payload {
			if value, exists := actual[key]; exists {
				managed[key] = value
			} else {
				managed[key] = expected
			}
		}
		return managed
	}
	defaults := fortiOS74PolicySemanticDefaults()
	for key, value := range command.Payload {
		if _, exists := defaults[key]; !exists {
			defaults[key] = value
		}
	}
	for key := range defaults {
		if value, exists := actual[key]; exists {
			defaults[key] = value
		}
	}
	return defaults
}

func validatePolicySemanticsVersion(command deploymentCommand) error {
	expected := ""
	switch command.Kind {
	case "policy":
		expected = fortiOSPolicySemanticsVersion
	case "address", "address6", "service":
		expected = fortiOSObjectSemanticsVersion
	default:
		return nil
	}
	if strings.TrimSpace(command.SemanticsVersion) != expected {
		return fmt.Errorf("policy command uses unsupported semantics projection %q", command.SemanticsVersion)
	}
	return nil
}
