package backend

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

func newStableRuleID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil { panic(err) }
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func derivePolicyNames(p *editablePolicy) error {
	if len(p.TargetContexts) == 0 { return nil }
	normalizeCatalog(&p.NamingCatalog)
	allowedZones := map[string]bool{"EXT":true,"OeDMZ":true,"GDMZ":true,"IDMZ":true,"LAN":true,"MGMT":true,"VPN":true}
	tenants := map[string]tenant{}
	for _, t := range p.Tenants {
		if !mkzRE.MatchString(t.MKZ) || strings.TrimSpace(t.Name) == "" { return fmt.Errorf("ungültiger Mandant %q", t.MKZ) }
		if _, exists := tenants[t.MKZ]; exists { return fmt.Errorf("doppelte MKZ %q", t.MKZ) }
		tenants[t.MKZ] = t
	}
	contexts := map[string]targetContext{}
	for _, c := range p.TargetContexts {
		if c.Name == "" || (c.ContextType != "dedicated" && c.ContextType != "shared") { return fmt.Errorf("Zielkontext %q muss dedicated oder shared sein", c.Name) }
		if _, exists := contexts[c.Name]; exists { return fmt.Errorf("duplicate target context %q", c.Name) }
		if c.ContextType == "dedicated" {
			if !mkzRE.MatchString(c.AssignedMKZ) { return fmt.Errorf("dedizierter Zielkontext %q benötigt eine gültige assigned_mkz", c.Name) }
			if _, ok := tenants[c.AssignedMKZ]; !ok { return fmt.Errorf("Zielkontext %q referenziert unbekannte MKZ %q", c.Name, c.AssignedMKZ) }
		}
		contexts[c.Name] = c
	}
	zones := map[string]string{}
	for _, n := range p.Networks {
		if !allowedZones[n.Zone] { return fmt.Errorf("Netzwerk %q hat eine ungültige oder fehlende Zone", n.Name) }
		zones["network:"+n.Name] = n.Zone
		for _, h := range n.Hosts { zone := h.Zone; if zone == "" { zone = n.Zone }; if !allowedZones[zone] { return fmt.Errorf("Host %q hat eine ungültige Zone", h.Name) }; zones["host:"+h.Name] = zone }
	}
	for _, f := range p.FQDNs { if !allowedZones[f.Zone] { return fmt.Errorf("FQDN %q hat eine ungültige oder fehlende Zone", f.Name) }; zones["fqdn:"+f.Name] = f.Zone }
	usedIDs, usedNames := map[string]string{}, map[string]string{}
	groups := map[string]bool{"PUB":true,"USR":true,"SRV":true,"POS":true,"VPN":true,"INF":true,"TMP":true}
	for si := range p.Services {
		for ri := range p.Services[si].Rules {
			rule := &p.Services[si].Rules[ri]
			if !groups[rule.RuleGroup] { return fmt.Errorf("Dienst %q: ungültige Regelgruppe %q", p.Services[si].Name, rule.RuleGroup) }
			if rule.Owner == "" || rule.ChangeReference == "" || rule.Purpose == "" || !validISODate(rule.ReviewDate) { return fmt.Errorf("Dienst %q: Zweck, Owner, Change-Referenz und Reviewdatum sind erforderlich", p.Services[si].Name) }
			ctx, ok := contexts[rule.TargetContext]; if !ok { return fmt.Errorf("Dienst %q: unbekannter Zielkontext %q", p.Services[si].Name, rule.TargetContext) }
			mkz := ctx.AssignedMKZ
			if ctx.ContextType == "shared" { mkz = rule.TenantMKZ; t, exists := tenants[mkz]; if !exists || !t.Active { return fmt.Errorf("Shared-Regel benötigt eine aktive gültige MKZ") } }
			src, err := determineRuleZone(rule.Sources, zones); if err != nil { return fmt.Errorf("Dienst %q: %w", p.Services[si].Name, err) }
			dst, err := determineRuleZone(rule.Destinations, zones); if err != nil { return fmt.Errorf("Dienst %q: %w", p.Services[si].Name, err) }
			direction, err := determineDirection(src, dst, p.NamingCatalog.ZoneRanks); if err != nil { return err }
			serviceCode, err := determineServiceCode(rule.Protocols, p.NamingCatalog); if err != nil { return err }
			if !stableIDRE.MatchString(rule.StableRuleID) { rule.StableRuleID = newStableRuleID(); rule.ShortID = "" }
			if !shortIDRE.MatchString(rule.ShortID) || (usedIDs[ctx.Name+":"+rule.ShortID] != "" && usedIDs[ctx.Name+":"+rule.ShortID] != rule.StableRuleID) {
				for attempt := 0; ; attempt++ { candidate := shortIDCandidate(rule.StableRuleID, attempt); key := ctx.Name+":"+candidate; if usedIDs[key] == "" || usedIDs[key] == rule.StableRuleID { rule.ShortID = candidate; break } }
			}
			usedIDs[ctx.Name+":"+rule.ShortID] = rule.StableRuleID
			name, err := makePolicyName(rule.RuleGroup, mkz, src, dst, serviceCode, direction, rule.ShortID, ctx.ContextType == "shared", p.NamingCatalog); if err != nil { return err }
			nameKey := ctx.Name+":"+name; if prior := usedNames[nameKey]; prior != "" && prior != rule.StableRuleID { return fmt.Errorf("Policy-Name %q ist im Zielkontext %q bereits vergeben", name, ctx.Name) }
			comment, err := generatePolicyComment(rule, direction); if err != nil { return err }
			rule.PolicyName, rule.PolicyComment, rule.NamingVersion = name, comment, p.NamingCatalog.Version
			usedNames[nameKey] = rule.StableRuleID
		}
	}
	return nil
}

const currentNamingVersion = "fortigate-v1"

var (
	mkzRE       = regexp.MustCompile(`^M(00[1-9]|0[1-9][0-9]|[1-9][0-9]{2})$`)
	shortIDRE   = regexp.MustCompile(`^[0-9A-F]{5}$`)
	policyNameAllowedRE = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	stableIDRE  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
)

type tenant struct {
	MKZ    string `json:"mkz"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

type targetContext struct {
	Name        string `json:"name"`
	ContextType string `json:"context_type"`
	AssignedMKZ string `json:"assigned_mkz,omitempty"`
}

type namingCatalog struct {
	Version          string            `json:"version"`
	ZoneRanks        map[string]int    `json:"zone_ranks"`
	ZoneShortCodes   map[string]string `json:"zone_short_codes"`
	ServiceCodes     map[string]string `json:"service_codes"`
	ServiceShortCodes map[string]string `json:"service_short_codes"`
}

func defaultNamingCatalog() namingCatalog {
	return namingCatalog{
		Version: currentNamingVersion,
		ZoneRanks: map[string]int{"EXT": 0, "OeDMZ": 1, "GDMZ": 2, "IDMZ": 3, "LAN": 3, "MGMT": 4, "VPN": 1},
		ZoneShortCodes: map[string]string{"OeDMZ": "OD", "GDMZ": "GD", "IDMZ": "ID"},
		ServiceCodes: map[string]string{
			"tcp 443": "h", "https": "h", "tcp 1433": "sql", "mssql": "sql",
			"tcp 445": "smb", "smb": "smb", "dns": "dns", "tcp 53": "dns", "udp 53": "dns",
			"tcp 3389": "rdp", "rdp": "rdp", "microsoft 365-servicegruppe": "m365", "microsoft-365": "m365", "m365": "m365",
		},
		ServiceShortCodes: map[string]string{"HTTPS": "h", "MSSQL": "sql", "Microsoft-365": "m365"},
	}
}

func normalizeCatalog(c *namingCatalog) {
	defaults := defaultNamingCatalog()
	if c.Version == "" { c.Version = defaults.Version }
	if c.ZoneRanks == nil { c.ZoneRanks = defaults.ZoneRanks }
	if c.ZoneShortCodes == nil { c.ZoneShortCodes = defaults.ZoneShortCodes }
	if c.ServiceCodes == nil { c.ServiceCodes = defaults.ServiceCodes }
	if c.ServiceShortCodes == nil { c.ServiceShortCodes = defaults.ServiceShortCodes }
}

func canonicalProtocolKey(protocols []string) string {
	values := make([]string, 0, len(protocols))
	for _, value := range protocols {
		value = strings.ToLower(strings.Join(strings.Fields(value), " "))
		if value != "" { values = append(values, value) }
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func determineServiceCode(protocols []string, catalog namingCatalog) (string, error) {
	key := canonicalProtocolKey(protocols)
	if code := catalog.ServiceCodes[key]; code != "" { return code, nil }
	if len(protocols) == 1 {
		if code := catalog.ServiceCodes[strings.ToLower(strings.TrimSpace(protocols[0]))]; code != "" { return code, nil }
	}
	return "", fmt.Errorf("für die Protokollkombination %q ist kein Servicecode definiert", key)
}

func determineObjectZone(ref string, zones map[string]string) (string, error) {
	zone := strings.TrimSpace(zones[ref])
	if zone == "" { return "", fmt.Errorf("Objekt %q hat keine Zonenzuordnung", ref) }
	return zone, nil
}

func determineRuleZone(refs []string, zones map[string]string) (string, error) {
	var result string
	for _, ref := range refs {
		zone, err := determineObjectZone(ref, zones)
		if err != nil { return "", err }
		if result != "" && result != zone { return "", fmt.Errorf("Objekte liegen in mehreren Zonen (%s und %s)", result, zone) }
		result = zone
	}
	if result == "" { return "", fmt.Errorf("Zone kann ohne Objekt nicht ermittelt werden") }
	return result, nil
}

func determineDirection(src, dst string, ranks map[string]int) (string, error) {
	srcRank, srcOK := ranks[src]
	dstRank, dstOK := ranks[dst]
	if !srcOK || !dstOK { return "", fmt.Errorf("Zonenrang für %s oder %s ist nicht konfiguriert", src, dst) }
	switch { case dstRank > srcRank: return "in", nil; case srcRank > dstRank: return "out", nil; default: return "ew", nil }
}

func policyType(direction string) string {
	switch direction { case "in": return "INGRESS"; case "out": return "EGRESS"; default: return "EASTWEST" }
}

func shortIDCandidate(stableID string, attempt int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", stableID, attempt)))
	return strings.ToUpper(fmt.Sprintf("%x", sum[:]))[:5]
}

func makePolicyName(group, mkz, src, dst, service, direction, shortID string, shared bool, catalog namingCatalog) (string, error) {
	parts := []string{group}
	if shared { parts = append(parts, mkz) }
	parts = append(parts, src, dst, service, direction, shortID)
	name := strings.Join(parts, "_")
	if len(name) > 35 {
		if value := catalog.ZoneShortCodes[src]; value != "" { parts[len(parts)-5] = value }
		if value := catalog.ZoneShortCodes[dst]; value != "" { parts[len(parts)-4] = value }
		if value := catalog.ServiceShortCodes[service]; value != "" { parts[len(parts)-3] = value }
		name = strings.Join(parts, "_")
	}
	if len(name) > 35 { return "", fmt.Errorf("der generierte Policy-Name %q überschreitet 35 Zeichen", name) }
	if !policyNameAllowedRE.MatchString(name) { return "", fmt.Errorf("der generierte Policy-Name %q enthält unzulässige Zeichen", name) }
	return name, nil
}

func generatePolicyComment(rule *editableRule, direction string) (string, error) {
	if rule.RuleGroup == "TMP" {
		if rule.ExpiresAt == "" || rule.RollbackOwner == "" { return "", fmt.Errorf("TMP-Regeln benötigen Ablaufdatum und Rückbauverantwortlichen") }
		if !validISODate(rule.ExpiresAt) { return "", fmt.Errorf("TMP rule requires a valid expiry date") }
		return fmt.Sprintf("Type: %s | Zweck: %s | Owner: %s | CHG: %s | Expires: %s | Rollback: %s", policyType(direction), rule.Purpose, rule.Owner, rule.ChangeReference, rule.ExpiresAt, rule.RollbackOwner), nil
	}
	return fmt.Sprintf("Type: %s | Zweck: %s | Owner: %s | CHG: %s | Review: %s", policyType(direction), rule.Purpose, rule.Owner, rule.ChangeReference, rule.ReviewDate), nil
}

func validISODate(value string) bool {
	_, err := time.Parse("2006-01-02", value)
	return err == nil
}
