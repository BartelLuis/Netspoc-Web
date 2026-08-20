package backend

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
)

type editablePolicy struct {
	Name     string            `json:"name"`
	Owners   []editableOwner   `json:"owners"`
	Users    []editableUser    `json:"users"`
	Networks []editableNetwork `json:"networks"`
	FQDNs    []editableFQDN    `json:"fqdns"`
	Services []editableService `json:"services"`
}

type editableOwner struct {
	Name       string   `json:"name"`
	Parent     string   `json:"parent,omitempty"`
	ReadAll    bool     `json:"read_all,omitempty"`
	ReadOwners []string `json:"read_owners,omitempty"`
	Users      []string `json:"users,omitempty"`
	Admins     []string `json:"admins"`
	Watchers   []string `json:"watchers"`
}

type editableUser struct {
	Email    string `json:"email"`
	Role     string `json:"role"`
	Password string `json:"password,omitempty"`
}

type editableNetwork struct {
	Name  string         `json:"name"`
	CIDR  string         `json:"cidr"`
	Owner string         `json:"owner"`
	Hosts []editableHost `json:"hosts"`
}

type editableHost struct {
	Name  string `json:"name"`
	IP    string `json:"ip"`
	Owner string `json:"owner,omitempty"`
}

type editableFQDN struct {
	Name  string `json:"name"`
	FQDN  string `json:"fqdn"`
	Owner string `json:"owner"`
}

type editableService struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Owners      []string       `json:"owners"`
	Rules       []editableRule `json:"rules"`
}

type editableRule struct {
	Action       string   `json:"action"`
	HasUser      string   `json:"has_user"`
	Sources      []string `json:"sources"`
	Destinations []string `json:"destinations"`
	Protocols    []string `json:"protocols"`
}

var policyNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)

func (s *state) adminStatus(w http.ResponseWriter, r *http.Request) {
	initialized := s.policyInitialized()
	result := map[string]any{"success": true, "initialized": initialized}
	if initialized && loggedIn(r) {
		result["authenticated"] = true
		p := s.readDraft()
		role := policyRole(p, getEmailFromSession(r))
		result["role"] = role
		if role == "admin" || role == "editor" {
			result["policy"] = p
			if revisions, err := s.listRevisions(); err == nil {
				result["revisions"] = revisions
			}
		}
	}
	writeJSON(w, result)
}

func (s *state) adminBootstrap(w http.ResponseWriter, r *http.Request) {
	if s.policyInitialized() {
		writeError(w, "Policy administration is already initialized", http.StatusForbidden)
		return
	}
	p, err := decodePolicy(r)
	if err == nil {
		err = s.publishPolicy(p)
	}
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"success": true})
}

func (s *state) adminPolicy(w http.ResponseWriter, r *http.Request) {
	p := s.readDraft()
	if !hasPolicyRole(p, getEmailFromSession(r), "admin", "editor") {
		writeError(w, "Policy editor role required", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"success": true, "policy": s.readDraft()})
	case http.MethodPost:
		p, err := decodePolicy(r)
		if err == nil {
			err = s.saveDraft(p)
		}
		if err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"success": true})
	default:
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *state) adminDiff(w http.ResponseWriter, r *http.Request) {
	current := s.readDraft()
	if !hasPolicyRole(current, getEmailFromSession(r), "admin", "editor") {
		writeError(w, "Policy editor role required", http.StatusForbidden)
		return
	}
	p, err := decodePolicy(r)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	previous, err := s.latestPublication()
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	baseVersion, err := s.latestPublicationVersion()
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	version := newPolicyVersion()
	changes := diffPolicies(previous, p)
	hash, err := approvalHash(version, previous, p)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.storeRevision(version, baseVersion, p, changes); err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"success": true, "policy_id": version, "approval": hash, "changes": changes})
}

func (s *state) adminPublish(w http.ResponseWriter, r *http.Request) {
	current := s.readDraft()
	if !hasPolicyRole(current, getEmailFromSession(r), "admin") {
		writeError(w, "Policy administrator role required", http.StatusForbidden)
		return
	}
	defer r.Body.Close()
	var request struct {
		PolicyID string `json:"policy_id"`
		Approval string `json:"approval"`
	}
	err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&request)
	var revision *editablePolicy
	var revisionBase string
	if err == nil && request.PolicyID == "" {
		err = errors.New("policy_id is required")
	}
	if err == nil {
		revision, revisionBase, err = s.loadRevision(request.PolicyID)
	}
	p := revision
	if err == nil {
		err = validateEditablePolicy(p)
	}
	previous, previousErr := s.latestPublication()
	if err == nil && previousErr != nil {
		err = previousErr
	}
	currentBase, baseErr := s.latestPublicationVersion()
	if err == nil && baseErr != nil {
		err = baseErr
	}
	if err == nil && revisionBase != currentBase {
		err = errors.New("the base policy changed; create a new diff")
	}
	var hash string
	if err == nil {
		hash, err = approvalHash(request.PolicyID, previous, p)
	}
	if err == nil && (request.Approval == "" || request.Approval != hash) {
		err = errors.New("policy changed after diff approval; create and confirm a new diff")
	}
	if err == nil {
		err = s.publishPolicyVersion(p, request.PolicyID)
	}
	if err == nil {
		err = s.markRevisionPublished(request.PolicyID)
	}
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"success": true})
}

func (s *state) adminRevision(w http.ResponseWriter, r *http.Request) {
	current := s.readDraft()
	if !hasPolicyRole(current, getEmailFromSession(r), "admin", "editor") {
		writeError(w, "Policy editor role required", http.StatusForbidden)
		return
	}
	version := r.FormValue("policy_id")
	p, base, err := s.loadRevision(version)
	currentBase, baseErr := s.latestPublicationVersion()
	if err == nil && baseErr != nil {
		err = baseErr
	}
	if err == nil && base != currentBase {
		err = errors.New("the base policy changed; create a new diff")
	}
	previous, previousErr := s.latestPublication()
	if err == nil && previousErr != nil {
		err = previousErr
	}
	var approval string
	if err == nil {
		approval, err = approvalHash(version, previous, p)
	}
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"success": true, "policy_id": version, "policy": p, "approval": approval, "changes": diffPolicies(previous, p)})
}

func policyRole(p *editablePolicy, email string) string {
	email = strings.ToLower(email)
	for i, user := range p.Users {
		if strings.ToLower(user.Email) == email {
			if user.Role == "" && i == 0 {
				return "admin"
			}
			if user.Role == "" {
				return "viewer"
			}
			return user.Role
		}
	}
	return ""
}

func hasPolicyRole(p *editablePolicy, email string, roles ...string) bool {
	return slices.Contains(roles, policyRole(p, email))
}

func decodePolicy(r *http.Request) (*editablePolicy, error) {
	defer r.Body.Close()
	var p editablePolicy
	dec := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	return &p, validateEditablePolicy(&p)
}

func validateEditablePolicy(p *editablePolicy) error {
	normalizeEditablePolicy(p)
	if !policyNameRE.MatchString(p.Name) {
		return errors.New("policy name is required and may contain letters, digits, '.', '_', ':' and '-'")
	}
	owners := map[string]bool{}
	users := map[string]bool{}
	objects := map[string]bool{}
	for i := range p.Owners {
		o := &p.Owners[i]
		if !policyNameRE.MatchString(o.Name) || owners[o.Name] {
			return fmt.Errorf("invalid or duplicate owner %q", o.Name)
		}
		owners[o.Name] = true
		for j := range o.ReadOwners {
			o.ReadOwners[j] = strings.TrimSpace(o.ReadOwners[j])
		}
	}
	for i := range p.Users {
		p.Users[i].Email = strings.ToLower(strings.TrimSpace(p.Users[i].Email))
		email := p.Users[i].Email
		if p.Users[i].Role == "" {
			if i == 0 {
				p.Users[i].Role = "admin"
			} else {
				p.Users[i].Role = "viewer"
			}
		}
		if !slices.Contains([]string{"admin", "editor", "viewer"}, p.Users[i].Role) {
			return fmt.Errorf("user %q has invalid role %q", email, p.Users[i].Role)
		}
		if !strings.Contains(email, "@") || users[email] {
			return fmt.Errorf("invalid or duplicate user %q", email)
		}
		users[email] = true
	}
	hasAdmin := false
	for i := range p.Owners {
		for j := range p.Owners[i].Admins {
			p.Owners[i].Admins[j] = strings.ToLower(strings.TrimSpace(p.Owners[i].Admins[j]))
		}
		for j := range p.Owners[i].Users {
			p.Owners[i].Users[j] = strings.ToLower(strings.TrimSpace(p.Owners[i].Users[j]))
		}
		for j := range p.Owners[i].Watchers {
			p.Owners[i].Watchers[j] = strings.ToLower(strings.TrimSpace(p.Owners[i].Watchers[j]))
		}
		if len(p.Owners[i].Admins) != 0 {
			hasAdmin = true
		}
		assigned := slices.Concat(p.Owners[i].Admins, p.Owners[i].Users, p.Owners[i].Watchers)
		for _, email := range assigned {
			if email != "guest" && !users[strings.ToLower(email)] {
				return fmt.Errorf("owner %q references unknown user %q", p.Owners[i].Name, email)
			}
		}
	}
	if len(p.Owners) == 0 || len(p.Users) == 0 {
		return errors.New("at least one owner and one user are required")
	}
	if !hasAdmin {
		return errors.New("at least one owner administrator is required")
	}
	hasPolicyAdmin := false
	for _, user := range p.Users {
		if user.Role == "admin" {
			hasPolicyAdmin = true
		}
	}
	if !hasPolicyAdmin {
		return errors.New("at least one policy administrator is required")
	}
	for _, owner := range p.Owners {
		if owner.Parent != "" && !owners[owner.Parent] {
			return fmt.Errorf("owner %q references unknown parent %q", owner.Name, owner.Parent)
		}
		seen := map[string]bool{owner.Name: true}
		parent := owner.Parent
		for parent != "" {
			if seen[parent] {
				return fmt.Errorf("owner hierarchy contains a cycle at %q", parent)
			}
			seen[parent] = true
			for _, candidate := range p.Owners {
				if candidate.Name == parent {
					parent = candidate.Parent
					break
				}
			}
		}
		readOwners := map[string]bool{}
		for _, readable := range owner.ReadOwners {
			if readable == "" {
				return fmt.Errorf("owner %q contains an empty readable owner", owner.Name)
			}
			if readable == owner.Name {
				return fmt.Errorf("owner %q must not grant read access to itself", owner.Name)
			}
			if !owners[readable] {
				return fmt.Errorf("owner %q references unknown readable owner %q", owner.Name, readable)
			}
			if readOwners[readable] {
				return fmt.Errorf("owner %q contains duplicate readable owner %q", owner.Name, readable)
			}
			readOwners[readable] = true
		}
	}
	for i := range p.Networks {
		n := &p.Networks[i]
		if !policyNameRE.MatchString(n.Name) || objects["network:"+n.Name] {
			return fmt.Errorf("invalid or duplicate network %q", n.Name)
		}
		if !owners[n.Owner] {
			return fmt.Errorf("network %q references unknown owner %q", n.Name, n.Owner)
		}
		_, ipNet, err := net.ParseCIDR(n.CIDR)
		if err != nil {
			return fmt.Errorf("network %q has invalid CIDR: %w", n.Name, err)
		}
		objects["network:"+n.Name] = true
		for j := range p.Networks[i].Hosts {
			h := &p.Networks[i].Hosts[j]
			h.IP = strings.TrimSpace(h.IP)
			if h.IP == "" {
				return fmt.Errorf("network %q contains a host without an IP address", n.Name)
			}
			if h.Name == "" {
				h.Name = hostNameFromIP(h.IP)
			}
			if h.Owner == "" {
				return fmt.Errorf("host %q requires an explicit owner", h.Name)
			}
			if !owners[h.Owner] {
				return fmt.Errorf("host %q references unknown owner %q", h.Name, h.Owner)
			}
			hostIP := net.ParseIP(h.IP)
			if hostIP == nil {
				return fmt.Errorf("host %q has invalid IP address %q", h.Name, h.IP)
			}
			if !policyNameRE.MatchString(h.Name) {
				return fmt.Errorf("host name %q is invalid", h.Name)
			}
			if objects["host:"+h.Name] {
				return fmt.Errorf("duplicate host name %q", h.Name)
			}
			if !ipNet.Contains(hostIP) {
				return fmt.Errorf("host %q is outside network %q", h.Name, n.Name)
			}
			objects["host:"+h.Name] = true
		}
	}
	fqdnValues := map[string]bool{}
	for i := range p.FQDNs {
		f := &p.FQDNs[i]
		if !policyNameRE.MatchString(f.Name) || objects["fqdn:"+f.Name] {
			return fmt.Errorf("invalid or duplicate FQDN object %q", f.Name)
		}
		if !owners[f.Owner] {
			return fmt.Errorf("FQDN object %q references unknown owner %q", f.Name, f.Owner)
		}
		fqdn, err := canonicalFQDN(f.FQDN)
		if err != nil {
			return fmt.Errorf("FQDN object %q has invalid FQDN %q: %w", f.Name, f.FQDN, err)
		}
		if fqdnValues[fqdn] {
			return fmt.Errorf("duplicate FQDN %q", fqdn)
		}
		f.FQDN = fqdn
		fqdnValues[fqdn] = true
		objects["fqdn:"+f.Name] = true
	}
	services := map[string]bool{}
	for _, svc := range p.Services {
		if !policyNameRE.MatchString(svc.Name) || services[svc.Name] {
			return fmt.Errorf("invalid or duplicate service %q", svc.Name)
		}
		services[svc.Name] = true
		if len(svc.Owners) == 0 {
			return fmt.Errorf("service %q requires at least one owner", svc.Name)
		}
		for _, owner := range svc.Owners {
			if !owners[owner] {
				return fmt.Errorf("service %q references unknown owner %q", svc.Name, owner)
			}
		}
		for _, rule := range svc.Rules {
			if rule.Action != "permit" && rule.Action != "deny" {
				return fmt.Errorf("service %q rule action must be permit or deny", svc.Name)
			}
			if !slices.Contains([]string{"src", "dst", "both", "none"}, rule.HasUser) {
				return fmt.Errorf("service %q rule has invalid user side %q", svc.Name, rule.HasUser)
			}
			if len(rule.Sources) == 0 || len(rule.Destinations) == 0 || len(rule.Protocols) == 0 {
				return fmt.Errorf("service %q rules require source, destination and protocol", svc.Name)
			}
			for _, ref := range rule.Sources {
				if strings.HasPrefix(ref, "fqdn:") {
					return fmt.Errorf("service %q may only use FQDN object %q as a destination", svc.Name, ref)
				}
				if !objects[ref] {
					return fmt.Errorf("service %q references unknown object %q", svc.Name, ref)
				}
			}
			for _, ref := range rule.Destinations {
				if !objects[ref] {
					return fmt.Errorf("service %q references unknown object %q", svc.Name, ref)
				}
			}
		}
	}
	return nil
}

func hostNameFromIP(ip string) string {
	replacer := strings.NewReplacer(".", "-", ":", "-", "%", "-")
	return "ip-" + replacer.Replace(strings.TrimSpace(ip))
}

func canonicalFQDN(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	if len(value) == 0 || len(value) > 253 || !strings.Contains(value, ".") || net.ParseIP(value) != nil {
		return "", errors.New("expected a fully-qualified DNS name")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", errors.New("DNS labels must contain between 1 and 63 characters")
		}
		for i, char := range label {
			isAlphaNumeric := char >= 'a' && char <= 'z' || char >= '0' && char <= '9'
			if !isAlphaNumeric && (char != '-' || i == 0 || i == len(label)-1) {
				return "", errors.New("DNS labels may only contain letters, digits and interior hyphens")
			}
		}
	}
	return value, nil
}

func ownerIsWithin(ownerByName map[string]editableOwner, child, ancestor string) bool {
	seen := map[string]bool{}
	for child != "" && !seen[child] {
		if child == ancestor {
			return true
		}
		seen[child] = true
		owner, ok := ownerByName[child]
		if !ok {
			return false
		}
		child = owner.Parent
	}
	return false
}

// ownerScopeContains reports whether target is part of reader's effective
// view. Explicit grants include the target's regular hierarchy descendants,
// but deliberately do not follow any read grants configured on that target.
func ownerScopeContains(ownerByName map[string]editableOwner, reader, target string) bool {
	if ownerIsWithin(ownerByName, target, reader) {
		return true
	}
	readerOwner, ok := ownerByName[reader]
	if !ok {
		return false
	}
	if readerOwner.ReadAll {
		return true
	}
	for _, readable := range readerOwner.ReadOwners {
		if ownerIsWithin(ownerByName, target, readable) {
			return true
		}
	}
	return false
}

func approvalHash(policyID string, previous, next *editablePolicy) (string, error) {
	data, err := json.Marshal(struct {
		PolicyID string          `json:"policy_id"`
		Previous *editablePolicy `json:"previous"`
		Next     *editablePolicy `json:"next"`
	}{policyID, previous, next})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func diffPolicies(old, next *editablePolicy) []map[string]string {
	result := []map[string]string{}
	diffNamed := func(kind string, oldItems, newItems any) {
		oldMap := namedItems(oldItems)
		newMap := namedItems(newItems)
		for name, item := range newMap {
			change := "added"
			if previous, ok := oldMap[name]; ok {
				if reflect.DeepEqual(previous, item) {
					continue
				}
				change = "changed"
			}
			result = append(result, map[string]string{"type": kind, "name": name, "change": change})
		}
		for name := range oldMap {
			if _, ok := newMap[name]; !ok {
				result = append(result, map[string]string{"type": kind, "name": name, "change": "removed"})
			}
		}
	}
	if old == nil {
		old = &editablePolicy{}
	}
	diffNamed("user", old.Users, next.Users)
	diffNamed("owner", old.Owners, next.Owners)
	diffNamed("network", old.Networks, next.Networks)
	diffNamed("fqdn", old.FQDNs, next.FQDNs)
	diffNamed("service", old.Services, next.Services)
	slices.SortFunc(result, func(a, b map[string]string) int { return strings.Compare(a["type"]+a["name"], b["type"]+b["name"]) })
	return result
}

func namedItems(items any) map[string]any {
	result := map[string]any{}
	data, _ := json.Marshal(items)
	var values []map[string]any
	_ = json.Unmarshal(data, &values)
	for _, value := range values {
		name, _ := value["name"].(string)
		if name == "" {
			name, _ = value["email"].(string)
		}
		result[name] = value
	}
	return result
}

func (s *state) policyInitialized() bool {
	_, err := os.Stat(filepath.Join(s.config.NetspocData, "current", "email"))
	return err == nil
}

func (s *state) draftPath() string { return filepath.Join(s.config.NetspocData, "draft.json") }

func (s *state) readDraft() *editablePolicy {
	p, err := s.loadPolicyDraft()
	if err != nil {
		return &editablePolicy{Name: "policy"}
	}
	return p
}

func (s *state) saveDraft(p *editablePolicy) error {
	for i := range p.Users {
		p.Users[i].Password = ""
	}
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	return s.storePolicyDraft(db, p)
}

func (s *state) publishPolicy(p *editablePolicy) error {
	return s.publishPolicyVersion(p, newPolicyVersion())
}

func newPolicyVersion() string {
	return "p" + time.Now().UTC().Format("20060102T150405.000000000")
}

func (s *state) publishPolicyVersion(p *editablePolicy, version string) error {
	normalizeEditablePolicy(p)
	for _, u := range p.Users {
		if u.Password != "" {
			if err := SetUserPassword(s.config.UserDir, u.Email, u.Password); err != nil {
				return err
			}
		} else if _, err := os.Stat(filepath.Join(s.config.UserDir, u.Email)); err != nil {
			return fmt.Errorf("password is required for new user %s", u.Email)
		}
	}
	dir := filepath.Join(s.config.NetspocData, version)
	if err := os.MkdirAll(filepath.Join(dir, "owner"), 0750); err != nil {
		return err
	}
	emails := map[string][]string{}
	objects := map[string]any{}
	services := map[string]any{}
	ownerServices := map[string][]string{}
	ownerNetworks := map[string][]string{}
	ownerFQDNs := map[string][]string{}
	objectOwners := map[string]string{}
	ownerServiceUsers := map[string]map[string][]string{}
	networkChildren := map[string][]string{}
	networkOwner := map[string]string{}
	hostOwnerByName := map[string]string{}
	ownerByName := map[string]editableOwner{}
	for _, o := range p.Owners {
		ownerByName[o.Name] = o
	}
	for _, child := range p.Owners {
		// Membership in an ancestor grants read access to every descendant.
		for ancestor := child.Name; ancestor != ""; ancestor = ownerByName[ancestor].Parent {
			o := ownerByName[ancestor]
			for _, email := range append(slices.Clone(o.Admins), o.Users...) {
				emails[strings.ToLower(email)] = append(emails[strings.ToLower(email)], child.Name)
			}
		}
	}
	for email, authorizedOwners := range emails {
		slices.Sort(authorizedOwners)
		emails[email] = slices.Compact(authorizedOwners)
	}
	for _, n := range p.Networks {
		key := "network:" + n.Name
		objects[key] = map[string]any{"ip": n.CIDR, "zone": "", "owner": n.Owner}
		objectOwners[key] = n.Owner
		networkOwner[key] = n.Owner
		ownerNetworks[n.Owner] = append(ownerNetworks[n.Owner], key)
		for _, h := range n.Hosts {
			hostOwner := h.Owner
			name := "host:" + h.Name
			objects[name] = map[string]any{"ip": h.IP, "zone": "", "owner": hostOwner}
			objectOwners[name] = hostOwner
			networkChildren[key] = append(networkChildren[key], name)
			hostOwnerByName[name] = hostOwner
			// A responsibility owning an address needs its containing network in
			// the assets index so the legacy network view can display the address.
			ownerNetworks[hostOwner] = append(ownerNetworks[hostOwner], key)
		}
	}
	for _, f := range p.FQDNs {
		name := "fqdn:" + f.Name
		objects[name] = map[string]any{"fqdn": f.FQDN, "zone": "", "owner": f.Owner}
		objectOwners[name] = f.Owner
		ownerFQDNs[f.Owner] = append(ownerFQDNs[f.Owner], name)
	}
	for _, svc := range p.Services {
		rules := []map[string]any{}
		for _, rule := range svc.Rules {
			exportedHasUser := rule.HasUser
			if exportedHasUser == "none" {
				exportedHasUser = ""
			}
			rules = append(rules, map[string]any{"action": rule.Action, "src": rule.Sources, "dst": rule.Destinations, "prt": rule.Protocols, "has_user": exportedHasUser})

			userObjects := []string{}
			switch rule.HasUser {
			case "src":
				userObjects = rule.Sources
			case "dst":
				userObjects = rule.Destinations
			case "both":
				userObjects = slices.Concat(slices.Clone(rule.Sources), rule.Destinations)
			}
			for _, objectName := range userObjects {
				owner := objectOwners[objectName]
				if ownerServiceUsers[owner] == nil {
					ownerServiceUsers[owner] = map[string][]string{}
				}
				ownerServiceUsers[owner][svc.Name] = append(ownerServiceUsers[owner][svc.Name], objectName)
			}
		}
		services[svc.Name] = map[string]any{"Details": map[string]any{"Description": svc.Description, "Owner": svc.Owners}, "Rules": rules}
		for _, owner := range svc.Owners {
			ownerServices[owner] = append(ownerServices[owner], svc.Name)
		}
	}
	if err := writeJSONFile(filepath.Join(dir, "email"), emails); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "objects"), objects); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "services"), services); err != nil {
		return err
	}
	// The legacy reader uses the first token in POLICY as the directory key,
	// not merely as a display name. It must therefore match the generated
	// version directory exactly.
	if err := os.WriteFile(filepath.Join(dir, "POLICY"), []byte("# "+version+" #\n"), 0640); err != nil {
		return err
	}
	for _, o := range p.Owners {
		od := filepath.Join(dir, "owner", o.Name)
		if err := os.MkdirAll(od, 0750); err != nil {
			return err
		}
		effectiveServices := []string{}
		effectiveUserServices := []string{}
		effectiveUsers := map[string][]string{}
		effectiveNetworks := []string{}
		effectiveFQDNs := []string{}
		for child, names := range ownerServices {
			if ownerScopeContains(ownerByName, o.Name, child) {
				effectiveServices = append(effectiveServices, names...)
			}
		}
		for child, names := range ownerNetworks {
			if ownerScopeContains(ownerByName, o.Name, child) {
				effectiveNetworks = append(effectiveNetworks, names...)
			}
		}
		for child, names := range ownerFQDNs {
			if ownerScopeContains(ownerByName, o.Name, child) {
				effectiveFQDNs = append(effectiveFQDNs, names...)
			}
		}
		for child, serviceUsers := range ownerServiceUsers {
			if !ownerScopeContains(ownerByName, o.Name, child) {
				continue
			}
			for serviceName, objectNames := range serviceUsers {
				effectiveUsers[serviceName] = append(effectiveUsers[serviceName], objectNames...)
			}
		}
		for serviceName, objectNames := range effectiveUsers {
			slices.Sort(objectNames)
			effectiveUsers[serviceName] = slices.Compact(objectNames)
			effectiveUserServices = append(effectiveUserServices, serviceName)
		}
		slices.Sort(effectiveServices)
		effectiveServices = slices.Compact(effectiveServices)
		slices.Sort(effectiveUserServices)
		slices.Sort(effectiveNetworks)
		effectiveNetworks = slices.Compact(effectiveNetworks)
		slices.Sort(effectiveFQDNs)
		effectiveFQDNs = slices.Compact(effectiveFQDNs)
		extendedBy := []map[string]string{}
		if o.Parent != "" {
			extendedBy = append(extendedBy, map[string]string{"Name": o.Parent})
		}
		files := map[string]any{
			"assets": map[string]any{"anys": map[string]any{"all": map[string]any{"networks": map[string]any{}, "fqdns": effectiveFQDNs}}}, "nat_set": []string{},
			"users": effectiveUsers, "service_lists": map[string]any{"Owner": effectiveServices, "User": effectiveUserServices, "Visible": []string{}},
			"emails": emailEntries(o.Admins), "watchers": emailEntries(o.Watchers), "extended_by": extendedBy,
		}
		nets := files["assets"].(map[string]any)["anys"].(map[string]any)["all"].(map[string]any)["networks"].(map[string]any)
		for _, name := range effectiveNetworks {
			children := []string{}
			for _, child := range networkChildren[name] {
				if ownerScopeContains(ownerByName, o.Name, hostOwnerByName[child]) || ownerScopeContains(ownerByName, o.Name, networkOwner[name]) {
					children = append(children, child)
				}
			}
			nets[name] = children
		}
		for name, value := range files {
			if err := writeJSONFile(filepath.Join(od, name), value); err != nil {
				return err
			}
		}
	}
	if err := s.saveDraft(p); err != nil {
		return err
	}
	tmp := filepath.Join(s.config.NetspocData, ".current-"+version)
	_ = os.Remove(tmp)
	if err := os.Symlink(version, tmp); err != nil {
		return err
	}
	current := filepath.Join(s.config.NetspocData, "current")
	_ = os.Remove(current)
	if err := os.Rename(tmp, current); err != nil {
		return err
	}
	if err := s.storePublication(version, p); err != nil {
		return err
	}
	s.cache = newCache(s.config.NetspocData, 8)
	return nil
}

func emailEntries(values []string) []map[string]string {
	result := make([]map[string]string, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]string{"Email": value})
	}
	return result
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0640)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(value)
}
