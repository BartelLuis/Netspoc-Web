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
	Name           string            `json:"name"`
	Tenants        []tenant          `json:"tenants,omitempty"`
	TargetContexts []targetContext   `json:"target_contexts,omitempty"`
	NamingCatalog  namingCatalog     `json:"naming_catalog,omitempty"`
	Owners         []editableOwner   `json:"owners"`
	Users          []editableUser    `json:"users"`
	Networks       []editableNetwork `json:"networks"`
	FQDNs          []editableFQDN    `json:"fqdns"`
	Services       []editableService `json:"services"`
	// AccountsVersion binds an in-memory policy to the account catalog used
	// for owner-reference validation. It is never policy data and is therefore
	// deliberately omitted from every JSON representation.
	AccountsVersion *int64 `json:"-"`
}

// policyDocument is the wire and persistence representation. It deliberately
// has no account field, so strict policy endpoints reject a legacy "users"
// member instead of silently treating it as a policy change.
type policyDocument struct {
	Name           string            `json:"name"`
	Tenants        []tenant          `json:"tenants,omitempty"`
	TargetContexts []targetContext   `json:"target_contexts,omitempty"`
	NamingCatalog  namingCatalog     `json:"naming_catalog,omitempty"`
	Owners         []editableOwner   `json:"owners"`
	Networks       []editableNetwork `json:"networks"`
	FQDNs          []editableFQDN    `json:"fqdns"`
	Services       []editableService `json:"services"`
}

func (p policyDocument) editable() *editablePolicy {
	return &editablePolicy{
		Name: p.Name, Tenants: p.Tenants, TargetContexts: p.TargetContexts,
		NamingCatalog: p.NamingCatalog, Owners: p.Owners, Networks: p.Networks,
		FQDNs: p.FQDNs, Services: p.Services,
	}
}

// MarshalJSON deliberately excludes Users. Accounts and roles are operational
// administration data with their own immediately effective store; they are
// never part of a draft, revision, publication, approval hash or policy API
// response. The normal decoder is intentionally kept so legacy documents can
// still be read once and migrated into the account store.
func (p editablePolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(policyDocument{
		Name: p.Name, Tenants: p.Tenants, TargetContexts: p.TargetContexts,
		NamingCatalog: p.NamingCatalog, Owners: p.Owners, Networks: p.Networks,
		FQDNs: p.FQDNs, Services: p.Services,
	})
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
	Email string `json:"email"`
	Role  string `json:"role"`
	// Password exists only for source compatibility with older in-memory
	// callers. Credentials are never part of policy JSON; local accounts are
	// activated through register/verify or the create-user command.
	Password    string `json:"-"`
	Source      string `json:"source,omitempty"`
	DirectoryID string `json:"directory_id,omitempty"`
	Username    string `json:"username,omitempty"`
	Active      bool   `json:"active,omitempty"`
	Revision    int64  `json:"revision,omitempty"`
}

type editableNetwork struct {
	Name  string         `json:"name"`
	CIDR  string         `json:"cidr"`
	Owner string         `json:"owner"`
	Zone  string         `json:"zone,omitempty"`
	Hosts []editableHost `json:"hosts"`
}

type editableHost struct {
	Name  string `json:"name"`
	IP    string `json:"ip"`
	Owner string `json:"owner,omitempty"`
	Zone  string `json:"zone,omitempty"`
}

type editableFQDN struct {
	Name  string `json:"name"`
	FQDN  string `json:"fqdn"`
	Owner string `json:"owner"`
	Zone  string `json:"zone,omitempty"`
}

type editableService struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Owners      []string       `json:"owners"`
	Rules       []editableRule `json:"rules"`
}

type editableRule struct {
	Action          string   `json:"action"`
	HasUser         string   `json:"has_user"`
	Sources         []string `json:"sources"`
	Destinations    []string `json:"destinations"`
	Protocols       []string `json:"protocols"`
	RuleGroup       string   `json:"rule_group,omitempty"`
	Owner           string   `json:"owner,omitempty"`
	ChangeReference string   `json:"change_reference,omitempty"`
	ReviewDate      string   `json:"review_date,omitempty"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	RollbackOwner   string   `json:"rollback_owner,omitempty"`
	Purpose         string   `json:"purpose,omitempty"`
	StableRuleID    string   `json:"stable_rule_id,omitempty"`
	ShortID         string   `json:"short_id,omitempty"`
	TenantMKZ       string   `json:"tenant_mkz,omitempty"`
	TargetContext   string   `json:"target_context,omitempty"`
	PolicyName      string   `json:"policy_name,omitempty"`
	PolicyComment   string   `json:"policy_comment,omitempty"`
	NamingVersion   string   `json:"naming_version,omitempty"`
}

// policyChange is the immutable reviewer-facing representation of a policy
// difference. Before and After intentionally remain structured JSON values;
// encoding them as JSON strings would force reviewers to trust an opaque blob
// and made field-level changes (including server-derived rule fields) easy to
// overlook.
type policyChange struct {
	Type         string              `json:"type"`
	Name         string              `json:"name"`
	Change       string              `json:"change"`
	Path         string              `json:"path"`
	Before       any                 `json:"before"`
	After        any                 `json:"after"`
	FieldChanges []policyFieldChange `json:"field_changes,omitempty"`
}

type policyFieldChange struct {
	Path   string `json:"path"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

var policyNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)

const policyDeveloperRole = "developer"

func (s *state) adminStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie")
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// A previously ambiguous first-publication commit is repaired once its
	// short claim lease has expired and SQLite is readable again.
	_ = s.reconcileStaleSetupClaim()
	initialized := s.policyInitialized()
	result := map[string]any{"success": true, "initialized": initialized}
	if initialized && loggedIn(r) {
		result["authenticated"] = true
		result["fortigate_read_only"] = s.config.FortiGateReadOnly
		actor := strings.ToLower(strings.TrimSpace(getEmailFromSession(r)))
		result["current_user"] = actor
		p := s.readDraft()
		role := policyRole(s.authorizationPolicy(), actor)
		result["role"] = role
		if role == policyDeveloperRole || role == "admin" || role == "editor" {
			result["policy"] = p
		}
		if role == policyDeveloperRole || role == "admin" || role == "editor" || role == "reviewer" || role == "deployer" {
			if revisions, err := s.listRevisions(); err == nil {
				result["revisions"] = revisions
			}
		}
		if meta, err := s.draftInfo(); err == nil {
			result["draft_version"], result["draft_updated_at"], result["draft_updated_by"] = meta.Version, meta.UpdatedAt, meta.UpdatedBy
		}
		if version, err := s.latestPublicationVersion(); err == nil {
			result["current_version"] = version
		}
		if role == policyDeveloperRole || role == "admin" {
			active, settings := s.effectiveMaintenance()
			result["maintenance"] = map[string]any{"active": active, "settings": settings}
		}
	}
	writeJSON(w, result)
}

func (s *state) adminBootstrap(w http.ResponseWriter, r *http.Request) {
	p, err := decodePolicy(r)
	if err == nil && len(p.Users) == 0 {
		// Compatibility for the token-protected legacy bootstrap client after
		// accounts stopped being serialized in policy JSON. Owner administrators
		// become initial administrators; other referenced identities become
		// viewers. Normal authenticated policy writes never use this path.
		roles := map[string]string{}
		for _, owner := range p.Owners {
			for _, email := range owner.Admins {
				if canonical, canonicalErr := canonicalAccountEmail(email); canonicalErr == nil {
					roles[canonical] = "admin"
				}
			}
			for _, email := range slices.Concat(slices.Clone(owner.Users), owner.Watchers) {
				if canonical, canonicalErr := canonicalAccountEmail(email); canonicalErr == nil && roles[canonical] == "" {
					roles[canonical] = "viewer"
				}
			}
		}
		for email, role := range roles {
			p.Users = append(p.Users, editableUser{Email: email, Role: role, Source: "local", Active: true})
		}
		slices.SortFunc(p.Users, func(a, b editableUser) int { return strings.Compare(a.Email, b.Email) })
	}
	if err == nil {
		err = protectDirectoryUsers(nil, p)
	}
	if err == nil {
		protectManualRuleIdentities(nil, p)
		err = validateEditablePolicy(p)
	}
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The legacy migration endpoint shares the exact first-run lock and leased
	// database claim with /setup. It can therefore never race a credentialed
	// first-administrator setup and replace its authorization policy.
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if err := s.reconcileStaleSetupClaim(); err != nil {
		writeError(w, "Setup state could not be recovered", http.StatusInternalServerError)
		return
	}
	if s.policyInitialized() {
		writeError(w, "Policy administration is already initialized", http.StatusForbidden)
		return
	}
	claim, err := s.acquireSetupClaim()
	if errors.Is(err, errSetupAlreadyClaimed) {
		writeError(w, "Policy administration is already being initialized", http.StatusConflict)
		return
	}
	if err != nil {
		writeError(w, "Setup state could not be reserved", http.StatusInternalServerError)
		return
	}
	releaseClaim := true
	defer func() {
		if releaseClaim {
			claim.Release()
		}
	}()
	if s.policyInitialized() {
		writeError(w, "Policy administration is already initialized", http.StatusForbidden)
		return
	}
	normalizeEditablePolicy(p)
	if err := prepareManualPolicyNames(p); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	version := newPolicyVersion()
	digest, err := setupPolicyDigest(p)
	if err != nil {
		writeError(w, "Initial policy could not be prepared", http.StatusInternalServerError)
		return
	}
	draftSnapshot, err := s.snapshotStoredPolicyDraft()
	if err != nil {
		writeError(w, "Initial policy state could not be recorded", http.StatusInternalServerError)
		return
	}
	rollbackDraftVersion := int64(0)
	if draftSnapshot.Exists {
		rollbackDraftVersion = draftSnapshot.Version
	}
	if err := s.recordSetupClaimPublication(claim.ID, version, digest, rollbackDraftVersion); err != nil {
		writeError(w, "Setup state could not be recorded", http.StatusInternalServerError)
		return
	}
	if err := s.publishSetupPolicyVersion(p, version, claim.ID); err != nil {
		state, published := s.inspectSetupPublication(version, digest)
		switch state {
		case setupPublicationExact:
			if repairErr := s.restoreSetupPublicationArtifacts(version, digest, rollbackDraftVersion, published); repairErr == nil {
				break
			}
			fallthrough
		case setupPublicationUnknown:
			releaseClaim = false
			claim.Abandon()
			writeError(w, "Initial policy recovery is pending", http.StatusInternalServerError)
			return
		default:
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if !releaseClaim {
		return
	}
	writeJSON(w, map[string]any{"success": true})
}

func (s *state) adminPolicy(w http.ResponseWriter, r *http.Request) {
	current := s.readDraft()
	actor := getEmailFromSession(r)
	role := policyRole(s.authorizationPolicy(), actor)
	if role != policyDeveloperRole && role != "admin" && role != "editor" {
		s.audit(actor, "draft.access", "denied", nil)
		writeError(w, "Policy editor role required", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		meta, _ := s.draftInfo()
		writeJSON(w, map[string]any{"success": true, "policy": current, "draft_version": meta.Version, "draft_updated_at": meta.UpdatedAt, "draft_updated_by": meta.UpdatedBy})
	case http.MethodPost:
		p, err := decodePolicy(r)
		if err == nil {
			err = s.attachPolicyAccounts(p)
		}
		if err == nil {
			err = protectDirectoryUsers(current, p)
		}
		if err == nil {
			protectManualRuleIdentities(current, p)
		}
		if err == nil && role == "editor" {
			err = enforceEditorPolicyScope(current, p)
		}
		if err == nil {
			err = validateEditablePolicy(p)
		}
		if err == nil {
			var expected *int64
			expected, err = draftVersionFromRequest(r)
			if err == nil && expected == nil && s.policyInitialized() {
				err = errors.New("X-Policy-Draft-Version is required")
			}
			if err == nil {
				var meta draftMetadata
				meta, err = s.saveDraftAs(p, actor, expected)
				if err == nil {
					s.audit(actor, "draft.save", "success", map[string]any{"draft_version": meta.Version})
					writeJSON(w, map[string]any{"success": true, "policy": p, "draft_version": meta.Version, "draft_updated_at": meta.UpdatedAt, "draft_updated_by": meta.UpdatedBy})
					return
				}
			}
		}
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errDraftConflict) || errors.Is(err, errAccountConflict) {
				status = http.StatusConflict
			}
			s.audit(actor, "draft.save", "failed", map[string]any{"error": err.Error()})
			writeError(w, err.Error(), status)
			return
		}
	default:
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// adminPolicyNamePreview remains as a compatibility endpoint for older admin
// clients. Names are manual; the response only returns their validated form
// together with server-owned identity metadata.
func (s *state) adminPolicyNamePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	current := s.readDraft()
	authorization := s.authorizationPolicy()
	if !hasPolicyRole(authorization, getEmailFromSession(r), "admin", "editor") {
		writeError(w, "Policy editor role required", http.StatusForbidden)
		return
	}
	p, err := decodePolicy(r)
	if err == nil {
		err = s.attachPolicyAccounts(p)
	}
	if err == nil {
		err = protectDirectoryUsers(current, p)
	}
	if err == nil {
		protectManualRuleIdentities(current, p)
	}
	if err == nil && policyRole(authorization, getEmailFromSession(r)) == "editor" {
		err = enforceEditorPolicyScope(current, p)
	}
	if err == nil {
		err = validateEditablePolicy(p)
	}
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	type preview struct {
		Service       string `json:"service"`
		Index         int    `json:"index"`
		Name          string `json:"policy_name"`
		Comment       string `json:"policy_comment"`
		ShortID       string `json:"short_id"`
		NamingVersion string `json:"naming_version"`
	}
	result := []preview{}
	for _, service := range p.Services {
		for i, rule := range service.Rules {
			result = append(result, preview{service.Name, i, rule.PolicyName, rule.PolicyComment, rule.ShortID, rule.NamingVersion})
		}
	}
	writeJSON(w, map[string]any{"success": true, "records": result, "policy": p})
}

func (s *state) adminDiff(w http.ResponseWriter, r *http.Request) {
	writeError(w, "The legacy diff endpoint is disabled; use /admin/stage with comment, change_reference and draft_version", http.StatusGone)
}

// protectDirectoryUsers keeps directory identity fields server-owned. Only
// role and effective email address may be changed in policy administration.
func protectDirectoryUsers(current, next *editablePolicy) error {
	existing := map[string]editableUser{}
	if current != nil {
		for _, user := range current.Users {
			if strings.EqualFold(strings.TrimSpace(user.Source), "ldap") {
				id := strings.TrimSpace(user.DirectoryID)
				if id != "" {
					user.Source = "ldap"
					user.DirectoryID = id
					existing[id] = user
				}
			}
		}
	}
	seen := map[string]bool{}
	for i := range next.Users {
		user := &next.Users[i]
		id := strings.TrimSpace(user.DirectoryID)
		if !strings.EqualFold(strings.TrimSpace(user.Source), "ldap") && id == "" {
			continue
		}
		if id == "" {
			return fmt.Errorf("LDAP users require a directory_id")
		}
		old, ok := existing[id]
		if !ok {
			return fmt.Errorf("LDAP users can only be created by directory sync")
		}
		if seen[id] {
			return fmt.Errorf("LDAP directory_id %q is duplicated", id)
		}
		user.Source = "ldap"
		user.DirectoryID = old.DirectoryID
		user.Username = old.Username
		user.Active = old.Active
		user.Password = ""
		seen[old.DirectoryID] = true
	}
	for id, user := range existing {
		if !seen[id] {
			next.Users = append(next.Users, user)
		}
	}
	return nil
}

func (s *state) adminPublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin", "reviewer") {
		s.audit(actor, "revision.publish", "denied", nil)
		writeError(w, "Policy reviewer role required", http.StatusForbidden)
		return
	}
	defer r.Body.Close()
	var request struct {
		PolicyID string `json:"policy_id"`
		Approval string `json:"approval"`
	}
	err := decodeJSONRequest(w, r, 2<<20, &request)
	var record *policyRevisionRecord
	if err == nil && request.PolicyID == "" {
		err = errors.New("policy_id is required")
	}
	if err == nil {
		record, err = s.loadRevisionRecord(request.PolicyID, true)
	}
	var p *editablePolicy
	if record != nil {
		p = record.Policy
	}
	if err == nil && (record.CreatedBy == "" || strings.EqualFold(record.CreatedBy, actor)) && !bypassesFourEyes(s.authorizationPolicy(), actor) {
		err = errors.New("revision creator may not approve their own revision")
	}
	if err == nil {
		err = s.ensurePolicyRequestApproverIsIndependent(request.PolicyID, actor)
	}
	if err == nil {
		err = validateStagedRevision(record)
	}
	if err == nil && revisionValidationHasErrors(record.Validation) {
		err = errors.New("revision validation contains blocking errors")
	}
	if err == nil {
		err = validateEditablePolicy(p)
	}
	previous, currentBase, snapshotErr := s.latestPublicationSnapshot()
	if err == nil && snapshotErr != nil {
		err = snapshotErr
	}
	if err == nil && record.Base != currentBase {
		err = errors.New("the base policy changed; create a new diff")
	}
	var hash string
	if err == nil {
		hash, err = revisionApprovalHash(request.PolicyID, previous, p, record.DeploymentPlan, record.Validation)
	}
	if err == nil && (request.Approval == "" || request.Approval != hash) {
		err = errors.New("policy changed after diff approval; create and confirm a new diff")
	}
	if err == nil {
		err = s.publishPolicyVersionBy(p, request.PolicyID, actor)
	}
	if err != nil {
		s.audit(actor, "revision.publish", "failed", map[string]any{"policy_id": request.PolicyID, "error": err.Error()})
		status := http.StatusBadRequest
		if errors.Is(err, errDeploymentRunning) || errors.Is(err, errPublicationRequiresDeployment) || errors.Is(err, errAccountConflict) {
			status = http.StatusConflict
		}
		writeError(w, err.Error(), status)
		return
	}
	s.audit(actor, "revision.publish", "success", map[string]any{"policy_id": request.PolicyID, "created_by": record.CreatedBy})
	writeJSON(w, map[string]any{"success": true, "approved_by": actor})
}

func (s *state) adminRevision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin", "editor", "reviewer", "deployer") {
		s.audit(actor, "revision.read", "denied", nil)
		writeError(w, "Policy editor role required", http.StatusForbidden)
		return
	}
	version := r.FormValue("policy_id")
	record, err := s.loadRevisionRecord(version, false)
	var p *editablePolicy
	if record != nil {
		p = record.Policy
	}
	var approval string
	if err == nil && record.Status == "pending" {
		previous, currentBase, snapshotErr := s.latestPublicationSnapshot()
		if snapshotErr != nil {
			err = snapshotErr
		}
		if err == nil && record.Base != currentBase {
			err = errors.New("the base policy changed; create a new diff")
		}
		if err == nil {
			approval, err = revisionApprovalHash(version, previous, p, record.DeploymentPlan, record.Validation)
		}
	}
	var requestID, requester string
	if err == nil {
		requestID, requester, err = s.linkedPolicyRequestIdentity(version)
	}
	if err != nil {
		s.audit(actor, "revision.read", "failed", map[string]any{"policy_id": version, "error": err.Error()})
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit(actor, "revision.read", "success", map[string]any{"policy_id": version})
	writeJSON(w, map[string]any{"success": true, "policy_id": version, "status": record.Status, "policy": p, "approval": approval, "changes": record.Changes, "created_by": record.CreatedBy, "approved_by": record.ApprovedBy, "comment": record.Comment, "change_reference": record.ChangeReference, "findings": record.Findings, "deployment_plan": record.DeploymentPlan, "validation": record.Validation, "commands": revisionCommands(record.DeploymentPlan), "request_id": requestID, "requester": requester})
}

func policyRole(p *editablePolicy, email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	for i, user := range p.Users {
		if strings.ToLower(user.Email) == email {
			if strings.EqualFold(user.Source, "ldap") && !user.Active {
				return ""
			}
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
	role := policyRole(p, email)
	return role == policyDeveloperRole || slices.Contains(roles, role)
}

func isPolicyDeveloper(p *editablePolicy, email string) bool {
	return policyRole(p, email) == policyDeveloperRole
}

// A developer still has to stage a valid, immutable revision and provide the
// approval hash, but may approve or reject work created under the same account.
func bypassesFourEyes(p *editablePolicy, email string) bool {
	return isPolicyDeveloper(p, email)
}

func decodePolicy(r *http.Request) (*editablePolicy, error) {
	defer r.Body.Close()
	var p policyDocument
	dec := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("invalid policy: multiple JSON documents")
	}
	return p.editable(), nil
}

func validateEditablePolicy(p *editablePolicy) error {
	normalizeEditablePolicy(p)
	if !policyNameRE.MatchString(p.Name) {
		return errors.New("policy name is required and may contain letters, digits, '.', '_', ':' and '-'")
	}
	owners := map[string]bool{}
	users := map[string]bool{}
	effectiveUsers := map[string]bool{}
	directoryIDs := map[string]bool{}
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
		email, emailErr := canonicalAccountEmail(p.Users[i].Email)
		if emailErr != nil {
			return fmt.Errorf("invalid user email")
		}
		p.Users[i].Email = email
		source := strings.ToLower(strings.TrimSpace(p.Users[i].Source))
		directoryID := strings.TrimSpace(p.Users[i].DirectoryID)
		switch source {
		case "ldap":
			if directoryID == "" {
				return fmt.Errorf("LDAP user %q requires a directory_id", email)
			}
			if directoryIDs[directoryID] {
				return fmt.Errorf("LDAP directory_id %q is duplicated", directoryID)
			}
			directoryIDs[directoryID] = true
			p.Users[i].Source = "ldap"
			p.Users[i].DirectoryID = directoryID
		case "", "local":
			if directoryID != "" {
				return fmt.Errorf("local user %q must not have a directory_id", email)
			}
			p.Users[i].Source = source
			p.Users[i].DirectoryID = ""
		default:
			return fmt.Errorf("user %q has invalid source %q", email, p.Users[i].Source)
		}
		if p.Users[i].Role == "" {
			if i == 0 {
				p.Users[i].Role = "admin"
			} else {
				p.Users[i].Role = "viewer"
			}
		}
		if !slices.Contains([]string{policyDeveloperRole, "admin", "editor", "reviewer", "deployer", "viewer"}, p.Users[i].Role) {
			return fmt.Errorf("user %q has invalid role %q", email, p.Users[i].Role)
		}
		if users[email] {
			return fmt.Errorf("invalid or duplicate user %q", email)
		}
		users[email] = true
		effectiveUsers[email] = !strings.EqualFold(strings.TrimSpace(p.Users[i].Source), "ldap") || p.Users[i].Active
	}
	hasAdmin := false
	loginAuthorizedUsers := map[string]bool{}
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
		for _, email := range p.Owners[i].Admins {
			if effectiveUsers[email] {
				hasAdmin = true
			}
		}
		for _, email := range slices.Concat(p.Owners[i].Admins, p.Owners[i].Users) {
			if effectiveUsers[email] {
				loginAuthorizedUsers[email] = true
			}
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
	hasLoginCapablePolicyAdmin := false
	for _, user := range p.Users {
		if (user.Role == policyDeveloperRole || user.Role == "admin") && (!strings.EqualFold(strings.TrimSpace(user.Source), "ldap") || user.Active) {
			hasPolicyAdmin = true
			if loginAuthorizedUsers[user.Email] {
				hasLoginCapablePolicyAdmin = true
			}
		}
	}
	if !hasPolicyAdmin {
		return errors.New("at least one policy administrator is required")
	}
	if !hasLoginCapablePolicyAdmin {
		return errors.New("at least one active policy administrator must be assigned to an owner as administrator or user")
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
			if err := validateRuleLifecycle(rule, time.Now()); err != nil {
				return fmt.Errorf("service %q rule lifecycle: %w", svc.Name, err)
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
	return prepareManualPolicyNames(p)
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
	return revisionApprovalHash(policyID, previous, next, nil, nil)
}

func revisionApprovalHash(policyID string, previous, next *editablePolicy, deploymentPlan, validation any) (string, error) {
	canonicalPlan, err := canonicalJSONValue(deploymentPlan)
	if err != nil {
		return "", err
	}
	canonicalValidation, err := canonicalJSONValue(validation)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(struct {
		PolicyID       string          `json:"policy_id"`
		Previous       *editablePolicy `json:"previous"`
		Next           *editablePolicy `json:"next"`
		DeploymentPlan any             `json:"deployment_plan"`
		Validation     any             `json:"validation"`
	}{policyID, previous, next, canonicalPlan, canonicalValidation})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func diffPolicies(old, next *editablePolicy) []policyChange {
	result := []policyChange{}
	appendChange := func(kind, name, path, change string, before, after any) {
		entry := policyChange{
			Type: kind, Name: name, Path: path, Change: change,
			Before: canonicalDiffValue(before), After: canonicalDiffValue(after),
		}
		if change == "changed" {
			entry.FieldChanges = diffStructuredFields(entry.Before, entry.After, path)
		}
		result = append(result, entry)
	}
	diffNamed := func(kind, keyField, collectionPath string, oldItems, newItems any) {
		oldMap := namedItems(oldItems, keyField)
		newMap := namedItems(newItems, keyField)
		for name, item := range newMap {
			path := collectionPath + "/" + jsonPointerSegment(name)
			if previous, ok := oldMap[name]; ok {
				if reflect.DeepEqual(previous, item) {
					continue
				}
				appendChange(kind, name, path, "changed", previous, item)
				continue
			}
			appendChange(kind, name, path, "added", nil, item)
		}
		for name, item := range oldMap {
			if _, ok := newMap[name]; !ok {
				appendChange(kind, name, collectionPath+"/"+jsonPointerSegment(name), "removed", item, nil)
			}
		}
	}
	if old == nil {
		old = &editablePolicy{}
	}
	if next == nil {
		next = &editablePolicy{}
	}
	if old.Name != next.Name {
		name := next.Name
		if name == "" {
			name = old.Name
		}
		appendChange("policy", name, "/name", "changed", old.Name, next.Name)
	}
	diffNamed("owner", "name", "/owners", old.Owners, next.Owners)
	diffNamed("tenant", "mkz", "/tenants", old.Tenants, next.Tenants)
	diffNamed("target_context", "name", "/target_contexts", old.TargetContexts, next.TargetContexts)
	diffNamed("network", "name", "/networks", old.Networks, next.Networks)
	diffNamed("fqdn", "name", "/fqdns", old.FQDNs, next.FQDNs)
	diffNamed("service", "name", "/services", old.Services, next.Services)
	if !reflect.DeepEqual(old.NamingCatalog, next.NamingCatalog) {
		appendChange("naming_catalog", "Naming-Katalog", "/naming_catalog", "changed", old.NamingCatalog, next.NamingCatalog)
	}
	slices.SortFunc(result, func(a, b policyChange) int { return strings.Compare(a.Type+a.Name, b.Type+b.Name) })
	return result
}

func namedItems(items any, keyField string) map[string]any {
	result := map[string]any{}
	data, _ := json.Marshal(items)
	var values []map[string]any
	_ = json.Unmarshal(data, &values)
	for _, value := range values {
		name, _ := value[keyField].(string)
		result[name] = value
	}
	return result
}

func canonicalDiffValue(value any) any {
	if value == nil {
		return nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	var result any
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Sprint(value)
	}
	return result
}

func jsonPointerSegment(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func diffStructuredFields(before, after any, path string) []policyFieldChange {
	result := []policyFieldChange{}
	var walk func(any, any, string)
	walk = func(oldValue, newValue any, currentPath string) {
		if reflect.DeepEqual(oldValue, newValue) {
			return
		}
		oldMap, oldIsMap := oldValue.(map[string]any)
		newMap, newIsMap := newValue.(map[string]any)
		if oldIsMap && newIsMap {
			keys := make([]string, 0, len(oldMap)+len(newMap))
			seen := map[string]bool{}
			for key := range oldMap {
				seen[key] = true
				keys = append(keys, key)
			}
			for key := range newMap {
				if !seen[key] {
					keys = append(keys, key)
				}
			}
			slices.Sort(keys)
			for _, key := range keys {
				walk(oldMap[key], newMap[key], currentPath+"/"+jsonPointerSegment(key))
			}
			return
		}
		oldList, oldIsList := oldValue.([]any)
		newList, newIsList := newValue.([]any)
		if oldIsList && newIsList {
			length := max(len(oldList), len(newList))
			for i := 0; i < length; i++ {
				var oldItem, newItem any
				if i < len(oldList) {
					oldItem = oldList[i]
				}
				if i < len(newList) {
					newItem = newList[i]
				}
				walk(oldItem, newItem, fmt.Sprintf("%s/%d", currentPath, i))
			}
			return
		}
		result = append(result, policyFieldChange{Path: currentPath, Before: oldValue, After: newValue})
	}
	walk(before, after, path)
	return result
}

func (s *state) policyInitialized() bool {
	// A legacy compiled Netspoc policy also contains current/email, but has no
	// editable authorization publication. Treating that file as the admin
	// initialization marker would lock every existing installation out of the
	// token-protected migration/bootstrap flow after an upgrade.
	version, err := s.latestPublicationVersion()
	return err == nil && version != ""
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
	return s.publishPolicyVersionBy(p, version, "")
}

type currentPolicyLinkSnapshot struct {
	Exists bool
	Target string
}

func snapshotCurrentPolicyLink(path string) (currentPolicyLinkSnapshot, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return currentPolicyLinkSnapshot{}, nil
	}
	if err != nil {
		return currentPolicyLinkSnapshot{}, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return currentPolicyLinkSnapshot{}, fmt.Errorf("current policy pointer %q is not a symbolic link", path)
	}
	target, err := os.Readlink(path)
	if err != nil {
		return currentPolicyLinkSnapshot{}, err
	}
	return currentPolicyLinkSnapshot{Exists: true, Target: target}, nil
}

func restoreCurrentPolicyLink(path, temporary string, snapshot currentPolicyLinkSnapshot) error {
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if snapshot.Exists {
		if err := os.Symlink(snapshot.Target, temporary); err != nil {
			return err
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(temporary)
		return err
	}
	if snapshot.Exists {
		if err := os.Rename(temporary, path); err != nil {
			return err
		}
	}
	return nil
}

func publicationRollbackError(cause, linkErr, draftErr error) error {
	rollbackErrors := []error{}
	if linkErr != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("restore current policy pointer: %w", linkErr))
	}
	if draftErr != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("restore policy draft: %w", draftErr))
	}
	if len(rollbackErrors) == 0 {
		return cause
	}
	return errors.Join(append([]error{cause}, rollbackErrors...)...)
}

func canonicalJSONValue(value any) (any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var canonical any
	if err := json.Unmarshal(data, &canonical); err != nil {
		return nil, err
	}
	return canonical, nil
}

func (s *state) publishPolicyVersionBy(p *editablePolicy, version, actor string) error {
	return s.publishPolicyVersionBySetupClaim(p, version, actor, "")
}

func (s *state) publishSetupPolicyVersion(p *editablePolicy, version, setupClaimID string) error {
	return s.publishPolicyVersionBySetupClaim(p, version, "", setupClaimID)
}

func (s *state) publishPolicyVersionBySetupClaim(p *editablePolicy, version, actor, setupClaimID string) error {
	normalizeEditablePolicy(p)
	if err := prepareManualPolicyNames(p); err != nil {
		return err
	}
	publicationLock, err := s.acquirePublicationLock(version)
	if err != nil {
		return err
	}
	defer s.releaseDeploymentLock(publicationLock)
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
			assigned := append(slices.Clone(o.Admins), o.Users...)
			for _, email := range assigned {
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
		objects[key] = map[string]any{"ip": n.CIDR, "zone": n.Zone, "owner": n.Owner}
		objectOwners[key] = n.Owner
		networkOwner[key] = n.Owner
		ownerNetworks[n.Owner] = append(ownerNetworks[n.Owner], key)
		for _, h := range n.Hosts {
			hostOwner := h.Owner
			name := "host:" + h.Name
			zone := h.Zone
			if zone == "" {
				zone = n.Zone
			}
			objects[name] = map[string]any{"ip": h.IP, "zone": zone, "owner": hostOwner}
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
		objects[name] = map[string]any{"fqdn": f.FQDN, "zone": f.Zone, "owner": f.Owner}
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
			rules = append(rules, map[string]any{"action": rule.Action, "src": rule.Sources, "dst": rule.Destinations, "prt": rule.Protocols, "has_user": exportedHasUser, "policy_name": rule.PolicyName, "policy_comment": rule.PolicyComment, "stable_rule_id": rule.StableRuleID, "short_id": rule.ShortID, "naming_version": rule.NamingVersion, "target_context": rule.TargetContext})

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
	tmp := filepath.Join(s.config.NetspocData, ".current-"+version)
	current := filepath.Join(s.config.NetspocData, "current")
	currentSnapshot, err := snapshotCurrentPolicyLink(current)
	if err != nil {
		return err
	}
	draftSnapshot, err := s.snapshotStoredPolicyDraft()
	if err != nil {
		return err
	}
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Symlink(version, tmp); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := s.saveDraft(p); err != nil {
		return err
	}
	if err := os.Remove(current); err != nil && !errors.Is(err, os.ErrNotExist) {
		return publicationRollbackError(err, nil, s.restoreStoredPolicyDraft(draftSnapshot))
	}
	if err := os.Rename(tmp, current); err != nil {
		linkErr := restoreCurrentPolicyLink(current, tmp+".restore", currentSnapshot)
		return publicationRollbackError(err, linkErr, s.restoreStoredPolicyDraft(draftSnapshot))
	}
	if err := s.finalizePublicationWithSetupClaim(version, p, actor, actor != "", setupClaimID); err != nil {
		linkErr := restoreCurrentPolicyLink(current, tmp+".restore", currentSnapshot)
		return publicationRollbackError(err, linkErr, s.restoreStoredPolicyDraft(draftSnapshot))
	}
	return nil
}

func emailEntries(values []string) []map[string]string {
	result := make([]map[string]string, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]string{"Email": value})
	}
	return result
}

func inactiveLDAPAccountEmails(p *editablePolicy) map[string]bool {
	result := map[string]bool{}
	if p == nil {
		return result
	}
	for _, user := range p.Users {
		if strings.EqualFold(strings.TrimSpace(user.Source), "ldap") && !user.Active {
			result[strings.ToLower(strings.TrimSpace(user.Email))] = true
		}
	}
	return result
}

func withoutInactiveLDAPAccounts(values []string, inactive map[string]bool) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !inactive[strings.ToLower(strings.TrimSpace(value))] {
			result = append(result, value)
		}
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
