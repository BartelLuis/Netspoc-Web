package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type policyFinding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Service  string `json:"service,omitempty"`
	Rule     int    `json:"rule,omitempty"`
	Object   string `json:"object,omitempty"`
}

type revisionCreateResult struct {
	PolicyID string          `json:"policy_id"`
	Approval string          `json:"approval"`
	Changes  []policyChange  `json:"changes"`
	Findings []policyFinding `json:"findings"`
}

func (s *state) createPendingRevision(p *editablePolicy, actor, comment, changeReference string, deploymentPlan, validation any) (revisionCreateResult, error) {
	if err := validateEditablePolicy(p); err != nil {
		return revisionCreateResult{}, err
	}
	previous, base, err := s.latestPublicationSnapshot()
	if err != nil {
		return revisionCreateResult{}, err
	}
	return s.createPendingRevisionAgainstBase(p, previous, base, actor, comment, changeReference, deploymentPlan, validation)
}

func (s *state) createPendingRevisionAgainstBase(p, previous *editablePolicy, base, actor, comment, changeReference string, deploymentPlan, validation any) (revisionCreateResult, error) {
	if err := validateEditablePolicy(p); err != nil {
		return revisionCreateResult{}, err
	}
	version := newPolicyVersion()
	changes := diffPolicies(previous, p)
	findings := analyzePolicyRisk(previous, p)
	approval, err := revisionApprovalHash(version, previous, p, deploymentPlan, validation)
	if err != nil {
		return revisionCreateResult{}, err
	}
	meta := revisionMetadata{CreatedBy: strings.ToLower(actor), Comment: strings.TrimSpace(comment), ChangeReference: strings.TrimSpace(changeReference), Findings: findings, DeploymentPlan: deploymentPlan, Validation: validation}
	if err := s.storeRevisionWithMetadata(version, base, p, changes, meta); err != nil {
		return revisionCreateResult{}, err
	}
	return revisionCreateResult{version, approval, changes, findings}, nil
}

func draftVersionFromRequest(r *http.Request) (*int64, error) {
	value := strings.TrimSpace(r.Header.Get("X-Policy-Draft-Version"))
	if value == "" {
		return nil, nil
	}
	version, err := strconv.ParseInt(value, 10, 64)
	if err != nil || version < 0 {
		return nil, errors.New("invalid X-Policy-Draft-Version")
	}
	return &version, nil
}

func (s *state) saveDraftAs(p *editablePolicy, actor string, expected *int64) (draftMetadata, error) {
	// Legacy in-memory callers can still populate Password, but credentials are
	// never part of a policy document. Account activation is a separate,
	// verified workflow after the identity has been published.
	for i := range p.Users {
		p.Users[i].Password = ""
	}
	db, err := s.policyDB()
	if err != nil {
		return draftMetadata{}, err
	}
	defer db.Close()
	return s.storePolicyDraftVersion(db, p, strings.ToLower(actor), expected)
}

func enforceEditorPolicyScope(current, next *editablePolicy) error {
	if !reflect.DeepEqual(current.NamingCatalog, next.NamingCatalog) ||
		!reflect.DeepEqual(current.Tenants, next.Tenants) ||
		!reflect.DeepEqual(current.TargetContexts, next.TargetContexts) {
		return errors.New("editors may not change the naming catalog, tenants or target contexts")
	}
	type ownerAccess struct {
		Parent                              string
		ReadAll                             bool
		ReadOwners, Users, Admins, Watchers []string
	}
	access := func(o editableOwner) ownerAccess {
		return ownerAccess{o.Parent, o.ReadAll, o.ReadOwners, o.Users, o.Admins, o.Watchers}
	}
	oldOwners := map[string]ownerAccess{}
	for _, owner := range current.Owners {
		oldOwners[owner.Name] = access(owner)
	}
	for _, owner := range next.Owners {
		old, exists := oldOwners[owner.Name]
		if !exists {
			if !reflect.DeepEqual(access(owner), ownerAccess{}) {
				return fmt.Errorf("editors may not assign access rights to new owner %q", owner.Name)
			}
			continue
		}
		if !reflect.DeepEqual(old, access(owner)) {
			return fmt.Errorf("editors may not change access rights of owner %q", owner.Name)
		}
		delete(oldOwners, owner.Name)
	}
	if len(oldOwners) != 0 {
		return errors.New("editors may not remove owners with access assignments")
	}
	return nil
}

func validateRuleLifecycle(rule editableRule, now time.Time) error {
	parse := func(name, value string) (time.Time, error) {
		if value == "" {
			return time.Time{}, nil
		}
		parsed, err := time.Parse("2006-01-02", value)
		if err != nil {
			return time.Time{}, fmt.Errorf("%s must use YYYY-MM-DD", name)
		}
		return parsed, nil
	}
	if _, err := parse("review_date", rule.ReviewDate); err != nil {
		return err
	}
	expires, err := parse("expires_at", rule.ExpiresAt)
	if err != nil {
		return err
	}
	if rule.ExpiresAt != "" && rule.RuleGroup != "TMP" {
		return errors.New("expires_at is only allowed for TMP rules")
	}
	if rule.RuleGroup == "TMP" {
		if rule.ExpiresAt == "" || strings.TrimSpace(rule.RollbackOwner) == "" {
			return errors.New("TMP rules require expires_at and rollback_owner")
		}
		if strings.TrimSpace(rule.Purpose) == "" || strings.TrimSpace(rule.ChangeReference) == "" {
			return errors.New("TMP rules require purpose and change_reference")
		}
		if expires.Before(now.UTC().Truncate(24 * time.Hour)) {
			return errors.New("TMP rule expires_at must not be in the past")
		}
	}
	if rule.RollbackOwner != "" && rule.ExpiresAt == "" {
		return errors.New("rollback_owner requires expires_at")
	}
	return nil
}

func analyzePolicyRisk(previous, next *editablePolicy) []policyFinding {
	findings := []policyFinding{}
	networks := map[string]string{}
	for _, n := range next.Networks {
		networks["network:"+n.Name] = n.CIDR
	}
	for si, service := range next.Services {
		_ = si
		for ri, rule := range service.Rules {
			if rule.Action == "permit" {
				for _, object := range append(append([]string{}, rule.Sources...), rule.Destinations...) {
					if cidr := networks[object]; cidr != "" {
						if _, parsed, err := net.ParseCIDR(cidr); err == nil {
							ones, bits := parsed.Mask.Size()
							if bits == 32 && ones <= 8 || bits == 128 && ones <= 32 {
								findings = append(findings, policyFinding{"high", "broad-network", "Permit rule references a very broad network", service.Name, ri + 1, object})
							}
						}
					}
				}
			}
			if rule.ExpiresAt != "" {
				if expiry, err := time.Parse("2006-01-02", rule.ExpiresAt); err == nil && time.Until(expiry) <= 30*24*time.Hour {
					findings = append(findings, policyFinding{"warning", "rule-expiry", "Rule expires within 30 days", service.Name, ri + 1, ""})
				}
			}
		}
	}
	if previous != nil {
		oldServices := map[string]editableService{}
		for _, service := range previous.Services {
			oldServices[service.Name] = service
		}
		for _, service := range next.Services {
			if old, ok := oldServices[service.Name]; ok {
				for i, rule := range service.Rules {
					if i < len(old.Rules) && old.Rules[i].Action == "deny" && rule.Action == "permit" {
						findings = append(findings, policyFinding{"high", "deny-to-permit", "Rule action changed from deny to permit", service.Name, i + 1, ""})
					}
				}
			}
		}
	}
	return findings
}

func revisionValidationHasErrors(value any) bool {
	m, ok := value.(map[string]any)
	if !ok || m == nil {
		return false
	}
	if valid, ok := m["valid"].(bool); ok && !valid {
		return true
	}
	switch errorsValue := m["errors"].(type) {
	case []any:
		return len(errorsValue) != 0
	case []string:
		return len(errorsValue) != 0
	case string:
		return strings.TrimSpace(errorsValue) != ""
	}
	return false
}

func validateStagedRevision(record *policyRevisionRecord) error {
	if record == nil {
		return errors.New("staged revision is missing")
	}
	if strings.TrimSpace(record.CreatedBy) == "" || strings.TrimSpace(record.Comment) == "" || strings.TrimSpace(record.ChangeReference) == "" {
		return errors.New("revision was not created by the mandatory staging workflow")
	}
	plan, err := decodeStoredDeploymentPlan(record.DeploymentPlan)
	if err != nil {
		return fmt.Errorf("invalid staged deployment plan: %w", err)
	}
	validation, ok := record.Validation.(map[string]any)
	if !ok || validation == nil {
		return errors.New("staged validation result is missing")
	}
	valid, hasValid := validation["valid"].(bool)
	planHash, hasPlanHash := validation["plan_hash"].(string)
	if !hasValid || !hasPlanHash || strings.TrimSpace(planHash) == "" || planHash != plan.Hash {
		return errors.New("staged validation is incomplete or does not match the deployment plan")
	}
	if !valid || revisionValidationHasErrors(validation) {
		return errors.New("revision validation contains blocking errors")
	}
	return nil
}

func revisionCommands(plan any) any {
	if value, ok := plan.(map[string]any); ok {
		if commands, exists := value["commands"]; exists {
			return commands
		}
	}
	return []any{}
}

func (s *state) audit(actor, action, result string, metadata any) {
	db, err := s.policyDB()
	if err != nil {
		return
	}
	defer db.Close()
	data, err := json.Marshal(metadata)
	if err != nil {
		data = []byte(`{"encoding_error":true}`)
	}
	_, _ = db.Exec(`INSERT INTO policy_audit(actor, action, result, metadata, created_at) VALUES(?,?,?,?,?)`, strings.ToLower(actor), action, result, string(data), time.Now().UTC().Format(time.RFC3339Nano))
}

func (s *state) adminAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !hasPolicyRole(s.authorizationPolicy(), getEmailFromSession(r), "admin", "reviewer") {
		writeError(w, "Policy reviewer role required", http.StatusForbidden)
		return
	}
	limit := 100
	if parsed, err := strconv.Atoi(r.FormValue("limit")); err == nil && parsed > 0 && parsed <= 500 {
		limit = parsed
	}
	db, err := s.policyDB()
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()
	rows, err := db.Query(`SELECT actor, action, result, metadata, created_at FROM policy_audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	records := []map[string]any{}
	for rows.Next() {
		var actor, action, result, raw, created string
		if err := rows.Scan(&actor, &action, &result, &raw, &created); err != nil {
			writeError(w, err.Error(), 500)
			return
		}
		var metadata any
		_ = json.Unmarshal([]byte(raw), &metadata)
		records = append(records, map[string]any{"actor": actor, "action": action, "result": result, "metadata": metadata, "created_at": created})
	}
	writeJSON(w, map[string]any{"success": true, "records": records, "items": records})
}

func (s *state) adminReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin", "reviewer") {
		s.audit(actor, "revision.reject", "denied", nil)
		writeError(w, "Policy reviewer role required", http.StatusForbidden)
		return
	}
	var request struct {
		PolicyID string `json:"policy_id"`
		Comment  string `json:"comment"`
	}
	err := decodeJSONRequest(w, r, 1<<20, &request)
	if err == nil && strings.TrimSpace(request.Comment) == "" {
		err = errors.New("rejection comment is required")
	}
	if err == nil {
		var record *policyRevisionRecord
		record, err = s.loadRevisionRecord(request.PolicyID, true)
		if err == nil && strings.EqualFold(record.CreatedBy, actor) && !bypassesFourEyes(s.authorizationPolicy(), actor) {
			err = errors.New("revision creator may not reject their own revision")
		}
	}
	if err == nil {
		err = s.rejectRevision(request.PolicyID, actor, request.Comment)
	}
	if err != nil {
		s.audit(actor, "revision.reject", "failed", map[string]any{"policy_id": request.PolicyID, "error": err.Error()})
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit(actor, "revision.reject", "success", map[string]any{"policy_id": request.PolicyID, "comment": request.Comment})
	writeJSON(w, map[string]any{"success": true})
}

func (s *state) adminRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin") {
		s.audit(actor, "policy.rollback", "denied", nil)
		writeError(w, "Policy administrator role required", http.StatusForbidden)
		return
	}
	var request struct {
		Version      string `json:"version"`
		Comment      string `json:"comment"`
		DraftVersion *int64 `json:"draft_version"`
	}
	err := decodeJSONRequest(w, r, 1<<20, &request)
	if err == nil && strings.TrimSpace(request.Version) == "" {
		err = errors.New("version is required")
	}
	if err == nil && strings.TrimSpace(request.Comment) == "" {
		err = errors.New("rollback comment is required")
	}
	if err == nil && request.DraftVersion == nil {
		err = errors.New("draft_version is required")
	}
	var target *editablePolicy
	if err == nil {
		target, err = s.loadPublication(request.Version)
	}
	if err == nil {
		err = validateEditablePolicy(target)
	}
	var previous *editablePolicy
	var base string
	if err == nil {
		previous, base, err = s.latestPublicationSnapshot()
	}
	plan := deploymentPlan{}
	validation := map[string]any{}
	if err == nil {
		var planBase *editablePolicy
		var previousPlan *deploymentPlan
		planBase, previousPlan, err = s.deploymentPlanBase(previous, base)
		if err == nil {
			plan = generateDeploymentPlanWithBase(planBase, target, s.config.FortinetTargets)
			if previous != nil && planBase == nil {
				plan.Warnings = append(plan.Warnings, "Die bisherige Publikation besitzt keinen verifizierten Deploymentplan; dieser Rollback-Stage ist deshalb ein sicherer Vollabgleich ohne automatische Löschannahmen.")
			}
			if bindErr := bindPolicyDeletePayloadsToPreviousPlan(&plan, previousPlan); bindErr != nil {
				plan.Errors = append(plan.Errors, "Deployment-Baseline: "+bindErr.Error())
				plan.Ready = false
			}
			if previousPlan != nil {
				if topologyErr := validateDeploymentTopologyTransition(*previousPlan, plan); topologyErr != nil {
					plan.Errors = append(plan.Errors, "Deployment-Topologie: "+topologyErr.Error())
					plan.Ready = false
				}
			}
		}
	}
	if err == nil {
		validation = map[string]any{
			"valid": len(plan.Errors) == 0, "errors": plan.Errors, "warnings": plan.Warnings,
			"deployment_ready": plan.Ready, "plan_hash": plan.Hash,
		}
	}
	var meta draftMetadata
	if err == nil {
		meta, err = s.saveDraftAs(target, actor, request.DraftVersion)
	}
	var result revisionCreateResult
	if err == nil {
		result, err = s.createPendingRevisionAgainstBase(target, previous, base, actor, "Rollback: "+strings.TrimSpace(request.Comment), "ROLLBACK-"+request.Version, plan, validation)
	}
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errDraftConflict) {
			status = http.StatusConflict
		}
		s.audit(actor, "policy.rollback", "failed", map[string]any{"version": request.Version, "error": err.Error()})
		writeError(w, err.Error(), status)
		return
	}
	s.audit(actor, "policy.rollback", "success", map[string]any{"source_version": request.Version, "policy_id": result.PolicyID})
	writeJSON(w, map[string]any{
		"success": true, "draft_version": meta.Version, "draft_updated_at": meta.UpdatedAt, "draft_updated_by": meta.UpdatedBy,
		"policy":    target,
		"policy_id": result.PolicyID, "approval": result.Approval, "changes": result.Changes, "findings": result.Findings,
		"validation": validation, "deployment_plan": plan, "commands": plan.Commands, "created_by": actor,
	})
}

type whereUsedRecord struct {
	Service      string `json:"service"`
	Rule         int    `json:"rule"`
	Side         string `json:"side"`
	StableRuleID string `json:"stable_rule_id,omitempty"`
}

func whereUsed(p *editablePolicy, object string) []whereUsedRecord {
	result := []whereUsedRecord{}
	for _, service := range p.Services {
		for i, rule := range service.Rules {
			for _, ref := range rule.Sources {
				if ref == object {
					result = append(result, whereUsedRecord{service.Name, i + 1, "source", rule.StableRuleID})
				}
			}
			for _, ref := range rule.Destinations {
				if ref == object {
					result = append(result, whereUsedRecord{service.Name, i + 1, "destination", rule.StableRuleID})
				}
			}
		}
	}
	return result
}

func (s *state) adminWhereUsed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !hasPolicyRole(s.authorizationPolicy(), getEmailFromSession(r), "admin", "editor") {
		writeError(w, "Policy access required", http.StatusForbidden)
		return
	}
	p := s.readDraft()
	object := strings.TrimSpace(r.FormValue("object"))
	if object == "" {
		writeError(w, "object is required", http.StatusBadRequest)
		return
	}
	records := whereUsed(p, object)
	writeJSON(w, map[string]any{"success": true, "object": object, "records": records, "items": records, "can_delete": len(records) == 0})
}

type ldapSyncPreview struct {
	Added, Updated, Disabled int
	Users                    []editableUser
}

func calculateLDAPSyncPreview(p *editablePolicy, entries []ldapIdentity) (ldapSyncPreview, error) {
	copyPolicy := *p
	copyPolicy.Users = append([]editableUser(nil), p.Users...)
	seen := map[string]bool{}
	emailOwner := map[string]string{}
	for _, user := range copyPolicy.Users {
		emailOwner[strings.ToLower(user.Email)] = user.DirectoryID
	}
	preview := ldapSyncPreview{}
	for _, entry := range entries {
		seen[entry.DirectoryID] = true
		user := findLDAPPolicyUser(&copyPolicy, entry)
		if user == nil {
			if owner, exists := emailOwner[entry.Email]; exists && owner != entry.DirectoryID {
				return preview, fmt.Errorf("LDAP email %q is already assigned to another user", entry.Email)
			}
			copyPolicy.Users = append(copyPolicy.Users, editableUser{Email: entry.Email, Role: "viewer", Source: "ldap", DirectoryID: entry.DirectoryID, Username: entry.Username, Active: true})
			emailOwner[entry.Email] = entry.DirectoryID
			preview.Added++
			continue
		}
		user.DirectoryID, user.Username, user.Source, user.Active = entry.DirectoryID, entry.Username, "ldap", true
		if user.Email == "" {
			user.Email = entry.Email
		}
		preview.Updated++
	}
	for i := range copyPolicy.Users {
		if copyPolicy.Users[i].Source == "ldap" && !seen[copyPolicy.Users[i].DirectoryID] && copyPolicy.Users[i].Active {
			copyPolicy.Users[i].Active = false
			preview.Disabled++
		}
	}
	preview.Users = copyPolicy.Users
	return preview, nil
}

func (s *state) adminLDAPSyncPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin") {
		writeError(w, "Policy administrator role required", http.StatusForbidden)
		return
	}
	var request struct {
		UsersVersion *int64 `json:"users_version"`
	}
	if err := decodeJSONRequest(w, r, 64<<10, &request); err != nil || request.UsersVersion == nil {
		writeError(w, "users_version is required", http.StatusBadRequest)
		return
	}
	users, usersVersion, err := s.accountCatalog()
	if err != nil {
		s.audit(actor, "ldap.sync.preview", "failed", map[string]any{"error": err.Error()})
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if *request.UsersVersion != usersVersion {
		writeError(w, errAccountConflict.Error(), http.StatusConflict)
		return
	}
	entries, err := s.ldapUsers()
	var preview ldapSyncPreview
	if err == nil {
		preview, err = calculateLDAPSyncPreview(&editablePolicy{Users: users}, entries)
	}
	if err != nil {
		s.audit(actor, "ldap.sync.preview", "failed", map[string]any{"error": err.Error()})
		writeError(w, err.Error(), http.StatusBadGateway)
		return
	}
	var stored storedLDAPSyncPreview
	stored, err = s.storeLDAPSyncPreview(actor, usersVersion, preview)
	if err != nil {
		s.audit(actor, "ldap.sync.preview", "failed", map[string]any{"error": err.Error()})
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(actor, "ldap.sync.preview", "success", map[string]any{
		"added": preview.Added, "updated": preview.Updated, "disabled": preview.Disabled,
		"users_version": stored.UsersVersion, "expires_at": stored.ExpiresAt,
	})
	writeJSON(w, map[string]any{
		"success": true, "added": preview.Added, "updated": preview.Updated, "disabled": preview.Disabled,
		"users": preview.Users, "preview_token": stored.Token, "users_version": stored.UsersVersion, "expires_at": stored.ExpiresAt,
	})
}
