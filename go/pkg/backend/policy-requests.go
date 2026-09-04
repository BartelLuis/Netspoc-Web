package backend

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	policyRequestBodyLimit       = int64(128 << 10)
	policyRequestPayloadLimit    = 64 << 10
	policyRequestListLimit       = 100
	policyRequestAdminPageLimit  = 50
	policyRequestPageLimitMax    = 100
	policyRequestSubmitLimit     = 200
	policyRequestSubmitWindow    = 24 * time.Hour
	policyRequestCursorSizeLimit = 1024
	policyRequestEventLimit      = 100
	policyRequestValueLimit      = 100
	policyRequestRuleLimit       = 100
	policyRequestOwnerLimit      = 100
	policyRequestTimestampLayout = "2006-01-02T15:04:05.000000000Z07:00"
)

var (
	errPolicyRequestConflict          = errors.New("policy request changed concurrently")
	errPolicyRequestForbidden         = errors.New("policy request access denied")
	errPolicyRequestRateLimited       = errors.New("policy request submission limit reached")
	errPolicyRequestStorage           = errors.New("policy request storage failed")
	errPolicyRequestPayloadTooLarge   = errors.New("policy request payload is too large")
	errPolicyRequestObjectUnavailable = fmt.Errorf("%w: one or more policy objects are unavailable for active_owner", errPolicyRequestForbidden)
	errPolicyRequestFQDNSource        = errors.New("FQDN references are not allowed as sources")
)

type policyRequestRecord struct {
	ID               string               `json:"id"`
	RequestID        string               `json:"request_id"`
	Type             string               `json:"type"`
	RequestType      string               `json:"request_type"`
	Requester        string               `json:"requester"`
	ActiveOwner      string               `json:"active_owner"`
	BaseVersion      string               `json:"base_version"`
	Payload          any                  `json:"payload"`
	Reason           string               `json:"reason"`
	Status           string               `json:"status"`
	Revision         int64                `json:"revision"`
	RevisionVersion  string               `json:"revision_version,omitempty"`
	RejectionComment string               `json:"rejection_comment,omitempty"`
	CreatedAt        string               `json:"created_at"`
	UpdatedAt        string               `json:"updated_at"`
	Events           []policyRequestEvent `json:"events,omitempty"`
	EventsTruncated  bool                 `json:"events_truncated,omitempty"`
}

type policyRequestEvent struct {
	Actor      string `json:"actor"`
	Action     string `json:"action"`
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
	Comment    string `json:"comment,omitempty"`
	Metadata   any    `json:"metadata,omitempty"`
	CreatedAt  string `json:"created_at"`
}

type policyRequestCursor struct {
	CreatedAt string `json:"created_at"`
	ID        string `json:"id"`
}

type ruleChangeRequest struct {
	Type         string   `json:"type,omitempty"`
	RequestType  string   `json:"request_type,omitempty"`
	Kind         string   `json:"kind,omitempty"`
	StableRuleID string   `json:"stable_rule_id"`
	Service      string   `json:"service"`
	Field        string   `json:"field"`
	Operation    string   `json:"operation"`
	Values       []string `json:"values"`
	Reason       string   `json:"reason"`
	ActiveOwner  string   `json:"active_owner"`
	BaseVersion  string   `json:"base_version"`
}

type newServiceRequest struct {
	Type        string          `json:"type,omitempty"`
	RequestType string          `json:"request_type,omitempty"`
	Kind        string          `json:"kind,omitempty"`
	Service     editableService `json:"service"`
	Reason      string          `json:"reason"`
	ActiveOwner string          `json:"active_owner"`
	BaseVersion string          `json:"base_version"`
}

type nestedRuleChangeInput struct {
	StableRuleID string   `json:"stable_rule_id"`
	Service      string   `json:"service"`
	Field        string   `json:"field"`
	Operation    string   `json:"operation"`
	Value        string   `json:"value,omitempty"`
	Values       []string `json:"values,omitempty"`
}

type nestedRuleChangeRequest struct {
	RequestType string                `json:"request_type,omitempty"`
	Type        string                `json:"type,omitempty"`
	Kind        string                `json:"kind,omitempty"`
	RuleChange  nestedRuleChangeInput `json:"rule_change"`
	Reason      string                `json:"reason"`
	ActiveOwner string                `json:"active_owner"`
	BaseVersion string                `json:"base_version"`
}

type nestedNewServiceRequest struct {
	RequestType string          `json:"request_type,omitempty"`
	Type        string          `json:"type,omitempty"`
	Kind        string          `json:"kind,omitempty"`
	NewService  editableService `json:"new_service"`
	Reason      string          `json:"reason"`
	ActiveOwner string          `json:"active_owner"`
	BaseVersion string          `json:"base_version"`
}

type storedRuleChangePayload struct {
	StableRuleID string   `json:"stable_rule_id"`
	Service      string   `json:"service"`
	Field        string   `json:"field"`
	Operation    string   `json:"operation"`
	Values       []string `json:"values"`
}

type storedNewServicePayload struct {
	Service editableService `json:"service"`
}

type policyRequestMutation struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
}

type policyRequestRejection struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Comment  string `json:"comment"`
}

type requestStageResult struct {
	PolicyID        string
	Approval        string
	Policy          *editablePolicy
	Changes         []policyChange
	Findings        []policyFinding
	Validation      map[string]any
	DeploymentPlan  deploymentPlan
	RequestRevision int64
}

func (s *state) policyRequests(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listPolicyRequests(w, r, false)
	case http.MethodPost:
		s.submitPolicyRequest(w, r)
	default:
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *state) adminPolicyRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin", "editor", "reviewer", "deployer") {
		s.audit(actor, "request.list", "denied", nil)
		writeError(w, "Policy operations role required", http.StatusForbidden)
		return
	}
	s.listPolicyRequests(w, r, true)
}

func namedPolicyRequestActor(r *http.Request) (string, error) {
	actor := strings.ToLower(strings.TrimSpace(getEmailFromSession(r)))
	if actor == "" || actor == "guest" {
		return "", errPolicyRequestForbidden
	}
	canonical, err := canonicalAccountEmail(actor)
	if err != nil {
		return "", errPolicyRequestForbidden
	}
	return canonical, nil
}

func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "sqlite_busy") || strings.Contains(message, "database is locked") || strings.Contains(message, "database is busy")
}

func wrapPolicyRequestStoreError(err error) error {
	if err == nil || errors.Is(err, errPolicyRequestConflict) || errors.Is(err, errPolicyRequestRateLimited) || errors.Is(err, errPolicyRequestPayloadTooLarge) {
		return err
	}
	return fmt.Errorf("%w: %v", errPolicyRequestStorage, err)
}

func writePolicyRequestSubmissionError(w http.ResponseWriter, err error) {
	status, message := http.StatusBadRequest, err.Error()
	switch {
	case errors.Is(err, errPolicyRequestForbidden):
		status = http.StatusForbidden
	case errors.Is(err, errPolicyRequestConflict):
		status = http.StatusConflict
	case errors.Is(err, errPolicyRequestRateLimited):
		status = http.StatusTooManyRequests
		w.Header().Set("Retry-After", strconv.FormatInt(int64(policyRequestSubmitWindow/time.Second), 10))
	case errors.Is(err, errPolicyRequestPayloadTooLarge):
		status = http.StatusRequestEntityTooLarge
		message = errPolicyRequestPayloadTooLarge.Error()
	case isSQLiteBusyError(err):
		status = http.StatusServiceUnavailable
		message = "policy request service is temporarily busy"
		w.Header().Set("Retry-After", "1")
	case errors.Is(err, errPolicyRequestStorage):
		status = http.StatusInternalServerError
		message = "policy request could not be stored"
	}
	writeError(w, message, status)
}

func (s *state) checkPolicyRequestSubmissionQuota(actor string) error {
	db, err := s.policyDB()
	if err != nil {
		return wrapPolicyRequestStoreError(err)
	}
	defer db.Close()
	cutoff := policyRequestTimestamp(time.Now().Add(-policyRequestSubmitWindow))
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_request WHERE requester=? AND created_at>=?`, actor, cutoff).Scan(&count); err != nil {
		return wrapPolicyRequestStoreError(err)
	}
	if count >= policyRequestSubmitLimit {
		return errPolicyRequestRateLimited
	}
	return nil
}

func readStrictRequestBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("request body is required")
	}
	return data, nil
}

func decodeStrictRequestBytes(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func normalizeRequestReason(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("reason is required")
	}
	if len(value) > 4000 {
		return "", errors.New("reason is too long")
	}
	return value, nil
}

func normalizeRequestValues(values []string, protocol bool) ([]string, error) {
	if len(values) == 0 || len(values) > policyRequestValueLimit {
		return nil, fmt.Errorf("values must contain between 1 and %d entries", policyRequestValueLimit)
	}
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if protocol {
			value = strings.ToLower(strings.Join(strings.Fields(value), " "))
		}
		if value == "" || len(value) > 512 {
			return nil, errors.New("values contain an invalid entry")
		}
		if seen[value] {
			return nil, fmt.Errorf("duplicate value %q", value)
		}
		seen[value] = true
		result = append(result, value)
	}
	return result, nil
}

func policyRequestTimestamp(value time.Time) string {
	return value.UTC().Format(policyRequestTimestampLayout)
}

func (s *state) currentPolicyRequestBase(r *http.Request, activeOwner, baseVersion string) (*editablePolicy, string, error) {
	activeOwner = strings.TrimSpace(activeOwner)
	baseVersion = strings.TrimSpace(baseVersion)
	if !policyNameRE.MatchString(activeOwner) {
		return nil, "", errors.New("active_owner is invalid")
	}
	p, version, err := s.latestPublicationSnapshot()
	if err != nil {
		return nil, "", err
	}
	if p == nil || version == "" {
		return nil, "", errors.New("there is no published policy")
	}
	if baseVersion != "" && baseVersion != version {
		return nil, version, fmt.Errorf("%w: base policy changed", errPolicyRequestConflict)
	}
	if !s.canAccessOwner(r, activeOwner) {
		return nil, version, errPolicyRequestForbidden
	}
	return p, version, nil
}

func (s *state) requestServiceVisible(version, owner, service string) bool {
	service = strings.TrimSpace(service)
	if service == "" {
		return false
	}
	lists := s.loadServiceLists(version, owner)
	return lists != nil && lists.accessible[service]
}

func clonePolicyRequestEditablePolicy(p *editablePolicy) (*editablePolicy, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var result editablePolicy
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	// Accounts are intentionally absent from policy JSON. Preserve the live,
	// separately loaded catalog for in-memory owner-reference validation only.
	result.Users = append([]editableUser(nil), p.Users...)
	if p.AccountsVersion != nil {
		version := *p.AccountsVersion
		result.AccountsVersion = &version
	}
	return &result, nil
}

func editablePolicyObjects(p *editablePolicy) map[string]editableObjectContext {
	result := map[string]editableObjectContext{}
	for _, network := range p.Networks {
		result["network:"+network.Name] = editableObjectContext{"network:" + network.Name, "network", network.Name, network.Owner, network.Zone, network.CIDR}
		for _, host := range network.Hosts {
			zone := host.Zone
			if zone == "" {
				zone = network.Zone
			}
			result["host:"+host.Name] = editableObjectContext{"host:" + host.Name, "host", host.Name, host.Owner, zone, host.IP}
		}
	}
	for _, fqdn := range p.FQDNs {
		result["fqdn:"+fqdn.Name] = editableObjectContext{"fqdn:" + fqdn.Name, "fqdn", fqdn.Name, fqdn.Owner, fqdn.Zone, fqdn.FQDN}
	}
	return result
}

type editableObjectContext struct {
	Reference string `json:"reference"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Owner     string `json:"owner"`
	Zone      string `json:"zone,omitempty"`
	Value     string `json:"value"`
}

func findEditableRule(p *editablePolicy, serviceName, stableRuleID string) (*editableRule, error) {
	for si := range p.Services {
		if p.Services[si].Name != serviceName {
			continue
		}
		for ri := range p.Services[si].Rules {
			if p.Services[si].Rules[ri].StableRuleID == stableRuleID {
				return &p.Services[si].Rules[ri], nil
			}
		}
		return nil, errors.New("stable_rule_id does not identify a rule in the selected service")
	}
	return nil, errors.New("service does not exist")
}

func protocolValueKey(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func applyStringDelta(current []string, values []string, operation string, protocol bool) ([]string, error) {
	result := slices.Clone(current)
	key := func(value string) string {
		if protocol {
			return protocolValueKey(value)
		}
		return value
	}
	for _, value := range values {
		index := -1
		for i, existing := range result {
			if key(existing) == key(value) {
				index = i
				break
			}
		}
		switch operation {
		case "add":
			if index >= 0 {
				return nil, fmt.Errorf("value %q already exists", value)
			}
			result = append(result, value)
		case "remove":
			if index < 0 {
				return nil, fmt.Errorf("value %q is not present", value)
			}
			result = slices.Delete(result, index, index+1)
		default:
			return nil, errors.New("operation must be add or remove")
		}
	}
	return result, nil
}

func applyRuleChange(p *editablePolicy, payload storedRuleChangePayload) error {
	rule, err := findEditableRule(p, payload.Service, payload.StableRuleID)
	if err != nil {
		return err
	}
	switch payload.Field {
	case "sources":
		rule.Sources, err = applyStringDelta(rule.Sources, payload.Values, payload.Operation, false)
	case "destinations":
		rule.Destinations, err = applyStringDelta(rule.Destinations, payload.Values, payload.Operation, false)
	case "protocols":
		rule.Protocols, err = applyStringDelta(rule.Protocols, payload.Values, payload.Operation, true)
	default:
		return errors.New("field must be sources, destinations or protocols")
	}
	return err
}

func policyActorOwnerMemberships(owners map[string]editableOwner, actor string) map[string]bool {
	actor = strings.TrimSpace(actor)
	memberships := make(map[string]bool, len(owners))
	visiting := make(map[string]bool, len(owners))
	var hasMembership func(string) bool
	hasMembership = func(name string) bool {
		if member, resolved := memberships[name]; resolved {
			return member
		}
		owner, exists := owners[name]
		if !exists || visiting[name] {
			return false
		}
		visiting[name] = true
		member := slices.ContainsFunc(slices.Concat(slices.Clone(owner.Admins), owner.Users), func(candidate string) bool {
			return strings.EqualFold(strings.TrimSpace(candidate), actor)
		})
		if !member && owner.Parent != "" {
			member = hasMembership(owner.Parent)
		}
		delete(visiting, name)
		memberships[name] = member
		return member
	}
	for name := range owners {
		hasMembership(name)
	}
	return memberships
}

func policyActorOwnerMembershipsForPolicy(p *editablePolicy, actor string) map[string]bool {
	owners := policyOwnerMaps(p)
	memberships := policyActorOwnerMemberships(owners, actor)
	if isPolicyDeveloper(p, actor) {
		for name := range owners {
			memberships[name] = true
		}
	}
	return memberships
}

func sanitizeRequestedService(service *editableService) error {
	if len(service.Owners) > policyRequestOwnerLimit {
		return fmt.Errorf("new service may contain at most %d owners", policyRequestOwnerLimit)
	}
	if len(service.Rules) > policyRequestRuleLimit {
		return fmt.Errorf("new service may contain at most %d rules", policyRequestRuleLimit)
	}
	service.Name = strings.TrimSpace(service.Name)
	service.Description = strings.TrimSpace(service.Description)
	for i := range service.Owners {
		service.Owners[i] = strings.TrimSpace(service.Owners[i])
	}
	for ri := range service.Rules {
		rule := &service.Rules[ri]
		if len(rule.Sources) > policyRequestValueLimit || len(rule.Destinations) > policyRequestValueLimit || len(rule.Protocols) > policyRequestValueLimit {
			return fmt.Errorf("new service rule values may contain at most %d entries per field", policyRequestValueLimit)
		}
		if rule.StableRuleID != "" || rule.ShortID != "" || rule.PolicyComment != "" || rule.NamingVersion != "" {
			return errors.New("server-owned rule identity fields must be empty")
		}
		rule.PolicyName = strings.TrimSpace(rule.PolicyName)
		// These legacy fields are intentionally absent from the applicant UI.
		// Ignore stale-client values and derive safe internal defaults from the
		// current policy instead of allowing applicants to select deployment
		// routing or lifecycle metadata themselves.
		rule.RuleGroup = ""
		rule.ChangeReference = ""
		rule.ReviewDate = ""
		rule.ExpiresAt = ""
		rule.RollbackOwner = ""
		rule.Purpose = ""
		rule.TenantMKZ = ""
		rule.TargetContext = ""
		for i := range rule.Sources {
			rule.Sources[i] = strings.TrimSpace(rule.Sources[i])
		}
		for i := range rule.Destinations {
			rule.Destinations[i] = strings.TrimSpace(rule.Destinations[i])
		}
		for i := range rule.Protocols {
			rule.Protocols[i] = strings.ToLower(strings.Join(strings.Fields(rule.Protocols[i]), " "))
		}
	}
	return nil
}

func applyNewService(p *editablePolicy, payload storedNewServicePayload) error {
	for _, service := range p.Services {
		if service.Name == payload.Service.Name {
			return fmt.Errorf("service %q already exists", payload.Service.Name)
		}
	}
	p.Services = append(p.Services, payload.Service)
	return nil
}

func cloneRequestedService(service editableService) editableService {
	cloned := service
	cloned.Owners = slices.Clone(service.Owners)
	cloned.Rules = make([]editableRule, len(service.Rules))
	for i, rule := range service.Rules {
		cloned.Rules[i] = rule
		cloned.Rules[i].Sources = slices.Clone(rule.Sources)
		cloned.Rules[i].Destinations = slices.Clone(rule.Destinations)
		cloned.Rules[i].Protocols = slices.Clone(rule.Protocols)
	}
	return cloned
}

func validateRequestCandidate(previous, candidate *editablePolicy) error {
	protectManualRuleIdentities(previous, candidate)
	return validateEditablePolicy(candidate)
}

func policyRequestObjectReferenceKind(reference string) (string, bool) {
	kind, name, found := strings.Cut(strings.TrimSpace(reference), ":")
	if !found || !policyNameRE.MatchString(name) {
		return "", false
	}
	switch kind {
	case "network", "host", "fqdn":
		return kind, true
	default:
		return "", false
	}
}

// validatePolicyRequestObjectReferences deliberately returns the same public
// error for an unknown object and an object outside activeOwner. Callers must
// not be able to use request validation as an object-catalog oracle.
func validatePolicyRequestObjectReferences(objects map[string]editableObjectContext, owners map[string]editableOwner, activeOwner string, sources, destinations []string) error {
	validate := func(reference string, source bool) error {
		reference = strings.TrimSpace(reference)
		kind, valid := policyRequestObjectReferenceKind(reference)
		if !valid {
			return errors.New("invalid policy object reference")
		}
		// This rule depends only on the submitted reference, not on whether a
		// matching object exists or is visible.
		if source && kind == "fqdn" {
			return errPolicyRequestFQDNSource
		}
		object, exists := objects[reference]
		if !exists || !ownerScopeContains(owners, activeOwner, object.Owner) {
			return errPolicyRequestObjectUnavailable
		}
		return nil
	}
	for _, reference := range sources {
		if err := validate(reference, true); err != nil {
			return err
		}
	}
	for _, reference := range destinations {
		if err := validate(reference, false); err != nil {
			return err
		}
	}
	return nil
}

func (s *state) validateRuleChangeSubmission(p *editablePolicy, activeOwner string, payload storedRuleChangePayload) (*editablePolicy, error) {
	// Only additions resolve against the object catalog. Removals are checked
	// exclusively against the selected rule below; this avoids turning error
	// messages into an oracle for object names outside the caller's scope.
	if payload.Operation == "add" && (payload.Field == "sources" || payload.Field == "destinations") {
		sources, destinations := []string(nil), []string(nil)
		if payload.Field == "sources" {
			sources = payload.Values
		} else {
			destinations = payload.Values
		}
		if err := validatePolicyRequestObjectReferences(editablePolicyObjects(p), policyOwnerMaps(p), activeOwner, sources, destinations); err != nil {
			return nil, err
		}
	}
	candidate, err := clonePolicyRequestEditablePolicy(p)
	if err == nil {
		err = applyRuleChange(candidate, payload)
	}
	if err == nil {
		err = validateRequestCandidate(p, candidate)
	}
	return candidate, err
}

func (s *state) validateNewServiceSubmission(p *editablePolicy, actor, activeOwner string, payload storedNewServicePayload) (*editablePolicy, error) {
	// Candidate validation adds server-owned IDs and internal deployment
	// defaults. Work on a deep copy so those values never leak back into the
	// immutable applicant payload stored for four-eyes review.
	payload.Service = cloneRequestedService(payload.Service)
	if err := sanitizeRequestedService(&payload.Service); err != nil {
		return nil, err
	}
	if len(payload.Service.Owners) == 0 {
		return nil, errors.New("new service requires at least one owner")
	}
	objects, owners := editablePolicyObjects(p), policyOwnerMaps(p)
	memberships := policyActorOwnerMembershipsForPolicy(p, actor)
	seenOwners := map[string]bool{}
	for _, owner := range payload.Service.Owners {
		if seenOwners[owner] {
			return nil, fmt.Errorf("duplicate service owner %q", owner)
		}
		seenOwners[owner] = true
		if !memberships[owner] {
			return nil, fmt.Errorf("%w: no direct or hierarchy membership for owner %q", errPolicyRequestForbidden, owner)
		}
	}
	for _, rule := range payload.Service.Rules {
		if rule.Owner == "" || !seenOwners[rule.Owner] {
			return nil, fmt.Errorf("rule owner %q must be one of the requested service owners", rule.Owner)
		}
		if !memberships[rule.Owner] {
			return nil, fmt.Errorf("%w: no direct or hierarchy membership for rule owner %q", errPolicyRequestForbidden, rule.Owner)
		}
		if err := validatePolicyRequestObjectReferences(objects, owners, activeOwner, rule.Sources, rule.Destinations); err != nil {
			return nil, err
		}
	}
	candidate, err := clonePolicyRequestEditablePolicy(p)
	if err == nil {
		err = applyNewService(candidate, payload)
	}
	if err == nil {
		err = validateRequestCandidate(p, candidate)
	}
	return candidate, err
}

func newPolicyRequestID() (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "r-" + time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(random), nil
}

func insertPolicyRequestEventTx(tx *sql.Tx, requestID, actor, action, fromStatus, toStatus, comment string, metadata any, createdAt string) error {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO policy_request_event(request_id, actor, action, from_status, to_status, comment, metadata, created_at)
		VALUES(?,?,?,?,?,?,?,?)`, requestID, strings.ToLower(strings.TrimSpace(actor)), action, fromStatus, toStatus, strings.TrimSpace(comment), string(encoded), createdAt)
	return err
}

func (s *state) storeSubmittedPolicyRequest(actor, requestType, activeOwner, baseVersion, reason string, payload any) (*policyRequestRecord, error) {
	id, err := newPolicyRequestID()
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(encoded) > policyRequestPayloadLimit {
		return nil, errPolicyRequestPayloadTooLarge
	}
	now := policyRequestTimestamp(time.Now())
	db, err := s.policyDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	cutoff := policyRequestTimestamp(time.Now().Add(-policyRequestSubmitWindow))
	// The base-version and per-requester quota checks are part of the INSERT
	// write statement. This is the linearization point against publication:
	// either this request is visible to the publication conflict sweep, or a
	// publication that won the race makes the INSERT affect zero rows.
	result, err := tx.Exec(`INSERT INTO policy_request(id, type, requester, active_owner, base_version, payload, reason, status, revision, created_at, updated_at)
		SELECT ?,?,?,?,?,?,?,'submitted',1,?,?
		WHERE ?=(SELECT version FROM policy_publication ORDER BY published_at DESC LIMIT 1)
		  AND (SELECT COUNT(*) FROM policy_request WHERE requester=? AND created_at>=?)<?`,
		id, requestType, actor, activeOwner, baseVersion, string(encoded), reason, now, now,
		baseVersion, actor, cutoff, policyRequestSubmitLimit)
	if err == nil {
		var inserted int64
		inserted, err = result.RowsAffected()
		if err == nil && inserted != 1 {
			var latest string
			latestErr := tx.QueryRow(`SELECT version FROM policy_publication ORDER BY published_at DESC LIMIT 1`).Scan(&latest)
			if latestErr != nil && !errors.Is(latestErr, sql.ErrNoRows) {
				err = latestErr
			} else if latest != baseVersion {
				err = fmt.Errorf("%w: base policy changed", errPolicyRequestConflict)
			} else {
				err = errPolicyRequestRateLimited
			}
		}
	}
	if err == nil {
		err = insertPolicyRequestEventTx(tx, id, actor, "request.submitted", "", "submitted", reason, map[string]any{"type": requestType, "base_version": baseVersion}, now)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	record := &policyRequestRecord{ID: id, Type: requestType, Requester: actor, ActiveOwner: activeOwner, BaseVersion: baseVersion, Payload: payload, Reason: reason, Status: "submitted", Revision: 1, CreatedAt: now, UpdatedAt: now}
	decoratePolicyRequestRecord(record)
	return record, nil
}

func policyRequestTypeFromBytes(data []byte) (string, map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return "", nil, err
	}
	if fields == nil {
		return "", nil, errors.New("request must be a JSON object")
	}
	values := []string{}
	for _, name := range []string{"request_type", "type", "kind"} {
		if raw, exists := fields[name]; exists {
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return "", nil, fmt.Errorf("%s must be a string", name)
			}
			value = strings.ToLower(strings.TrimSpace(value))
			if value != "" {
				values = append(values, value)
			}
		}
	}
	if len(values) == 0 {
		if _, exists := fields["rule_change"]; exists {
			values = append(values, "rule_change")
		} else if _, exists := fields["new_service"]; exists {
			values = append(values, "new_service")
		}
	}
	if len(values) == 0 {
		return "", nil, errors.New("request_type is required")
	}
	for _, value := range values[1:] {
		if value != values[0] {
			return "", nil, errors.New("conflicting request type fields")
		}
	}
	return values[0], fields, nil
}

func (s *state) submitPolicyRequest(w http.ResponseWriter, r *http.Request) {
	actor, err := namedPolicyRequestActor(r)
	if err != nil {
		writeError(w, "Named authenticated user required", http.StatusForbidden)
		return
	}
	if err := s.checkPolicyRequestSubmissionQuota(actor); err != nil {
		s.audit(actor, "request.submit", "failed", map[string]any{"error": err.Error()})
		writePolicyRequestSubmissionError(w, err)
		return
	}
	data, err := readStrictRequestBody(w, r, policyRequestBodyLimit)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, errPolicyRequestPayloadTooLarge.Error(), http.StatusRequestEntityTooLarge)
		} else {
			writeError(w, err.Error(), http.StatusBadRequest)
		}
		return
	}
	requestType, fields, err := policyRequestTypeFromBytes(data)
	if err != nil {
		writeError(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	var record *policyRequestRecord
	switch requestType {
	case "rule_change":
		var request ruleChangeRequest
		if _, nested := fields["rule_change"]; nested {
			var submitted nestedRuleChangeRequest
			err = decodeStrictRequestBytes(data, &submitted)
			request = ruleChangeRequest{
				Type: requestType, StableRuleID: submitted.RuleChange.StableRuleID, Service: submitted.RuleChange.Service,
				Field: submitted.RuleChange.Field, Operation: submitted.RuleChange.Operation, Values: submitted.RuleChange.Values,
				Reason: submitted.Reason, ActiveOwner: submitted.ActiveOwner, BaseVersion: submitted.BaseVersion,
			}
			if err == nil && strings.TrimSpace(submitted.RuleChange.Value) != "" {
				if len(request.Values) != 0 {
					err = errors.New("rule_change must use value or values, not both")
				} else {
					request.Values = []string{submitted.RuleChange.Value}
				}
			}
		} else {
			err = decodeStrictRequestBytes(data, &request)
		}
		request.Service = strings.TrimSpace(request.Service)
		request.StableRuleID = strings.TrimSpace(request.StableRuleID)
		request.Field = strings.ToLower(strings.TrimSpace(request.Field))
		request.Operation = strings.ToLower(strings.TrimSpace(request.Operation))
		request.ActiveOwner = strings.TrimSpace(request.ActiveOwner)
		request.BaseVersion = strings.TrimSpace(request.BaseVersion)
		if err == nil {
			request.Reason, err = normalizeRequestReason(request.Reason)
		}
		if err == nil && !stableIDRE.MatchString(request.StableRuleID) {
			err = errors.New("stable_rule_id is required and invalid")
		}
		if err == nil && (request.Field != "sources" && request.Field != "destinations" && request.Field != "protocols") {
			err = errors.New("field must be sources, destinations or protocols")
		}
		if err == nil && request.Operation != "add" && request.Operation != "remove" {
			err = errors.New("operation must be add or remove")
		}
		if err == nil {
			request.Values, err = normalizeRequestValues(request.Values, request.Field == "protocols")
		}
		var p *editablePolicy
		var version string
		if err == nil {
			p, version, err = s.currentPolicyRequestBase(r, request.ActiveOwner, request.BaseVersion)
		}
		if err == nil && !s.requestServiceVisible(version, request.ActiveOwner, request.Service) {
			err = errPolicyRequestForbidden
		}
		payload := storedRuleChangePayload{request.StableRuleID, request.Service, request.Field, request.Operation, request.Values}
		if err == nil {
			_, err = s.validateRuleChangeSubmission(p, request.ActiveOwner, payload)
		}
		if err == nil {
			record, err = s.storeSubmittedPolicyRequest(actor, requestType, request.ActiveOwner, version, request.Reason, payload)
			err = wrapPolicyRequestStoreError(err)
		}
	case "new_service":
		var request newServiceRequest
		if _, nested := fields["new_service"]; nested {
			var submitted nestedNewServiceRequest
			err = decodeStrictRequestBytes(data, &submitted)
			request = newServiceRequest{Type: requestType, Service: submitted.NewService, Reason: submitted.Reason, ActiveOwner: submitted.ActiveOwner, BaseVersion: submitted.BaseVersion}
		} else {
			err = decodeStrictRequestBytes(data, &request)
		}
		request.ActiveOwner = strings.TrimSpace(request.ActiveOwner)
		request.BaseVersion = strings.TrimSpace(request.BaseVersion)
		if err == nil {
			request.Reason, err = normalizeRequestReason(request.Reason)
		}
		if err == nil {
			err = sanitizeRequestedService(&request.Service)
		}
		var p *editablePolicy
		var version string
		if err == nil {
			p, version, err = s.currentPolicyRequestBase(r, request.ActiveOwner, request.BaseVersion)
		}
		payload := storedNewServicePayload{Service: request.Service}
		if err == nil {
			_, err = s.validateNewServiceSubmission(p, actor, request.ActiveOwner, payload)
		}
		if err == nil {
			record, err = s.storeSubmittedPolicyRequest(actor, requestType, request.ActiveOwner, version, request.Reason, payload)
			err = wrapPolicyRequestStoreError(err)
		}
	default:
		err = errors.New("type must be rule_change or new_service")
	}
	if err != nil {
		s.audit(actor, "request.submit", "failed", map[string]any{"type": requestType, "error": err.Error()})
		writePolicyRequestSubmissionError(w, err)
		return
	}
	s.audit(actor, "request.submit", "success", map[string]any{"request_id": record.ID, "type": record.Type})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "request": record, "id": record.ID, "revision": record.Revision, "status": record.Status})
}

func scanPolicyRequest(scanner interface{ Scan(...any) error }) (*policyRequestRecord, error) {
	var record policyRequestRecord
	var payload string
	if err := scanner.Scan(&record.ID, &record.Type, &record.Requester, &record.ActiveOwner, &record.BaseVersion, &payload, &record.Reason, &record.Status, &record.Revision, &record.RevisionVersion, &record.RejectionComment, &record.CreatedAt, &record.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(payload), &record.Payload); err != nil {
		return nil, err
	}
	decoratePolicyRequestRecord(&record)
	return &record, nil
}

func decoratePolicyRequestRecord(record *policyRequestRecord) {
	if record == nil {
		return
	}
	record.RequestID = record.ID
	record.RequestType = record.Type
}

const policyRequestSelect = `SELECT id, type, requester, active_owner, base_version, payload, reason, status, revision, revision_version, rejection_comment, created_at, updated_at FROM policy_request`

func loadPolicyRequestDB(db *sql.DB, id string) (*policyRequestRecord, error) {
	return scanPolicyRequest(db.QueryRow(policyRequestSelect+` WHERE id=?`, id))
}

func encodePolicyRequestCursor(record *policyRequestRecord) (string, error) {
	encoded, err := json.Marshal(policyRequestCursor{CreatedAt: record.CreatedAt, ID: record.ID})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodePolicyRequestCursor(value string) (*policyRequestCursor, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if len(value) > policyRequestCursorSizeLimit {
		return nil, errors.New("cursor is invalid")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("cursor is invalid")
	}
	var cursor policyRequestCursor
	if err := decodeStrictRequestBytes(decoded, &cursor); err != nil || cursor.ID == "" || len(cursor.ID) > 256 {
		return nil, errors.New("cursor is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, cursor.CreatedAt); err != nil {
		return nil, errors.New("cursor is invalid")
	}
	return &cursor, nil
}

func policyRequestPageParameters(r *http.Request, defaultLimit int) (int, *policyRequestCursor, error) {
	limit := defaultLimit
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > policyRequestPageLimitMax {
			return 0, nil, fmt.Errorf("limit must be between 1 and %d", policyRequestPageLimitMax)
		}
		limit = parsed
	}
	cursor, err := decodePolicyRequestCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		return 0, nil, err
	}
	return limit, cursor, nil
}

type policyRequestRowsQueryer interface {
	Query(string, ...any) (*sql.Rows, error)
}

func loadPolicyRequestEvents(queryer policyRequestRowsQueryer, records []*policyRequestRecord) error {
	for _, record := range records {
		rows, err := queryer.Query(`SELECT actor, action, from_status, to_status, comment, metadata, created_at
			FROM policy_request_event WHERE request_id=? ORDER BY id DESC LIMIT ?`, record.ID, policyRequestEventLimit+1)
		if err != nil {
			return err
		}
		events := make([]policyRequestEvent, 0, policyRequestEventLimit+1)
		for rows.Next() {
			var metadata string
			var event policyRequestEvent
			if err := rows.Scan(&event.Actor, &event.Action, &event.FromStatus, &event.ToStatus, &event.Comment, &metadata, &event.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			_ = json.Unmarshal([]byte(metadata), &event.Metadata)
			events = append(events, event)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(events) > policyRequestEventLimit {
			record.EventsTruncated = true
			events = events[:policyRequestEventLimit]
		}
		slices.Reverse(events)
		record.Events = events
	}
	return nil
}

func (s *state) listPolicyRequests(w http.ResponseWriter, r *http.Request, admin bool) {
	actor, err := namedPolicyRequestActor(r)
	if err != nil {
		writeError(w, "Named authenticated user required", http.StatusForbidden)
		return
	}
	db, err := s.policyDB()
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()
	tx, err := db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	defaultLimit := policyRequestListLimit
	if admin {
		defaultLimit = policyRequestAdminPageLimit
	}
	limit, cursor, err := policyRequestPageParameters(r, defaultLimit)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	query := policyRequestSelect
	conditions := []string{}
	args := []any{}
	if id := strings.TrimSpace(r.FormValue("id")); id != "" {
		conditions = append(conditions, `id=?`)
		args = append(args, id)
		if !admin {
			conditions = append(conditions, `requester=?`)
			args = append(args, actor)
		}
		limit = 1
		cursor = nil
	} else if !admin {
		conditions = append(conditions, `requester=?`)
		args = append(args, actor)
	}
	if cursor != nil {
		conditions = append(conditions, `(created_at<? OR (created_at=? AND id<?))`)
		args = append(args, cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
	}
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := tx.Query(query, args...)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	records := []*policyRequestRecord{}
	for rows.Next() {
		record, scanErr := scanPolicyRequest(rows)
		if scanErr != nil {
			rows.Close()
			writeError(w, scanErr.Error(), http.StatusInternalServerError)
			return
		}
		records = append(records, record)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err == nil {
		err = closeErr
	}
	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	nextCursor := ""
	if err == nil && hasMore && len(records) > 0 {
		nextCursor, err = encodePolicyRequestCursor(records[len(records)-1])
	}
	if err == nil && admin {
		err = loadPolicyRequestEvents(tx, records)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pagination := map[string]any{"limit": limit, "has_more": hasMore, "next_cursor": nextCursor}
	writeJSON(w, map[string]any{"success": true, "records": records, "pagination": pagination})
	return
}

func policyOwnerMaps(p *editablePolicy) map[string]editableOwner {
	result := map[string]editableOwner{}
	for _, owner := range p.Owners {
		result[owner.Name] = owner
	}
	return result
}

func (s *state) policyRequestContext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor, err := namedPolicyRequestActor(r)
	if err != nil {
		writeError(w, "Named authenticated user required", http.StatusForbidden)
		return
	}
	owner := strings.TrimSpace(r.FormValue("active_owner"))
	p, version, err := s.currentPolicyRequestBase(r, owner, r.FormValue("base_version"))
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errPolicyRequestForbidden) {
			status = http.StatusForbidden
		} else if errors.Is(err, errPolicyRequestConflict) {
			status = http.StatusConflict
		}
		writeError(w, err.Error(), status)
		return
	}
	ownerByName := policyOwnerMaps(p)
	memberships := policyActorOwnerMembershipsForPolicy(p, actor)
	objects := []editableObjectContext{}
	for _, object := range editablePolicyObjects(p) {
		if ownerScopeContains(ownerByName, owner, object.Owner) {
			objects = append(objects, object)
		}
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Reference < objects[j].Reference })
	owners := []string{}
	for _, candidate := range p.Owners {
		if memberships[candidate.Name] {
			owners = append(owners, candidate.Name)
		}
	}
	sort.Strings(owners)
	result := map[string]any{
		"success": true, "active_owner": owner, "base_version": version, "current": true,
		"objects": objects, "owners": owners,
	}
	serviceName := strings.TrimSpace(r.FormValue("service"))
	if serviceName != "" {
		if !s.requestServiceVisible(version, owner, serviceName) {
			writeError(w, "Service is not visible for active_owner", http.StatusForbidden)
			return
		}
		rules := []map[string]any{}
		for _, service := range p.Services {
			if service.Name != serviceName {
				continue
			}
			for _, rule := range service.Rules {
				rules = append(rules, map[string]any{"stable_rule_id": rule.StableRuleID, "sources": rule.Sources, "destinations": rule.Destinations, "protocols": rule.Protocols})
			}
			break
		}
		result["service"] = serviceName
		result["rules"] = rules
		stableID := strings.TrimSpace(r.FormValue("stable_rule_id"))
		if stableID != "" {
			rule, findErr := findEditableRule(p, serviceName, stableID)
			if findErr != nil {
				writeError(w, findErr.Error(), http.StatusBadRequest)
				return
			}
			result["rule"] = map[string]any{"stable_rule_id": rule.StableRuleID, "sources": rule.Sources, "destinations": rule.Destinations, "protocols": rule.Protocols}
		}
	}
	writeJSON(w, result)
}

func decodeStoredPolicyRequest(record *policyRequestRecord) (any, error) {
	data, err := json.Marshal(record.Payload)
	if err != nil {
		return nil, err
	}
	switch record.Type {
	case "rule_change":
		var payload storedRuleChangePayload
		if err := decodeStrictRequestBytes(data, &payload); err != nil {
			return nil, err
		}
		return payload, nil
	case "new_service":
		var payload storedNewServicePayload
		if err := decodeStrictRequestBytes(data, &payload); err != nil {
			return nil, err
		}
		return payload, nil
	default:
		return nil, fmt.Errorf("unsupported request type %q", record.Type)
	}
}

func applyStoredPolicyRequest(previous *editablePolicy, record *policyRequestRecord) (*editablePolicy, error) {
	candidate, err := clonePolicyRequestEditablePolicy(previous)
	if err != nil {
		return nil, err
	}
	payload, err := decodeStoredPolicyRequest(record)
	if err != nil {
		return nil, err
	}
	switch value := payload.(type) {
	case storedRuleChangePayload:
		err = applyRuleChange(candidate, value)
	case storedNewServicePayload:
		err = applyNewService(candidate, value)
	}
	if err == nil {
		err = validateRequestCandidate(previous, candidate)
	}
	return candidate, err
}

func buildRequestDeploymentPlan(s *state, previous, candidate *editablePolicy, base string) (deploymentPlan, map[string]any, error) {
	planBase, previousPlan, err := s.deploymentPlanBase(previous, base)
	if err != nil {
		return deploymentPlan{}, nil, err
	}
	plan := generateDeploymentPlanWithBase(planBase, candidate, s.config.FortinetTargets)
	if previous != nil && planBase == nil {
		plan.Warnings = append(plan.Warnings, "Die bisherige Publikation besitzt keinen verifizierten Deploymentplan; dieser Stage ist deshalb ein sicherer Vollabgleich ohne automatische Löschannahmen.")
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
	validation := map[string]any{
		"valid": len(plan.Errors) == 0, "errors": plan.Errors, "warnings": plan.Warnings,
		"deployment_ready": plan.Ready, "plan_hash": plan.Hash,
	}
	return plan, validation, nil
}

func insertPolicyRevisionTx(tx *sql.Tx, version, base string, p *editablePolicy, changes []policyChange, meta revisionMetadata) error {
	document, err := json.Marshal(p)
	if err != nil {
		return err
	}
	diff, err := json.Marshal(changes)
	if err != nil {
		return err
	}
	findings, err := json.Marshal(meta.Findings)
	if err != nil {
		return err
	}
	plan, err := json.Marshal(meta.DeploymentPlan)
	if err != nil {
		return err
	}
	validation, err := json.Marshal(meta.Validation)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO policy_revision(version, base_version, document, changes, status, created_at, created_by, comment, change_reference, findings, deployment_plan, validation)
		VALUES(?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)`, version, base, string(document), string(diff), policyRequestTimestamp(time.Now()), meta.CreatedBy, meta.Comment, meta.ChangeReference, string(findings), string(plan), string(validation))
	return err
}

func (s *state) markRequestConflict(record *policyRequestRecord, actor, comment string) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := policyRequestTimestamp(time.Now())
	result, err := tx.Exec(`UPDATE policy_request SET status='conflict', revision=revision+1, rejection_comment=?, updated_at=? WHERE id=? AND revision=? AND status='submitted'`, comment, now, record.ID, record.Revision)
	if err == nil {
		if count, _ := result.RowsAffected(); count != 1 {
			return errPolicyRequestConflict
		}
		err = insertPolicyRequestEventTx(tx, record.ID, actor, "request.conflict", "submitted", "conflict", comment, nil, now)
	}
	if err == nil {
		err = tx.Commit()
	}
	return err
}

func (s *state) persistStagedPolicyRequest(record *policyRequestRecord, actor, version string, candidate *editablePolicy, changes []policyChange, findings []policyFinding, plan deploymentPlan, validation map[string]any) (int64, error) {
	db, err := s.policyDB()
	if err != nil {
		return 0, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := fencePolicyAccountsTx(tx, candidate); err != nil {
		return 0, err
	}
	var latest string
	if err := tx.QueryRow(`SELECT version FROM policy_publication ORDER BY published_at DESC LIMIT 1`).Scan(&latest); err != nil {
		return 0, err
	}
	now := policyRequestTimestamp(time.Now())
	if latest != record.BaseVersion {
		updated, updateErr := tx.Exec(`UPDATE policy_request SET status='conflict', revision=revision+1, rejection_comment=?, updated_at=? WHERE id=? AND revision=? AND status='submitted'`, "base policy changed", now, record.ID, record.Revision)
		if updateErr != nil {
			return 0, updateErr
		}
		if count, _ := updated.RowsAffected(); count != 1 {
			return 0, errPolicyRequestConflict
		}
		if err := insertPolicyRequestEventTx(tx, record.ID, actor, "request.conflict", "submitted", "conflict", "base policy changed", map[string]any{"current_version": latest}, now); err != nil {
			return 0, err
		}
		if err := tx.Commit(); err != nil {
			return 0, err
		}
		return record.Revision + 1, fmt.Errorf("%w: base policy changed", errPolicyRequestConflict)
	}
	processing, err := tx.Exec(`UPDATE policy_request SET status='processing', revision=revision+1, updated_at=? WHERE id=? AND revision=? AND status='submitted'`, now, record.ID, record.Revision)
	if err != nil {
		return 0, err
	}
	if count, _ := processing.RowsAffected(); count != 1 {
		return 0, errPolicyRequestConflict
	}
	if err := insertPolicyRequestEventTx(tx, record.ID, actor, "request.processing", "submitted", "processing", "", nil, now); err != nil {
		return 0, err
	}
	meta := revisionMetadata{CreatedBy: strings.ToLower(actor), Comment: record.Reason, ChangeReference: "REQ-" + record.ID, Findings: findings, DeploymentPlan: plan, Validation: validation}
	if err := insertPolicyRevisionTx(tx, version, record.BaseVersion, candidate, changes, meta); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`INSERT INTO policy_request_revision(request_id, revision_version, linked_at, linked_by) VALUES(?,?,?,?)`, record.ID, version, now, strings.ToLower(actor)); err != nil {
		return 0, err
	}
	staged, err := tx.Exec(`UPDATE policy_request SET status='staged', revision=revision+1, revision_version=?, rejection_comment='', updated_at=? WHERE id=? AND revision=? AND status='processing'`, version, now, record.ID, record.Revision+1)
	if err != nil {
		return 0, err
	}
	if count, _ := staged.RowsAffected(); count != 1 {
		return 0, errPolicyRequestConflict
	}
	if err := insertPolicyRequestEventTx(tx, record.ID, actor, "request.staged", "processing", "staged", record.Reason, map[string]any{"policy_id": version, "plan_hash": plan.Hash}, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return record.Revision + 2, nil
}

func (s *state) stagePolicyRequest(record *policyRequestRecord, actor string) (*requestStageResult, error) {
	previous, base, err := s.latestPublicationSnapshot()
	if err != nil {
		return nil, err
	}
	if previous == nil || base == "" || base != record.BaseVersion {
		_ = s.markRequestConflict(record, actor, "base policy changed")
		return nil, fmt.Errorf("%w: base policy changed", errPolicyRequestConflict)
	}
	candidate, err := applyStoredPolicyRequest(previous, record)
	if err != nil {
		_ = s.markRequestConflict(record, actor, err.Error())
		return nil, fmt.Errorf("%w: request can no longer be applied: %v", errPolicyRequestConflict, err)
	}
	plan, validation, err := buildRequestDeploymentPlan(s, previous, candidate, base)
	if err != nil {
		return nil, err
	}
	version := newPolicyVersion()
	validation["request_id"] = record.ID
	validation["request_revision"] = record.Revision + 2
	validation["request_type"] = record.Type
	changes := diffPolicies(previous, candidate)
	findings := analyzePolicyRisk(previous, candidate)
	approval, err := revisionApprovalHash(version, previous, candidate, plan, validation)
	if err != nil {
		return nil, err
	}
	requestRevision, err := s.persistStagedPolicyRequest(record, actor, version, candidate, changes, findings, plan, validation)
	if err != nil {
		return nil, err
	}
	return &requestStageResult{PolicyID: version, Approval: approval, Policy: candidate, Changes: changes, Findings: findings, Validation: validation, DeploymentPlan: plan, RequestRevision: requestRevision}, nil
}

func (s *state) adminStagePolicyRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin", "editor") {
		s.audit(actor, "request.stage", "denied", nil)
		writeError(w, "Policy editor role required", http.StatusForbidden)
		return
	}
	var request policyRequestMutation
	err := decodeJSONRequest(w, r, 64<<10, &request)
	request.ID = strings.TrimSpace(request.ID)
	if err == nil && (request.ID == "" || request.Revision < 1) {
		err = errors.New("id and revision are required")
	}
	var record *policyRequestRecord
	if err == nil {
		db, dbErr := s.policyDB()
		if dbErr != nil {
			err = dbErr
		} else {
			record, err = loadPolicyRequestDB(db, request.ID)
			db.Close()
		}
	}
	if err == nil && (record.Revision != request.Revision || record.Status != "submitted") {
		err = errPolicyRequestConflict
	}
	var result *requestStageResult
	if err == nil {
		result, err = s.stagePolicyRequest(record, actor)
	}
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errPolicyRequestConflict) || errors.Is(err, errAccountConflict) {
			status = http.StatusConflict
		}
		s.audit(actor, "request.stage", "failed", map[string]any{"request_id": request.ID, "error": err.Error()})
		writeError(w, err.Error(), status)
		return
	}
	s.audit(actor, "request.stage", "success", map[string]any{"request_id": request.ID, "policy_id": result.PolicyID, "plan_hash": result.DeploymentPlan.Hash})
	writeJSON(w, map[string]any{
		"success": true, "id": request.ID, "request_id": request.ID, "revision": result.RequestRevision, "status": "staged",
		"policy_id": result.PolicyID, "approval": result.Approval, "policy": result.Policy,
		"changes": result.Changes, "findings": result.Findings, "validation": result.Validation,
		"deployment_plan": result.DeploymentPlan, "commands": result.DeploymentPlan.Commands, "created_by": strings.ToLower(actor),
	})
}

func (s *state) rejectUnstagedPolicyRequest(record *policyRequestRecord, actor, comment string) (int64, error) {
	db, err := s.policyDB()
	if err != nil {
		return 0, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := policyRequestTimestamp(time.Now())
	result, err := tx.Exec(`UPDATE policy_request SET status='rejected', revision=revision+1, rejection_comment=?, updated_at=? WHERE id=? AND revision=? AND status=?`, comment, now, record.ID, record.Revision, record.Status)
	if err == nil {
		if count, _ := result.RowsAffected(); count != 1 {
			return 0, errPolicyRequestConflict
		}
		err = insertPolicyRequestEventTx(tx, record.ID, actor, "request.rejected", record.Status, "rejected", comment, nil, now)
	}
	if err == nil {
		err = tx.Commit()
	}
	return record.Revision + 1, err
}

func (s *state) rejectStagedPolicyRequest(record *policyRequestRecord, actor, comment string) (int64, error) {
	allowSelfRejection := bypassesFourEyes(s.authorizationPolicy(), actor)
	db, err := s.policyDB()
	if err != nil {
		return 0, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var createdBy, revisionStatus string
	if err := tx.QueryRow(`SELECT created_by, status FROM policy_revision WHERE version=?`, record.RevisionVersion).Scan(&createdBy, &revisionStatus); err != nil {
		return 0, err
	}
	if strings.EqualFold(createdBy, actor) && !allowSelfRejection {
		return 0, errors.New("revision creator may not reject their own revision")
	}
	if record.Status == "staged" && revisionStatus != "pending" {
		return 0, errors.New("linked revision is not pending")
	}
	if record.Status == "conflict" && revisionStatus != "pending" && revisionStatus != "rejected" {
		return 0, errors.New("linked revision cannot be rejected")
	}
	now := policyRequestTimestamp(time.Now())
	requestUpdate, err := tx.Exec(`UPDATE policy_request SET status='rejected', revision=revision+1, rejection_comment=?, updated_at=? WHERE id=? AND revision=? AND status=?`, comment, now, record.ID, record.Revision, record.Status)
	if err != nil {
		return 0, err
	}
	if count, _ := requestUpdate.RowsAffected(); count != 1 {
		return 0, errPolicyRequestConflict
	}
	if revisionStatus == "pending" {
		revisionUpdate, err := tx.Exec(`UPDATE policy_revision SET status='rejected', rejected_at=?, rejected_by=?, rejection_comment=? WHERE version=? AND status='pending'`, now, strings.ToLower(actor), comment, record.RevisionVersion)
		if err != nil {
			return 0, err
		}
		if count, _ := revisionUpdate.RowsAffected(); count != 1 {
			return 0, errPolicyRequestConflict
		}
	}
	if err := insertPolicyRequestEventTx(tx, record.ID, actor, "request.rejected", record.Status, "rejected", comment, map[string]any{"policy_id": record.RevisionVersion}, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return record.Revision + 1, nil
}

func (s *state) adminRejectPolicyRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin", "reviewer") {
		s.audit(actor, "request.reject", "denied", nil)
		writeError(w, "Policy reviewer role required", http.StatusForbidden)
		return
	}
	var request policyRequestRejection
	err := decodeJSONRequest(w, r, 64<<10, &request)
	request.ID = strings.TrimSpace(request.ID)
	request.Comment = strings.TrimSpace(request.Comment)
	if err == nil && (request.ID == "" || request.Revision < 1 || request.Comment == "") {
		err = errors.New("id, revision and comment are required")
	}
	var record *policyRequestRecord
	if err == nil {
		db, dbErr := s.policyDB()
		if dbErr != nil {
			err = dbErr
		} else {
			record, err = loadPolicyRequestDB(db, request.ID)
			db.Close()
		}
	}
	if err == nil && record.Revision != request.Revision {
		err = errPolicyRequestConflict
	}
	if err == nil && strings.EqualFold(record.Requester, actor) && !bypassesFourEyes(s.authorizationPolicy(), actor) {
		err = errors.New("requester may not reject their own request")
	}
	var revision int64
	if err == nil {
		switch record.Status {
		case "submitted":
			revision, err = s.rejectUnstagedPolicyRequest(record, actor, request.Comment)
		case "staged":
			revision, err = s.rejectStagedPolicyRequest(record, actor, request.Comment)
		case "conflict":
			if record.RevisionVersion == "" {
				revision, err = s.rejectUnstagedPolicyRequest(record, actor, request.Comment)
			} else {
				revision, err = s.rejectStagedPolicyRequest(record, actor, request.Comment)
			}
		default:
			err = fmt.Errorf("request in status %q cannot be rejected", record.Status)
		}
	}
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errPolicyRequestConflict) {
			status = http.StatusConflict
		}
		s.audit(actor, "request.reject", "failed", map[string]any{"request_id": request.ID, "error": err.Error()})
		writeError(w, err.Error(), status)
		return
	}
	s.audit(actor, "request.reject", "success", map[string]any{"request_id": request.ID, "comment": request.Comment})
	writeJSON(w, map[string]any{"success": true, "id": request.ID, "request_id": request.ID, "revision": revision, "status": "rejected"})
}

func linkedPolicyRequestTx(tx *sql.Tx, policyID string) (*policyRequestRecord, error) {
	return scanPolicyRequest(tx.QueryRow(policyRequestSelect+` WHERE id=(SELECT request_id FROM policy_request_revision WHERE revision_version=?)`, policyID))
}

func (s *state) linkedPolicyRequestIdentity(policyID string) (string, string, error) {
	db, err := s.policyDB()
	if err != nil {
		return "", "", err
	}
	defer db.Close()
	var requestID, requester string
	err = db.QueryRow(`SELECT pr.id, pr.requester
		FROM policy_request AS pr
		JOIN policy_request_revision AS link ON link.request_id=pr.id
		WHERE link.revision_version=?`, strings.TrimSpace(policyID)).Scan(&requestID, &requester)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return requestID, requester, err
}

func (s *state) ensurePolicyRequestApproverIsIndependent(policyID, actor string) error {
	if bypassesFourEyes(s.authorizationPolicy(), actor) {
		return nil
	}
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	record, err := scanPolicyRequest(db.QueryRow(policyRequestSelect+` WHERE id=(SELECT request_id FROM policy_request_revision WHERE revision_version=?)`, strings.TrimSpace(policyID)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(record.Requester), strings.TrimSpace(actor)) {
		return errors.New("requester may not approve their own policy request")
	}
	return nil
}

func approveLinkedPolicyRequestTx(tx *sql.Tx, policyID, actor string, allowSelfApproval bool) error {
	record, err := linkedPolicyRequestTx(tx, policyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !allowSelfApproval && strings.EqualFold(strings.TrimSpace(record.Requester), strings.TrimSpace(actor)) {
		return errors.New("requester may not approve their own policy request")
	}
	now := policyRequestTimestamp(time.Now())
	updated, err := tx.Exec(`UPDATE policy_request SET status='approved', revision=revision+1, updated_at=? WHERE id=? AND status='staged' AND revision_version=?`, now, record.ID, policyID)
	if err != nil {
		return err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return fmt.Errorf("linked policy request is not staged")
	}
	return insertPolicyRequestEventTx(tx, record.ID, actor, "request.approved", "staged", "approved", "", map[string]any{"policy_id": policyID}, now)
}

func rejectLinkedPolicyRequestTx(tx *sql.Tx, policyID, actor, comment string, allowSelfRejection bool) error {
	record, err := linkedPolicyRequestTx(tx, policyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !allowSelfRejection && strings.EqualFold(strings.TrimSpace(record.Requester), strings.TrimSpace(actor)) {
		return errors.New("requester may not reject their own policy request")
	}
	now := policyRequestTimestamp(time.Now())
	updated, err := tx.Exec(`UPDATE policy_request SET status='rejected', revision=revision+1, rejection_comment=?, updated_at=? WHERE id=? AND status IN ('staged','conflict') AND revision_version=?`, comment, now, record.ID, policyID)
	if err != nil {
		return err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return fmt.Errorf("linked policy request is not staged or conflicted")
	}
	return insertPolicyRequestEventTx(tx, record.ID, actor, "request.rejected", record.Status, "rejected", comment, map[string]any{"policy_id": policyID}, now)
}

// conflictObsoletePolicyRequestsTx invalidates every still-actionable request
// based on an older publication. Linked pending revisions are rejected in the
// same transaction so they can never be approved after their base changed.
func conflictObsoletePolicyRequestsTx(tx *sql.Tx, publishedVersion, actor string) error {
	rows, err := tx.Query(policyRequestSelect+` WHERE status IN ('submitted','staged') AND base_version<>? ORDER BY created_at`, publishedVersion)
	if err != nil {
		return err
	}
	records := []*policyRequestRecord{}
	for rows.Next() {
		record, scanErr := scanPolicyRequest(rows)
		if scanErr != nil {
			rows.Close()
			return scanErr
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	now := policyRequestTimestamp(time.Now())
	comment := "base policy changed after another revision was published"
	for _, record := range records {
		if record.Status == "staged" && record.RevisionVersion != "" {
			updated, updateErr := tx.Exec(`UPDATE policy_revision SET status='rejected', rejected_at=?, rejected_by=?, rejection_comment=? WHERE version=? AND status='pending'`, now, strings.ToLower(strings.TrimSpace(actor)), comment, record.RevisionVersion)
			if updateErr != nil {
				return updateErr
			}
			if count, _ := updated.RowsAffected(); count != 1 {
				return fmt.Errorf("linked revision %q is not pending", record.RevisionVersion)
			}
		}
		updated, updateErr := tx.Exec(`UPDATE policy_request SET status='conflict', revision=revision+1, rejection_comment=?, updated_at=? WHERE id=? AND revision=? AND status=?`, comment, now, record.ID, record.Revision, record.Status)
		if updateErr != nil {
			return updateErr
		}
		if count, _ := updated.RowsAffected(); count != 1 {
			return errPolicyRequestConflict
		}
		metadata := map[string]any{"current_version": publishedVersion}
		if record.RevisionVersion != "" {
			metadata["policy_id"] = record.RevisionVersion
		}
		if err := insertPolicyRequestEventTx(tx, record.ID, actor, "request.conflict", record.Status, "conflict", comment, metadata, now); err != nil {
			return err
		}
	}
	return nil
}

func updateLinkedPolicyRequestDeploymentTx(tx *sql.Tx, result *deploymentRunResult) error {
	record, err := linkedPolicyRequestTx(tx, result.PolicyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	now := policyRequestTimestamp(time.Now())
	metadata := map[string]any{"deployment_id": result.DeploymentID, "policy_id": result.PolicyID, "targets": result.Targets, "status": result.Status}
	if result.Status != "succeeded" {
		metadata["error"] = result.Error
		return insertPolicyRequestEventTx(tx, record.ID, result.Actor, "request.deployment_failed", record.Status, record.Status, result.Error, metadata, now)
	}
	completeErr := requireLatestPublicationDeployed(tx)
	if completeErr != nil && !errors.Is(completeErr, errPublicationRequiresDeployment) {
		return completeErr
	}
	if errors.Is(completeErr, errPublicationRequiresDeployment) {
		return insertPolicyRequestEventTx(tx, record.ID, result.Actor, "request.deployment_partial", record.Status, record.Status, "", metadata, now)
	}
	updated, err := tx.Exec(`UPDATE policy_request SET status='deployed', revision=revision+1, updated_at=? WHERE id=? AND status='approved' AND revision_version=?`, now, record.ID, result.PolicyID)
	if err != nil {
		return err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		if record.Status == "deployed" {
			return nil
		}
		return fmt.Errorf("linked policy request is not approved")
	}
	return insertPolicyRequestEventTx(tx, record.ID, result.Actor, "request.deployed", "approved", "deployed", "", metadata, now)
}
