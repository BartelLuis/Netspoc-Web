package backend

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"
)

// deployRequest intentionally contains both the immutable revision identifier
// and its reviewed plan hash. confirm is not optional: deployment must never be
// triggered by merely opening the endpoint or replaying a staging response.
type deployRequest struct {
	PolicyID string `json:"policy_id"`
	PlanHash string `json:"plan_hash"`
	Confirm  bool   `json:"confirm"`
	Target   string `json:"target,omitempty"`
}

type fortinetSystemInfo struct {
	Target  string `json:"target"`
	Version string `json:"version"`
	Build   string `json:"build,omitempty"`
}

type deploymentCommandResult struct {
	Target   string `json:"target"`
	Context  string `json:"context"`
	Sequence int    `json:"sequence"`
	Kind     string `json:"kind"`
	Method   string `json:"method"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

type deploymentRunResult struct {
	DeploymentID      string                    `json:"deployment_id"`
	PolicyID          string                    `json:"policy_id"`
	PlanHash          string                    `json:"plan_hash"`
	Actor             string                    `json:"actor"`
	Targets           []string                  `json:"targets"`
	Status            string                    `json:"status"`
	CommandsTotal     int                       `json:"commands_total"`
	CommandsApplied   int                       `json:"commands_applied"`
	Systems           []fortinetSystemInfo      `json:"systems"`
	Results           []deploymentCommandResult `json:"results"`
	Error             string                    `json:"error,omitempty"`
	RollbackAttempted bool                      `json:"rollback_attempted"`
	RollbackSucceeded bool                      `json:"rollback_succeeded"`
	RollbackErrors    []string                  `json:"rollback_errors"`
	StartedAt         string                    `json:"started_at"`
	FinishedAt        string                    `json:"finished_at,omitempty"`
}

type publishedDeployment struct {
	Record       *policyRevisionRecord
	Policy       *editablePolicy
	Previous     *editablePolicy
	PreviousPlan *deploymentPlan
	Plan         deploymentPlan
}

type runtimeTarget struct {
	Config             FortinetTarget
	Commands           []deploymentCommand
	Client             *http.Client
	System             fortinetSystemInfo
	PreconditionsBound bool
	ExpectedBefore     map[string]map[string]any
	// PolicyOrder is the exact, device-assigned mkey order observed during the
	// all-target snapshot. It is advanced only after a reviewed create/move or
	// delete has been verified, so later revalidation can distinguish our own
	// PREPARE changes from an administrator reorder.
	PolicyOrder map[string][]string
}

var errDeploymentRunning = errors.New("another deployment is already running")
var errDeploymentRevisionSuperseded = errors.New("only the latest published revision may be deployed; publish a new rollback revision instead")
var errPublicationRequiresDeployment = errors.New("the latest executable publication must be successfully deployed to every approved target before another revision can be published")

func publicationLockID(version string) string {
	return "publication:" + strings.TrimSpace(version)
}

// loadPublishedDeployment only accepts an immutable revision that completed
// the four-eyes publication workflow. It also checks that the publication and
// revision documents are byte-for-byte equal after canonical JSON encoding.
func (s *state) loadPublishedDeployment(version string) (*publishedDeployment, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return nil, errors.New("policy_id is required")
	}
	record, err := s.loadRevisionRecord(version, false)
	if err != nil {
		return nil, fmt.Errorf("load revision: %w", err)
	}
	if record.Status != "published" {
		return nil, errors.New("revision is not published")
	}
	published, err := s.loadPublication(version)
	if err != nil {
		return nil, fmt.Errorf("load published policy: %w", err)
	}
	if !samePolicyDocument(record.Policy, published) {
		return nil, errors.New("published policy does not match its approved revision")
	}
	var previous *editablePolicy
	var previousPlan *deploymentPlan
	if strings.TrimSpace(record.Base) != "" {
		previous, err = s.loadPublication(record.Base)
		if err != nil {
			return nil, fmt.Errorf("load base publication %q: %w", record.Base, err)
		}
		baseRecord, baseErr := s.loadRevisionRecord(record.Base, false)
		if errors.Is(baseErr, sql.ErrNoRows) {
			// Bootstrap/legacy publications predate immutable revisions. Staging
			// turns their successor into a nil->Next full reconciliation plan.
			baseRecord = nil
		} else if baseErr != nil {
			return nil, fmt.Errorf("load base revision %q: %w", record.Base, baseErr)
		}
		if baseRecord != nil {
			if baseRecord.Status != "published" || !samePolicyDocument(baseRecord.Policy, previous) {
				return nil, fmt.Errorf("base publication %q does not match its approved revision", record.Base)
			}
			if !missingStoredDeploymentPlan(baseRecord.DeploymentPlan) {
				decoded, decodeErr := decodeStoredDeploymentPlan(baseRecord.DeploymentPlan)
				if decodeErr != nil {
					return nil, fmt.Errorf("load base deployment plan %q: %w", record.Base, decodeErr)
				}
				previousPlan = &decoded
			}
		}
	}
	plan, err := decodeStoredDeploymentPlan(record.DeploymentPlan)
	if err != nil {
		return nil, err
	}
	return &publishedDeployment{Record: record, Policy: published, Previous: previous, PreviousPlan: previousPlan, Plan: plan}, nil
}

func samePolicyDocument(first, second *editablePolicy) bool {
	a, errA := json.Marshal(first)
	b, errB := json.Marshal(second)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

func missingStoredDeploymentPlan(value any) bool {
	if value == nil {
		return true
	}
	data, err := json.Marshal(value)
	return err == nil && string(data) == "null"
}

func decodeStoredDeploymentPlan(value any) (deploymentPlan, error) {
	if value == nil {
		return deploymentPlan{}, errors.New("published revision has no deployment plan")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return deploymentPlan{}, fmt.Errorf("encode stored deployment plan: %w", err)
	}
	var plan deploymentPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return deploymentPlan{}, fmt.Errorf("decode stored deployment plan: %w", err)
	}
	storedHash := strings.TrimSpace(plan.Hash)
	storedReady := plan.Ready
	if storedHash == "" {
		return deploymentPlan{}, errors.New("published deployment plan has no hash")
	}
	verified := plan
	verified.finish()
	if verified.Hash != storedHash {
		return deploymentPlan{}, errors.New("published deployment plan failed its integrity check")
	}
	if verified.Ready != storedReady {
		return deploymentPlan{}, errors.New("published deployment plan has inconsistent readiness metadata")
	}
	return plan, nil
}

// recomputePublishedDeploymentPlan binds runtime execution to both the base
// publication and the currently configured target mapping. The shared helper
// also emits narrowly-scoped policy DELETE commands for rules removed since
// the base revision.
func (s *state) recomputePublishedDeploymentPlan(item *publishedDeployment) (deploymentPlan, error) {
	base := item.Previous
	if item.PreviousPlan == nil {
		base = nil
	}
	current := generateDeploymentPlanWithBase(base, item.Policy, s.config.FortinetTargets)
	if err := bindPolicyDeletePayloadsToPreviousPlan(&current, item.PreviousPlan); err != nil {
		return current, fmt.Errorf("bind immutable policy DELETE baseline: %w", err)
	}
	if current.Hash != item.Plan.Hash {
		return current, errors.New("deployment plan no longer matches the approved revision and current target configuration")
	}
	if !current.Ready || len(current.Errors) != 0 {
		return current, errors.New("deployment plan is not executable")
	}
	return current, nil
}

func (s *state) requireLatestPublishedDeployment(version string) error {
	latest, err := s.latestPublicationVersion()
	if err != nil {
		return fmt.Errorf("load latest publication: %w", err)
	}
	if latest == "" {
		return errors.New("there is no published revision")
	}
	if latest != strings.TrimSpace(version) {
		return errDeploymentRevisionSuperseded
	}
	return nil
}

// bindRuntimePreconditions derives the exact approved state that may be
// replaced by every UPSERT from the base publication's stored plan. Rebuilding
// it with today's zone/interface mapping would invent a baseline that was
// never approved or deployed. An endpoint identity change is likewise blocked:
// moving a policy to another device/VDOM needs an explicit migration workflow.
func (s *state) bindRuntimePreconditions(targets []*runtimeTarget, published *publishedDeployment) error {
	selected := make(map[string]*runtimeTarget, len(targets))
	for _, target := range targets {
		target.PreconditionsBound = true
		target.ExpectedBefore = map[string]map[string]any{}
		selected[target.Config.Name] = target
	}
	if published.Previous == nil {
		return nil
	}
	if published.PreviousPlan == nil {
		for _, command := range published.Plan.Commands {
			if strings.EqualFold(command.Method, http.MethodDelete) {
				return errors.New("full reconciliation from a bootstrap/legacy base must not contain DELETE commands")
			}
		}
		return nil
	}
	if err := validateDeploymentTopologyTransition(*published.PreviousPlan, published.Plan); err != nil {
		return err
	}
	baseEndpoints, err := deploymentPlanTargetBindings(*published.PreviousPlan)
	if err != nil {
		return fmt.Errorf("invalid base deployment target identity: %w", err)
	}
	nextEndpoints, err := deploymentPlanTargetBindings(published.Plan)
	if err != nil {
		return fmt.Errorf("invalid approved deployment target identity: %w", err)
	}
	for name := range selected {
		previous, existed := baseEndpoints[name]
		if existed && previous != nextEndpoints[name] {
			return fmt.Errorf("target %q endpoint identity changed since the deployed base; an explicit device migration is required", name)
		}
	}
	for _, command := range published.PreviousPlan.Commands {
		if !strings.EqualFold(command.Method, "UPSERT") {
			continue
		}
		target := selected[command.Target]
		if target == nil {
			continue
		}
		identity, err := deploymentCommandIdentity(command)
		if err != nil {
			return fmt.Errorf("derive approved base deployment state: %w", err)
		}
		if existing, found := target.ExpectedBefore[identity]; found {
			if !sameJSONValue(existing, command.Payload) {
				return fmt.Errorf("approved base contains conflicting states for %q on target %q", command.Payload["name"], command.Target)
			}
			continue
		}
		target.ExpectedBefore[identity] = cloneDeploymentPayload(command.Payload)
	}
	return nil
}

type deploymentTargetBinding struct {
	Type       string
	Scope      string
	EndpointID string
}

// validateDeploymentTopologyTransition is shared by staging and runtime. A
// target-set, executable/preview, endpoint, type, or scope migration cannot be
// represented safely by ordinary policy deltas because it may orphan state on
// the old device or assume an undeployed baseline on the new one.
func validateDeploymentTopologyTransition(previous, next deploymentPlan) error {
	oldBindings, err := executableContextBindings(previous)
	if err != nil {
		return fmt.Errorf("invalid base deployment topology: %w", err)
	}
	newBindings, err := executableContextBindings(next)
	if err != nil {
		return fmt.Errorf("invalid next deployment topology: %w", err)
	}
	if len(oldBindings) != len(newBindings) {
		return errors.New("executable deployment target set changed; an explicit target migration is required")
	}
	for identity, previousBinding := range oldBindings {
		if nextBinding, exists := newBindings[identity]; !exists || nextBinding != previousBinding {
			parts := strings.SplitN(identity, "\x00", 2)
			return fmt.Errorf("target %q context %q deployment topology changed; an explicit target migration is required", parts[0], parts[1])
		}
	}
	return nil
}

func executableContextBindings(plan deploymentPlan) (map[string]deploymentTargetBinding, error) {
	if _, err := deploymentPlanTargetBindings(plan); err != nil {
		return nil, err
	}
	result := map[string]deploymentTargetBinding{}
	for _, target := range plan.Targets {
		if !target.Executable {
			continue
		}
		if strings.TrimSpace(target.Context) == "" {
			return nil, fmt.Errorf("executable target %q has no context binding", target.Name)
		}
		identity := target.Name + "\x00" + target.Context
		binding := deploymentTargetBinding{Type: target.Type, Scope: target.Scope, EndpointID: target.EndpointID}
		if previous, exists := result[identity]; exists && previous != binding {
			return nil, fmt.Errorf("target %q context %q has conflicting deployment bindings", target.Name, target.Context)
		}
		result[identity] = binding
	}
	return result, nil
}

func deploymentPlanTargetBindings(plan deploymentPlan) (map[string]deploymentTargetBinding, error) {
	result := map[string]deploymentTargetBinding{}
	for _, target := range plan.Targets {
		if target.Name == "" || target.EndpointID == "" {
			return nil, errors.New("deployment target has no endpoint identity")
		}
		binding := deploymentTargetBinding{Type: target.Type, Scope: target.Scope, EndpointID: target.EndpointID}
		if previous, exists := result[target.Name]; exists && previous != binding {
			return nil, fmt.Errorf("target %q has conflicting endpoint identities", target.Name)
		}
		result[target.Name] = binding
	}
	return result, nil
}

func deploymentCommandIdentity(command deploymentCommand) (string, error) {
	name, ok := command.Payload["name"].(string)
	if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(command.Path) == "" {
		return "", errors.New("deployment command has no stable path/name identity")
	}
	return command.Path + "\x00" + name, nil
}

func cloneDeploymentPayload(value map[string]any) map[string]any {
	data, _ := json.Marshal(value)
	result := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	_ = decoder.Decode(&result)
	return result
}

func sameJSONValue(first, second any) bool {
	a, errA := json.Marshal(first)
	b, errB := json.Marshal(second)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

func (s *state) runtimeTargets(plan deploymentPlan, requested string, requireDeploy bool) ([]*runtimeTarget, error) {
	if plan.ExecutionModel != fortiOSExecutionModelVersion || plan.PolicySemanticsVersion != fortiOSPolicySemanticsVersion {
		return nil, fmt.Errorf("approved plan uses unsupported FortiOS execution/semantics model %q/%q", plan.ExecutionModel, plan.PolicySemanticsVersion)
	}
	configured := make(map[string]FortinetTarget, len(s.config.FortinetTargets))
	for _, target := range s.config.FortinetTargets {
		if _, exists := configured[target.Name]; exists {
			return nil, fmt.Errorf("Fortinet target name %q is configured more than once", target.Name)
		}
		configured[target.Name] = target
	}

	planned := map[string]bool{}
	for _, summary := range plan.Targets {
		planned[summary.Name] = true
	}
	commandTargets := map[string]bool{}
	for _, command := range plan.Commands {
		commandTargets[command.Target] = true
	}

	requested = strings.TrimSpace(requested)
	names := []string{}
	if requested != "" {
		if !planned[requested] || !commandTargets[requested] {
			return nil, fmt.Errorf("target %q is not part of the approved deployment plan", requested)
		}
		names = append(names, requested)
	} else {
		for name := range commandTargets {
			target, exists := configured[name]
			if exists && (!requireDeploy || target.AllowDeploy) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
	}
	if len(names) == 0 {
		return nil, errors.New("the approved plan contains no selected Fortinet target")
	}

	result := make([]*runtimeTarget, 0, len(names))
	for _, name := range names {
		target, exists := configured[name]
		if !exists {
			return nil, fmt.Errorf("target %q is no longer configured", name)
		}
		if requireDeploy && !target.AllowDeploy {
			return nil, fmt.Errorf("target %q is preview-only (allow_deploy=false)", name)
		}
		commands := []deploymentCommand{}
		for _, command := range plan.Commands {
			if command.Target != name {
				continue
			}
			if err := validateRuntimeCommand(target, command); err != nil {
				return nil, err
			}
			commands = append(commands, command)
		}
		if len(commands) == 0 {
			return nil, fmt.Errorf("target %q has no commands", name)
		}
		if err := validateRuntimePolicyChain(target, commands); err != nil {
			return nil, err
		}
		anchor := strings.TrimSpace(target.PolicyInsertBefore)
		for _, command := range commands {
			if strings.EqualFold(command.Method, http.MethodDelete) && strings.TrimSpace(scalarString(command.Payload["name"])) == anchor {
				return nil, fmt.Errorf("target %q deployment plan attempts to delete its policy insertion anchor", name)
			}
		}
		result = append(result, &runtimeTarget{Config: target, Commands: commands})
	}
	return result, nil
}

func validateRuntimeCommand(target FortinetTarget, command deploymentCommand) error {
	if command.Sequence <= 0 || command.Target != target.Name {
		return fmt.Errorf("target %q contains an invalid command identity", target.Name)
	}
	switch command.Kind {
	case "address", "address6", "service", "policy":
	default:
		return fmt.Errorf("target %q contains unsupported command kind %q", target.Name, command.Kind)
	}
	if command.Path != deploymentPath(target, command.Kind) {
		return fmt.Errorf("target %q contains an unexpected API path", target.Name)
	}
	if err := validatePolicySemanticsVersion(command); err != nil {
		return fmt.Errorf("target %q command %d: %w", target.Name, command.Sequence, err)
	}
	method := strings.ToUpper(command.Method)
	if method != "UPSERT" && !(method == http.MethodDelete && command.Kind == "policy") {
		return fmt.Errorf("target %q contains unsupported %s operation for %s", target.Name, command.Method, command.Kind)
	}
	if command.Kind == "policy" && method == "UPSERT" {
		if strings.TrimSpace(command.InsertBefore) == "" || command.InsertBefore != strings.TrimSpace(command.InsertBefore) {
			return fmt.Errorf("target %q policy command %d has no reviewed insertion successor", target.Name, command.Sequence)
		}
		for _, character := range command.InsertBefore {
			if unicode.IsControl(character) {
				return fmt.Errorf("target %q policy command %d insertion successor contains control characters", target.Name, command.Sequence)
			}
		}
		if command.CreatePayload == nil || len(command.CreatePayload) != len(command.Payload)+1 || scalarString(command.CreatePayload["policyid"]) != "0" {
			return fmt.Errorf("target %q policy command %d has no reviewed FortiOS create payload with policyid=0", target.Name, command.Sequence)
		}
		createForComparison := make(map[string]any, len(command.CreatePayload)-1)
		for key, value := range command.CreatePayload {
			if key != "policyid" {
				createForComparison[key] = value
			}
		}
		if scalarString(createForComparison["status"]) != "disable" {
			return fmt.Errorf("target %q policy command %d create payload is not safely disabled", target.Name, command.Sequence)
		}
		createForComparison["status"] = "enable"
		desiredJSON, desiredErr := json.Marshal(command.Payload)
		createJSON, createErr := json.Marshal(createForComparison)
		if desiredErr != nil || createErr != nil || !bytes.Equal(desiredJSON, createJSON) {
			return fmt.Errorf("target %q policy command %d create payload differs from its reviewed desired state", target.Name, command.Sequence)
		}
		if len(command.ActivatePayload) != 1 || scalarString(command.ActivatePayload["status"]) != "enable" {
			return fmt.Errorf("target %q policy command %d has no reviewed activation payload", target.Name, command.Sequence)
		}
	} else if strings.TrimSpace(command.InsertBefore) != "" {
		return fmt.Errorf("target %q command %d contains an unexpected policy insertion anchor", target.Name, command.Sequence)
	} else if command.CreatePayload != nil || command.ActivatePayload != nil {
		return fmt.Errorf("target %q command %d contains an unexpected create/activation payload", target.Name, command.Sequence)
	}
	if command.Kind == "policy" && method == http.MethodDelete {
		required := []string{
			"name", "srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6",
			"status", "action", "match-vip", "match-vip-only", "service", "schedule", "logtraffic", "comments",
			"srcaddr-negate", "dstaddr-negate", "srcaddr6-negate", "dstaddr6-negate", "service-negate",
			"users", "groups", "fsso-groups", "tos", "tos-mask", "tos-negate", "sgt-check", "sgt",
			"ztna-status", "ztna-ems-tag", "ztna-ems-tag-secondary", "ztna-geo-tag",
			"ztna-policy-redirect", "ztna-device-ownership", "ztna-tags-match-logic",
			"internet-service", "internet-service-src", "internet-service6", "internet-service6-src",
			"internet-service-negate", "internet-service-src-negate", "internet-service6-negate", "internet-service6-src-negate",
			"nat", "nat46", "nat64", "policy-expiry",
		}
		for _, field := range required {
			if _, exists := command.Payload[field]; !exists {
				return fmt.Errorf("target %q policy DELETE command %d lacks approved base field %s", target.Name, command.Sequence, field)
			}
		}
		ipv4Source := deploymentCollectionNonEmpty(command.Payload["srcaddr"])
		ipv4Destination := deploymentCollectionNonEmpty(command.Payload["dstaddr"])
		ipv6Source := deploymentCollectionNonEmpty(command.Payload["srcaddr6"])
		ipv6Destination := deploymentCollectionNonEmpty(command.Payload["dstaddr6"])
		if ipv4Source != ipv4Destination || ipv6Source != ipv6Destination || ipv4Source == ipv6Source {
			return fmt.Errorf("target %q policy DELETE command %d has no unambiguous approved address family", target.Name, command.Sequence)
		}
	}
	name, ok := command.Payload["name"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		return fmt.Errorf("target %q command %d has no object name", target.Name, command.Sequence)
	}
	if command.Kind == "policy" && method == "UPSERT" && name == command.InsertBefore {
		return fmt.Errorf("target %q policy command %d cannot use itself as insertion anchor", target.Name, command.Sequence)
	}
	contextAllowed := false
	for _, context := range target.TargetContexts {
		if context == command.Context {
			contextAllowed = true
			break
		}
	}
	if !contextAllowed {
		return fmt.Errorf("target %q command %d uses an unconfigured target context", target.Name, command.Sequence)
	}
	return nil
}

func deploymentCollectionNonEmpty(value any) bool {
	switch item := value.(type) {
	case []any:
		return len(item) != 0
	case []string:
		return len(item) != 0
	case []map[string]string:
		return len(item) != 0
	default:
		return value != nil
	}
}

// validateRuntimePolicyChain ensures the reviewed policy commands describe one
// unambiguous contiguous block ending at the configured device-local anchor.
// Commands must be sequenced bottom-up so every managed successor is present
// before a newly created predecessor is moved in front of it.
func validateRuntimePolicyChain(target FortinetTarget, commands []deploymentCommand) error {
	policies := map[string]deploymentCommand{}
	for _, command := range commands {
		if command.Kind != "policy" || !strings.EqualFold(command.Method, "UPSERT") {
			continue
		}
		name := scalarString(command.Payload["name"])
		if _, exists := policies[name]; exists {
			return fmt.Errorf("target %q contains duplicate managed policy name %q", target.Name, name)
		}
		policies[name] = command
	}
	if len(policies) == 0 {
		return nil
	}
	terminal := strings.TrimSpace(target.PolicyInsertBefore)
	if terminal == "" || target.PolicyInsertBefore != terminal {
		return fmt.Errorf("target %q has no configured policy insertion anchor", target.Name)
	}
	for _, character := range terminal {
		if unicode.IsControl(character) {
			return fmt.Errorf("target %q policy insertion anchor contains control characters", target.Name)
		}
	}
	if _, collision := policies[terminal]; collision {
		return fmt.Errorf("target %q configured insertion anchor %q collides with a managed policy", target.Name, terminal)
	}

	referenced := map[string]bool{}
	terminalEdges := 0
	for name, command := range policies {
		successor := strings.TrimSpace(command.InsertBefore)
		if successor == terminal {
			terminalEdges++
		} else {
			successorCommand, exists := policies[successor]
			if !exists {
				return fmt.Errorf("target %q policy %q references unapproved insertion successor %q", target.Name, name, successor)
			}
			if referenced[successor] {
				return fmt.Errorf("target %q policy insertion chain branches at %q", target.Name, successor)
			}
			referenced[successor] = true
			if successorCommand.Sequence >= command.Sequence {
				return fmt.Errorf("target %q policy insertion chain is not sequenced bottom-up at %q", target.Name, name)
			}
		}
	}
	if terminalEdges != 1 {
		return fmt.Errorf("target %q policy insertion chain must end exactly once at configured anchor %q", target.Name, terminal)
	}
	heads := []string{}
	for name := range policies {
		if !referenced[name] {
			heads = append(heads, name)
		}
	}
	if len(heads) != 1 {
		return fmt.Errorf("target %q policy insertion chain is disconnected or cyclic", target.Name)
	}
	visited := map[string]bool{}
	for name := heads[0]; name != terminal; name = policies[name].InsertBefore {
		if visited[name] {
			return fmt.Errorf("target %q policy insertion chain is cyclic", target.Name)
		}
		visited[name] = true
		if _, exists := policies[name]; !exists {
			return fmt.Errorf("target %q policy insertion chain is incomplete", target.Name)
		}
	}
	if len(visited) != len(policies) {
		return fmt.Errorf("target %q policy insertion chain is disconnected", target.Name)
	}
	return nil
}

func targetNames(targets []*runtimeTarget) []string {
	result := make([]string, 0, len(targets))
	for _, target := range targets {
		result = append(result, target.Config.Name)
	}
	return result
}

func commandCount(targets []*runtimeTarget) int {
	total := 0
	for _, target := range targets {
		total += len(target.Commands)
	}
	return total
}

func (s *state) adminDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin", "deployer") {
		s.audit(actor, "deployment.execute", "denied", nil)
		writeError(w, "Policy deployer role required", http.StatusForbidden)
		return
	}
	if s.config.FortiGateReadOnly {
		s.audit(actor, "deployment.execute", "blocked", map[string]any{"error": errFortiGateReadOnly.Error()})
		writeError(w, errFortiGateReadOnly.Error(), http.StatusConflict)
		return
	}

	var request deployRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&request)
	if err == nil {
		err = requireJSONEOF(decoder)
	}
	if err == nil && !request.Confirm {
		err = errors.New("confirm=true is required")
	}
	if err == nil && strings.TrimSpace(request.PlanHash) == "" {
		err = errors.New("plan_hash is required")
	}
	if err != nil {
		s.audit(actor, "deployment.execute", "blocked", map[string]any{"policy_id": request.PolicyID, "target": request.Target, "error": err.Error()})
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var published *publishedDeployment
	err = s.requireLatestPublishedDeployment(request.PolicyID)
	if err == nil {
		published, err = s.loadPublishedDeployment(request.PolicyID)
	}
	var plan deploymentPlan
	if err == nil {
		plan, err = s.recomputePublishedDeploymentPlan(published)
	}
	if err == nil && request.PlanHash != plan.Hash {
		err = errors.New("plan_hash does not match the approved deployment plan")
	}
	var targets []*runtimeTarget
	if err == nil {
		targets, err = s.runtimeTargets(plan, request.Target, true)
	}
	if err == nil {
		err = s.bindRuntimePreconditions(targets, published)
	}
	if err != nil {
		s.audit(actor, "deployment.execute", "blocked", map[string]any{"policy_id": request.PolicyID, "target": request.Target, "error": err.Error()})
		writeError(w, err.Error(), http.StatusConflict)
		return
	}

	deploymentID, err := newDeploymentID()
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	result := deploymentRunResult{
		DeploymentID: deploymentID, PolicyID: request.PolicyID, PlanHash: plan.Hash, Actor: strings.ToLower(actor),
		Targets: targetNames(targets), Status: "running", CommandsTotal: commandCount(targets),
		Systems: []fortinetSystemInfo{}, Results: []deploymentCommandResult{}, RollbackErrors: []string{},
		StartedAt: now.Format(time.RFC3339Nano),
	}
	if err := s.startDeploymentLog(&result, request.Target); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errDeploymentRunning) || errors.Is(err, errDeploymentRevisionSuperseded) {
			status = http.StatusConflict
		}
		s.audit(actor, "deployment.execute", "blocked", map[string]any{"policy_id": request.PolicyID, "error": err.Error()})
		writeError(w, err.Error(), status)
		return
	}
	defer s.releaseDeploymentLock(deploymentID)

	// A confirmed deployment is a server-owned operation. Disconnecting the
	// browser/proxy must not cancel it halfway and consequently prevent the
	// compensating rollback. Individual Fortinet clients still have strict
	// request timeouts; this outer deadline bounds the whole run.
	operationContext, cancelOperation := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancelOperation()
	err = preflightFortiGateTargets(operationContext, targets)
	var snapshots []deploymentSnapshot
	if err == nil {
		snapshots, err = snapshotDeployment(operationContext, targets)
	}
	if err == nil {
		err = executeDeployment(operationContext, targets, snapshots, &result)
	}
	result.Systems = runtimeSystemInfo(targets)
	result.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	} else {
		result.Status = "succeeded"
	}
	logErr := s.finishDeploymentLog(&result)
	metadata := map[string]any{
		"deployment_id": result.DeploymentID, "policy_id": result.PolicyID, "plan_hash": result.PlanHash,
		"targets": result.Targets, "systems": result.Systems, "commands_total": result.CommandsTotal,
		"commands_applied": result.CommandsApplied, "rollback_attempted": result.RollbackAttempted,
		"rollback_succeeded": result.RollbackSucceeded, "rollback_errors": result.RollbackErrors,
	}
	if result.Error != "" {
		metadata["error"] = result.Error
	}
	if logErr != nil {
		metadata["log_error"] = logErr.Error()
	}
	s.audit(actor, "deployment.execute", result.Status, metadata)
	if err != nil {
		writeDeploymentJSON(w, http.StatusBadGateway, map[string]any{"success": false, "deployment": result})
		return
	}
	if logErr != nil {
		writeDeploymentJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "deployment": result, "error": "deployment succeeded, but its protocol could not be finalized"})
		return
	}
	writeDeploymentJSON(w, http.StatusOK, map[string]any{"success": true, "deployment": result})
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return errors.New("multiple JSON documents are not allowed")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func runtimeSystemInfo(targets []*runtimeTarget) []fortinetSystemInfo {
	result := make([]fortinetSystemInfo, 0, len(targets))
	for _, target := range targets {
		if target.System.Target != "" {
			result = append(result, target.System)
		}
	}
	return result
}

func newDeploymentID() (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("create deployment id: %w", err)
	}
	return "d-" + time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(random), nil
}

func (s *state) deploymentDB() (*sql.DB, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS policy_deployment_log (
			deployment_id TEXT PRIMARY KEY,
			revision TEXT NOT NULL,
			plan_hash TEXT NOT NULL,
			actor TEXT NOT NULL,
			requested_target TEXT NOT NULL DEFAULT '',
			targets TEXT NOT NULL DEFAULT '[]',
			status TEXT NOT NULL,
			commands_total INTEGER NOT NULL DEFAULT 0,
			commands_applied INTEGER NOT NULL DEFAULT 0,
			systems TEXT NOT NULL DEFAULT '[]',
			results TEXT NOT NULL DEFAULT '[]',
			error TEXT NOT NULL DEFAULT '',
			rollback_attempted INTEGER NOT NULL DEFAULT 0,
			rollback_succeeded INTEGER NOT NULL DEFAULT 0,
			rollback_errors TEXT NOT NULL DEFAULT '[]',
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS policy_deployment_lock (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			deployment_id TEXT NOT NULL,
			acquired_at TEXT NOT NULL
		);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func (s *state) startDeploymentLog(result *deploymentRunResult, requestedTarget string) error {
	db, err := s.deploymentDB()
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var latest string
	if err := tx.QueryRow(`SELECT version FROM policy_publication ORDER BY published_at DESC LIMIT 1`).Scan(&latest); errors.Is(err, sql.ErrNoRows) {
		return errors.New("there is no published revision")
	} else if err != nil {
		return err
	} else if latest != result.PolicyID {
		return errDeploymentRevisionSuperseded
	}
	cutoff := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	if _, err := tx.Exec(`DELETE FROM policy_deployment_lock WHERE acquired_at < ?`, cutoff); err != nil {
		return err
	}
	var active string
	if err := tx.QueryRow(`SELECT deployment_id FROM policy_deployment_lock WHERE id=1`).Scan(&active); err == nil {
		return errDeploymentRunning
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO policy_deployment_lock(id, deployment_id, acquired_at) VALUES(1, ?, ?)`, result.DeploymentID, result.StartedAt); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "constraint") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			return errDeploymentRunning
		}
		return err
	}
	targets, _ := json.Marshal(result.Targets)
	_, err = tx.Exec(`INSERT INTO policy_deployment_log(deployment_id, revision, plan_hash, actor, requested_target, targets, status, commands_total, started_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		result.DeploymentID, result.PolicyID, result.PlanHash, result.Actor, strings.TrimSpace(requestedTarget), string(targets), result.Status, result.CommandsTotal, result.StartedAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// acquirePublicationLock uses the same singleton row as deployment. Holding it
// across password/export/draft/current-link/database changes makes publication
// and device mutation mutually exclusive for the complete operation, not only
// for the final SQLite insert.
func (s *state) acquirePublicationLock(version string) (string, error) {
	lockID := publicationLockID(version)
	db, err := s.deploymentDB()
	if err != nil {
		return "", err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	cutoff := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	if _, err := tx.Exec(`DELETE FROM policy_deployment_lock WHERE acquired_at < ?`, cutoff); err != nil {
		return "", err
	}
	var active string
	if err := tx.QueryRow(`SELECT deployment_id FROM policy_deployment_lock WHERE id=1`).Scan(&active); err == nil {
		return "", errDeploymentRunning
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if err := requireLatestPublicationDeployed(tx); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`INSERT INTO policy_deployment_lock(id, deployment_id, acquired_at) VALUES(1, ?, ?)`, lockID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "constraint") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			return "", errDeploymentRunning
		}
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return lockID, nil
}

// requireLatestPublicationDeployed makes the immediately previous publication
// a trustworthy device baseline. Without this interlock, publishing A without
// deploying it and then publishing B would produce only an A->B delta even
// though a device could still run an older Z revision. Historical legacy
// publications without a stored plan remain migratable; every publication
// created by the reviewed workflow carries a verifiable plan and is gated.
func requireLatestPublicationDeployed(tx *sql.Tx) error {
	var version string
	var storedPlan sql.NullString
	err := tx.QueryRow(`SELECT p.version, r.deployment_plan
		FROM policy_publication p
		LEFT JOIN policy_revision r ON r.version=p.version
		ORDER BY p.published_at DESC LIMIT 1`).Scan(&version, &storedPlan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !storedPlan.Valid || strings.TrimSpace(storedPlan.String) == "" || strings.TrimSpace(storedPlan.String) == "null" {
		return nil
	}
	var encoded any
	if err := json.Unmarshal([]byte(storedPlan.String), &encoded); err != nil {
		return fmt.Errorf("decode latest publication deployment plan: %w", err)
	}
	plan, err := decodeStoredDeploymentPlan(encoded)
	if err != nil {
		return fmt.Errorf("verify latest publication deployment plan: %w", err)
	}
	commandTargets := map[string]bool{}
	for _, command := range plan.Commands {
		commandTargets[command.Target] = true
	}
	required := map[string]bool{}
	for _, target := range plan.Targets {
		if target.Executable && commandTargets[target.Name] {
			required[target.Name] = true
		}
	}
	if len(required) == 0 {
		return nil
	}
	rows, err := tx.Query(`SELECT targets, status FROM policy_deployment_log WHERE revision=? AND plan_hash=? ORDER BY started_at, deployment_id`, version, plan.Hash)
	if err != nil {
		return err
	}
	deployed := map[string]bool{}
	for rows.Next() {
		var encodedTargets, status string
		if err := rows.Scan(&encodedTargets, &status); err != nil {
			rows.Close()
			return err
		}
		var targets []string
		if err := json.Unmarshal([]byte(encodedTargets), &targets); err != nil {
			rows.Close()
			return fmt.Errorf("decode deployment protocol targets: %w", err)
		}
		for _, target := range targets {
			deployed[target] = status == "succeeded"
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	missing := []string{}
	for target := range required {
		if !deployed[target] {
			missing = append(missing, target)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("%w: revision %q is missing successful deployment for %s", errPublicationRequiresDeployment, version, strings.Join(missing, ", "))
}

func (s *state) finishDeploymentLog(result *deploymentRunResult) error {
	db, err := s.deploymentDB()
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	systems, _ := json.Marshal(result.Systems)
	results, _ := json.Marshal(result.Results)
	rollbackErrors, _ := json.Marshal(result.RollbackErrors)
	updated, err := tx.Exec(`UPDATE policy_deployment_log SET status=?, commands_applied=?, systems=?, results=?, error=?, rollback_attempted=?, rollback_succeeded=?, rollback_errors=?, finished_at=? WHERE deployment_id=?`,
		result.Status, result.CommandsApplied, string(systems), string(results), result.Error, result.RollbackAttempted, result.RollbackSucceeded, string(rollbackErrors), result.FinishedAt, result.DeploymentID)
	if err != nil {
		return err
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("deployment protocol row is missing")
	}
	if err := updateLinkedPolicyRequestDeploymentTx(tx, result); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *state) releaseDeploymentLock(deploymentID string) {
	db, err := s.deploymentDB()
	if err != nil {
		return
	}
	defer db.Close()
	_, _ = db.Exec(`DELETE FROM policy_deployment_lock WHERE deployment_id=?`, deploymentID)
}

func writeDeploymentJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
