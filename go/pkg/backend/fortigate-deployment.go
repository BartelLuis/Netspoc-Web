package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type fortiGateObject struct {
	MKey string
	Data map[string]any
}

type deploymentSnapshot struct {
	Target           *runtimeTarget
	Command          deploymentCommand
	Existed          bool
	AlreadyDesired   bool
	MKey             string
	UUID             string
	Data             map[string]any
	Restore          map[string]any
	BeforeMKey       string
	AfterMKey        string
	InsertBeforeMKey string
	PostObserved     bool
	PostAbsent       bool
	PostNoop         bool
	PostMKey         string
	PostUUID         string
	PostState        map[string]any
	PostBeforeMKey   string
	PostAfterMKey    string
	PostOrder        []string
	PositionRestored bool
	RollbackStatus   string
}

type appliedDeploymentStep struct {
	Snapshot deploymentSnapshot
}

type driftRecord struct {
	Target      string   `json:"target"`
	Context     string   `json:"context"`
	Sequence    int      `json:"sequence"`
	Kind        string   `json:"kind"`
	Method      string   `json:"method"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Differences []string `json:"differences"`
	Error       string   `json:"error,omitempty"`
}

type driftResponse struct {
	Success                  bool                 `json:"success"`
	Version                  string               `json:"version"`
	PlanHash                 string               `json:"plan_hash"`
	CurrentPlanHash          string               `json:"current_plan_hash"`
	PlanMatchesConfiguration bool                 `json:"plan_matches_configuration"`
	InSync                   bool                 `json:"in_sync"`
	Systems                  []fortinetSystemInfo `json:"systems"`
	Records                  []driftRecord        `json:"records"`
	Errors                   []string             `json:"errors"`
}

var fortiOSVersionRE = regexp.MustCompile(`(?i)^(?:fortios[ \t]+)?v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:,build[0-9]+(?:,[0-9][^,\r\n]*)*)?$`)
var fortiOSBuildRE = regexp.MustCompile(`(?i)build\s*([0-9]+)`)

func preflightFortiGateTargets(ctx context.Context, targets []*runtimeTarget) error {
	// Complete every read-only device/version check before the first mutation.
	// This prevents a mixed-version multi-target request from being half applied.
	for _, target := range targets {
		if target.Config.Type == "fortimanager" {
			return fmt.Errorf("target %q is FortiManager; execution is blocked because no explicit managed-device installation target is configured", target.Config.Name)
		}
		if target.Config.Type != "fortigate" {
			return fmt.Errorf("target %q has unsupported type %q", target.Config.Name, target.Config.Type)
		}
		if target.Config.InsecureSkipVerify {
			return fmt.Errorf("target %q requires verified TLS; insecure_skip_verify is forbidden for authenticated FortiGate requests", target.Config.Name)
		}
		if _, err := target.Config.apiToken(); err != nil {
			return fmt.Errorf("target %q credential: %w", target.Config.Name, err)
		}
		client, err := target.Config.httpClient()
		if err != nil {
			return fmt.Errorf("target %q: %w", target.Config.Name, err)
		}
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		target.Client = client
		system, err := readFortiGateSystem(ctx, client, target.Config)
		if err != nil {
			return fmt.Errorf("target %q status preflight: %w", target.Config.Name, err)
		}
		target.System = system
		matches := fortiOSVersionRE.FindStringSubmatch(strings.TrimSpace(system.Version))
		if len(matches) != 4 || matches[1] != "7" || matches[2] != "4" {
			return fmt.Errorf("target %q runs %q; deployment requires FortiOS 7.4.x", target.Config.Name, system.Version)
		}
	}
	return nil
}

func readFortiGateSystem(ctx context.Context, client *http.Client, target FortinetTarget) (fortinetSystemInfo, error) {
	body, err := fortiGateCall(ctx, client, target, http.MethodGet, "/api/v2/monitor/system/status", nil, nil)
	if err != nil {
		return fortinetSystemInfo{}, err
	}
	version := firstScalarString(body, "version")
	if version == "" {
		return fortinetSystemInfo{}, errors.New("status response contains no FortiOS version")
	}
	build := firstScalarString(body, "build")
	if build == "" {
		if match := fortiOSBuildRE.FindStringSubmatch(version); len(match) == 2 {
			build = match[1]
		}
	}
	return fortinetSystemInfo{Target: target.Name, Version: version, Build: build}, nil
}

func snapshotDeployment(ctx context.Context, targets []*runtimeTarget) ([]deploymentSnapshot, error) {
	result := []deploymentSnapshot{}
	for _, target := range targets {
		if !target.PreconditionsBound {
			return nil, fmt.Errorf("target %q has no approved base preconditions", target.Config.Name)
		}
		transitions, err := deploymentPolicyTransitions(target.Commands)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", target.Config.Name, err)
		}
		targetStart := len(result)
		for _, command := range target.Commands {
			name := command.Payload["name"].(string)
			commandIdentity, identityErr := deploymentCommandIdentity(command)
			if identityErr != nil {
				return nil, fmt.Errorf("target %q command %d: %w", target.Config.Name, command.Sequence, identityErr)
			}

			// A reviewed address-family transition is the sole legal duplicate
			// identity: the old unified firewall policy is deleted before the new
			// family is created. Snapshot the create against that approved future
			// absence rather than mistaking the still-present old policy for an
			// unowned name collision.
			if transitions[commandIdentity] && strings.EqualFold(command.Method, "UPSERT") {
				result = append(result, deploymentSnapshot{Target: target, Command: command})
				continue
			}

			object, err := lookupFortiGateObject(ctx, target.Client, target.Config, command)
			if err != nil {
				return nil, fmt.Errorf("snapshot target %q command %d: %w", target.Config.Name, command.Sequence, err)
			}
			snapshot := deploymentSnapshot{Target: target, Command: command}
			if object != nil {
				snapshot.Existed = true
				snapshot.MKey = object.MKey
				snapshot.UUID = scalarString(object.Data["uuid"])
				snapshot.Data = object.Data
				if strings.EqualFold(command.Method, http.MethodDelete) {
					if differences := fortiGateCommandDifferences(command, command.Payload, object.Data); len(differences) != 0 {
						return nil, fmt.Errorf("refuse DELETE of drifted policy %q on target %q: %s", name, target.Config.Name, strings.Join(differences, "; "))
					}
					snapshot.Restore = rollbackPayload(command, object.Data, command.Payload)
				} else if differences := fortiGateCommandDifferences(command, command.Payload, object.Data); len(differences) == 0 {
					snapshot.AlreadyDesired = true
					snapshot.Restore = rollbackPayload(command, object.Data, target.ExpectedBefore[commandIdentity])
				} else if expected, approved := target.ExpectedBefore[commandIdentity]; !approved {
					return nil, fmt.Errorf("refuse UPSERT name collision for unowned %s %q on target %q", command.Kind, name, target.Config.Name)
				} else if adoptedDifferences := fortiGateAdoptedPolicyMatchDifferences(command, expected, object.Data); len(adoptedDifferences) != 0 {
					return nil, fmt.Errorf("refuse UPSERT of %s %q on target %q: newly managed policy match state differs from its safe default: %s", command.Kind, name, target.Config.Name, strings.Join(adoptedDifferences, "; "))
				} else if baseDifferences := fortiGateCommandDifferences(command, expected, object.Data); len(baseDifferences) != 0 {
					return nil, fmt.Errorf("refuse UPSERT of drifted %s %q on target %q: %s", command.Kind, name, target.Config.Name, strings.Join(baseDifferences, "; "))
				} else if command.SemanticsVersion == fortiOSObjectSemanticsVersion && (command.Kind == "address" || command.Kind == "address6" || command.Kind == "service") && len(fortiGateCommandDifferences(command, expected, command.Payload)) != 0 {
					return nil, fmt.Errorf("refuse in-place update of immutable/content-addressed %s %q on target %q; changed semantics must use a new generated object name", command.Kind, name, target.Config.Name)
				} else if unsafeInPlaceDenyMatchChange(command, expected) {
					return nil, fmt.Errorf("refuse in-place match change of DENY policy %q on target %q; copy it to a new rule identity so the replacement can be prepared disabled before the old DENY is removed", name, target.Config.Name)
				} else {
					snapshot.Restore = rollbackPayload(command, object.Data, expected)
				}
				if command.Kind == "policy" {
					snapshot.BeforeMKey, snapshot.AfterMKey, err = policyNeighbours(ctx, target.Client, target.Config, command.Path, object.MKey)
					if err != nil {
						return nil, fmt.Errorf("snapshot policy order on target %q: %w", target.Config.Name, err)
					}
				}
			}
			result = append(result, snapshot)
		}
		if err := snapshotPolicyOrder(ctx, target, result[targetStart:]); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func unsafeInPlaceDenyMatchChange(command deploymentCommand, approvedBefore map[string]any) bool {
	defaults := fortiOS74PolicySemanticDefaults()
	beforeAction, desiredAction := defaults["action"], defaults["action"]
	if value, exists := approvedBefore["action"]; exists {
		beforeAction = value
	}
	if value, exists := command.Payload["action"]; exists {
		desiredAction = value
	}
	if command.Kind != "policy" || !strings.EqualFold(command.Method, "UPSERT") || scalarString(beforeAction) != "deny" || scalarString(desiredAction) != "deny" {
		return false
	}
	fields := []string{
		"srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "service", "schedule",
		"srcaddr-negate", "dstaddr-negate", "srcaddr6-negate", "dstaddr6-negate", "service-negate",
		"users", "groups", "fsso-groups", "src-vendor-mac", "tos", "tos-mask", "tos-negate", "sgt-check", "sgt",
		"match-vip", "match-vip-only", "reputation-minimum", "reputation-direction", "reputation-minimum6", "reputation-direction6", "vlan-filter",
		"ztna-status", "ztna-ems-tag", "ztna-ems-tag-secondary", "ztna-geo-tag", "ztna-policy-redirect", "ztna-device-ownership", "ztna-tags-match-logic",
		"internet-service", "internet-service-src", "internet-service6", "internet-service6-src",
		"internet-service-name", "internet-service-custom", "internet-service-src-name", "internet-service-src-custom",
		"internet-service6-name", "internet-service6-custom", "internet-service6-src-name", "internet-service6-src-custom",
	}
	before, desired := map[string]any{}, map[string]any{}
	for _, field := range fields {
		before[field], desired[field] = defaults[field], defaults[field]
		if value, exists := approvedBefore[field]; exists {
			before[field] = value
		}
		if value, exists := command.Payload[field]; exists {
			desired[field] = value
		}
	}
	return len(fortiGateDifferences(before, desired)) != 0
}

// A plan produced by an older release cannot approve values for policy fields
// that release did not own. When a newer release starts owning a match field,
// only an already-default/unset live value may be adopted automatically. This
// prevents an upgrade from silently clearing an operator-added user, TOS, SGT,
// ZTNA, or VIP restriction (which could widen an ACCEPT rule).
func fortiGateAdoptedPolicyMatchDifferences(command deploymentCommand, approvedBefore, actual map[string]any) []string {
	if command.Kind != "policy" || !strings.EqualFold(command.Method, "UPSERT") {
		return nil
	}
	fields := make([]string, 0, len(fortiOS74PolicySemanticDefaults()))
	for field := range fortiOS74PolicySemanticDefaults() {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	differences := []string{}
	defaults := fortiOS74PolicySemanticDefaults()
	for _, field := range fields {
		if _, alreadyOwned := approvedBefore[field]; alreadyOwned {
			continue
		}
		desired, managed := command.Payload[field]
		if !managed {
			continue
		}
		live, explicit := actual[field]
		// FortiOS can omit default and unset values from a CMDB response.
		if !explicit {
			live = defaults[field]
		}
		if live == nil && fortiGateEmptyCollection(desired) {
			continue
		}
		fieldDifferences := fortiGateDifferences(map[string]any{field: desired}, map[string]any{field: live})
		differences = append(differences, fieldDifferences...)
	}
	return differences
}

func deploymentPolicyTransitions(commands []deploymentCommand) (map[string]bool, error) {
	byIdentity := map[string][]deploymentCommand{}
	for _, command := range commands {
		identity, err := deploymentCommandIdentity(command)
		if err != nil {
			return nil, err
		}
		byIdentity[identity] = append(byIdentity[identity], command)
	}
	result := map[string]bool{}
	for identity, operations := range byIdentity {
		if len(operations) == 1 {
			continue
		}
		if len(operations) != 2 || operations[0].Kind != "policy" || operations[1].Kind != "policy" ||
			!strings.EqualFold(operations[0].Method, http.MethodDelete) || !strings.EqualFold(operations[1].Method, "UPSERT") ||
			operations[0].Sequence >= operations[1].Sequence || operations[0].Context != operations[1].Context {
			return nil, fmt.Errorf("approved plan contains unsupported duplicate operations for %q", identity)
		}
		result[identity] = true
	}
	return result, nil
}

func snapshotPolicyOrder(ctx context.Context, target *runtimeTarget, snapshots []deploymentSnapshot) error {
	byName := map[string]int{}
	deletedMKeys := map[string]bool{}
	hasPolicy := false
	for index := range snapshots {
		snapshot := &snapshots[index]
		if snapshot.Command.Kind != "policy" {
			continue
		}
		hasPolicy = true
		if strings.EqualFold(snapshot.Command.Method, "UPSERT") {
			byName[scalarString(snapshot.Command.Payload["name"])] = index
		} else if strings.EqualFold(snapshot.Command.Method, http.MethodDelete) && snapshot.Existed {
			deletedMKeys[snapshot.MKey] = true
		}
	}
	if !hasPolicy {
		return nil
	}
	path := deploymentPath(target.Config, "policy")
	ordered, err := listFortiGateObjects(ctx, target.Client, target.Config, path, nil)
	if err != nil {
		return fmt.Errorf("snapshot policy order on target %q: %w", target.Config.Name, err)
	}
	if target.PolicyOrder == nil {
		target.PolicyOrder = map[string][]string{}
	}
	target.PolicyOrder[path] = fortiGateObjectMKeys(ordered)
	anchors := map[string]*fortiGateObject{}
	for index := range snapshots {
		snapshot := &snapshots[index]
		if snapshot.Command.Kind != "policy" || !strings.EqualFold(snapshot.Command.Method, "UPSERT") {
			continue
		}
		immediate, effective, err := resolveSnapshotPolicySuccessors(ctx, target, snapshots, byName, anchors, snapshot.Command.InsertBefore)
		if err != nil {
			return fmt.Errorf("resolve policy-order successor %q on target %q: %w", snapshot.Command.InsertBefore, target.Config.Name, err)
		}
		if immediate != nil {
			snapshot.InsertBeforeMKey = immediate.MKey
		}
		if snapshot.Existed && !policyMKeysAdjacentAfterDeletes(ordered, deletedMKeys, snapshot.MKey, effective.MKey) {
			return fmt.Errorf("existing policy %q is not immediately before its approved successor %q on target %q", snapshot.Command.Payload["name"], effective.Data["name"], target.Config.Name)
		}
	}
	return nil
}

func policyMKeysAdjacentAfterDeletes(ordered []fortiGateObject, deleted map[string]bool, first, second string) bool {
	previous := ""
	for _, object := range ordered {
		if deleted[object.MKey] {
			continue
		}
		if previous == first && object.MKey == second {
			return true
		}
		previous = object.MKey
	}
	return false
}

func resolveSnapshotPolicySuccessors(ctx context.Context, target *runtimeTarget, snapshots []deploymentSnapshot, byName map[string]int, anchors map[string]*fortiGateObject, successor string) (*fortiGateObject, *fortiGateObject, error) {
	var immediate *fortiGateObject
	visited := map[string]bool{}
	first := true
	for {
		if visited[successor] {
			return nil, nil, errors.New("approved policy-order chain is cyclic")
		}
		visited[successor] = true
		if index, managed := byName[successor]; managed {
			snapshot := &snapshots[index]
			if snapshot.Existed {
				object := &fortiGateObject{MKey: snapshot.MKey, Data: snapshot.Data}
				if first {
					immediate = object
				}
				return immediate, object, nil
			}
			successor = snapshot.Command.InsertBefore
			first = false
			continue
		}
		object, cached := anchors[successor]
		if !cached {
			anchorCommand := deploymentCommand{Path: deploymentPath(target.Config, "policy"), Payload: map[string]any{"name": successor}}
			var err error
			object, err = lookupFortiGateObject(ctx, target.Client, target.Config, anchorCommand)
			if err != nil {
				return nil, nil, err
			}
			anchors[successor] = object
		}
		if object == nil {
			return nil, nil, fmt.Errorf("policy-order anchor %q is missing", successor)
		}
		if first {
			immediate = object
		}
		return immediate, object, nil
	}
}

func rollbackPayload(command deploymentCommand, actual, approvedBefore map[string]any) map[string]any {
	// CMDB GET responses contain read-only/helper properties that FortiOS 7.4
	// rejects on PUT/POST. Compensation therefore writes only reviewed fields:
	// the approved base for an update and the full approved deleted-policy
	// payload for a recreation. The original policyid is the sole identity field
	// copied from the snapshot so a DELETE rollback reclaims its prior mkey.
	result := cloneDeploymentPayload(approvedBefore)
	if len(result) == 0 {
		result = cloneDeploymentPayload(command.Payload)
	}
	if strings.EqualFold(command.Method, "UPSERT") {
		var defaults map[string]any
		switch command.Kind {
		case "policy":
			defaults = fortiOS74PolicySemanticDefaults()
		case "address", "address6":
			defaults, _ = fortiOS74AddressSemanticProjection(command.Kind, command.Payload)
		case "service":
			defaults = fortiOS74ServiceSemanticDefaults()
		}
		// Materialize only writable projected fields that this device actually
		// returned, plus every field the new command will mutate. This restores a
		// legacy omitted default (for example match-vip=enable) after a partial
		// PUT without sending model-specific fields unsupported by this device.
		for key, value := range actual {
			if fortiOSPolicyReadOnlyFields[key] {
				continue
			}
			if _, reviewed := defaults[key]; reviewed {
				result[key] = value
			}
		}
		for key := range command.Payload {
			if fortiOSPolicyReadOnlyFields[key] {
				continue
			}
			if value, exists := actual[key]; exists {
				result[key] = value
			} else if value, reviewed := defaults[key]; reviewed {
				result[key] = value
			}
		}
	}
	if command.Kind == "policy" && strings.EqualFold(command.Method, http.MethodDelete) {
		if policyID, exists := actual["policyid"]; exists {
			result["policyid"] = policyID
		}
	}
	return result
}

func executeDeployment(ctx context.Context, targets []*runtimeTarget, snapshots []deploymentSnapshot, result *deploymentRunResult) error {
	mutated := map[int]bool{}
	mutationOrder := []int{}
	resultIndex := map[int]int{}
	touchMutation := func(index int) {
		if mutated[index] {
			for position, existing := range mutationOrder {
				if existing == index {
					mutationOrder = append(mutationOrder[:position], mutationOrder[position+1:]...)
					break
				}
			}
		}
		mutated[index] = true
		mutationOrder = append(mutationOrder, index)
	}
	rollback := func() {
		if len(mutationOrder) == 0 {
			return
		}
		applied := make([]appliedDeploymentStep, 0, len(mutationOrder))
		for _, index := range mutationOrder {
			applied = append(applied, appliedDeploymentStep{Snapshot: snapshots[index]})
		}
		result.RollbackAttempted = true
		// The operation context may be canceled or exhausted precisely when
		// rollback becomes necessary. Compensation therefore gets a fresh,
		// bounded server-owned context.
		rollbackContext, cancelRollback := context.WithTimeout(context.Background(), 10*time.Minute)
		result.RollbackErrors = rollbackDeployment(rollbackContext, applied)
		cancelRollback()
		result.RollbackSucceeded = len(result.RollbackErrors) == 0
	}
	runCommand := func(index int) error {
		snapshot := &snapshots[index]
		commandResult, mutationAttempted, err := executeFortiGateCommand(ctx, snapshot)
		resultIndex[index] = len(result.Results)
		result.Results = append(result.Results, commandResult)
		if mutationAttempted {
			touchMutation(index)
		}
		if err != nil {
			return fmt.Errorf("target %q command %d failed: %w", snapshot.Target.Config.Name, snapshot.Command.Sequence, err)
		}
		if mutationAttempted {
			result.CommandsApplied++
		}
		return nil
	}
	fail := func(err error) error {
		rollback()
		return err
	}
	// PREPARE 1: content-addressed address/service objects are created before
	// policy changes. Existing active policies cannot reference a changed
	// payload under the same object name.
	for index := range snapshots {
		if snapshots[index].Command.Kind == "policy" {
			continue
		}
		if err := runCommand(index); err != nil {
			return fail(err)
		}
	}
	// PREPARE 2: every new policy is created disabled and positioned while it
	// cannot match traffic. Existing policies remain untouched in this phase.
	for index := range snapshots {
		if snapshots[index].Command.Kind != "policy" || !strings.EqualFold(snapshots[index].Command.Method, "UPSERT") || snapshots[index].Existed {
			continue
		}
		if err := runCommand(index); err != nil {
			return fail(err)
		}
	}
	finalizePolicies := func(action string) error {
		indices := []int{}
		for index := range snapshots {
			command := snapshots[index].Command
			if command.Kind == "policy" && strings.EqualFold(command.Method, "UPSERT") && scalarString(command.Payload["action"]) == action {
				indices = append(indices, index)
			}
		}
		sort.SliceStable(indices, func(i, j int) bool {
			left, right := snapshots[indices[i]], snapshots[indices[j]]
			if left.Target.Config.Name != right.Target.Config.Name {
				return left.Target.Config.Name < right.Target.Config.Name
			}
			// Policy commands are prepared bottom-up. Finalization is top-down.
			return left.Command.Sequence > right.Command.Sequence
		})
		for _, index := range indices {
			if snapshots[index].Existed {
				if err := runCommand(index); err != nil {
					return err
				}
				continue
			}
			if len(snapshots[index].Command.ActivatePayload) == 0 {
				// Compatibility for unit-level legacy snapshots. Runtime validation
				// rejects these from an approved executable plan.
				continue
			}
			activationResult, err := activatePreparedFortiGatePolicy(ctx, &snapshots[index])
			touchMutation(index)
			if resultPosition, exists := resultIndex[index]; exists {
				result.Results[resultPosition] = activationResult
			} else {
				result.Results = append(result.Results, activationResult)
			}
			if err != nil {
				return fmt.Errorf("target %q command %d activation failed: %w", snapshots[index].Target.Config.Name, snapshots[index].Command.Sequence, err)
			}
		}
		return nil
	}
	// DENYs become effective before any new/changed ACCEPT can broaden access.
	if err := finalizePolicies("deny"); err != nil {
		return fail(err)
	}
	// Removing an obsolete ACCEPT is restrictive and therefore safe before
	// desired ACCEPT finalization. Obsolete DENYs intentionally remain active.
	for index := range snapshots {
		command := snapshots[index].Command
		if command.Kind == "policy" && strings.EqualFold(command.Method, http.MethodDelete) && scalarString(command.Payload["action"]) != "deny" {
			if err := runCommand(index); err != nil {
				return fail(err)
			}
		}
	}
	if err := finalizePolicies("accept"); err != nil {
		return fail(err)
	}
	// A removed DENY is the final, potentially permissive transition.
	for index := range snapshots {
		command := snapshots[index].Command
		if command.Kind == "policy" && strings.EqualFold(command.Method, http.MethodDelete) && scalarString(command.Payload["action"]) == "deny" {
			if err := runCommand(index); err != nil {
				return fail(err)
			}
		}
	}
	if err := verifyDeploymentFinalState(ctx, targets); err != nil {
		return fail(err)
	}
	return nil
}

func executeFortiGateCommand(ctx context.Context, snapshot *deploymentSnapshot) (deploymentCommandResult, bool, error) {
	target := snapshot.Target
	command := snapshot.Command
	name := command.Payload["name"].(string)
	result := deploymentCommandResult{
		Target: target.Config.Name, Context: command.Context, Sequence: command.Sequence,
		Kind: command.Kind, Method: strings.ToUpper(command.Method), Name: name,
	}
	method := strings.ToUpper(command.Method)
	current, alreadyDesired, err := revalidateFortiGateSnapshot(ctx, *snapshot)
	if err != nil {
		result.Status, result.Error = "precondition_failed", err.Error()
		return result, false, err
	}
	if method == http.MethodDelete {
		if alreadyDesired {
			result.Status = "already_absent"
			return result, false, nil
		}
		_, err = fortiGateCall(ctx, target.Client, target.Config, http.MethodDelete, withMKey(command.Path, current.MKey), nil, nil)
		if err != nil {
			result.Status, result.Error = "failed", err.Error()
			return result, true, err
		}
		object, verifyErr := lookupFortiGateObject(ctx, target.Client, target.Config, command)
		if verifyErr != nil {
			err = fmt.Errorf("verify delete: %w", verifyErr)
		} else if object != nil {
			err = errors.New("verify delete: policy still exists")
		} else if command.Kind == "policy" {
			if orderErr := advanceExpectedPolicyOrder(ctx, snapshot, "delete", current.MKey); orderErr != nil {
				err = fmt.Errorf("verify delete order: %w", orderErr)
			} else if orderErr = observeAbsentPolicyPostState(ctx, snapshot); orderErr != nil {
				err = fmt.Errorf("record deleted policy order: %w", orderErr)
			}
		} else {
			snapshot.PostObserved = true
			snapshot.PostAbsent = true
		}
		if err != nil {
			result.Status, result.Error = "verification_failed", err.Error()
			return result, true, err
		}
		result.Status = "deleted"
		return result, true, nil
	}
	if alreadyDesired {
		result.Status = "already_in_sync"
		return result, false, nil
	}

	requestMethod, requestPath := http.MethodPost, command.Path
	requestPayload := command.Payload
	verificationPayload := command.Payload
	status := "created"
	if snapshot.Existed {
		requestMethod, requestPath, status = http.MethodPut, withMKey(command.Path, current.MKey), "updated"
	} else if command.Kind == "policy" && len(command.ActivatePayload) != 0 {
		// The separately reviewed create payload contains policyid=0 for
		// FortiOS 7.4 automatic allocation. Payload remains the update/desired
		// state and is deliberately used for verification below.
		requestPayload = command.CreatePayload
		verificationPayload = cloneDeploymentPayload(command.CreatePayload)
		delete(verificationPayload, "policyid")
		status = "prepared_disabled"
	}
	_, err = fortiGateCall(ctx, target.Client, target.Config, requestMethod, requestPath, nil, requestPayload)
	if err != nil {
		result.Status, result.Error = "failed", err.Error()
		return result, true, err
	}
	object, verifyErr := lookupFortiGateObject(ctx, target.Client, target.Config, command)
	if verifyErr != nil {
		err = fmt.Errorf("verify upsert: %w", verifyErr)
	} else if object == nil {
		err = errors.New("verify upsert: object is missing")
	} else {
		if observeErr := observeFortiGatePostStateFor(ctx, snapshot, object, verificationPayload); observeErr != nil {
			err = fmt.Errorf("record post-mutation state: %w", observeErr)
		} else if differences := fortiGateCommandDifferences(command, verificationPayload, object.Data); len(differences) != 0 {
			err = fmt.Errorf("verify upsert: %s", strings.Join(differences, "; "))
		}
	}
	if err == nil && !snapshot.Existed && command.Kind == "policy" {
		anchor, anchorErr := lookupLivePolicySuccessor(ctx, *snapshot)
		if anchorErr != nil {
			err = anchorErr
		} else {
			query := url.Values{"action": []string{"move"}, "before": []string{anchor.MKey}}
			if _, moveErr := fortiGateCall(ctx, target.Client, target.Config, http.MethodPut, withMKey(command.Path, object.MKey), query, nil); moveErr != nil {
				err = fmt.Errorf("position new policy before %q: %w", command.InsertBefore, moveErr)
			}
		}
	}
	if err == nil && command.Kind == "policy" {
		if snapshot.Existed {
			err = verifyExpectedPolicyOrder(ctx, snapshot.Target, command.Path)
		} else {
			err = verifyLivePolicySuccessor(ctx, *snapshot, object.MKey)
			if err == nil {
				err = advanceExpectedPolicyOrder(ctx, snapshot, "create", object.MKey)
			}
		}
		if err == nil {
			err = observeFortiGatePostStateFor(ctx, snapshot, object, verificationPayload)
		}
	}
	if err != nil {
		result.Status, result.Error = "verification_failed", err.Error()
		return result, true, err
	}
	result.Status = status
	return result, true, nil
}

func activatePreparedFortiGatePolicy(ctx context.Context, snapshot *deploymentSnapshot) (deploymentCommandResult, error) {
	command, target := snapshot.Command, snapshot.Target
	name := scalarString(command.Payload["name"])
	result := deploymentCommandResult{
		Target: target.Config.Name, Context: command.Context, Sequence: command.Sequence,
		Kind: command.Kind, Method: "ACTIVATE", Name: name,
	}
	prepared := cloneDeploymentPayload(command.CreatePayload)
	delete(prepared, "policyid")
	activationAttempted := false
	current, err := lookupFortiGateObject(ctx, target.Client, target.Config, command)
	if err != nil {
		result.Status, result.Error = "activation_precondition_failed", err.Error()
		return result, err
	}
	if current == nil || snapshot.PostMKey == "" || current.MKey != snapshot.PostMKey {
		err = errors.New("prepared policy identity changed before activation")
	} else if snapshot.PostUUID != "" && scalarString(current.Data["uuid"]) != snapshot.PostUUID {
		err = errors.New("prepared policy UUID changed before activation")
	} else if differences := fortiGateCommandDifferences(command, prepared, current.Data); len(differences) != 0 {
		err = fmt.Errorf("prepared policy changed before activation: %s", strings.Join(differences, "; "))
	} else if err = verifyExpectedPolicyOrder(ctx, target, command.Path); err == nil {
		err = verifyLivePolicySuccessor(ctx, *snapshot, current.MKey)
	}
	if err == nil {
		activationAttempted = true
		_, err = fortiGateCall(ctx, target.Client, target.Config, http.MethodPut, withMKey(command.Path, current.MKey), nil, command.ActivatePayload)
	}
	if err != nil {
		if activationAttempted {
			if bindErr := bindPolicyActivationOutcome(ctx, snapshot, prepared); bindErr != nil {
				err = fmt.Errorf("%v; activation outcome could not be bound for rollback: %w", err, bindErr)
			}
		}
		result.Status, result.Error = "activation_failed", err.Error()
		return result, err
	}
	current, err = lookupFortiGateObject(ctx, target.Client, target.Config, command)
	if err == nil && current == nil {
		err = errors.New("activated policy is missing")
	}
	if err == nil && current.MKey != snapshot.PostMKey {
		err = errors.New("activated policy mkey changed")
	}
	if err == nil {
		if differences := fortiGateCommandDifferences(command, command.Payload, current.Data); len(differences) != 0 {
			err = fmt.Errorf("verify activation: %s", strings.Join(differences, "; "))
		}
	}
	if err == nil {
		err = verifyLivePolicySuccessor(ctx, *snapshot, current.MKey)
	}
	if err == nil {
		err = verifyExpectedPolicyOrder(ctx, target, command.Path)
	}
	if err == nil {
		err = observeFortiGatePostState(ctx, snapshot, current)
	}
	if err != nil {
		if bindErr := bindPolicyActivationOutcome(ctx, snapshot, prepared); bindErr != nil {
			err = fmt.Errorf("%v; activation outcome could not be bound for rollback: %w", err, bindErr)
		}
		result.Status, result.Error = "activation_verification_failed", err.Error()
		return result, err
	}
	result.Status = "created_and_activated"
	return result, nil
}

func bindPolicyActivationOutcome(ctx context.Context, snapshot *deploymentSnapshot, prepared map[string]any) error {
	current, err := lookupFortiGateObject(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command)
	if err != nil {
		return err
	}
	if current == nil || snapshot.PostMKey == "" || current.MKey != snapshot.PostMKey {
		return errors.New("prepared policy identity is no longer attributable")
	}
	if snapshot.PostUUID != "" && scalarString(current.Data["uuid"]) != snapshot.PostUUID {
		return errors.New("prepared policy UUID is no longer attributable")
	}
	if err := verifyLivePolicySuccessor(ctx, *snapshot, current.MKey); err != nil {
		return err
	}
	if len(fortiGateCommandDifferences(snapshot.Command, prepared, current.Data)) == 0 {
		return observeFortiGatePostStateFor(ctx, snapshot, current, prepared)
	}
	if len(fortiGateCommandDifferences(snapshot.Command, snapshot.Command.Payload, current.Data)) == 0 {
		return observeFortiGatePostState(ctx, snapshot, current)
	}
	return errors.New("live policy is neither the reviewed disabled PREPARE state nor the reviewed final state")
}

func observeFortiGatePostState(ctx context.Context, snapshot *deploymentSnapshot, object *fortiGateObject) error {
	return observeFortiGatePostStateFor(ctx, snapshot, object, snapshot.Command.Payload)
}

func observeFortiGatePostStateFor(ctx context.Context, snapshot *deploymentSnapshot, object *fortiGateObject, expected map[string]any) error {
	if object == nil {
		return errors.New("cannot bind an absent post-mutation object")
	}
	stateCommand := snapshot.Command
	stateCommand.Payload = expected
	managed := observedDeploymentState(stateCommand, object.Data)
	snapshot.PostObserved = true
	snapshot.PostAbsent = false
	snapshot.PostMKey = object.MKey
	snapshot.PostUUID = scalarString(object.Data["uuid"])
	snapshot.PostState = managed
	snapshot.PostBeforeMKey, snapshot.PostAfterMKey = "", ""
	snapshot.PostOrder = nil
	if snapshot.Command.Kind == "policy" {
		ordered, err := listFortiGateObjects(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command.Path, nil)
		if err != nil {
			return err
		}
		snapshot.PostOrder = fortiGateObjectMKeys(ordered)
		before, after, found := neighboursInPolicyOrder(snapshot.PostOrder, object.MKey)
		if !found {
			return fmt.Errorf("policy mkey %q is absent from ordered policy list", object.MKey)
		}
		snapshot.PostBeforeMKey, snapshot.PostAfterMKey = before, after
	}
	return nil
}

func verifyDeploymentFinalState(ctx context.Context, targets []*runtimeTarget) error {
	differences := []string{}
	for _, target := range targets {
		commands, err := finalDeploymentCommands(target.Commands)
		if err != nil {
			return fmt.Errorf("final deployment verification: target %q: %w", target.Config.Name, err)
		}
		for _, command := range commands {
			record := inspectDrift(ctx, target, command)
			if record.Status == "in_sync" {
				continue
			}
			detail := record.Error
			if detail == "" {
				detail = strings.Join(record.Differences, "; ")
			}
			differences = append(differences, fmt.Sprintf("target %q command %d (%s): %s", target.Config.Name, command.Sequence, record.Name, detail))
		}
	}
	if len(differences) != 0 {
		return fmt.Errorf("final deployment verification failed: %s", strings.Join(differences, " | "))
	}
	return nil
}

func finalDeploymentCommands(commands []deploymentCommand) ([]deploymentCommand, error) {
	transitions, err := deploymentPolicyTransitions(commands)
	if err != nil {
		return nil, err
	}
	result := make([]deploymentCommand, 0, len(commands))
	for _, command := range commands {
		identity, err := deploymentCommandIdentity(command)
		if err != nil {
			return nil, err
		}
		if transitions[identity] && strings.EqualFold(command.Method, http.MethodDelete) {
			continue
		}
		result = append(result, command)
	}
	return result, nil
}

// revalidateFortiGateSnapshot closes the time-of-check/time-of-use window
// between the all-target snapshot phase and each mutation. Device-local or
// concurrent administrator changes are never overwritten based on a stale
// snapshot. A concurrent change that reached the exact approved desired state
// is safely treated as idempotently complete.
func revalidateFortiGateSnapshot(ctx context.Context, snapshot deploymentSnapshot) (*fortiGateObject, bool, error) {
	command := snapshot.Command
	if command.Kind == "policy" {
		if err := verifyExpectedPolicyOrder(ctx, snapshot.Target, command.Path); err != nil {
			return nil, false, fmt.Errorf("policy order precondition changed: %w", err)
		}
	}
	current, err := lookupFortiGateObject(ctx, snapshot.Target.Client, snapshot.Target.Config, command)
	if err != nil {
		return nil, false, fmt.Errorf("revalidate object: %w", err)
	}
	if strings.EqualFold(command.Method, http.MethodDelete) {
		if current == nil {
			return nil, true, nil
		}
		if !snapshot.Existed {
			return nil, false, errors.New("delete precondition changed: policy appeared after snapshot")
		}
		if current.MKey != snapshot.MKey {
			return nil, false, errors.New("delete precondition changed: policy mkey changed after snapshot")
		}
		if snapshot.UUID != "" && scalarString(current.Data["uuid"]) != snapshot.UUID {
			return nil, false, errors.New("delete precondition changed: policy identity changed after snapshot")
		}
		if differences := fortiGateCommandDifferences(command, command.Payload, current.Data); len(differences) != 0 {
			return nil, false, fmt.Errorf("delete precondition changed after snapshot: %s", strings.Join(differences, "; "))
		}
		return current, false, nil
	}

	if snapshot.Existed && current != nil {
		if current.MKey != snapshot.MKey {
			return nil, false, errors.New("update precondition changed: object mkey changed after snapshot")
		}
		if snapshot.UUID != "" && scalarString(current.Data["uuid"]) != snapshot.UUID {
			return nil, false, errors.New("update precondition changed: object identity changed after snapshot")
		}
	}
	if current != nil && len(fortiGateCommandDifferences(command, command.Payload, current.Data)) == 0 {
		if command.Kind == "policy" {
			if !snapshot.Existed {
				if err := verifyLivePolicySuccessor(ctx, snapshot, current.MKey); err != nil {
					return nil, false, err
				}
			} else if err := verifyExpectedPolicyOrder(ctx, snapshot.Target, command.Path); err != nil {
				return nil, false, err
			}
		}
		return current, true, nil
	}
	if snapshot.Existed {
		if current == nil {
			return nil, false, errors.New("update precondition changed: object disappeared after snapshot")
		}
		if current.MKey != snapshot.MKey {
			return nil, false, errors.New("update precondition changed: object mkey changed after snapshot")
		}
		if snapshot.UUID != "" && scalarString(current.Data["uuid"]) != snapshot.UUID {
			return nil, false, errors.New("update precondition changed: object identity changed after snapshot")
		}
		if differences := fortiGateCommandDifferences(command, snapshot.Restore, current.Data); len(differences) != 0 {
			return nil, false, fmt.Errorf("update precondition changed after snapshot: %s", strings.Join(differences, "; "))
		}
		return current, false, nil
	}
	if current != nil {
		return nil, false, errors.New("create precondition changed: same-named object appeared after snapshot")
	}
	if command.Kind == "policy" {
		if _, err := lookupLivePolicySuccessor(ctx, snapshot); err != nil {
			return nil, false, err
		}
	}
	return nil, false, nil
}

func lookupLivePolicySuccessor(ctx context.Context, snapshot deploymentSnapshot) (*fortiGateObject, error) {
	anchorCommand := snapshot.Command
	anchorCommand.Payload = map[string]any{"name": snapshot.Command.InsertBefore}
	anchor, err := lookupFortiGateObject(ctx, snapshot.Target.Client, snapshot.Target.Config, anchorCommand)
	if err != nil {
		return nil, fmt.Errorf("resolve approved policy successor %q: %w", snapshot.Command.InsertBefore, err)
	}
	if anchor == nil {
		return nil, fmt.Errorf("approved policy successor %q is missing", snapshot.Command.InsertBefore)
	}
	if snapshot.InsertBeforeMKey != "" && anchor.MKey != snapshot.InsertBeforeMKey {
		return nil, fmt.Errorf("approved policy successor %q changed mkey after snapshot", snapshot.Command.InsertBefore)
	}
	return anchor, nil
}

func verifyLivePolicySuccessor(ctx context.Context, snapshot deploymentSnapshot, policyMKey string) error {
	anchor, err := lookupLivePolicySuccessor(ctx, snapshot)
	if err != nil {
		return err
	}
	before, _, err := policyNeighbours(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command.Path, policyMKey)
	if err != nil {
		return fmt.Errorf("verify approved policy order: %w", err)
	}
	if before != anchor.MKey {
		return fmt.Errorf("verify approved policy order: policy is not immediately before %q", snapshot.Command.InsertBefore)
	}
	return nil
}

func observeAbsentPolicyPostState(ctx context.Context, snapshot *deploymentSnapshot) error {
	ordered, err := listFortiGateObjects(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command.Path, nil)
	if err != nil {
		return err
	}
	snapshot.PostObserved = true
	snapshot.PostAbsent = true
	snapshot.PostOrder = fortiGateObjectMKeys(ordered)
	return nil
}

// verifyExpectedPolicyOrder compares the whole ordered policy table, not a raw
// pre-PREPARE neighbour pair. New reviewed policies and approved deletes update
// PolicyOrder only after their exact move/delete result is verified. This lets
// E -> anchor safely become E -> N(disabled) -> anchor while still rejecting
// any unreviewed administrator reorder between snapshot and finalization.
func verifyExpectedPolicyOrder(ctx context.Context, target *runtimeTarget, path string) error {
	expected, bound := target.PolicyOrder[path]
	if !bound {
		return errors.New("policy order was not bound during snapshot")
	}
	ordered, err := listFortiGateObjects(ctx, target.Client, target.Config, path, nil)
	if err != nil {
		return err
	}
	actual := fortiGateObjectMKeys(ordered)
	if !sameStringSlice(expected, actual) {
		return fmt.Errorf("ordered policy mkeys changed: expected %v, observed %v", expected, actual)
	}
	return nil
}

func advanceExpectedPolicyOrder(ctx context.Context, snapshot *deploymentSnapshot, mutation, mkey string) error {
	path := snapshot.Command.Path
	current, bound := snapshot.Target.PolicyOrder[path]
	if !bound {
		return errors.New("policy order was not bound during snapshot")
	}
	next := append([]string(nil), current...)
	switch mutation {
	case "create":
		for _, existing := range next {
			if existing == mkey {
				return fmt.Errorf("created policy mkey %q already exists in expected order", mkey)
			}
		}
		anchor, err := lookupLivePolicySuccessor(ctx, *snapshot)
		if err != nil {
			return err
		}
		position := -1
		for index, existing := range next {
			if existing == anchor.MKey {
				position = index
				break
			}
		}
		if position < 0 {
			return fmt.Errorf("approved successor mkey %q is absent from expected order", anchor.MKey)
		}
		next = append(next, "")
		copy(next[position+1:], next[position:])
		next[position] = mkey
	case "delete":
		position := -1
		for index, existing := range next {
			if existing == mkey {
				position = index
				break
			}
		}
		if position < 0 {
			return fmt.Errorf("deleted policy mkey %q is absent from expected order", mkey)
		}
		next = append(next[:position], next[position+1:]...)
	default:
		return fmt.Errorf("unsupported policy-order mutation %q", mutation)
	}
	ordered, err := listFortiGateObjects(ctx, snapshot.Target.Client, snapshot.Target.Config, path, nil)
	if err != nil {
		return err
	}
	actual := fortiGateObjectMKeys(ordered)
	if !sameStringSlice(next, actual) {
		return fmt.Errorf("reviewed %s produced unexpected policy order: expected %v, observed %v", mutation, next, actual)
	}
	snapshot.Target.PolicyOrder[path] = next
	return nil
}

func fortiGateObjectMKeys(objects []fortiGateObject) []string {
	result := make([]string, 0, len(objects))
	for _, object := range objects {
		result = append(result, object.MKey)
	}
	return result
}

func neighboursInPolicyOrder(order []string, mkey string) (string, string, bool) {
	for index, candidate := range order {
		if candidate != mkey {
			continue
		}
		before, after := "", ""
		if index+1 < len(order) {
			before = order[index+1]
		}
		if index > 0 {
			after = order[index-1]
		}
		return before, after, true
	}
	return "", "", false
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func rollbackDeployment(ctx context.Context, applied []appliedDeploymentStep) []string {
	errorsFound := []string{}
	snapshots := make([]deploymentSnapshot, len(applied))
	reconciled := make([]bool, len(applied))
	controlledPolicyMKeys := map[string]bool{}
	for index, step := range applied {
		snapshots[index] = step.Snapshot
		if snapshots[index].Command.Kind == "policy" {
			if snapshots[index].MKey != "" {
				controlledPolicyMKeys[snapshots[index].MKey] = true
			}
			if snapshots[index].PostMKey != "" {
				controlledPolicyMKeys[snapshots[index].PostMKey] = true
			}
		}
	}
	// First bind every ambiguous timeout/connection-loss outcome with this
	// fresh rollback context. No compensation write is allowed until the exact
	// reviewed post-state (or a proven no-op) is attributable.
	for index := len(snapshots) - 1; index >= 0; index-- {
		if err := prepareRollbackState(ctx, &snapshots[index]); err != nil {
			errorsFound = append(errorsFound, fmt.Sprintf("target %q command %d: %v", snapshots[index].Target.Config.Name, snapshots[index].Command.Sequence, err))
			continue
		}
		reconciled[index] = true
		if snapshots[index].Command.Kind == "policy" && snapshots[index].PostMKey != "" {
			controlledPolicyMKeys[snapshots[index].PostMKey] = true
		}
	}
	// Rollback is an all-or-nothing compensation plan. If even one applied
	// mutation cannot be attributed, compensating any of the others can remove
	// a DENY guard while leaving an uncertain ACCEPT live. Return the complete
	// reconciliation error set before the first rollback write.
	if len(errorsFound) != 0 {
		return errorsFound
	}

	restoredPolicies := []deploymentSnapshot{}
	rolledBack := map[int]bool{}
	rollbackIndices := func(indices []int) {
		for _, index := range indices {
			if !reconciled[index] {
				continue
			}
			snapshot := &snapshots[index]
			if err := rollbackFortiGateCommand(ctx, snapshot, controlledPolicyMKeys); err != nil {
				errorsFound = append(errorsFound, fmt.Sprintf("target %q command %d: %v", snapshot.Target.Config.Name, snapshot.Command.Sequence, err))
			} else {
				rolledBack[index] = true
				if snapshot.PositionRestored {
					restoredPolicies = append(restoredPolicies, *snapshot)
				}
			}
		}
	}
	activateIndices := func(indices []int) {
		for _, index := range indices {
			if !rolledBack[index] {
				continue
			}
			snapshot := &snapshots[index]
			if err := activateRestoredPolicy(ctx, snapshot); err != nil {
				errorsFound = append(errorsFound, fmt.Sprintf("target %q command %d rollback activation: %v", snapshot.Target.Config.Name, snapshot.Command.Sequence, err))
			}
		}
	}
	deletedPolicies, deletedDenies, deletedAccepts := []int{}, []int{}, []int{}
	existingDenies, existingAccepts, newDenies, newAccepts, objects := []int{}, []int{}, []int{}, []int{}, []int{}
	for index := len(snapshots) - 1; index >= 0; index-- {
		snapshot := snapshots[index]
		if snapshot.Command.Kind != "policy" {
			objects = append(objects, index)
			continue
		}
		if strings.EqualFold(snapshot.Command.Method, http.MethodDelete) {
			deletedPolicies = append(deletedPolicies, index)
			if rollbackPolicyAction(snapshot) == "deny" {
				deletedDenies = append(deletedDenies, index)
			} else {
				deletedAccepts = append(deletedAccepts, index)
			}
		} else if snapshot.Existed {
			if rollbackPolicyAction(snapshot) == "deny" {
				existingDenies = append(existingDenies, index)
			} else {
				existingAccepts = append(existingAccepts, index)
			}
		} else {
			if scalarString(snapshot.Command.Payload["action"]) == "deny" {
				newDenies = append(newDenies, index)
			} else {
				newAccepts = append(newAccepts, index)
			}
		}
	}
	// Deleted policies are recreated disabled. Baseline DENYs are restored and
	// activated before baseline ACCEPTs; new DENYs remain as guards until last.
	rollbackIndices(deletedPolicies)
	for pass := 0; pass < len(deletedPolicies); pass++ {
		for _, index := range deletedPolicies {
			if !rolledBack[index] {
				continue
			}
			current, err := lookupFortiGateObject(ctx, snapshots[index].Target.Client, snapshots[index].Target.Config, snapshots[index].Command)
			if err == nil && current == nil {
				err = errors.New("restored policy is missing")
			}
			if err == nil {
				err = restorePolicyPosition(ctx, snapshots[index], current.MKey)
			}
			if err != nil && pass == len(deletedPolicies)-1 {
				errorsFound = append(errorsFound, fmt.Sprintf("target %q command %d policy positioning: %v", snapshots[index].Target.Config.Name, snapshots[index].Command.Sequence, err))
				rolledBack[index] = false
			}
		}
	}
	rollbackIndices(existingDenies)
	activateIndices(deletedDenies)
	rollbackIndices(newAccepts)
	rollbackIndices(existingAccepts)
	activateIndices(deletedAccepts)
	rollbackIndices(newDenies)
	// Restore policy positions only after every deleted policy's content exists
	// again. A single inline move cannot reliably place a run of adjacent
	// policies when both saved neighbours were still absent at that moment.
	for pass := 0; pass < len(restoredPolicies); pass++ {
		for _, snapshot := range restoredPolicies {
			current, err := lookupFortiGateObject(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command)
			if err != nil || current == nil {
				if pass == len(restoredPolicies)-1 {
					if err == nil {
						err = errors.New("restored policy is missing")
					}
					errorsFound = append(errorsFound, fmt.Sprintf("target %q command %d policy positioning: %v", snapshot.Target.Config.Name, snapshot.Command.Sequence, err))
				}
				continue
			}
			if err := restorePolicyPosition(ctx, snapshot, current.MKey); err != nil && pass == len(restoredPolicies)-1 {
				errorsFound = append(errorsFound, fmt.Sprintf("target %q command %d policy positioning: %v", snapshot.Target.Config.Name, snapshot.Command.Sequence, err))
			}
		}
	}
	// Policy order affects matching. Content-only rollback is not successful
	// until every restored policy is back next to its original neighbour.
	for _, snapshot := range restoredPolicies {
		current, err := lookupFortiGateObject(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command)
		if err != nil || current == nil {
			if err == nil {
				err = errors.New("restored policy is missing")
			}
			errorsFound = append(errorsFound, fmt.Sprintf("target %q command %d policy-order verification: %v", snapshot.Target.Config.Name, snapshot.Command.Sequence, err))
			continue
		}
		before, after, err := policyNeighbours(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command.Path, current.MKey)
		if err != nil {
			errorsFound = append(errorsFound, fmt.Sprintf("target %q command %d policy-order verification: %v", snapshot.Target.Config.Name, snapshot.Command.Sequence, err))
			continue
		}
		if snapshot.BeforeMKey != "" && before != snapshot.BeforeMKey || snapshot.AfterMKey != "" && after != snapshot.AfterMKey {
			errorsFound = append(errorsFound, fmt.Sprintf("target %q command %d policy-order verification failed", snapshot.Target.Config.Name, snapshot.Command.Sequence))
		}
	}
	// Generated objects are immutable/content-addressed. Policies are restored
	// first so no live policy references a newly created object when it is
	// removed. Legacy object updates are also compensated only after policies.
	rollbackIndices(objects)
	return errorsFound
}

func rollbackFortiGateCommand(ctx context.Context, snapshot *deploymentSnapshot, controlledPolicyMKeys map[string]bool) error {
	target, command := snapshot.Target, snapshot.Command
	if err := prepareRollbackState(ctx, snapshot); err != nil {
		return err
	}
	if snapshot.PostNoop {
		return nil
	}
	if command.Kind == "policy" {
		if err := verifyRollbackPolicyOrder(ctx, snapshot, controlledPolicyMKeys); err != nil {
			return err
		}
	}
	current, err := lookupFortiGateObject(ctx, target.Client, target.Config, command)
	if err != nil {
		return err
	}
	if strings.EqualFold(command.Method, http.MethodDelete) {
		if !snapshot.PostObserved || !snapshot.PostAbsent {
			return errors.New("rollback conflict: deleted post-state was not safely observed")
		}
		if current != nil {
			return errors.New("rollback conflict: same-named policy appeared after deletion")
		}
	} else {
		if !snapshot.PostObserved || snapshot.PostAbsent || current == nil {
			return errors.New("rollback conflict: mutated object no longer matches the observed post-state")
		}
		if snapshot.PostMKey == "" || current.MKey != snapshot.PostMKey {
			return errors.New("rollback conflict: mutated object mkey changed")
		}
		if snapshot.PostUUID != "" && scalarString(current.Data["uuid"]) != snapshot.PostUUID {
			return errors.New("rollback conflict: mutated object identity changed")
		}
		if differences := fortiGateCommandDifferences(command, snapshot.PostState, current.Data); len(differences) != 0 {
			return fmt.Errorf("rollback conflict: mutated object changed after verification: %s", strings.Join(differences, "; "))
		}
	}
	if !snapshot.Existed {
		if _, err := fortiGateCall(ctx, target.Client, target.Config, http.MethodDelete, withMKey(command.Path, current.MKey), nil, nil); err != nil {
			return err
		}
		current, err = lookupFortiGateObject(ctx, target.Client, target.Config, command)
		if err != nil {
			return err
		}
		if current != nil {
			return errors.New("newly created object still exists after rollback")
		}
		return nil
	}

	verificationRestore := snapshot.Restore
	if current == nil {
		restore := cloneDeploymentPayload(snapshot.Restore)
		if command.Kind == "policy" {
			desiredStatus := scalarString(restore["status"])
			if desiredStatus == "" {
				desiredStatus = scalarString(fortiOS74PolicySemanticDefaults()["status"])
			}
			snapshot.RollbackStatus = desiredStatus
			// A recreated policy is inert until its reviewed original position is
			// restored. DENYs are then enabled before ACCEPTs by rollbackDeployment.
			restore["status"] = "disable"
			verificationRestore = restore
			policyID, exists := snapshot.Data["policyid"]
			if !exists || snapshot.MKey == "" || scalarString(policyID) != snapshot.MKey {
				return errors.New("deleted policy snapshot has no consistent original policyid")
			}
			restore["policyid"] = policyID
		}
		if _, err := fortiGateCall(ctx, target.Client, target.Config, http.MethodPost, command.Path, nil, restore); err != nil {
			return err
		}
		current, err = lookupFortiGateObject(ctx, target.Client, target.Config, command)
		if err != nil {
			return err
		}
		if current == nil {
			return errors.New("deleted object could not be recreated")
		}
		if command.Kind == "policy" && current.MKey != snapshot.MKey {
			return fmt.Errorf("recreated policy has policyid %q, want original policyid %q", current.MKey, snapshot.MKey)
		}
	} else {
		restore := cloneDeploymentPayload(snapshot.Restore)
		delete(restore, "policyid")
		if _, err := fortiGateCall(ctx, target.Client, target.Config, http.MethodPut, withMKey(command.Path, current.MKey), nil, restore); err != nil {
			return err
		}
	}
	current, err = lookupFortiGateObject(ctx, target.Client, target.Config, command)
	if err != nil {
		return err
	}
	if current == nil {
		return errors.New("restored object is missing")
	}
	if differences := fortiGateCommandDifferences(command, verificationRestore, current.Data); len(differences) != 0 {
		return fmt.Errorf("rollback verification failed: %s", strings.Join(differences, "; "))
	}
	snapshot.PositionRestored = snapshot.Existed && command.Kind == "policy"
	return nil
}

func verifyRollbackPolicyOrder(ctx context.Context, snapshot *deploymentSnapshot, controlled map[string]bool) error {
	if snapshot.PostOrder == nil {
		return errors.New("rollback conflict: policy post-order was not observed")
	}
	ordered, err := listFortiGateObjects(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command.Path, nil)
	if err != nil {
		return fmt.Errorf("rollback conflict: read policy order: %w", err)
	}
	filter := func(order []string) []string {
		result := make([]string, 0, len(order))
		for _, mkey := range order {
			if !controlled[mkey] {
				result = append(result, mkey)
			}
		}
		return result
	}
	if expected, actual := filter(snapshot.PostOrder), filter(fortiGateObjectMKeys(ordered)); !sameStringSlice(expected, actual) {
		return fmt.Errorf("rollback conflict: unmanaged policy order changed: expected %v, observed %v", expected, actual)
	}
	return nil
}

func activateRestoredPolicy(ctx context.Context, snapshot *deploymentSnapshot) error {
	if snapshot.RollbackStatus == "" || snapshot.RollbackStatus == "disable" || snapshot.PostNoop {
		return nil
	}
	current, err := lookupFortiGateObject(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command)
	if err != nil {
		return err
	}
	if current == nil {
		return errors.New("restored policy is missing before rollback activation")
	}
	if err := restorePolicyPosition(ctx, *snapshot, current.MKey); err != nil {
		return fmt.Errorf("position restored policy before activation: %w", err)
	}
	if _, err := fortiGateCall(ctx, snapshot.Target.Client, snapshot.Target.Config, http.MethodPut, withMKey(snapshot.Command.Path, current.MKey), nil, map[string]any{"status": snapshot.RollbackStatus}); err != nil {
		return err
	}
	current, err = lookupFortiGateObject(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command)
	if err != nil {
		return err
	}
	if current == nil {
		return errors.New("restored policy disappeared during rollback activation")
	}
	if differences := fortiGateCommandDifferences(snapshot.Command, snapshot.Restore, current.Data); len(differences) != 0 {
		return fmt.Errorf("rollback activation verification failed: %s", strings.Join(differences, "; "))
	}
	return nil
}

func rollbackPolicyAction(snapshot deploymentSnapshot) string {
	action := scalarString(snapshot.Restore["action"])
	if action == "" {
		action = scalarString(fortiOS74PolicySemanticDefaults()["action"])
	}
	return action
}

func prepareRollbackState(ctx context.Context, snapshot *deploymentSnapshot) error {
	if snapshot.PostNoop {
		return nil
	}
	if !snapshot.Existed && snapshot.Command.Kind == "policy" && strings.EqualFold(snapshot.Command.Method, "UPSERT") {
		current, err := lookupFortiGateObject(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command)
		if err != nil {
			return fmt.Errorf("reconcile new policy for rollback: %w", err)
		}
		if current == nil {
			snapshot.PostNoop = true
			return nil
		}
		if snapshot.PostMKey != "" && current.MKey != snapshot.PostMKey {
			return errors.New("rollback conflict: new policy mkey changed")
		}
		if snapshot.PostUUID != "" && scalarString(current.Data["uuid"]) != snapshot.PostUUID {
			return errors.New("rollback conflict: new policy UUID changed")
		}
		prepared := cloneDeploymentPayload(snapshot.Command.CreatePayload)
		delete(prepared, "policyid")
		expected := prepared
		if len(fortiGateCommandDifferences(snapshot.Command, prepared, current.Data)) != 0 {
			if differences := fortiGateCommandDifferences(snapshot.Command, snapshot.Command.Payload, current.Data); len(differences) != 0 {
				return fmt.Errorf("rollback conflict: new policy is neither reviewed PREPARE nor final state: %s", strings.Join(differences, "; "))
			}
			expected = snapshot.Command.Payload
		}
		return observeFortiGatePostStateFor(ctx, snapshot, current, expected)
	}
	if snapshot.PostObserved {
		return nil
	}
	current, err := lookupFortiGateObject(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command)
	if err != nil {
		return fmt.Errorf("establish rollback post-state: %w", err)
	}
	if strings.EqualFold(snapshot.Command.Method, http.MethodDelete) {
		if current == nil {
			if snapshot.Command.Kind == "policy" {
				if err := observeAbsentPolicyPostState(ctx, snapshot); err != nil {
					return fmt.Errorf("bind deleted policy order: %w", err)
				}
			} else {
				snapshot.PostObserved, snapshot.PostAbsent = true, true
			}
			return nil
		}
		if snapshot.Existed && current.MKey == snapshot.MKey && (snapshot.UUID == "" || scalarString(current.Data["uuid"]) == snapshot.UUID) && len(fortiGateCommandDifferences(snapshot.Command, snapshot.Restore, current.Data)) == 0 {
			snapshot.PostNoop = true
			return nil
		}
		return errors.New("rollback conflict: delete result could not be attributed to this deployment")
	}
	if current == nil {
		if !snapshot.Existed {
			snapshot.PostNoop = true
			return nil
		}
		return errors.New("rollback conflict: updated object disappeared before its post-state could be bound")
	}
	if snapshot.Existed && snapshot.UUID != "" && scalarString(current.Data["uuid"]) != snapshot.UUID {
		return errors.New("rollback conflict: mutation result has a different object identity")
	}
	if snapshot.Existed && current.MKey == snapshot.MKey && len(fortiGateCommandDifferences(snapshot.Command, snapshot.Restore, current.Data)) == 0 {
		snapshot.PostNoop = true
		return nil
	}
	if differences := fortiGateCommandDifferences(snapshot.Command, snapshot.Command.Payload, current.Data); len(differences) != 0 {
		return fmt.Errorf("rollback conflict: mutation result could not be attributed to this deployment: %s", strings.Join(differences, "; "))
	}
	if snapshot.Existed && current.MKey != snapshot.MKey {
		return errors.New("rollback conflict: updated object mkey changed")
	}
	return observeFortiGatePostState(ctx, snapshot, current)
}

func restorePolicyPosition(ctx context.Context, snapshot deploymentSnapshot, restoredMKey string) error {
	query := url.Values{"action": []string{"move"}}
	reference, direction := "", ""
	if snapshot.BeforeMKey != "" {
		exists, err := fortiGateMKeyExists(ctx, snapshot.Target, snapshot.Command.Path, snapshot.BeforeMKey)
		if err != nil {
			return err
		}
		if exists {
			reference, direction = snapshot.BeforeMKey, "before"
		}
	}
	if reference == "" && snapshot.AfterMKey != "" {
		exists, err := fortiGateMKeyExists(ctx, snapshot.Target, snapshot.Command.Path, snapshot.AfterMKey)
		if err != nil {
			return err
		}
		if exists {
			reference, direction = snapshot.AfterMKey, "after"
		}
	}
	if reference == "" {
		return nil
	}
	query.Set(direction, reference)
	if _, err := fortiGateCall(ctx, snapshot.Target.Client, snapshot.Target.Config, http.MethodPut, withMKey(snapshot.Command.Path, restoredMKey), query, nil); err != nil {
		return fmt.Errorf("restore policy order: %w", err)
	}
	before, after, err := policyNeighbours(ctx, snapshot.Target.Client, snapshot.Target.Config, snapshot.Command.Path, restoredMKey)
	if err != nil {
		return err
	}
	if direction == "before" && before != reference || direction == "after" && after != reference {
		return errors.New("restored policy position could not be verified")
	}
	return nil
}

func fortiGateMKeyExists(ctx context.Context, target *runtimeTarget, path, mkey string) (bool, error) {
	objects, err := listFortiGateObjects(ctx, target.Client, target.Config, path, nil)
	if err != nil {
		return false, err
	}
	for _, object := range objects {
		if object.MKey == mkey {
			return true, nil
		}
	}
	return false, nil
}

func policyNeighbours(ctx context.Context, client *http.Client, target FortinetTarget, path, mkey string) (string, string, error) {
	objects, err := listFortiGateObjects(ctx, client, target, path, nil)
	if err != nil {
		return "", "", err
	}
	for i, object := range objects {
		if object.MKey != mkey {
			continue
		}
		before, after := "", ""
		if i+1 < len(objects) {
			before = objects[i+1].MKey
		}
		if i > 0 {
			after = objects[i-1].MKey
		}
		return before, after, nil
	}
	return "", "", fmt.Errorf("policy mkey %q is absent from ordered policy list", mkey)
}

func lookupFortiGateObject(ctx context.Context, client *http.Client, target FortinetTarget, command deploymentCommand) (*fortiGateObject, error) {
	name := command.Payload["name"].(string)
	query := url.Values{"filter": []string{"name==" + name}}
	objects, err := listFortiGateObjects(ctx, client, target, command.Path, query)
	if err != nil {
		return nil, err
	}
	matches := []*fortiGateObject{}
	for _, object := range objects {
		if value, _ := object.Data["name"].(string); value == name {
			copy := object
			matches = append(matches, &copy)
		}
	}
	if len(matches) == 0 {
		return nil, nil
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("object name %q is ambiguous", name)
	}
	return matches[0], nil
}

func listFortiGateObjects(ctx context.Context, client *http.Client, target FortinetTarget, path string, query url.Values) ([]fortiGateObject, error) {
	const pageSize = 500
	const maxRows = 250000
	result := []fortiGateObject{}
	seenMKeys := map[string]bool{}
	start := 0
	revision := ""
	policyKind := strings.HasSuffix(path, "/policy")
	for page := 0; page < 10000; page++ {
		pageQuery := url.Values{}
		for key, values := range query {
			pageQuery[key] = append([]string(nil), values...)
		}
		pageQuery.Set("start", strconv.Itoa(start))
		pageQuery.Set("count", strconv.Itoa(pageSize))
		body, err := fortiGateCall(ctx, client, target, http.MethodGet, path, pageQuery, nil)
		if err != nil {
			return nil, err
		}
		pageRevision := scalarString(body["revision"])
		if page == 0 {
			revision = pageRevision
		} else if revision == "" || pageRevision == "" || pageRevision != revision {
			return nil, errors.New("FortiGate object table changed while a paginated snapshot was read")
		}
		rawResults, resultsPresent := body["results"]
		if !resultsPresent {
			return nil, errors.New("FortiGate object response has no results field")
		}
		if _, ordered := rawResults.([]any); policyKind && !ordered {
			return nil, errors.New("FortiGate policy response is not an ordered array")
		}
		values, err := resultMaps(rawResults)
		if err != nil {
			return nil, fmt.Errorf("FortiGate object response has malformed results: %w", err)
		}
		if fortiGateTruthy(body["limit_reached"]) && len(values) == 0 {
			return nil, errors.New("FortiGate paginated response returned an empty limited page")
		}
		for _, value := range values {
			mkey := firstScalarString(value, "name")
			if policyKind {
				mkey = scalarString(value["policyid"])
			}
			if mkey == "" {
				return nil, errors.New("FortiGate object response contains no mkey")
			}
			if seenMKeys[mkey] {
				return nil, fmt.Errorf("FortiGate paginated response repeats mkey %q", mkey)
			}
			seenMKeys[mkey] = true
			result = append(result, fortiGateObject{MKey: mkey, Data: value})
			if len(result) > maxRows {
				return nil, fmt.Errorf("FortiGate object table exceeds the safety limit of %d rows", maxRows)
			}
		}
		if !fortiGateTruthy(body["limit_reached"]) {
			return result, nil
		}
		if revision == "" {
			return nil, errors.New("FortiGate paginated response has no stable revision")
		}
		nextIndex, err := strconv.Atoi(scalarString(body["next_idx"]))
		if err != nil || nextIndex < start || nextIndex+1 <= start {
			return nil, errors.New("FortiGate paginated response has an invalid next_idx")
		}
		// FortiOS next_idx is the zero-based index of the last returned row.
		start = nextIndex + 1
	}
	return nil, errors.New("FortiGate pagination exceeded the safety page limit")
}

func fortiGateTruthy(value any) bool {
	if flag, ok := value.(bool); ok {
		return flag
	}
	switch strings.ToLower(strings.TrimSpace(scalarString(value))) {
	case "1", "true", "yes", "enable", "enabled":
		return true
	default:
		return false
	}
}

func resultMaps(value any) ([]map[string]any, error) {
	result := []map[string]any{}
	switch item := value.(type) {
	case []any:
		for index, child := range item {
			object, ok := child.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("array element %d is not an object", index)
			}
			result = append(result, object)
		}
	case map[string]any:
		if _, object := item["name"]; object {
			result = append(result, item)
		} else {
			keys := make([]string, 0, len(item))
			for key := range item {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				object, ok := item[key].(map[string]any)
				if !ok {
					return nil, fmt.Errorf("object child %q is not an object", key)
				}
				result = append(result, object)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported results type %T", value)
	}
	return result, nil
}

func withMKey(path, mkey string) string {
	return strings.TrimRight(path, "/") + "/" + url.PathEscape(mkey)
}

func fortiGateCall(ctx context.Context, client *http.Client, target FortinetTarget, method, path string, query url.Values, payload map[string]any) (map[string]any, error) {
	if !strings.EqualFold(method, http.MethodGet) {
		readOnly, settingErr := fortiGateReadOnlySetting()
		if settingErr != nil {
			return nil, settingErr
		}
		if readOnly {
			return nil, errFortiGateReadOnly
		}
	}
	allowedMonitorPath := path == "/api/v2/monitor/system/status" ||
		path == "/api/v2/monitor/router/ipv4" ||
		path == "/api/v2/monitor/router/ipv6"
	if !strings.HasPrefix(path, "/api/v2/cmdb/") && !allowedMonitorPath {
		return nil, errors.New("FortiGate API path is outside the allowed deployment endpoints")
	}
	if allowedMonitorPath && method != http.MethodGet {
		return nil, errors.New("FortiGate monitor endpoints are read-only")
	}
	baseURL, err := normalizedFortinetEndpoint(target.URL)
	if err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(baseURL + path)
	if err != nil {
		return nil, err
	}
	values := endpoint.Query()
	for key, entries := range query {
		for _, value := range entries {
			values.Add(key, value)
		}
	}
	if target.VDOM != "" {
		values.Set("vdom", target.VDOM)
	}
	endpoint.RawQuery = values.Encode()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, err
	}
	token, err := target.apiToken()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if readErr != nil {
		return nil, readErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("FortiGate returned HTTP %d", response.StatusCode)
	}
	result := map[string]any{}
	if len(bytes.TrimSpace(data)) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&result); err != nil {
			return nil, fmt.Errorf("decode FortiGate response: %w", err)
		}
	}
	if err := fortiGateApplicationError(result); err != nil {
		return nil, errors.New(redactedFortinetError(target, err))
	}
	return result, nil
}

var errFortiGateReadOnly = fmt.Errorf("FortiGate connectivity is read-only (%s=true)", fortiGateReadOnlyEnv)

func fortiGateApplicationError(result map[string]any) error {
	status := strings.ToLower(firstScalarString(result, "status"))
	httpStatus, _ := strconv.Atoi(firstScalarString(result, "http_status"))
	if status == "error" || status == "failed" || httpStatus >= 400 {
		return errors.New("FortiGate rejected the request")
	}
	return nil
}

func firstScalarString(value any, keys ...string) string {
	switch item := value.(type) {
	case map[string]any:
		for _, key := range keys {
			if result := scalarString(item[key]); result != "" {
				return result
			}
		}
		for _, child := range item {
			if result := firstScalarString(child, keys...); result != "" {
				return result
			}
		}
	case []any:
		for _, child := range item {
			if result := firstScalarString(child, keys...); result != "" {
				return result
			}
		}
	}
	return ""
}

func scalarString(value any) string {
	switch item := value.(type) {
	case string:
		return item
	case json.Number:
		return item.String()
	case float64:
		return strconv.FormatFloat(item, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(item), 'f', -1, 32)
	case int:
		return strconv.Itoa(item)
	case int64:
		return strconv.FormatInt(item, 10)
	}
	return ""
}

func fortiGateDifferences(expected, actual any) []string {
	result := []string{}
	compareFortiGateValue("", expected, actual, &result)
	if len(result) > 20 {
		return append(result[:20], "additional differences omitted")
	}
	return result
}

func compareFortiGateValue(path string, expected, actual any, result *[]string) {
	switch wanted := expected.(type) {
	case map[string]any:
		got, ok := actual.(map[string]any)
		if !ok {
			*result = append(*result, displayPath(path)+" has a different type")
			return
		}
		keys := make([]string, 0, len(wanted))
		for key := range wanted {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value, exists := got[key]
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			if !exists {
				if fortiGateEmptyCollection(wanted[key]) {
					continue
				}
				*result = append(*result, childPath+" is missing")
				continue
			}
			if fortiGateEmptyCollection(wanted[key]) && (value == nil || fortiGateEmptyCollection(value)) {
				continue
			}
			compareFortiGateValue(childPath, wanted[key], value, result)
		}
	case []map[string]string:
		converted := make([]any, 0, len(wanted))
		for _, value := range wanted {
			entry := map[string]any{}
			for key, field := range value {
				entry[key] = field
			}
			converted = append(converted, entry)
		}
		compareFortiGateSlice(path, converted, actual, result)
	case []any:
		compareFortiGateSlice(path, wanted, actual, result)
	case []string:
		converted := make([]any, len(wanted))
		for i := range wanted {
			converted[i] = wanted[i]
		}
		compareFortiGateSlice(path, converted, actual, result)
	default:
		if !fortiGateScalarEqual(expected, actual) {
			*result = append(*result, displayPath(path)+" differs")
		}
	}
}

func fortiGateEmptyCollection(value any) bool {
	switch item := value.(type) {
	case []any:
		return len(item) == 0
	case []string:
		return len(item) == 0
	case []map[string]string:
		return len(item) == 0
	default:
		return false
	}
}

func fortiGateScalarEqual(expected, actual any) bool {
	if expected == nil || actual == nil {
		return expected == nil && actual == nil
	}
	if wanted, ok := expected.(bool); ok {
		got, sameType := actual.(bool)
		return sameType && wanted == got
	}
	if _, ok := actual.(bool); ok {
		return false
	}
	return scalarString(expected) == scalarString(actual)
}

func compareFortiGateSlice(path string, expected []any, actual any, result *[]string) {
	got, ok := actual.([]any)
	if !ok || len(got) != len(expected) {
		*result = append(*result, displayPath(path)+" differs")
		return
	}
	used := make([]bool, len(got))
	for _, wanted := range expected {
		matched := false
		for i, candidate := range got {
			if used[i] {
				continue
			}
			differences := []string{}
			compareFortiGateValue(path, wanted, candidate, &differences)
			if len(differences) == 0 {
				used[i], matched = true, true
				break
			}
		}
		if !matched {
			*result = append(*result, displayPath(path)+" differs")
			return
		}
	}
}

func displayPath(path string) string {
	if path == "" {
		return "value"
	}
	return path
}

func (s *state) adminDrift(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin", "reviewer", "deployer") {
		s.audit(actor, "deployment.drift", "denied", nil)
		writeError(w, "Policy reviewer or deployer role required", http.StatusForbidden)
		return
	}
	version := strings.TrimSpace(r.FormValue("version"))
	var err error
	if version == "" {
		version, err = s.latestPublicationVersion()
	}
	var published *publishedDeployment
	if err == nil {
		published, err = s.loadPublishedDeployment(version)
	}
	if err != nil {
		s.audit(actor, "deployment.drift", "failed", map[string]any{"version": version, "error": err.Error()})
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	base := published.Previous
	if published.PreviousPlan == nil {
		base = nil
	}
	current := generateDeploymentPlanWithBase(base, published.Policy, s.config.FortinetTargets)
	if bindErr := bindPolicyDeletePayloadsToPreviousPlan(&current, published.PreviousPlan); bindErr != nil {
		s.audit(actor, "deployment.drift", "blocked", map[string]any{"version": version, "error": bindErr.Error()})
		writeError(w, bindErr.Error(), http.StatusConflict)
		return
	}
	response := driftResponse{
		Success: true, Version: version, PlanHash: published.Plan.Hash, CurrentPlanHash: current.Hash,
		PlanMatchesConfiguration: current.Hash == published.Plan.Hash, InSync: true,
		Systems: []fortinetSystemInfo{}, Records: []driftRecord{}, Errors: []string{},
	}
	if !response.PlanMatchesConfiguration {
		response.InSync = false
		response.Errors = append(response.Errors, "current target configuration produces a different deployment plan; no unapproved endpoint was queried")
		s.audit(actor, "deployment.drift", "blocked", map[string]any{"version": version, "plan_hash": response.PlanHash, "current_plan_hash": response.CurrentPlanHash, "errors": response.Errors})
		writeDeploymentJSON(w, http.StatusOK, response)
		return
	}
	targets, err := s.runtimeTargets(published.Plan, r.FormValue("target"), false)
	if err != nil {
		response.Success, response.InSync = false, false
		response.Errors = append(response.Errors, err.Error())
		s.audit(actor, "deployment.drift", "blocked", map[string]any{"version": version, "plan_hash": response.PlanHash, "error": err.Error()})
		writeDeploymentJSON(w, http.StatusConflict, response)
		return
	}
	for _, target := range targets {
		if target.Config.Type == "fortimanager" {
			response.InSync = false
			response.Errors = append(response.Errors, fmt.Sprintf("target %q is FortiManager; device drift cannot be checked without an explicit managed-device installation target", target.Config.Name))
			continue
		}
		if err := preflightFortiGateTargets(r.Context(), []*runtimeTarget{target}); err != nil {
			response.InSync = false
			response.Errors = append(response.Errors, err.Error())
			continue
		}
		response.Systems = append(response.Systems, target.System)
		commands, commandErr := finalDeploymentCommands(target.Commands)
		if commandErr != nil {
			response.InSync = false
			response.Errors = append(response.Errors, fmt.Sprintf("target %q: %v", target.Config.Name, commandErr))
			continue
		}
		for _, command := range commands {
			record := inspectDrift(r.Context(), target, command)
			response.Records = append(response.Records, record)
			if record.Status != "in_sync" {
				response.InSync = false
			}
		}
	}
	result := "success"
	if !response.InSync {
		result = "drift"
	}
	s.audit(actor, "deployment.drift", result, map[string]any{"version": version, "plan_hash": response.PlanHash, "current_plan_hash": response.CurrentPlanHash, "in_sync": response.InSync, "systems": response.Systems, "errors": response.Errors})
	writeDeploymentJSON(w, http.StatusOK, response)
}

func inspectDrift(ctx context.Context, target *runtimeTarget, command deploymentCommand) driftRecord {
	name := command.Payload["name"].(string)
	record := driftRecord{
		Target: target.Config.Name, Context: command.Context, Sequence: command.Sequence,
		Kind: command.Kind, Method: strings.ToUpper(command.Method), Name: name, Differences: []string{},
	}
	object, err := lookupFortiGateObject(ctx, target.Client, target.Config, command)
	if err != nil {
		record.Status, record.Error = "error", err.Error()
		return record
	}
	if strings.EqualFold(command.Method, http.MethodDelete) {
		if object == nil {
			record.Status = "in_sync"
		} else {
			record.Status = "unexpected"
			record.Differences = append(record.Differences, "policy should be absent")
		}
		return record
	}
	if object == nil {
		record.Status = "missing"
		record.Differences = append(record.Differences, "object is missing")
		return record
	}
	record.Differences = fortiGateCommandDifferences(command, command.Payload, object.Data)
	if len(record.Differences) == 0 && command.Kind == "policy" && command.InsertBefore != "" {
		anchorCommand := command
		anchorCommand.Payload = map[string]any{"name": command.InsertBefore}
		anchor, anchorErr := lookupFortiGateObject(ctx, target.Client, target.Config, anchorCommand)
		if anchorErr != nil {
			record.Status, record.Error = "error", anchorErr.Error()
			return record
		}
		if anchor == nil {
			record.Differences = append(record.Differences, "policy insertion anchor is missing")
		} else if before, _, orderErr := policyNeighbours(ctx, target.Client, target.Config, command.Path, object.MKey); orderErr != nil {
			record.Status, record.Error = "error", orderErr.Error()
			return record
		} else if before != anchor.MKey {
			record.Differences = append(record.Differences, "policy is not immediately before its approved successor")
		}
	}
	if len(record.Differences) == 0 {
		record.Status = "in_sync"
	} else {
		record.Status = "changed"
	}
	return record
}
