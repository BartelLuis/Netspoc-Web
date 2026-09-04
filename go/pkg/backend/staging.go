package backend

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type stageRequest struct {
	Policy          json.RawMessage `json:"policy"`
	DraftVersion    *int64          `json:"draft_version"`
	Comment         string          `json:"comment"`
	ChangeReference string          `json:"change_reference"`
}

// deploymentPlanBase returns a previously published policy only when its
// immutable, integrity-checked deployment plan is available. Bootstrap and
// legacy publications have no such device baseline; their next reviewed plan
// must therefore be a safe full nil->Next plan with no assumed DELETEs.
func (s *state) deploymentPlanBase(previous *editablePolicy, version string) (*editablePolicy, *deploymentPlan, error) {
	if previous == nil || strings.TrimSpace(version) == "" {
		return nil, nil, nil
	}
	record, err := s.loadRevisionRecord(version, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("load deployment baseline revision %q: %w", version, err)
	}
	if record.Status != "published" || !samePolicyDocument(record.Policy, previous) {
		return nil, nil, fmt.Errorf("deployment baseline publication %q is not bound to its approved revision", version)
	}
	if record.DeploymentPlan == nil {
		return nil, nil, nil
	}
	plan, err := decodeStoredDeploymentPlan(record.DeploymentPlan)
	if err != nil {
		return nil, nil, fmt.Errorf("verify deployment baseline plan %q: %w", version, err)
	}
	return previous, &plan, nil
}

func decodeStagePolicy(raw json.RawMessage) (*editablePolicy, error) {
	if len(raw) == 0 {
		return nil, errors.New("policy is required")
	}
	var p policyDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("invalid policy: multiple JSON documents")
	}
	return p.editable(), nil
}

// adminStage freezes the exact policy and deployment plan that a second person
// will review. The approval hash covers both documents, so neither commands nor
// policy data can be changed between staging and approval.
func (s *state) adminStage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	current := s.readDraft()
	role := policyRole(s.authorizationPolicy(), actor)
	if role != policyDeveloperRole && role != "admin" && role != "editor" {
		s.audit(actor, "revision.stage", "denied", nil)
		writeError(w, "Policy editor role required", http.StatusForbidden)
		return
	}

	var request stageRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&request)
	if err == nil {
		if trailingErr := decoder.Decode(&struct{}{}); trailingErr != io.EOF {
			err = errors.New("invalid staging request: multiple JSON documents")
		}
	}
	if err == nil && request.DraftVersion == nil {
		err = errors.New("draft_version is required")
	}
	var p *editablePolicy
	if err == nil {
		p, err = decodeStagePolicy(request.Policy)
	}
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
	if err == nil && strings.TrimSpace(request.Comment) == "" {
		err = errors.New("a staging comment is required")
	}
	if err == nil && strings.TrimSpace(request.ChangeReference) == "" {
		err = errors.New("a change reference is required")
	}

	var draft draftMetadata
	if err == nil {
		draft, err = s.saveDraftAs(p, actor, request.DraftVersion)
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
			plan = generateDeploymentPlanWithBase(planBase, p, s.config.FortinetTargets)
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
		}
	}
	if err == nil {
		validation = map[string]any{
			"valid":            len(plan.Errors) == 0,
			"errors":           plan.Errors,
			"warnings":         plan.Warnings,
			"deployment_ready": plan.Ready,
			"plan_hash":        plan.Hash,
		}
	}
	var result revisionCreateResult
	if err == nil {
		result, err = s.createPendingRevisionAgainstBase(p, previous, base, actor, request.Comment, request.ChangeReference, plan, validation)
	}
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errDraftConflict) || errors.Is(err, errAccountConflict) {
			status = http.StatusConflict
		}
		s.audit(actor, "revision.stage", "failed", map[string]any{"error": err.Error()})
		writeError(w, err.Error(), status)
		return
	}

	s.audit(actor, "revision.stage", "success", map[string]any{"policy_id": result.PolicyID, "plan_hash": plan.Hash, "commands": len(plan.Commands), "deployment_ready": plan.Ready})
	writeJSON(w, map[string]any{
		"success": true, "policy_id": result.PolicyID, "approval": result.Approval,
		"policy":  p,
		"changes": result.Changes, "findings": result.Findings, "risks": result.Findings,
		"validation": validation, "deployment_plan": plan, "commands": plan.Commands,
		"created_by": actor, "draft_version": draft.Version, "draft_updated_at": draft.UpdatedAt, "draft_updated_by": draft.UpdatedBy,
	})
}
