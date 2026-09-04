package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// deploymentCommand is the immutable, reviewable unit produced during
// staging. Command is deliberately human-readable while Method, Path and
// Payload are the machine-readable operation used by a deployment driver.
type deploymentCommand struct {
	Target           string         `json:"target"`
	Context          string         `json:"context"`
	Sequence         int            `json:"sequence"`
	Kind             string         `json:"kind"`
	Method           string         `json:"method"`
	Path             string         `json:"path"`
	InsertBefore     string         `json:"insert_before,omitempty"`
	Command          string         `json:"command"`
	Payload          map[string]any `json:"payload"`
	CreatePayload    map[string]any `json:"create_payload,omitempty"`
	ActivatePayload  map[string]any `json:"activate_payload,omitempty"`
	SemanticsVersion string         `json:"semantics_version,omitempty"`
}

type deploymentTargetSummary struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	Context         string `json:"context"`
	Scope           string `json:"scope"`
	Endpoint        string `json:"endpoint,omitempty"`
	EndpointID      string `json:"endpoint_id"`
	Executable      bool   `json:"executable"`
	RequiredVersion string `json:"required_version,omitempty"`
}

type deploymentPlan struct {
	Hash                   string                    `json:"hash"`
	ExecutionModel         string                    `json:"execution_model"`
	PolicySemanticsVersion string                    `json:"policy_semantics_version"`
	Ready                  bool                      `json:"ready"`
	Errors                 []string                  `json:"errors"`
	Warnings               []string                  `json:"warnings"`
	Targets                []deploymentTargetSummary `json:"targets"`
	Commands               []deploymentCommand       `json:"commands"`
}

type deploymentObject struct {
	name    string
	kind    string
	payload map[string]any
	cli     []string
}

const supportedFortiOSRelease = "7.4.x"
const fortiOSExecutionModelVersion = "fortios-7.4-prepare-disabled-deny-first-v1"
const fortiOSPolicySemanticsVersion = "fortios-7.4-policy-semantics-v1"
const fortiOSObjectSemanticsVersion = "fortios-7.4-object-semantics-v1"

func generateDeploymentPlan(p *editablePolicy, configured []FortinetTarget) deploymentPlan {
	return generateDeploymentPlanWithBase(nil, p, configured)
}

func generateDeploymentPlanWithBase(previous, p *editablePolicy, configured []FortinetTarget) deploymentPlan {
	plan := deploymentPlan{
		ExecutionModel: fortiOSExecutionModelVersion, PolicySemanticsVersion: fortiOSPolicySemanticsVersion,
		Errors: []string{}, Warnings: []string{}, Targets: []deploymentTargetSummary{}, Commands: []deploymentCommand{},
	}
	appendConfiguredDeploymentTargets(&plan, configured)
	if len(p.TargetContexts) == 0 && (previous == nil || len(previous.TargetContexts) == 0) {
		plan.Warnings = append(plan.Warnings, "Keine Zielkontexte konfiguriert; die Policy kann veröffentlicht, aber nicht direkt ausgerollt werden.")
		plan.finish()
		return plan
	}

	contextMap := make(map[string]targetContext, len(p.TargetContexts))
	for _, context := range p.TargetContexts {
		contextMap[context.Name] = context
	}
	zones := policyObjectZones(p)
	objects := policyDeploymentObjects(p)

	type stagedRule struct {
		service string
		rule    editableRule
	}
	byContext := map[string][]stagedRule{}
	for _, service := range p.Services {
		for _, rule := range service.Rules {
			byContext[rule.TargetContext] = append(byContext[rule.TargetContext], stagedRule{service: service.Name, rule: rule})
		}
	}
	contexts := make([]string, 0, len(byContext))
	for context := range byContext {
		contexts = append(contexts, context)
	}
	sort.Strings(contexts)

	sequence := 0
	// FortiOS address and custom-service objects live in the VDOM, not in a
	// PolicyWeb target context. A target may serve multiple logical contexts;
	// emit each physical object mutation only once.
	seenObjects := map[string]bool{}
	seenServices := map[string]string{}
	for _, contextName := range contexts {
		if _, ok := contextMap[contextName]; !ok {
			plan.Errors = append(plan.Errors, fmt.Sprintf("Regeln referenzieren den unbekannten Zielkontext %q.", contextName))
			continue
		}
		targets := targetsForContext(configured, contextName)
		if len(targets) == 0 {
			plan.Errors = append(plan.Errors, fmt.Sprintf("Für den Zielkontext %q ist kein Fortinet-Ziel konfiguriert.", contextName))
			continue
		}
		rules := byContext[contextName]
		// Preserve the reviewed service/rule order. Policy names are editable;
		// sorting by them would make a harmless rename silently change firewall
		// evaluation order.
		for _, target := range targets {
			scope := target.VDOM
			if target.Type == "fortimanager" {
				scope = target.ADOM + "/" + target.PolicyPackage
			}
			appendDeploymentTargetSummary(&plan, target, contextName, scope)
			for _, item := range rules {
				rule := item.rule
				if anchor := strings.TrimSpace(target.PolicyInsertBefore); anchor != "" && strings.EqualFold(rule.PolicyName, anchor) {
					plan.Errors = append(plan.Errors, fmt.Sprintf("%s/%s auf Ziel %q: Der Regelname kollidiert mit dem konfigurierten Policy-Anker.", item.service, rule.PolicyName, target.Name))
					continue
				}
				addressFamily, familyErr := deploymentAddressFamily(rule, objects)
				if familyErr != nil {
					plan.Errors = append(plan.Errors, fmt.Sprintf("%s/%s: %v", item.service, rule.PolicyName, familyErr))
					continue
				}
				srcZone, srcErr := determineRuleZone(rule.Sources, zones)
				dstZone, dstErr := determineRuleZone(rule.Destinations, zones)
				if srcErr != nil || dstErr != nil {
					plan.Errors = append(plan.Errors, fmt.Sprintf("%s/%s: Zonen konnten nicht bestimmt werden.", item.service, rule.PolicyName))
					continue
				}
				srcInterface := strings.TrimSpace(target.ZoneInterfaces[srcZone])
				dstInterface := strings.TrimSpace(target.ZoneInterfaces[dstZone])
				if srcInterface == "" || dstInterface == "" {
					plan.Errors = append(plan.Errors, fmt.Sprintf("Ziel %q benötigt Interface-Zuordnungen für %s und %s.", target.Name, srcZone, dstZone))
					continue
				}
				if limitErrors := fortiOS74RuleLimitErrors(rule, srcInterface, dstInterface); len(limitErrors) != 0 {
					for _, limitErr := range limitErrors {
						plan.Errors = append(plan.Errors, fmt.Sprintf("%s/%s auf Ziel %q: %s", item.service, rule.PolicyName, target.Name, limitErr))
					}
					continue
				}

				refs := append(append([]string{}, rule.Sources...), rule.Destinations...)
				for _, ref := range refs {
					object, ok := objects[ref]
					if !ok {
						plan.Errors = append(plan.Errors, fmt.Sprintf("Deployment-Objekt %q wurde nicht gefunden.", ref))
						continue
					}
					key := deploymentObjectScopeKey(target) + "\x00" + object.name
					if seenObjects[key] {
						continue
					}
					sequence++
					plan.Commands = append(plan.Commands, deploymentObjectCommand(target, contextName, sequence, object))
					seenObjects[key] = true
				}

				serviceName, servicePayload, serviceCLI, err := deploymentService(rule.Protocols, addressFamily)
				if err != nil {
					plan.Errors = append(plan.Errors, fmt.Sprintf("%s/%s: %v", item.service, rule.PolicyName, err))
					continue
				}
				serviceKey := deploymentObjectScopeKey(target) + "\x00" + serviceName
				serviceJSON, _ := json.Marshal(servicePayload)
				if previousPayload, exists := seenServices[serviceKey]; exists && previousPayload != string(serviceJSON) {
					plan.Errors = append(plan.Errors, fmt.Sprintf("Service-ID %q kollidiert auf Ziel %q mit einem anderen Payload.", serviceName, target.Name))
					continue
				}
				if _, exists := seenServices[serviceKey]; !exists {
					sequence++
					plan.Commands = append(plan.Commands, deploymentServiceCommand(target, contextName, sequence, serviceName, servicePayload, serviceCLI))
					seenServices[serviceKey] = string(serviceJSON)
				}

				renderedRule := rule
				renderedRule.Sources = deploymentObjectNames(rule.Sources, objects)
				renderedRule.Destinations = deploymentObjectNames(rule.Destinations, objects)
				sequence++
				plan.Commands = append(plan.Commands, deploymentPolicyCommand(target, contextName, sequence, addressFamily, renderedRule, serviceName, srcInterface, dstInterface))
			}
		}
	}
	appendRemovedPolicyCommands(&plan, previous, p, configured, &sequence)
	finalizePolicyUpsertOrder(&plan, configured)
	appendUnsafeDenyTransitionErrors(&plan, previous, configured)
	plan.finish()
	return plan
}

// A DENY match cannot be replaced safely by an in-place PUT on every 7.4.x
// target: swapping D1(A) and D2(B), for example, necessarily leaves A or B
// temporarily uncovered. Reject that immutable-plan transition during staging
// so the reviewed preview is executable; snapshot repeats the check against
// the bound live baseline as defense in depth.
func appendUnsafeDenyTransitionErrors(plan *deploymentPlan, previous *editablePolicy, configured []FortinetTarget) {
	if previous == nil {
		return
	}
	previousPlan := generateDeploymentPlan(previous, configured)
	approved := map[string]map[string]any{}
	for _, command := range previousPlan.Commands {
		if command.Kind != "policy" || !strings.EqualFold(command.Method, "UPSERT") {
			continue
		}
		key := command.Target + "\x00" + command.Context + "\x00" + command.Path + "\x00" + scalarString(command.Payload["name"])
		approved[key] = command.Payload
	}
	for _, command := range plan.Commands {
		if command.Kind != "policy" || !strings.EqualFold(command.Method, "UPSERT") {
			continue
		}
		key := command.Target + "\x00" + command.Context + "\x00" + command.Path + "\x00" + scalarString(command.Payload["name"])
		before, existed := approved[key]
		if existed && unsafeInPlaceDenyMatchChange(command, before) {
			plan.Errors = append(plan.Errors, fmt.Sprintf("DENY-Policy %q auf Ziel %q ändert ihr Match in-place. Bitte die Regel kopieren und mit einer neuen Policy-ID bereitstellen, damit der neue DENY deaktiviert positioniert und vor dem alten aktiviert werden kann.", command.Payload["name"], command.Target))
		}
	}
}

// Keep deployment topology in every plan independently of its delta commands.
// This makes adding/removing/enabling a device or changing its VDOM an explicit
// reviewed migration, including after the last managed policy was deleted.
func appendConfiguredDeploymentTargets(plan *deploymentPlan, configured []FortinetTarget) {
	targets := append([]FortinetTarget(nil), configured...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })
	for _, target := range targets {
		contexts := append([]string(nil), target.TargetContexts...)
		sort.Strings(contexts)
		for _, context := range contexts {
			scope := target.VDOM
			if target.Type == "fortimanager" {
				scope = target.ADOM + "/" + target.PolicyPackage
			}
			appendDeploymentTargetSummary(plan, target, context, scope)
		}
	}
}

func fortiOS74RuleLimitErrors(rule editableRule, srcInterface, dstInterface string) []string {
	errorsFound := []string{}
	for _, reference := range append(append([]string{}, rule.Sources...), rule.Destinations...) {
		if utf8.RuneCountInString(reference) > 79 {
			errorsFound = append(errorsFound, fmt.Sprintf("Adressobjektname %q überschreitet das FortiOS-7.4-Limit von 79 Zeichen", reference))
		}
	}
	for _, iface := range []string{srcInterface, dstInterface} {
		if utf8.RuneCountInString(iface) > 79 {
			errorsFound = append(errorsFound, fmt.Sprintf("Interface-Referenz %q überschreitet das FortiOS-7.4-Limit von 79 Zeichen", iface))
		}
	}
	if utf8.RuneCountInString(rule.PolicyComment) > 1023 {
		errorsFound = append(errorsFound, "Policy-Kommentar überschreitet das FortiOS-7.4-Limit von 1023 Zeichen")
	}
	return errorsFound
}

// finalizePolicyUpsertOrder turns the approved, deterministic policy order
// into an executable insertion chain. FortiOS creates a policy first and then
// moves it before another policy. Executing the desired block from bottom to
// top guarantees that the next policy already exists, even when every policy
// in the block is new.
func finalizePolicyUpsertOrder(plan *deploymentPlan, configured []FortinetTarget) {
	targets := make(map[string]FortinetTarget, len(configured))
	for _, target := range configured {
		targets[target.Name] = target
	}
	nonPolicies := make([]deploymentCommand, 0, len(plan.Commands))
	deletes := make([]deploymentCommand, 0)
	byTarget := map[string][]deploymentCommand{}
	for _, command := range plan.Commands {
		if command.Kind == "policy" && command.Method == "UPSERT" {
			byTarget[command.Target] = append(byTarget[command.Target], command)
			continue
		}
		if command.Kind == "policy" && strings.EqualFold(command.Method, http.MethodDelete) {
			deletes = append(deletes, command)
			continue
		}
		nonPolicies = append(nonPolicies, command)
	}

	targetNames := make([]string, 0, len(byTarget))
	for targetName := range byTarget {
		targetNames = append(targetNames, targetName)
	}
	sort.Strings(targetNames)
	ordered := nonPolicies
	for _, targetName := range targetNames {
		commands := byTarget[targetName]
		for i := range commands {
			insertBefore := strings.TrimSpace(targets[targetName].PolicyInsertBefore)
			if i+1 < len(commands) {
				insertBefore = scalarString(commands[i+1].Payload["name"])
			}
			commands[i].InsertBefore = insertBefore
			commands[i].Command = appendPolicyInsertionPreview(commands[i].Command, commands[i].Path, scalarString(commands[i].Payload["name"]), insertBefore)
		}
		for i := len(commands) - 1; i >= 0; i-- {
			ordered = append(ordered, commands[i])
		}
	}
	sort.SliceStable(deletes, func(i, j int) bool {
		leftDeny := scalarString(deletes[i].Payload["action"]) == "deny"
		rightDeny := scalarString(deletes[j].Payload["action"]) == "deny"
		if leftDeny != rightDeny {
			return !leftDeny
		}
		return scalarString(deletes[i].Payload["name"]) < scalarString(deletes[j].Payload["name"])
	})
	ordered = append(ordered, deletes...)
	for i := range ordered {
		ordered[i].Sequence = i + 1
	}
	plan.Commands = ordered
}

func appendPolicyInsertionPreview(command, path, policyName, insertBefore string) string {
	if insertBefore == "" {
		return command
	}
	return strings.Join([]string{
		command,
		"# Nur bei Neuanlage: Policy-IDs anhand der eindeutigen Namen auflösen:",
		"GET " + path + "?filter=name==" + urlQueryPreview(policyName),
		"GET " + path + "?filter=name==" + urlQueryPreview(insertBefore),
		"# Neu angelegte Policy vor den geprüften Nachfolger verschieben:",
		"PUT " + path + "/<policyid>?action=move&before=<anchor-policyid>",
	}, "\n")
}

func deploymentObjectScopeKey(target FortinetTarget) string {
	scope := target.VDOM
	if target.Type == "fortimanager" {
		scope = target.ADOM
	}
	return target.Name + "\x00" + target.Type + "\x00" + scope
}

type removedDeploymentPolicy struct {
	context       string
	name          string
	addressFamily string
	rule          editableRule
}

// appendRemovedPolicyCommands deliberately deletes only policy entries whose
// exact generated names existed in the approved base publication. Address and
// service objects may be shared with device-local rules and are therefore
// never removed automatically.
func appendRemovedPolicyCommands(plan *deploymentPlan, previous, next *editablePolicy, configured []FortinetTarget, sequence *int) {
	if previous == nil {
		return
	}
	// The unified FortiOS 7.4 policy endpoint can switch families atomically
	// because every desired payload explicitly clears the opposite family.
	// A still-present generated name is therefore updated in place; DELETE is
	// reserved for policies which are genuinely absent from the next revision.
	nextFamilies := map[string]string{}
	nextObjects := policyDeploymentObjects(next)
	for _, service := range next.Services {
		for _, rule := range service.Rules {
			if rule.PolicyName != "" {
				family, err := deploymentAddressFamily(rule, nextObjects)
				if err == nil {
					nextFamilies[rule.TargetContext+"\x00"+rule.PolicyName] = family
				}
			}
		}
	}
	removed := []removedDeploymentPolicy{}
	seen := map[string]bool{}
	previousObjects := policyDeploymentObjects(previous)
	previousZones := policyObjectZones(previous)
	for _, service := range previous.Services {
		for _, rule := range service.Rules {
			key := rule.TargetContext + "\x00" + rule.PolicyName
			if rule.PolicyName == "" || seen[key] {
				continue
			}
			addressFamily, err := deploymentAddressFamily(rule, previousObjects)
			if err != nil {
				plan.Errors = append(plan.Errors, fmt.Sprintf("Die entfernte Policy %q kann nicht sicher zugeordnet werden: %v", rule.PolicyName, err))
				continue
			}
			if _, stillPresent := nextFamilies[key]; stillPresent {
				continue
			}
			seen[key] = true
			removed = append(removed, removedDeploymentPolicy{context: rule.TargetContext, name: rule.PolicyName, addressFamily: addressFamily, rule: rule})
		}
	}
	sort.Slice(removed, func(i, j int) bool {
		return removed[i].context+"\x00"+removed[i].name < removed[j].context+"\x00"+removed[j].name
	})
	for _, item := range removed {
		targets := targetsForContext(configured, item.context)
		if len(targets) == 0 {
			plan.Errors = append(plan.Errors, fmt.Sprintf("Die entfernte Policy %q aus Zielkontext %q kann keinem Fortinet-Ziel zugeordnet werden.", item.name, item.context))
			continue
		}
		for _, target := range targets {
			scope := target.VDOM
			if target.Type == "fortimanager" {
				scope = target.ADOM + "/" + target.PolicyPackage
			}
			appendDeploymentTargetSummary(plan, target, item.context, scope)
			srcZone, srcErr := determineRuleZone(item.rule.Sources, previousZones)
			dstZone, dstErr := determineRuleZone(item.rule.Destinations, previousZones)
			srcInterface := strings.TrimSpace(target.ZoneInterfaces[srcZone])
			dstInterface := strings.TrimSpace(target.ZoneInterfaces[dstZone])
			serviceName, _, _, serviceErr := deploymentService(item.rule.Protocols, item.addressFamily)
			if srcErr != nil || dstErr != nil || srcInterface == "" || dstInterface == "" || serviceErr != nil {
				plan.Errors = append(plan.Errors, fmt.Sprintf("Die entfernte Policy %q kann für Ziel %q nicht sicher rekonstruiert werden.", item.name, target.Name))
				continue
			}
			expected := deploymentPolicyPayload(item.addressFamily, item.rule, serviceName, srcInterface, dstInterface)
			(*sequence)++
			plan.Commands = append(plan.Commands, deploymentPolicyDeleteCommand(target, item.context, *sequence, item.name, expected))
		}
	}
}

// bindPolicyDeletePayloadsToPreviousPlan replaces reconstructed DELETE
// preconditions with the exact immutable payload approved for the deployed
// base. In particular, an interface mapping may legitimately change in the
// next plan; deleting the old policy must still compare against its old
// srcintf/dstintf rather than today's mapping.
func bindPolicyDeletePayloadsToPreviousPlan(plan *deploymentPlan, previous *deploymentPlan) error {
	if previous == nil {
		for _, command := range plan.Commands {
			if command.Kind == "policy" && strings.EqualFold(command.Method, http.MethodDelete) {
				return errors.New("policy DELETE has no immutable deployment baseline")
			}
		}
		return nil
	}
	approved := map[string]map[string]any{}
	for _, command := range previous.Commands {
		if command.Kind != "policy" || !strings.EqualFold(command.Method, "UPSERT") {
			continue
		}
		identity, err := deploymentCommandIdentity(command)
		if err != nil {
			return fmt.Errorf("invalid previous policy command: %w", err)
		}
		key := command.Target + "\x00" + identity
		if existing, found := approved[key]; found && !sameJSONValue(existing, command.Payload) {
			return fmt.Errorf("previous deployment plan contains conflicting policy payloads for target %q", command.Target)
		}
		approved[key] = command.Payload
	}
	changed := false
	for i := range plan.Commands {
		command := &plan.Commands[i]
		if command.Kind != "policy" || !strings.EqualFold(command.Method, http.MethodDelete) {
			continue
		}
		identity, err := deploymentCommandIdentity(*command)
		if err != nil {
			return fmt.Errorf("invalid policy DELETE: %w", err)
		}
		expected, found := approved[command.Target+"\x00"+identity]
		if !found {
			return fmt.Errorf("policy DELETE %q on target %q is absent from the immutable deployment baseline", command.Payload["name"], command.Target)
		}
		command.Payload = cloneDeploymentPayload(expected)
		changed = true
	}
	if changed {
		plan.finish()
	}
	return nil
}

func appendDeploymentTargetSummary(plan *deploymentPlan, target FortinetTarget, context, scope string) {
	for _, existing := range plan.Targets {
		if existing.Name == target.Name && existing.Context == context {
			return
		}
	}
	requiredVersion := ""
	if target.Type == "fortigate" {
		requiredVersion = supportedFortiOSRelease
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("Ziel %q wird vor dem Deployment auf FortiOS %s geprüft.", target.Name, supportedFortiOSRelease))
	}
	if !target.AllowDeploy {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("Ziel %q ist auf Vorschau beschränkt (allow_deploy=false).", target.Name))
	}
	executable := target.AllowDeploy && target.Type == "fortigate"
	endpointID, err := deploymentTargetEndpointID(target)
	if err != nil {
		plan.Errors = append(plan.Errors, fmt.Sprintf("Ziel %q kann nicht an seine TLS-Konfiguration gebunden werden: %v", target.Name, err))
	}
	endpoint, endpointErr := normalizedFortinetEndpoint(target.URL)
	if endpointErr != nil {
		plan.Errors = append(plan.Errors, fmt.Sprintf("Ziel %q hat keine reviewbare normalisierte Endpoint-URL: %v", target.Name, endpointErr))
	}
	plan.Targets = append(plan.Targets, deploymentTargetSummary{
		Name: target.Name, Type: target.Type, Context: context, Scope: scope,
		Endpoint: endpoint, EndpointID: endpointID, Executable: executable, RequiredVersion: requiredVersion,
	})
}

func deploymentTargetEndpointID(target FortinetTarget) (string, error) {
	canonical, err := normalizedFortinetEndpoint(target.URL)
	if err != nil {
		return "", err
	}
	trust := "system-roots"
	if strings.TrimSpace(target.CAFile) != "" {
		contents, readErr := os.ReadFile(target.CAFile)
		if readErr != nil {
			return "", fmt.Errorf("read ca_file: %w", readErr)
		}
		sum := sha256.Sum256(contents)
		trust = "ca-sha256:" + hex.EncodeToString(sum[:])
	}
	principal := "token-env:" + strings.TrimSpace(target.TokenEnv)
	scope := "vdom:" + strings.TrimSpace(target.VDOM)
	if target.Type == "fortimanager" {
		principal = "basic-env:" + strings.TrimSpace(target.UsernameEnv) + ":" + strings.TrimSpace(target.PasswordEnv)
		scope = "adom-package:" + strings.TrimSpace(target.ADOM) + "/" + strings.TrimSpace(target.PolicyPackage)
	}
	identity := strings.Join([]string{"v1", target.Type, canonical, scope, principal, trust, "insecure-skip-verify:" + strconv.FormatBool(target.InsecureSkipVerify)}, "\n")
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:]), nil
}

func deploymentEndpointID(rawURL string) string {
	canonical, err := normalizedFortinetEndpoint(rawURL)
	if err != nil {
		canonical = strings.TrimRight(strings.TrimSpace(rawURL), "/")
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func normalizedFortinetEndpoint(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("endpoint must be an absolute https URL without credentials, query or fragment")
	}
	u.Scheme = "https"
	hostname := strings.ToLower(u.Hostname())
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	if port := u.Port(); port != "" && port != "443" {
		hostname += ":" + port
	}
	u.Host = hostname
	u.RawPath = ""
	u.Path = pathpkg.Clean(u.Path)
	if u.Path == "." || u.Path == "/" {
		u.Path = ""
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func (p *deploymentPlan) finish() {
	seen := map[string]string{}
	for _, command := range p.Commands {
		name := scalarString(command.Payload["name"])
		if name == "" {
			continue
		}
		key := command.Target + "\x00" + command.Path + "\x00" + strings.ToLower(name)
		operation := strings.ToUpper(command.Method)
		if previous, exists := seen[key]; exists && !(command.Kind == "policy" && previous == "DELETE" && operation == "UPSERT") {
			p.Errors = append(p.Errors, fmt.Sprintf("Deployment-Objekt %q ist für Ziel %q widersprüchlich (%s und %s).", name, command.Target, previous, operation))
			continue
		}
		seen[key] = operation
	}
	p.Ready = len(p.Errors) == 0 && len(p.Commands) != 0
	var data []byte
	if p.ExecutionModel == "" && p.PolicySemanticsVersion == "" {
		// Integrity verification for plans stored before the versioned FortiOS
		// execution model was introduced must retain their original hash input.
		legacy := struct {
			Targets  []deploymentTargetSummary `json:"targets"`
			Commands []deploymentCommand       `json:"commands"`
		}{Targets: p.Targets, Commands: p.Commands}
		data, _ = json.Marshal(legacy)
	} else {
		versioned := struct {
			ExecutionModel         string                    `json:"execution_model"`
			PolicySemanticsVersion string                    `json:"policy_semantics_version"`
			Targets                []deploymentTargetSummary `json:"targets"`
			Commands               []deploymentCommand       `json:"commands"`
		}{ExecutionModel: p.ExecutionModel, PolicySemanticsVersion: p.PolicySemanticsVersion, Targets: p.Targets, Commands: p.Commands}
		data, _ = json.Marshal(versioned)
	}
	sum := sha256.Sum256(data)
	p.Hash = hex.EncodeToString(sum[:])
}

func targetsForContext(configured []FortinetTarget, context string) []FortinetTarget {
	result := []FortinetTarget{}
	for _, target := range configured {
		for _, candidate := range target.TargetContexts {
			if candidate == context {
				result = append(result, target)
				break
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func policyObjectZones(p *editablePolicy) map[string]string {
	result := map[string]string{}
	for _, network := range p.Networks {
		result["network:"+network.Name] = network.Zone
		for _, host := range network.Hosts {
			zone := host.Zone
			if zone == "" {
				zone = network.Zone
			}
			result["host:"+host.Name] = zone
		}
	}
	for _, fqdn := range p.FQDNs {
		result["fqdn:"+fqdn.Name] = fqdn.Zone
	}
	return result
}

func policyDeploymentObjects(p *editablePolicy) map[string]deploymentObject {
	result := map[string]deploymentObject{}
	for _, network := range p.Networks {
		name := "network:" + network.Name
		if object, err := subnetDeploymentObject(name, network.CIDR); err == nil {
			result[name] = object
		}
		for _, host := range network.Hosts {
			name = "host:" + host.Name
			if object, err := hostDeploymentObject(name, host.IP); err == nil {
				result[name] = object
			}
		}
	}
	for _, fqdn := range p.FQDNs {
		reference := "fqdn:" + fqdn.Name
		payload := map[string]any{"type": "fqdn", "fqdn": fqdn.FQDN}
		name := contentAddressedDeploymentObjectName("address", payload)
		payload["name"] = name
		result[reference] = deploymentObject{name: name, kind: "address", payload: payload, cli: []string{"set type fqdn", "set fqdn " + fortinetQuote(fqdn.FQDN)}}
	}
	return result
}

func deploymentObjectNames(references []string, objects map[string]deploymentObject) []string {
	result := make([]string, 0, len(references))
	for _, reference := range references {
		if object, exists := objects[reference]; exists {
			result = append(result, object.name)
		}
	}
	return result
}

func contentAddressedDeploymentObjectName(kind string, payload map[string]any) string {
	encoded, _ := json.Marshal(struct {
		Version string         `json:"version"`
		Kind    string         `json:"kind"`
		Payload map[string]any `json:"payload"`
	}{Version: fortiOSObjectSemanticsVersion, Kind: kind, Payload: payload})
	sum := sha256.Sum256(encoded)
	prefix := "PW_A4_"
	if kind == "address6" {
		prefix = "PW_A6_"
	}
	return prefix + strings.ToUpper(hex.EncodeToString(sum[:12]))
}

func deploymentAddressFamily(rule editableRule, objects map[string]deploymentObject) (string, error) {
	family := ""
	for _, ref := range append(append([]string{}, rule.Sources...), rule.Destinations...) {
		object, ok := objects[ref]
		if !ok {
			return "", fmt.Errorf("Deployment-Objekt %q wurde nicht gefunden", ref)
		}
		candidate := "ipv4"
		if object.kind == "address6" {
			candidate = "ipv6"
		}
		if family != "" && family != candidate {
			return "", errors.New("IPv4- und IPv6-Objekte dürfen nicht in derselben FortiOS-Regel gemischt werden")
		}
		family = candidate
	}
	if family == "" {
		return "", errors.New("Adressfamilie der Regel kann nicht bestimmt werden")
	}
	return family, nil
}

func subnetDeploymentObject(name, cidr string) (deploymentObject, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return deploymentObject{}, err
	}
	ones, bits := network.Mask.Size()
	if bits == 32 {
		mask := net.IP(network.Mask).String()
		value := network.IP.String() + " " + mask
		payload := map[string]any{"type": "ipmask", "subnet": value}
		name = contentAddressedDeploymentObjectName("address", payload)
		payload["name"] = name
		return deploymentObject{name: name, kind: "address", payload: payload, cli: []string{"set type ipmask", "set subnet " + value}}, nil
	}
	value := ip.Mask(network.Mask).String() + "/" + strconv.Itoa(ones)
	payload := map[string]any{"type": "ipprefix", "ip6": value}
	name = contentAddressedDeploymentObjectName("address6", payload)
	payload["name"] = name
	return deploymentObject{name: name, kind: "address6", payload: payload, cli: []string{"set type ipprefix", "set ip6 " + value}}, nil
}

func hostDeploymentObject(name, value string) (deploymentObject, error) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return deploymentObject{}, fmt.Errorf("invalid IP %q", value)
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		subnet := ipv4.String() + " 255.255.255.255"
		payload := map[string]any{"type": "ipmask", "subnet": subnet}
		name = contentAddressedDeploymentObjectName("address", payload)
		payload["name"] = name
		return deploymentObject{name: name, kind: "address", payload: payload, cli: []string{"set type ipmask", "set subnet " + subnet}}, nil
	}
	ip6 := ip.String() + "/128"
	payload := map[string]any{"type": "ipprefix", "ip6": ip6}
	name = contentAddressedDeploymentObjectName("address6", payload)
	payload["name"] = name
	return deploymentObject{name: name, kind: "address6", payload: payload, cli: []string{"set type ipprefix", "set ip6 " + ip6}}, nil
}

func deploymentObjectCommand(target FortinetTarget, context string, sequence int, object deploymentObject) deploymentCommand {
	lines := []string{"config firewall " + object.kind, "edit " + fortinetQuote(object.name)}
	lines = append(lines, object.cli...)
	lines = append(lines, "next", "end")
	return deploymentCommand{Target: target.Name, Context: context, Sequence: sequence, Kind: object.kind, Method: "UPSERT", Path: deploymentPath(target, object.kind), Command: strings.Join(lines, "\n"), Payload: object.payload, SemanticsVersion: fortiOSObjectSemanticsVersion}
}

func deploymentService(protocols []string, addressFamily string) (string, map[string]any, []string, error) {
	canonical := addressFamily + ":" + canonicalProtocolKey(protocols)
	payload := map[string]any{}
	cli := []string{}
	tcpPorts, udpPorts := []string{}, []string{}
	mode := "tcpudp"
	for _, protocol := range protocols {
		fields := strings.Fields(strings.ToLower(protocol))
		if len(fields) == 2 && (fields[0] == "tcp" || fields[0] == "udp") {
			converted, err := fortinetPortRange(fields[1])
			if err != nil {
				return "", nil, nil, err
			}
			if mode != "tcpudp" {
				return "", nil, nil, fmt.Errorf("ICMP/IP und TCP/UDP können nicht in demselben FortiGate-Service kombiniert werden")
			}
			if fields[0] == "tcp" {
				tcpPorts = append(tcpPorts, converted)
			} else {
				udpPorts = append(udpPorts, converted)
			}
			continue
		}
		if len(protocols) != 1 {
			return "", nil, nil, fmt.Errorf("nicht unterstützte Protokollkombination %q", canonical)
		}
		switch {
		case len(fields) >= 1 && fields[0] == "icmp":
			mode = "icmp"
			icmpProtocol := "ICMP"
			if addressFamily == "ipv6" {
				icmpProtocol = "ICMP6"
			}
			payload["protocol"] = icmpProtocol
			cli = append(cli, "set protocol "+icmpProtocol)
			if len(fields) == 2 {
				parts := strings.Split(fields[1], "/")
				if len(parts) > 2 || !decimalByte(parts[0]) || len(parts) == 2 && !decimalByte(parts[1]) {
					return "", nil, nil, fmt.Errorf("ungültiger ICMP-Typ/Code %q", fields[1])
				}
				payload["icmptype"] = parts[0]
				cli = append(cli, "set icmptype "+parts[0])
				if len(parts) == 2 {
					payload["icmpcode"] = parts[1]
					cli = append(cli, "set icmpcode "+parts[1])
				}
			}
		case len(fields) == 2 && fields[0] == "proto" && decimalProtocol(fields[1]):
			mode = "ip"
			payload["protocol"] = "IP"
			payload["protocol-number"] = fields[1]
			cli = append(cli, "set protocol IP", "set protocol-number "+fields[1])
		default:
			return "", nil, nil, fmt.Errorf("Protokoll %q kann noch nicht sicher gerendert werden", protocol)
		}
	}
	if mode == "tcpudp" {
		payload["protocol"] = "TCP/UDP/SCTP"
		cli = append([]string{"set protocol TCP/UDP/SCTP"}, cli...)
		portRanges := []struct {
			field  string
			values []string
		}{
			{field: "tcp-portrange", values: tcpPorts},
			{field: "udp-portrange", values: udpPorts},
			{field: "sctp-portrange", values: nil},
		}
		for _, portRange := range portRanges {
			value := strings.Join(portRange.values, " ")
			payload[portRange.field] = value
			if value == "" {
				cli = append(cli, "unset "+portRange.field)
			} else {
				cli = append(cli, "set "+portRange.field+" "+value)
			}
		}
	}
	// The immutable name is derived from the final wire semantics, not merely
	// the input protocol spelling. A renderer/default change therefore creates
	// a new object and cannot silently alter every live policy referencing an
	// older same-named service.
	semanticBytes, _ := json.Marshal(struct {
		Version string         `json:"version"`
		Family  string         `json:"family"`
		Payload map[string]any `json:"payload"`
	}{Version: fortiOSObjectSemanticsVersion, Family: addressFamily, Payload: payload})
	sum := sha256.Sum256(semanticBytes)
	name := "PW_SVC_" + strings.ToUpper(hex.EncodeToString(sum[:12]))
	payload["name"] = name
	return name, payload, cli, nil
}

func deploymentServiceCommand(target FortinetTarget, context string, sequence int, name string, payload map[string]any, serviceCLI []string) deploymentCommand {
	lines := []string{"config firewall service custom", "edit " + fortinetQuote(name)}
	lines = append(lines, serviceCLI...)
	lines = append(lines, "next", "end")
	return deploymentCommand{Target: target.Name, Context: context, Sequence: sequence, Kind: "service", Method: "UPSERT", Path: deploymentPath(target, "service"), Command: strings.Join(lines, "\n"), Payload: payload, SemanticsVersion: fortiOSObjectSemanticsVersion}
}

func deploymentPolicyCommand(target FortinetTarget, context string, sequence int, addressFamily string, rule editableRule, serviceName, srcInterface, dstInterface string) deploymentCommand {
	payload := deploymentPolicyPayload(addressFamily, rule, serviceName, srcInterface, dstInterface)
	action := "accept"
	if rule.Action == "deny" {
		action = "deny"
	}
	sourceField, destinationField := "srcaddr", "dstaddr"
	oppositeSourceField, oppositeDestinationField := "srcaddr6", "dstaddr6"
	if addressFamily == "ipv6" {
		sourceField, destinationField = "srcaddr6", "dstaddr6"
		oppositeSourceField, oppositeDestinationField = "srcaddr", "dstaddr"
	}
	createPayload := make(map[string]any, len(payload)+1)
	for key, value := range payload {
		createPayload[key] = value
	}
	// A new policy is always created disabled. It is positioned while inert and
	// activated only in the separately reviewed deny-first runtime phase.
	createPayload["status"] = "disable"
	createPayload["policyid"] = 0
	activatePayload := map[string]any{"status": "enable"}
	settings := []string{
		"set name " + fortinetQuote(rule.PolicyName),
		"set status enable",
		"set srcintf " + fortinetQuotedList([]string{srcInterface}), "set dstintf " + fortinetQuotedList([]string{dstInterface}),
		"unset " + oppositeSourceField, "unset " + oppositeDestinationField,
		"set " + sourceField + " " + fortinetQuotedList(rule.Sources), "set " + destinationField + " " + fortinetQuotedList(rule.Destinations),
		"set srcaddr-negate disable", "set dstaddr-negate disable", "set srcaddr6-negate disable", "set dstaddr6-negate disable",
		"unset users", "unset groups", "unset fsso-groups",
		"unset src-vendor-mac", "set reputation-minimum 0", "set reputation-direction destination",
		"set reputation-minimum6 0", "set reputation-direction6 destination", "unset vlan-filter",
		"set tos 0x00", "set tos-mask 0x00", "set tos-negate disable",
		"set sgt-check disable", "unset sgt",
		"set ztna-status disable", "unset ztna-ems-tag", "unset ztna-ems-tag-secondary", "unset ztna-geo-tag",
		"set ztna-policy-redirect disable", "set ztna-device-ownership disable", "set ztna-tags-match-logic or",
		"set action " + action, "set match-vip disable", "set match-vip-only disable", "set schedule always", "set service " + fortinetQuotedList([]string{serviceName}),
		"set service-negate disable", "set internet-service disable", "set internet-service-src disable",
		"set internet-service6 disable", "set internet-service6-src disable",
		"set internet-service-negate disable", "set internet-service-src-negate disable",
		"set internet-service6-negate disable", "set internet-service6-src-negate disable",
		"unset internet-service-name", "unset internet-service-custom", "unset internet-service-src-name", "unset internet-service-src-custom",
		"unset internet-service6-name", "unset internet-service6-custom", "unset internet-service6-src-name", "unset internet-service6-src-custom",
		"set http-policy-redirect disable", "set ssh-policy-redirect disable",
		"set utm-status disable", "set wccp disable", "set webcache disable", "set webcache-https disable", "set wanopt disable",
		"unset identity-based-route", "set rtp-nat disable", "set ippool disable", "unset poolname", "unset poolname6",
		"set radius-mac-auth-bypass disable", "set auth-path disable", "set captive-portal-exempt disable",
		"set permit-any-host disable", "set permit-stun-host disable", "set tcp-session-without-syn disable", "set anti-replay enable",
		"set geoip-anycast disable", "set geoip-match physical-location",
		"set nat disable", "set nat46 disable", "set nat64 disable", "set policy-expiry disable",
		"set logtraffic all", "set comments " + fortinetQuote(rule.PolicyComment),
	}
	createSettings := append([]string(nil), settings...)
	for index, line := range createSettings {
		if line == "set status enable" {
			createSettings[index] = "set status disable"
			break
		}
	}
	createCLI := append([]string{"config firewall policy", "edit 0"}, createSettings...)
	createCLI = append(createCLI, "next", "end")
	updateCLI := append([]string{"config firewall policy", "edit <resolved-policyid>"}, settings...)
	updateCLI = append(updateCLI, "next", "end")
	lines := []string{
		"# Conditional CLI preview after resolving the policy name:",
		"# PREPARE branch (name is absent): create DISABLED and position it while inert:",
		strings.Join(createCLI, "\n"),
		"# FINALIZE branch (name already exists): apply the final payload atomically in DENY-before-ACCEPT order:",
		strings.Join(updateCLI, "\n"),
		"# ACTIVATE branch (only after a successful disabled create and positioning):",
		"config firewall policy\nedit <resolved-policyid>\nset status enable\nnext\nend",
	}
	return deploymentCommand{
		Target: target.Name, Context: context, Sequence: sequence, Kind: "policy", Method: "UPSERT", Path: deploymentPath(target, "policy"),
		Command: strings.Join(lines, "\n"), Payload: payload, CreatePayload: createPayload, ActivatePayload: activatePayload,
		SemanticsVersion: fortiOSPolicySemanticsVersion,
	}
}

func deploymentPolicyPayload(addressFamily string, rule editableRule, serviceName, srcInterface, dstInterface string) map[string]any {
	action := "accept"
	if rule.Action == "deny" {
		action = "deny"
	}
	payload := map[string]any{
		"name": rule.PolicyName, "srcintf": fortinetMembers([]string{srcInterface}), "dstintf": fortinetMembers([]string{dstInterface}),
		"status": "enable", "action": action, "match-vip": "disable", "match-vip-only": "disable", "service": fortinetMembers([]string{serviceName}), "schedule": "always", "logtraffic": "all", "comments": rule.PolicyComment,
		"srcaddr-negate": "disable", "dstaddr-negate": "disable", "srcaddr6-negate": "disable", "dstaddr6-negate": "disable",
		"users": fortinetMembers(nil), "groups": fortinetMembers(nil), "fsso-groups": fortinetMembers(nil),
		"src-vendor-mac": fortinetMembers(nil), "reputation-minimum": 0, "reputation-direction": "destination",
		"reputation-minimum6": 0, "reputation-direction6": "destination", "vlan-filter": "",
		"tos": "0x00", "tos-mask": "0x00", "tos-negate": "disable",
		"sgt-check": "disable", "sgt": fortinetMembers(nil),
		"ztna-status": "disable", "ztna-ems-tag": fortinetMembers(nil), "ztna-ems-tag-secondary": fortinetMembers(nil), "ztna-geo-tag": fortinetMembers(nil),
		"ztna-policy-redirect": "disable", "ztna-device-ownership": "disable", "ztna-tags-match-logic": "or",
		"service-negate": "disable", "internet-service": "disable", "internet-service-src": "disable",
		"internet-service6": "disable", "internet-service6-src": "disable",
		"internet-service-negate": "disable", "internet-service-src-negate": "disable",
		"internet-service6-negate": "disable", "internet-service6-src-negate": "disable",
		"internet-service-name": fortinetMembers(nil), "internet-service-custom": fortinetMembers(nil),
		"internet-service-src-name": fortinetMembers(nil), "internet-service-src-custom": fortinetMembers(nil),
		"internet-service6-name": fortinetMembers(nil), "internet-service6-custom": fortinetMembers(nil),
		"internet-service6-src-name": fortinetMembers(nil), "internet-service6-src-custom": fortinetMembers(nil),
		"http-policy-redirect": "disable", "ssh-policy-redirect": "disable",
		"utm-status": "disable", "wccp": "disable", "webcache": "disable", "webcache-https": "disable", "wanopt": "disable",
		"identity-based-route": "", "rtp-nat": "disable", "ippool": "disable", "poolname": fortinetMembers(nil), "poolname6": fortinetMembers(nil),
		"radius-mac-auth-bypass": "disable", "auth-path": "disable", "captive-portal-exempt": "disable",
		"permit-any-host": "disable", "permit-stun-host": "disable", "tcp-session-without-syn": "disable", "anti-replay": "enable",
		"geoip-anycast": "disable", "geoip-match": "physical-location",
		"nat": "disable", "nat46": "disable", "nat64": "disable", "policy-expiry": "disable",
	}
	if addressFamily == "ipv6" {
		payload["srcaddr"] = fortinetMembers(nil)
		payload["dstaddr"] = fortinetMembers(nil)
		payload["srcaddr6"] = fortinetMembers(rule.Sources)
		payload["dstaddr6"] = fortinetMembers(rule.Destinations)
	} else {
		payload["srcaddr"] = fortinetMembers(rule.Sources)
		payload["dstaddr"] = fortinetMembers(rule.Destinations)
		payload["srcaddr6"] = fortinetMembers(nil)
		payload["dstaddr6"] = fortinetMembers(nil)
	}
	return payload
}

func deploymentPolicyDeleteCommand(target FortinetTarget, context string, sequence int, policyName string, expected map[string]any) deploymentCommand {
	path := deploymentPath(target, "policy")
	command := strings.Join([]string{
		"# Policy-MKey anhand des eindeutigen Namens auflösen:",
		"GET " + path + "?filter=name==" + urlQueryPreview(policyName),
		"# Anschließend den ermittelten policyid-MKey löschen:",
		"DELETE " + path + "/<policyid>",
	}, "\n")
	return deploymentCommand{
		Target: target.Name, Context: context, Sequence: sequence, Kind: "policy",
		Method: "DELETE", Path: path, Command: command, Payload: expected, SemanticsVersion: fortiOSPolicySemanticsVersion,
	}
}

func urlQueryPreview(value string) string {
	value = strings.ReplaceAll(value, "%", "%25")
	value = strings.ReplaceAll(value, " ", "%20")
	value = strings.ReplaceAll(value, "#", "%23")
	value = strings.ReplaceAll(value, "&", "%26")
	return value
}

func deploymentPath(target FortinetTarget, kind string) string {
	if target.Type == "fortimanager" {
		base := "/pm/config/adom/" + target.ADOM
		switch kind {
		case "address", "address6":
			return base + "/obj/firewall/" + kind
		case "service":
			return base + "/obj/firewall/service/custom"
		default:
			return base + "/pkg/" + target.PolicyPackage + "/firewall/policy"
		}
	}
	switch kind {
	case "address", "address6":
		return "/api/v2/cmdb/firewall/" + kind
	case "service":
		return "/api/v2/cmdb/firewall.service/custom"
	default:
		return "/api/v2/cmdb/firewall/policy"
	}
}

func fortinetPortRange(value string) (string, error) {
	parts := strings.Split(value, ":")
	if len(parts) > 2 {
		return "", fmt.Errorf("ungültiger Portbereich %q", value)
	}
	for _, part := range parts {
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return "", fmt.Errorf("ungültiger Portbereich %q", value)
		}
		for _, bound := range bounds {
			port, err := strconv.Atoi(bound)
			if err != nil || port < 1 || port > 65535 {
				return "", fmt.Errorf("ungültiger Port %q", bound)
			}
		}
	}
	if len(parts) == 2 {
		// Netspoc uses source:destination, FortiOS destination:source.
		return parts[1] + ":" + parts[0], nil
	}
	return value, nil
}

func decimalByte(value string) bool {
	n, err := strconv.Atoi(value)
	return err == nil && n >= 0 && n <= 255
}

func decimalProtocol(value string) bool {
	n, err := strconv.Atoi(value)
	return err == nil && n >= 0 && n <= 254
}

func fortinetMembers(values []string) []map[string]string {
	result := make([]map[string]string, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]string{"name": value})
	}
	return result
}

func fortinetQuotedList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, fortinetQuote(value))
	}
	return strings.Join(quoted, " ")
}

func fortinetQuote(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return "\"" + value + "\""
}
