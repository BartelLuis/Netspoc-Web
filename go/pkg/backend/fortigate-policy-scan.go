package backend

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	fortiGatePolicyScanPageSize = 100
	fortiGatePolicyScanTimeout  = 45 * time.Second
	fortiGatePolicyScanLease    = 2 * time.Minute
	unknownFortiGateService     = "unbekannt"
)

var (
	errFortiGatePolicyScanRunning         = errors.New("a FortiGate policy scan is already running")
	errFortiGatePolicyObservationConflict = errors.New("FortiGate policy inventory changed since it was loaded")
	errFortiGatePolicyObservationAbsent   = errors.New("FortiGate policy is no longer present")
)

type fortiGatePolicyScanTarget struct {
	ID                  string
	EndpointID          string
	Config              FortinetTarget
	Managed             bool
	ManagedRevision     int64
	ManagedCredentialID string
}

type fortiGatePolicySnapshot struct {
	ID             string
	RemoteIdentity string
	IdentityWeak   bool
	PolicyID       string
	PolicyName     string
	Fingerprint    string
	Document       string
}

type fortiGatePolicyObservationView struct {
	ID                    string   `json:"id"`
	Revision              int64    `json:"revision"`
	TargetID              string   `json:"target_id"`
	TargetName            string   `json:"target_name"`
	VDOM                  string   `json:"vdom"`
	PolicyID              string   `json:"policy_id"`
	PolicyName            string   `json:"policy_name"`
	Action                string   `json:"action"`
	Status                string   `json:"status"`
	SourceInterfaces      []string `json:"source_interfaces"`
	DestinationInterfaces []string `json:"destination_interfaces"`
	Sources               []string `json:"sources"`
	Destinations          []string `json:"destinations"`
	Services              []string `json:"services"`
	Schedule              string   `json:"schedule"`
	Comments              string   `json:"comments"`
	AssignedService       string   `json:"assigned_service"`
	AssignmentSource      string   `json:"assignment_source"`
	IdentityWeak          bool     `json:"identity_weak"`
	FirstSeenAt           string   `json:"first_seen_at"`
	LastSeenAt            string   `json:"last_seen_at"`
}

type fortiGatePolicyScanStateView struct {
	TargetID      string `json:"target_id"`
	TargetName    string `json:"target_name"`
	VDOM          string `json:"vdom"`
	LastStartedAt string `json:"last_started_at"`
	LastSuccessAt string `json:"last_success_at"`
	LastError     string `json:"last_error,omitempty"`
	ObservedCount int    `json:"observed_count"`
	UnknownCount  int    `json:"unknown_count"`
	NewCount      int    `json:"new_count"`
}

type fortiGatePolicyScanSummary struct {
	Targets     int      `json:"targets"`
	Succeeded   int      `json:"succeeded"`
	Failed      int      `json:"failed"`
	Observed    int      `json:"observed"`
	NewPolicies int      `json:"new_policies"`
	NewUnknown  int      `json:"new_unknown"`
	Errors      []string `json:"errors"`
	CompletedAt string   `json:"completed_at"`
}

type fortiGatePolicyAssignmentRequest struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Service  string `json:"service"`
}

type publishedPolicyServiceIndex struct {
	services map[string]string
	byName   map[string][]publishedPolicyRuleIdentity
}

type publishedPolicyRuleIdentity struct {
	Service string
	Context string
}

func newPublishedPolicyServiceIndex(p *editablePolicy) publishedPolicyServiceIndex {
	index := publishedPolicyServiceIndex{services: map[string]string{}, byName: map[string][]publishedPolicyRuleIdentity{}}
	if p == nil {
		return index
	}
	for _, service := range p.Services {
		canonicalService := strings.ToLower(strings.TrimSpace(service.Name))
		if canonicalService == "" {
			continue
		}
		index.services[canonicalService] = service.Name
		for _, rule := range service.Rules {
			name := strings.ToLower(strings.TrimSpace(rule.PolicyName))
			if name == "" {
				continue
			}
			index.byName[name] = append(index.byName[name], publishedPolicyRuleIdentity{Service: service.Name, Context: rule.TargetContext})
		}
	}
	return index
}

func (index publishedPolicyServiceIndex) match(target FortinetTarget, policyName string) string {
	candidates := index.byName[strings.ToLower(strings.TrimSpace(policyName))]
	if len(candidates) == 0 {
		return ""
	}
	contexts := map[string]bool{}
	for _, name := range target.TargetContexts {
		contexts[strings.TrimSpace(name)] = true
	}
	services := map[string]string{}
	for _, candidate := range candidates {
		if len(contexts) != 0 && !contexts[candidate.Context] {
			continue
		}
		services[strings.ToLower(candidate.Service)] = candidate.Service
	}
	if len(services) != 1 {
		return ""
	}
	for _, service := range services {
		return service
	}
	return ""
}

func fortiGatePolicyTargetIdentity(target FortinetTarget) (string, string) {
	endpointID := deploymentEndpointID(target.URL)
	sum := sha256.Sum256([]byte(endpointID + "\x00" + strings.ToLower(strings.TrimSpace(target.VDOM))))
	return "fortigate-" + hex.EncodeToString(sum[:]), endpointID
}

func (s *state) fortiGatePolicyScanTargets() ([]fortiGatePolicyScanTarget, []fortiGatePolicyScanTarget, error) {
	targets := []fortiGatePolicyScanTarget{}
	failures := []fortiGatePolicyScanTarget{}
	seen := map[string]bool{}
	for _, target := range s.config.FortinetTargets {
		if target.Type != "fortigate" {
			continue
		}
		id, endpointID := fortiGatePolicyTargetIdentity(target)
		item := fortiGatePolicyScanTarget{ID: id, EndpointID: endpointID, Config: target}
		if strings.TrimSpace(target.VDOM) == "" {
			failures = append(failures, item)
			continue
		}
		if !seen[id] {
			targets = append(targets, item)
			seen[id] = true
		}
	}
	managed, err := s.readManagedFortiGates(true)
	if err != nil {
		return nil, nil, err
	}
	for _, record := range managed {
		base := managedFortiGateRuntime(record, "")
		id, endpointID := fortiGatePolicyTargetIdentity(base)
		item := fortiGatePolicyScanTarget{
			ID: id, EndpointID: endpointID, Config: base, Managed: true,
			ManagedRevision: record.Revision, ManagedCredentialID: record.CredentialID,
		}
		if seen[id] {
			continue
		}
		token, readErr := s.readManagedFortiGateCredential(record.CredentialID)
		if readErr != nil {
			failures = append(failures, item)
			seen[id] = true
			continue
		}
		item.Config = managedFortiGateRuntime(record, token)
		targets = append(targets, item)
		seen[id] = true
	}
	sort.Slice(targets, func(i, j int) bool {
		return strings.ToLower(targets[i].Config.Name)+"\x00"+targets[i].Config.VDOM < strings.ToLower(targets[j].Config.Name)+"\x00"+targets[j].Config.VDOM
	})
	return targets, failures, nil
}

func (s *state) latestPublishedPolicyForScan() (*editablePolicy, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var document string
	err = db.QueryRow(`SELECT document FROM policy_publication ORDER BY published_at DESC LIMIT 1`).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p editablePolicy
	if err := json.Unmarshal([]byte(document), &p); err != nil {
		return nil, fmt.Errorf("decode published policy for FortiGate matching: %w", err)
	}
	normalizeEditablePolicy(&p)
	return &p, nil
}

func (s *state) runFortiGatePolicyScan(ctx context.Context) (fortiGatePolicyScanSummary, error) {
	summary := fortiGatePolicyScanSummary{Errors: []string{}}
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	holder, err := randomFortiGateID(16)
	if err != nil {
		return summary, err
	}
	acquired, err := s.acquireFortiGatePolicyScanLease(holder)
	if err != nil {
		return summary, err
	}
	if !acquired {
		return summary, errFortiGatePolicyScanRunning
	}
	defer s.releaseFortiGatePolicyScanLease(holder)

	policy, err := s.latestPublishedPolicyForScan()
	if err != nil {
		return summary, err
	}
	serviceIndex := newPublishedPolicyServiceIndex(policy)
	targets, targetFailures, err := s.fortiGatePolicyScanTargets()
	if err != nil {
		return summary, err
	}
	activeTargetIDs := make(map[string]bool, len(targets)+len(targetFailures))
	for _, target := range targets {
		activeTargetIDs[target.ID] = true
	}
	for _, target := range targetFailures {
		activeTargetIDs[target.ID] = true
	}
	if err := s.reconcileFortiGatePolicyScanTargets(activeTargetIDs); err != nil {
		return summary, err
	}
	summary.Targets = len(targets) + len(targetFailures)
	for _, target := range targetFailures {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		if err := s.renewFortiGatePolicyScanLease(holder); err != nil {
			return summary, err
		}
		message := "VDOM oder API-Zugang ist für den Policy-Scan nicht verfügbar"
		if err := s.recordFortiGatePolicyScanFailure(target, message); err != nil {
			return summary, err
		}
		summary.Failed++
		summary.Errors = append(summary.Errors, fmt.Sprintf("%s (%s): %s", target.Config.Name, target.Config.VDOM, message))
	}
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		if err := s.renewFortiGatePolicyScanLease(holder); err != nil {
			return summary, err
		}
		targetContext, cancel := context.WithTimeout(ctx, fortiGatePolicyScanTimeout)
		observed, newPolicies, newUnknown, scanErr := s.scanFortiGatePolicyTarget(targetContext, target, serviceIndex)
		cancel()
		if scanErr != nil {
			if err := ctx.Err(); err != nil {
				return summary, err
			}
			message := redactedFortinetError(target.Config, scanErr)
			if len(message) > 1000 {
				message = message[:1000]
			}
			if err := s.recordFortiGatePolicyScanFailure(target, message); err != nil {
				return summary, err
			}
			summary.Failed++
			summary.Errors = append(summary.Errors, fmt.Sprintf("%s (%s): %s", target.Config.Name, target.Config.VDOM, message))
			continue
		}
		summary.Succeeded++
		summary.Observed += observed
		summary.NewPolicies += newPolicies
		summary.NewUnknown += newUnknown
		if newPolicies != 0 {
			s.audit("system", "fortigate.policy.scan", "new", map[string]any{
				"target_id": target.ID, "target": target.Config.Name, "vdom": target.Config.VDOM,
				"new_policies": newPolicies, "new_unknown": newUnknown,
			})
		}
	}
	summary.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return summary, nil
}

// reconcileFortiGatePolicyScanTargets retires inventory that belongs to a
// removed or disabled target. Rows stay in the database so a target restored
// with the same endpoint and VDOM also regains its manual assignments.
func (s *state) reconcileFortiGatePolicyScanTargets(active map[string]bool) error {
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
	rows, err := tx.Query(`SELECT target_id FROM fortigate_policy_observation UNION SELECT target_id FROM fortigate_policy_scan_state`)
	if err != nil {
		return err
	}
	known := []string{}
	for rows.Next() {
		var targetID string
		if err := rows.Scan(&targetID); err != nil {
			rows.Close()
			return err
		}
		known = append(known, targetID)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, targetID := range known {
		if active[targetID] {
			continue
		}
		if _, err := tx.Exec(`UPDATE fortigate_policy_observation SET present=0, revision=revision+1 WHERE target_id=? AND present=1`, targetID); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM fortigate_policy_scan_state WHERE target_id=?`, targetID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *state) acquireFortiGatePolicyScanLease(holder string) (bool, error) {
	db, err := s.policyDB()
	if err != nil {
		return false, err
	}
	defer db.Close()
	now := time.Now().Unix()
	result, err := db.Exec(`INSERT INTO fortigate_policy_scan_lock(id, holder, expires_at) VALUES(1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET holder=excluded.holder, expires_at=excluded.expires_at
		WHERE fortigate_policy_scan_lock.expires_at < ?`, holder, now+int64(fortiGatePolicyScanLease/time.Second), now)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func (s *state) renewFortiGatePolicyScanLease(holder string) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	result, err := db.Exec(`UPDATE fortigate_policy_scan_lock SET expires_at=? WHERE id=1 AND holder=?`, time.Now().Add(fortiGatePolicyScanLease).Unix(), holder)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("FortiGate policy scan lease was lost")
	}
	return nil
}

func (s *state) releaseFortiGatePolicyScanLease(holder string) {
	db, err := s.policyDB()
	if err != nil {
		return
	}
	defer db.Close()
	_, _ = db.Exec(`DELETE FROM fortigate_policy_scan_lock WHERE id=1 AND holder=?`, holder)
}

func (s *state) scanFortiGatePolicyTarget(ctx context.Context, target fortiGatePolicyScanTarget, services publishedPolicyServiceIndex) (int, int, int, error) {
	client, err := target.Config.httpClient()
	if err != nil {
		return 0, 0, 0, err
	}
	defer client.CloseIdleConnections()
	objects, err := listFortiGateObjectsCompleteSnapshot(ctx, client, target.Config, "/api/v2/cmdb/firewall/policy", nil, fortiGatePolicyScanPageSize)
	if err != nil {
		return 0, 0, 0, err
	}
	snapshots := make([]fortiGatePolicySnapshot, 0, len(objects))
	seenRemote := map[string]bool{}
	for _, object := range objects {
		snapshot, snapshotErr := makeFortiGatePolicySnapshot(target, object)
		if snapshotErr != nil {
			return 0, 0, 0, snapshotErr
		}
		if seenRemote[snapshot.RemoteIdentity] {
			return 0, 0, 0, fmt.Errorf("FortiGate returned duplicate policy identity %q", snapshot.RemoteIdentity)
		}
		seenRemote[snapshot.RemoteIdentity] = true
		snapshots = append(snapshots, snapshot)
	}
	return s.commitFortiGatePolicySnapshots(target, snapshots, services)
}

func makeFortiGatePolicySnapshot(target fortiGatePolicyScanTarget, object fortiGateObject) (fortiGatePolicySnapshot, error) {
	document, err := json.Marshal(object.Data)
	if err != nil {
		return fortiGatePolicySnapshot{}, err
	}
	if len(document) > 512<<10 {
		return fortiGatePolicySnapshot{}, errors.New("FortiGate policy exceeds the 512 KiB inventory limit")
	}
	policyID := strings.TrimSpace(object.MKey)
	policyName := strings.TrimSpace(scalarString(object.Data["name"]))
	remoteIdentity, err := normalizedFortiGatePolicyUUID(object.Data["uuid"])
	if err != nil {
		return fortiGatePolicySnapshot{}, err
	}
	weak := remoteIdentity == ""
	if weak {
		remoteIdentity = "policyid:" + policyID + "\x00name:" + strings.ToLower(policyName)
	}
	fingerprint := sha256.Sum256(document)
	idHash := sha256.Sum256([]byte(target.ID + "\x00" + remoteIdentity))
	return fortiGatePolicySnapshot{
		ID: "policy-" + hex.EncodeToString(idHash[:]), RemoteIdentity: remoteIdentity, IdentityWeak: weak,
		PolicyID: policyID, PolicyName: policyName, Fingerprint: hex.EncodeToString(fingerprint[:]), Document: string(document),
	}, nil
}

func normalizedFortiGatePolicyUUID(value any) (string, error) {
	uuid := strings.TrimSpace(scalarString(value))
	if uuid == "" {
		return "", nil
	}
	if len(uuid) != 36 || uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' {
		return "", fmt.Errorf("FortiGate policy has an invalid top-level UUID %q", uuid)
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil || len(decoded) != 16 {
		return "", fmt.Errorf("FortiGate policy has an invalid top-level UUID %q", uuid)
	}
	return strings.ToLower(uuid), nil
}

func (s *state) commitFortiGatePolicySnapshots(target fortiGatePolicyScanTarget, snapshots []fortiGatePolicySnapshot, services publishedPolicyServiceIndex) (int, int, int, error) {
	db, err := s.policyDB()
	if err != nil {
		return 0, 0, 0, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return 0, 0, 0, err
	}
	defer tx.Rollback()
	if target.Managed {
		var revision int64
		var credentialID, url, vdom string
		var enabled bool
		err = tx.QueryRow(`SELECT revision, credential_id, url, vdom, enabled FROM managed_fortigate WHERE id=?`, target.Config.managedID).Scan(&revision, &credentialID, &url, &vdom, &enabled)
		if err != nil || !enabled || revision != target.ManagedRevision || credentialID != target.ManagedCredentialID || url != target.Config.URL || vdom != target.Config.VDOM {
			if err == nil {
				err = errors.New("managed FortiGate changed while its policies were scanned")
			}
			return 0, 0, 0, err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	scanID, err := randomFortiGateID(16)
	if err != nil {
		return 0, 0, 0, err
	}
	newPolicies, newUnknown := 0, 0
	for _, snapshot := range snapshots {
		automaticService := services.match(target.Config, snapshot.PolicyName)
		desiredService, desiredSource := automaticService, "automatic"
		if desiredService == "" {
			desiredSource = "unknown"
		}
		var existingFingerprint, existingService, existingSource string
		var existingPresent bool
		var existingRevision int64
		err = tx.QueryRow(`SELECT fingerprint, assigned_service, assignment_source, present, revision FROM fortigate_policy_observation WHERE id=?`, snapshot.ID).
			Scan(&existingFingerprint, &existingService, &existingSource, &existingPresent, &existingRevision)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			newPolicies++
			if desiredService == "" {
				newUnknown++
			}
			_, err = tx.Exec(`INSERT INTO fortigate_policy_observation(
				id, target_id, target_name, endpoint_id, vdom, remote_identity, identity_weak,
				policy_id, policy_name, fingerprint, document, assigned_service, assignment_source,
				present, first_seen_at, last_seen_at, last_scan_id, revision
			) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?, ?,?,?,1)`,
				snapshot.ID, target.ID, target.Config.Name, target.EndpointID, target.Config.VDOM, snapshot.RemoteIdentity, snapshot.IdentityWeak,
				snapshot.PolicyID, snapshot.PolicyName, snapshot.Fingerprint, snapshot.Document, desiredService, desiredSource,
				true, now, now, scanID)
		case err != nil:
			return 0, 0, 0, err
		default:
			if existingSource == "manual" {
				if existingService == "" {
					desiredService, desiredSource = "", "manual"
				} else if canonical := services.services[strings.ToLower(existingService)]; canonical != "" {
					desiredService, desiredSource = canonical, "manual"
				}
			}
			nextRevision := existingRevision
			if existingFingerprint != snapshot.Fingerprint || existingService != desiredService || existingSource != desiredSource || !existingPresent {
				nextRevision++
			}
			_, err = tx.Exec(`UPDATE fortigate_policy_observation SET
				target_name=?, endpoint_id=?, vdom=?, remote_identity=?, identity_weak=?, policy_id=?, policy_name=?,
				fingerprint=?, document=?, assigned_service=?, assignment_source=?, present=1,
				last_seen_at=?, last_scan_id=?, revision=? WHERE id=?`,
				target.Config.Name, target.EndpointID, target.Config.VDOM, snapshot.RemoteIdentity, snapshot.IdentityWeak, snapshot.PolicyID, snapshot.PolicyName,
				snapshot.Fingerprint, snapshot.Document, desiredService, desiredSource, now, scanID, nextRevision, snapshot.ID)
		}
		if err != nil {
			return 0, 0, 0, err
		}
	}
	if _, err = tx.Exec(`UPDATE fortigate_policy_observation SET present=0, revision=revision+1
		WHERE target_id=? AND present=1 AND last_scan_id<>?`, target.ID, scanID); err != nil {
		return 0, 0, 0, err
	}
	var unknownCount int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM fortigate_policy_observation WHERE target_id=? AND present=1 AND assigned_service=''`, target.ID).Scan(&unknownCount); err != nil {
		return 0, 0, 0, err
	}
	if _, err = tx.Exec(`INSERT INTO fortigate_policy_scan_state(
		target_id, target_name, endpoint_id, vdom, last_started_at, last_success_at, last_error, observed_count, unknown_count, new_count
	) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET
		target_name=excluded.target_name, endpoint_id=excluded.endpoint_id, vdom=excluded.vdom,
		last_started_at=excluded.last_started_at, last_success_at=excluded.last_success_at, last_error='',
		observed_count=excluded.observed_count, unknown_count=excluded.unknown_count, new_count=excluded.new_count`,
		target.ID, target.Config.Name, target.EndpointID, target.Config.VDOM, now, now, "", len(snapshots), unknownCount, newPolicies); err != nil {
		return 0, 0, 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, 0, err
	}
	return len(snapshots), newPolicies, newUnknown, nil
}

func (s *state) recordFortiGatePolicyScanFailure(target fortiGatePolicyScanTarget, message string) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.Exec(`INSERT INTO fortigate_policy_scan_state(
		target_id, target_name, endpoint_id, vdom, last_started_at, last_error
	) VALUES(?,?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET
		target_name=excluded.target_name, endpoint_id=excluded.endpoint_id, vdom=excluded.vdom,
		last_started_at=excluded.last_started_at, last_error=excluded.last_error`,
		target.ID, target.Config.Name, target.EndpointID, target.Config.VDOM, now, message)
	return err
}

func (s *state) startFortiGatePolicyScanner(ctx context.Context) {
	if s == nil || s.config == nil || s.config.FortiGatePolicyScanInterval <= 0 {
		return
	}
	interval := s.config.FortiGatePolicyScanInterval
	go func() {
		run := func() {
			summary, err := s.runFortiGatePolicyScan(ctx)
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, errFortiGatePolicyScanRunning) {
				log.Printf("FortiGate policy scan failed: %v", err)
				return
			}
			if summary.Failed != 0 {
				log.Printf("FortiGate policy scan completed with %d/%d failed targets", summary.Failed, summary.Targets)
			}
		}
		run()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
}

func (s *state) adminFortiGatePolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin") {
		writeError(w, "Policy administrator role required", http.StatusForbidden)
		return
	}
	records, scans, services, err := s.listFortiGatePolicyInventory()
	if err != nil {
		writeError(w, "Read FortiGate policy inventory: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"success": true, "records": records, "scans": scans, "services": services,
		"unknown_service": unknownFortiGateService,
		"scanner_enabled": s.config.FortiGatePolicyScanInterval > 0,
		"scan_interval":   s.config.FortiGatePolicyScanInterval.String(),
	})
}

func (s *state) adminScanFortiGatePolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin") {
		s.audit(actor, "fortigate.policy.scan", "denied", nil)
		writeError(w, "Policy administrator role required", http.StatusForbidden)
		return
	}
	summary, err := s.runFortiGatePolicyScan(r.Context())
	if err != nil {
		status := http.StatusInternalServerError
		result := "failed"
		if errors.Is(err, errFortiGatePolicyScanRunning) {
			status = http.StatusConflict
			result = "conflict"
		}
		s.audit(actor, "fortigate.policy.scan", result, nil)
		writeError(w, err.Error(), status)
		return
	}
	result := "success"
	if summary.Failed != 0 {
		result = "partial"
	}
	s.audit(actor, "fortigate.policy.scan", result, map[string]any{
		"targets": summary.Targets, "succeeded": summary.Succeeded, "failed": summary.Failed,
		"observed": summary.Observed, "new_policies": summary.NewPolicies, "new_unknown": summary.NewUnknown,
	})
	writeJSON(w, map[string]any{"success": true, "scan": summary})
}

func (s *state) adminAssignFortiGatePolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin") {
		s.audit(actor, "fortigate.policy.assign", "denied", nil)
		writeError(w, "Policy administrator role required", http.StatusForbidden)
		return
	}
	var request fortiGatePolicyAssignmentRequest
	if err := decodeFortiGateAdminJSON(w, r, &request); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if request.Revision < 1 || !validFortiGatePolicyObservationID(request.ID) {
		writeError(w, "id and revision are required", http.StatusBadRequest)
		return
	}
	requestedService := strings.TrimSpace(request.Service)
	policy, err := s.latestPublishedPolicyForScan()
	if err != nil {
		writeError(w, "Read published services: "+err.Error(), http.StatusInternalServerError)
		return
	}
	index := newPublishedPolicyServiceIndex(policy)
	service := ""
	if requestedService != "" {
		service = index.services[strings.ToLower(requestedService)]
		if service == "" {
			writeError(w, "The selected service is not published", http.StatusConflict)
			return
		}
	}
	previous, revision, err := s.assignFortiGatePolicy(request.ID, request.Revision, service)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, sql.ErrNoRows) {
			status = http.StatusNotFound
		} else if errors.Is(err, errFortiGatePolicyObservationConflict) || errors.Is(err, errFortiGatePolicyObservationAbsent) {
			status = http.StatusConflict
		}
		writeError(w, err.Error(), status)
		return
	}
	displayService := service
	if displayService == "" {
		displayService = unknownFortiGateService
	}
	s.audit(actor, "fortigate.policy.assign", "success", map[string]any{
		"observation_id": request.ID, "from": previous, "to": displayService, "revision": revision,
	})
	writeJSON(w, map[string]any{"success": true, "id": request.ID, "revision": revision, "assigned_service": service, "assigned_service_label": displayService, "assignment_source": "manual"})
}

func validFortiGatePolicyObservationID(value string) bool {
	if !strings.HasPrefix(value, "policy-") || len(value) != len("policy-")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "policy-"))
	return err == nil
}

func (s *state) assignFortiGatePolicy(id string, expectedRevision int64, service string) (string, int64, error) {
	db, err := s.policyDB()
	if err != nil {
		return "", 0, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()
	var previous string
	var revision int64
	var present bool
	if err := tx.QueryRow(`SELECT assigned_service, revision, present FROM fortigate_policy_observation WHERE id=?`, id).Scan(&previous, &revision, &present); err != nil {
		return "", 0, err
	}
	if !present {
		return "", 0, errFortiGatePolicyObservationAbsent
	}
	if revision != expectedRevision {
		return "", 0, errFortiGatePolicyObservationConflict
	}
	source := "manual"
	revision++
	result, err := tx.Exec(`UPDATE fortigate_policy_observation SET assigned_service=?, assignment_source=?, revision=? WHERE id=? AND revision=? AND present=1`, service, source, revision, id, expectedRevision)
	if err != nil {
		return "", 0, err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil {
		return "", 0, rowsErr
	} else if rows != 1 {
		return "", 0, errFortiGatePolicyObservationConflict
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	if previous == "" {
		previous = unknownFortiGateService
	}
	return previous, revision, nil
}

func (s *state) listFortiGatePolicyInventory() ([]fortiGatePolicyObservationView, []fortiGatePolicyScanStateView, []string, error) {
	policy, err := s.latestPublishedPolicyForScan()
	if err != nil {
		return nil, nil, nil, err
	}
	index := newPublishedPolicyServiceIndex(policy)
	services := make([]string, 0, len(index.services))
	for _, service := range index.services {
		services = append(services, service)
	}
	sort.Slice(services, func(i, j int) bool { return strings.ToLower(services[i]) < strings.ToLower(services[j]) })
	db, err := s.policyDB()
	if err != nil {
		return nil, nil, nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id, revision, target_id, target_name, vdom, policy_id, policy_name, document,
		assigned_service, assignment_source, identity_weak, first_seen_at, last_seen_at
		FROM fortigate_policy_observation WHERE present=1
		ORDER BY CASE WHEN assigned_service='' THEN 0 ELSE 1 END, lower(assigned_service), lower(target_name), lower(vdom), CAST(policy_id AS INTEGER), lower(policy_name)`)
	if err != nil {
		return nil, nil, nil, err
	}
	observations := []fortiGatePolicyObservationView{}
	for rows.Next() {
		var item fortiGatePolicyObservationView
		var document, assignedService string
		if err := rows.Scan(&item.ID, &item.Revision, &item.TargetID, &item.TargetName, &item.VDOM, &item.PolicyID, &item.PolicyName, &document,
			&assignedService, &item.AssignmentSource, &item.IdentityWeak, &item.FirstSeenAt, &item.LastSeenAt); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(document), &raw); err != nil {
			rows.Close()
			return nil, nil, nil, fmt.Errorf("decode stored FortiGate policy %q: %w", item.ID, err)
		}
		item.Action = firstScalarString(raw, "action")
		item.Status = firstScalarString(raw, "status")
		item.SourceInterfaces = fortiGatePolicyMemberNames(raw["srcintf"])
		item.DestinationInterfaces = fortiGatePolicyMemberNames(raw["dstintf"])
		item.Sources = append(fortiGatePolicyMemberNames(raw["srcaddr"]), fortiGatePolicyMemberNames(raw["srcaddr6"])...)
		item.Destinations = append(fortiGatePolicyMemberNames(raw["dstaddr"]), fortiGatePolicyMemberNames(raw["dstaddr6"])...)
		item.Services = fortiGatePolicyMemberNames(raw["service"])
		item.Schedule = firstScalarString(raw, "schedule")
		item.Comments = firstScalarString(raw, "comments")
		if canonical := index.services[strings.ToLower(assignedService)]; canonical != "" {
			item.AssignedService = canonical
		} else if assignedService != "" {
			item.AssignmentSource = "unknown"
		}
		observations = append(observations, item)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, nil, err
	}
	stateRows, err := db.Query(`SELECT target_id, target_name, vdom, last_started_at, last_success_at, last_error, observed_count, unknown_count, new_count
		FROM fortigate_policy_scan_state ORDER BY lower(target_name), lower(vdom)`)
	if err != nil {
		return nil, nil, nil, err
	}
	scans := []fortiGatePolicyScanStateView{}
	for stateRows.Next() {
		var item fortiGatePolicyScanStateView
		if err := stateRows.Scan(&item.TargetID, &item.TargetName, &item.VDOM, &item.LastStartedAt, &item.LastSuccessAt, &item.LastError, &item.ObservedCount, &item.UnknownCount, &item.NewCount); err != nil {
			stateRows.Close()
			return nil, nil, nil, err
		}
		scans = append(scans, item)
	}
	if err := stateRows.Close(); err != nil {
		return nil, nil, nil, err
	}
	return observations, scans, services, nil
}

func fortiGatePolicyMemberNames(value any) []string {
	result := []string{}
	seen := map[string]bool{}
	var appendName func(any)
	appendName = func(item any) {
		switch typed := item.(type) {
		case []any:
			for _, child := range typed {
				appendName(child)
			}
		case map[string]any:
			name := strings.TrimSpace(firstScalarString(typed, "name"))
			if name != "" && !seen[name] {
				seen[name] = true
				result = append(result, name)
			}
		case string:
			name := strings.TrimSpace(typed)
			if name != "" && !seen[name] {
				seen[name] = true
				result = append(result, name)
			}
		}
	}
	appendName(value)
	return result
}
