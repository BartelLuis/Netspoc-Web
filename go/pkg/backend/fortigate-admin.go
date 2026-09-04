package backend

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxManagedFortiGateRequest = 80 << 10
	maxManagedFortiGateToken   = 4096
	maxManagedFortiGateCAPEM   = 64 << 10
	managedCredentialStageTTL  = 5 * time.Minute
)

var (
	errManagedFortiGateConflict              = errors.New("FortiGate changed since it was loaded")
	errManagedFortiGateNotFound              = errors.New("FortiGate not found")
	errManagedFortiGateCredentialUnavailable = errors.New("FortiGate credential is unavailable")
)

type managedFortiGate struct {
	ID           string
	Name         string
	URL          string
	VDOM         string
	CAPEM        string
	CredentialID string
	Enabled      bool
	Revision     int64
	CreatedAt    string
	CreatedBy    string
	UpdatedAt    string
	UpdatedBy    string
}

type managedFortiGateRequest struct {
	ID       string  `json:"id,omitempty"`
	Revision int64   `json:"revision,omitempty"`
	Name     string  `json:"name,omitempty"`
	URL      string  `json:"url,omitempty"`
	VDOM     string  `json:"vdom,omitempty"`
	Token    *string `json:"token,omitempty"`
	CAPEM    *string `json:"ca_pem,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
}

type managedFortiGateTestRequest struct {
	ID string `json:"id"`
}

type managedFortiGateView struct {
	ID              string `json:"id"`
	Revision        int64  `json:"revision"`
	Name            string `json:"name"`
	URL             string `json:"url"`
	VDOM            string `json:"vdom"`
	Enabled         bool   `json:"enabled"`
	ManagedBy       string `json:"managed_by"`
	Editable        bool   `json:"editable"`
	TokenConfigured bool   `json:"token_configured"`
	CAConfigured    bool   `json:"ca_configured"`
}

func (s *state) adminFortiGates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin") {
		s.audit(actor, "fortigate.manage", "denied", nil)
		writeError(w, "Policy administrator role required", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.listAdminFortiGates(w)
	case http.MethodPost:
		s.createAdminFortiGate(w, r, actor)
	case http.MethodPut:
		s.updateAdminFortiGate(w, r, actor)
	case http.MethodDelete:
		s.deleteAdminFortiGate(w, r, actor)
	default:
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *state) adminTestFortiGate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin") {
		s.audit(actor, "fortigate.test", "denied", nil)
		writeError(w, "Policy administrator role required", http.StatusForbidden)
		return
	}
	var request managedFortiGateTestRequest
	if err := decodeFortiGateAdminJSON(w, r, &request); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	target, err := s.findOperationalFortiGate(request.ID)
	if err != nil {
		status := http.StatusInternalServerError
		message := "FortiGate store is unavailable"
		switch {
		case errors.Is(err, errManagedFortiGateNotFound):
			status = http.StatusNotFound
			message = errManagedFortiGateNotFound.Error()
		case errors.Is(err, errManagedFortiGateCredentialUnavailable):
			status = http.StatusConflict
			message = errManagedFortiGateCredentialUnavailable.Error()
		}
		s.audit(actor, "fortigate.test", "failed", map[string]any{"id": request.ID, "reason": message})
		writeError(w, message, status)
		return
	}
	status := probeFortinetContext(r.Context(), target)
	result := "success"
	if !status.Online {
		result = "failed"
	}
	s.audit(actor, "fortigate.test", result, map[string]any{"id": request.ID, "name": target.Name})
	writeJSON(w, map[string]any{"success": true, "record": status})
}

func (s *state) listAdminFortiGates(w http.ResponseWriter) {
	if err := s.cleanupManagedFortiGateCredentials(); err != nil {
		log.Printf("clean up stale FortiGate credentials: %v", err)
	}
	managed, err := s.readManagedFortiGates(false)
	if err != nil {
		writeError(w, "Read managed FortiGates: "+err.Error(), http.StatusInternalServerError)
		return
	}
	views := make([]managedFortiGateView, 0, len(s.config.FortinetTargets)+len(managed))
	for _, target := range s.config.FortinetTargets {
		if target.Type != "fortigate" {
			continue
		}
		_, tokenErr := target.apiToken()
		views = append(views, managedFortiGateView{
			ID: configuredFortiGateID(target), Name: target.Name, URL: target.URL, VDOM: target.VDOM,
			Enabled: true, ManagedBy: "configuration", Editable: false,
			TokenConfigured: tokenErr == nil, CAConfigured: target.CAFile != "",
		})
	}
	for _, record := range managed {
		_, tokenErr := s.readManagedFortiGateCredential(record.CredentialID)
		views = append(views, managedFortiGateView{
			ID: record.ID, Revision: record.Revision, Name: record.Name, URL: record.URL, VDOM: record.VDOM,
			Enabled: record.Enabled, ManagedBy: "web", Editable: true,
			TokenConfigured: tokenErr == nil, CAConfigured: record.CAPEM != "",
		})
	}
	writeJSON(w, map[string]any{"success": true, "records": views, "totalCount": len(views)})
}

func (s *state) createAdminFortiGate(w http.ResponseWriter, r *http.Request, actor string) {
	request, err := decodeManagedFortiGateRequest(w, r)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if request.ID != "" || request.Revision != 0 || request.Token == nil {
		writeError(w, "A new FortiGate requires name, url and token", http.StatusBadRequest)
		return
	}
	token, err := validateManagedFortiGateToken(*request.Token)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := randomFortiGateID(16)
	if err != nil {
		writeError(w, "Generate FortiGate ID", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	record := managedFortiGate{ID: id, Revision: 1, CreatedAt: now, CreatedBy: actor, UpdatedAt: now, UpdatedBy: actor, Enabled: true}
	if request.Enabled != nil {
		record.Enabled = *request.Enabled
	}
	autoDiscover := strings.TrimSpace(request.VDOM) == ""
	if autoDiscover {
		request.VDOM = "root" // temporary valid scope used to construct the scan client
	}
	if err := applyManagedFortiGateFields(&record, request); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	records := []managedFortiGate{record}
	if autoDiscover {
		target := managedFortiGateRuntime(record, token)
		target.VDOM = ""
		client, clientErr := target.httpClient()
		if clientErr != nil {
			writeError(w, "Prepare FortiGate VDOM scan: "+clientErr.Error(), http.StatusBadRequest)
			return
		}
		vdoms, scanErr := discoverFortiGateVDOMs(r.Context(), client, target)
		if scanErr != nil {
			writeError(w, "Scan FortiGate VDOMs: "+redactedFortinetError(target, scanErr), http.StatusBadGateway)
			return
		}
		records = make([]managedFortiGate, 0, len(vdoms))
		for index, vdom := range vdoms {
			item := record
			if index != 0 {
				item.ID, err = randomFortiGateID(16)
				if err != nil {
					writeError(w, "Generate FortiGate ID", http.StatusInternalServerError)
					return
				}
			}
			item.VDOM = vdom
			item.Name = managedFortiGateVDOMName(record.Name, vdom)
			records = append(records, item)
		}
	}
	for _, item := range records {
		if err := s.validateManagedFortiGateConflicts(item, ""); err != nil {
			writeError(w, err.Error(), http.StatusConflict)
			return
		}
	}
	for index := range records {
		records[index].CredentialID, err = s.writeManagedFortiGateCredential(token)
		if err != nil {
			for previous := 0; previous < index; previous++ {
				s.discardManagedFortiGateCredential(records[previous].CredentialID)
			}
			writeError(w, "Store FortiGate credential", http.StatusInternalServerError)
			return
		}
	}
	if err := s.insertManagedFortiGates(records); err != nil {
		for _, item := range records {
			s.discardManagedFortiGateCredential(item.CredentialID)
		}
		status := http.StatusInternalServerError
		if isSQLiteUniqueError(err) {
			status = http.StatusConflict
		}
		writeError(w, "Create FortiGate: "+err.Error(), status)
		return
	}
	views := make([]managedFortiGateView, len(records))
	for index, item := range records {
		if err := s.clearManagedFortiGateCredentialCleanup(item.CredentialID); err != nil {
			log.Printf("clear active FortiGate credential cleanup marker for %q: %v", item.ID, err)
		}
		s.audit(actor, "fortigate.create", "success", fortiGateAuditMetadata(item))
		views[index] = s.managedFortiGateView(item, true)
	}
	writeJSONStatus(w, http.StatusCreated, map[string]any{"success": true, "record": views[0], "records": views, "created_count": len(views)})
}

func discoverFortiGateVDOMs(ctx context.Context, client *http.Client, target FortinetTarget) ([]string, error) {
	objects, err := listFortiGateObjects(ctx, client, target, "/api/v2/cmdb/system/vdom", nil)
	if err != nil {
		return nil, err
	}
	vdoms, seen := make([]string, 0, len(objects)), map[string]bool{}
	for _, object := range objects {
		name := strings.TrimSpace(object.MKey)
		probe := target
		probe.Name, probe.VDOM = "VDOM scan", name
		if err := probe.validate(); err != nil {
			return nil, fmt.Errorf("invalid VDOM %q returned by FortiGate: %w", name, err)
		}
		canonical := strings.ToLower(name)
		if seen[canonical] {
			return nil, fmt.Errorf("FortiGate returned duplicate VDOM %q", name)
		}
		seen[canonical] = true
		vdoms = append(vdoms, name)
	}
	if len(vdoms) == 0 {
		return nil, errors.New("FortiGate returned no visible VDOMs; check the API administrator's VDOM assignments and system read permission")
	}
	sort.Slice(vdoms, func(i, j int) bool { return strings.ToLower(vdoms[i]) < strings.ToLower(vdoms[j]) })
	return vdoms, nil
}

func managedFortiGateVDOMName(base, vdom string) string {
	suffix := []rune(" [" + vdom + "]")
	prefix := []rune(base)
	if len(prefix)+len(suffix) > 64 {
		prefix = prefix[:64-len(suffix)]
	}
	return string(prefix) + string(suffix)
}

func (s *state) updateAdminFortiGate(w http.ResponseWriter, r *http.Request, actor string) {
	request, err := decodeManagedFortiGateRequest(w, r)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	current, err := s.readManagedFortiGate(request.ID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, errManagedFortiGateNotFound.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		writeError(w, "Read FortiGate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if request.Revision <= 0 || request.Revision != current.Revision {
		writeError(w, errManagedFortiGateConflict.Error(), http.StatusConflict)
		return
	}
	updated := current
	if request.Enabled != nil {
		updated.Enabled = *request.Enabled
	}
	if err := applyManagedFortiGateFields(&updated, request); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	trustChanged := updated.URL != current.URL || updated.CAPEM != current.CAPEM
	if trustChanged && (request.Token == nil || *request.Token == "") {
		writeError(w, "Changing the FortiGate URL or CA certificate requires a new API token", http.StatusBadRequest)
		return
	}
	if err := s.validateManagedFortiGateConflicts(updated, current.ID); err != nil {
		writeError(w, err.Error(), http.StatusConflict)
		return
	}
	newCredentialID := ""
	if request.Token != nil && *request.Token != "" {
		token, tokenErr := validateManagedFortiGateToken(*request.Token)
		if tokenErr != nil {
			writeError(w, tokenErr.Error(), http.StatusBadRequest)
			return
		}
		newCredentialID, err = s.writeManagedFortiGateCredential(token)
		if err != nil {
			writeError(w, "Store FortiGate credential", http.StatusInternalServerError)
			return
		}
		updated.CredentialID = newCredentialID
	} else if _, err := s.readManagedFortiGateCredential(current.CredentialID); err != nil {
		writeError(w, "The existing credential is unavailable; enter a new API token", http.StatusConflict)
		return
	}
	updated.Revision++
	updated.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	updated.UpdatedBy = actor
	var replaceErr error
	if newCredentialID != "" {
		replaceErr = s.replaceManagedFortiGateWithCredentialRotation(updated, current)
	} else {
		replaceErr = s.replaceManagedFortiGate(updated, current.Revision)
	}
	if replaceErr != nil {
		if newCredentialID != "" {
			s.discardManagedFortiGateCredential(newCredentialID)
		}
		status := http.StatusInternalServerError
		if errors.Is(replaceErr, errManagedFortiGateConflict) || isSQLiteUniqueError(replaceErr) {
			status = http.StatusConflict
		}
		writeError(w, "Update FortiGate: "+replaceErr.Error(), status)
		return
	}
	s.audit(actor, "fortigate.update", "success", fortiGateAuditMetadata(updated))
	writeJSON(w, map[string]any{"success": true, "record": s.managedFortiGateView(updated, true)})
}

func (s *state) deleteAdminFortiGate(w http.ResponseWriter, r *http.Request, actor string) {
	request, err := decodeManagedFortiGateRequest(w, r)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if request.ID == "" || request.Revision <= 0 {
		writeError(w, "id and revision are required", http.StatusBadRequest)
		return
	}
	current, err := s.readManagedFortiGate(request.ID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, errManagedFortiGateNotFound.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		writeError(w, "Read FortiGate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if request.Revision != current.Revision {
		writeError(w, errManagedFortiGateConflict.Error(), http.StatusConflict)
		return
	}
	if err := s.removeManagedFortiGate(current); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errManagedFortiGateConflict) {
			status = http.StatusConflict
		}
		writeError(w, "Delete FortiGate: "+err.Error(), status)
		return
	}
	s.audit(actor, "fortigate.delete", "success", fortiGateAuditMetadata(current))
	writeJSON(w, map[string]any{"success": true})
}

func decodeManagedFortiGateRequest(w http.ResponseWriter, r *http.Request) (managedFortiGateRequest, error) {
	var request managedFortiGateRequest
	if err := decodeFortiGateAdminJSON(w, r, &request); err != nil {
		return request, err
	}
	return request, nil
}

func decodeFortiGateAdminJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if contentType := strings.TrimSpace(r.Header.Get("Content-Type")); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || mediaType != "application/json" {
			return errors.New("Content-Type must be application/json")
		}
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxManagedFortiGateRequest))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("Invalid JSON request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("Request body must contain exactly one JSON object")
	}
	return nil
}

func applyManagedFortiGateFields(record *managedFortiGate, request managedFortiGateRequest) error {
	name := strings.TrimSpace(request.Name)
	vdom := strings.TrimSpace(request.VDOM)
	canonicalURL, err := validateManagedFortiGateEndpoint(request.URL)
	if err != nil {
		return err
	}
	caPEM := record.CAPEM
	if request.CAPEM != nil {
		caPEM, err = validateManagedFortiGateCAPEM(*request.CAPEM)
		if err != nil {
			return err
		}
	}
	target := FortinetTarget{Name: name, Type: "fortigate", URL: canonicalURL, VDOM: vdom, TokenEnv: "managed:" + record.ID, managedCAPEM: caPEM}
	if err := target.validate(); err != nil {
		return err
	}
	if vdom == "" {
		return errors.New("vdom is required for a web-managed FortiGate")
	}
	record.Name, record.URL, record.VDOM, record.CAPEM = name, canonicalURL, vdom, caPEM
	return nil
}

func validateManagedFortiGateEndpoint(raw string) (string, error) {
	canonical, err := normalizedFortinetEndpoint(raw)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(canonical)
	if u.Path != "" {
		return "", errors.New("web-managed FortiGate URLs must not contain a path")
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "", errors.New("loopback FortiGate endpoints are not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
		return "", errors.New("loopback, multicast and link-local FortiGate endpoints are not allowed")
	}
	return canonical, nil
}

func validateManagedFortiGateToken(token string) (string, error) {
	if token == "" || len(token) > maxManagedFortiGateToken || !utf8.ValidString(token) || token != strings.TrimSpace(token) {
		return "", errors.New("API token must contain 1 to 4096 valid characters without surrounding whitespace")
	}
	for _, character := range token {
		if unicode.IsControl(character) {
			return "", errors.New("API token must not contain control characters")
		}
	}
	return token, nil
}

func validateManagedFortiGateCAPEM(value string) (string, error) {
	if len(value) > maxManagedFortiGateCAPEM {
		return "", errors.New("CA certificate is invalid or exceeds 64 KiB")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	remaining := []byte(value)
	var normalized bytes.Buffer
	certificateCount := 0
	for len(bytes.TrimSpace(remaining)) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return "", errors.New("CA certificate must contain only PEM encoded certificates")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", errors.New("CA certificate contains an invalid certificate")
		}
		if err := pem.Encode(&normalized, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}); err != nil {
			return "", errors.New("CA certificate could not be normalized")
		}
		certificateCount++
		remaining = rest
	}
	if certificateCount == 0 {
		return "", errors.New("CA certificate must contain a PEM encoded certificate")
	}
	return normalized.String(), nil
}

func (s *state) validateManagedFortiGateConflicts(candidate managedFortiGate, excludeID string) error {
	canonicalName := strings.ToLower(candidate.Name)
	for _, target := range s.config.FortinetTargets {
		if strings.EqualFold(target.Name, candidate.Name) {
			return fmt.Errorf("FortiGate name %q is already configured", candidate.Name)
		}
		if target.Type == "fortigate" {
			canonicalURL, _ := normalizedFortinetEndpoint(target.URL)
			if canonicalURL == candidate.URL && target.VDOM == candidate.VDOM {
				return fmt.Errorf("FortiGate endpoint and VDOM are already configured as %q", target.Name)
			}
		}
	}
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	var id, name string
	err = db.QueryRow(`SELECT id, name FROM managed_fortigate WHERE id <> ? AND (canonical_name = ? OR (url = ? AND vdom = ?)) LIMIT 1`, excludeID, canonicalName, candidate.URL, candidate.VDOM).Scan(&id, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("FortiGate conflicts with existing web target %q", name)
}

func (s *state) insertManagedFortiGates(records []managedFortiGate) error {
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
	for _, record := range records {
		if _, err = tx.Exec(`INSERT INTO managed_fortigate(id, canonical_name, name, url, vdom, ca_pem, credential_id, enabled, revision, created_at, created_by, updated_at, updated_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			record.ID, strings.ToLower(record.Name), record.Name, record.URL, record.VDOM, record.CAPEM, record.CredentialID, record.Enabled, record.Revision, record.CreatedAt, record.CreatedBy, record.UpdatedAt, record.UpdatedBy); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *state) replaceManagedFortiGate(record managedFortiGate, expectedRevision int64) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	result, err := db.Exec(`UPDATE managed_fortigate SET canonical_name=?, name=?, url=?, vdom=?, ca_pem=?, credential_id=?, enabled=?, revision=?, updated_at=?, updated_by=? WHERE id=? AND revision=?`,
		strings.ToLower(record.Name), record.Name, record.URL, record.VDOM, record.CAPEM, record.CredentialID, record.Enabled, record.Revision, record.UpdatedAt, record.UpdatedBy, record.ID, expectedRevision)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errManagedFortiGateConflict
	}
	return nil
}

// replaceManagedFortiGateWithCredentialRotation commits the new reference and
// a durable cleanup marker for the old credential in one SQLite transaction.
// File deletion is intentionally after commit: a process crash can then leave
// only an orphan queued for idempotent cleanup, never a live row without a key.
func (s *state) replaceManagedFortiGateWithCredentialRotation(updated, current managedFortiGate) error {
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
	result, err := tx.Exec(`UPDATE managed_fortigate SET canonical_name=?, name=?, url=?, vdom=?, ca_pem=?, credential_id=?, enabled=?, revision=?, updated_at=?, updated_by=? WHERE id=? AND revision=?`,
		strings.ToLower(updated.Name), updated.Name, updated.URL, updated.VDOM, updated.CAPEM, updated.CredentialID, updated.Enabled, updated.Revision, updated.UpdatedAt, updated.UpdatedBy, updated.ID, current.Revision)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errManagedFortiGateConflict
	}
	if _, err := tx.Exec(`DELETE FROM managed_fortigate_credential_cleanup WHERE credential_id=?`, updated.CredentialID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO managed_fortigate_credential_cleanup(credential_id, not_before) VALUES(?, 0)
		ON CONFLICT(credential_id) DO UPDATE SET not_before=0`, current.CredentialID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := s.cleanupManagedFortiGateCredentials(); err != nil {
		log.Printf("clean up rotated FortiGate credential for %q: %v", current.ID, err)
	}
	return nil
}

func (s *state) removeManagedFortiGate(record managedFortiGate) error {
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
	result, err := tx.Exec(`DELETE FROM managed_fortigate WHERE id=? AND revision=?`, record.ID, record.Revision)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errManagedFortiGateConflict
	}
	if _, err := tx.Exec(`INSERT INTO managed_fortigate_credential_cleanup(credential_id, not_before) VALUES(?, 0)
		ON CONFLICT(credential_id) DO UPDATE SET not_before=0`, record.CredentialID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := s.cleanupManagedFortiGateCredentials(); err != nil {
		log.Printf("clean up deleted FortiGate credential for %q: %v", record.ID, err)
	}
	return nil
}

func scanManagedFortiGate(scanner interface{ Scan(...any) error }) (managedFortiGate, error) {
	var record managedFortiGate
	err := scanner.Scan(&record.ID, &record.Name, &record.URL, &record.VDOM, &record.CAPEM, &record.CredentialID, &record.Enabled, &record.Revision, &record.CreatedAt, &record.CreatedBy, &record.UpdatedAt, &record.UpdatedBy)
	return record, err
}

const managedFortiGateColumns = `id, name, url, vdom, ca_pem, credential_id, enabled, revision, created_at, created_by, updated_at, updated_by`

func (s *state) readManagedFortiGate(id string) (managedFortiGate, error) {
	if !validFortiGateID(id, 16) {
		return managedFortiGate{}, sql.ErrNoRows
	}
	db, err := s.policyDB()
	if err != nil {
		return managedFortiGate{}, err
	}
	defer db.Close()
	return scanManagedFortiGate(db.QueryRow(`SELECT `+managedFortiGateColumns+` FROM managed_fortigate WHERE id=?`, id))
}

func (s *state) readManagedFortiGates(enabledOnly bool) ([]managedFortiGate, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	query := `SELECT ` + managedFortiGateColumns + ` FROM managed_fortigate`
	if enabledOnly {
		query += ` WHERE enabled=1`
	}
	query += ` ORDER BY canonical_name, id`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []managedFortiGate{}
	for rows.Next() {
		record, scanErr := scanManagedFortiGate(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (s *state) routingFortinetTargets() ([]FortinetTarget, error) {
	if err := s.cleanupManagedFortiGateCredentials(); err != nil {
		log.Printf("clean up stale FortiGate credentials: %v", err)
	}
	managed, err := s.readManagedFortiGates(true)
	if err != nil {
		return nil, err
	}
	targets := append([]FortinetTarget(nil), s.config.FortinetTargets...)
	names := make(map[string]bool, len(targets)+len(managed))
	scopes := make(map[string]string, len(targets)+len(managed))
	for _, target := range targets {
		names[strings.ToLower(target.Name)] = true
		if target.Type == "fortigate" {
			canonical, _ := normalizedFortinetEndpoint(target.URL)
			scopes[canonical+"\x00"+target.VDOM] = target.Name
		}
	}
	for _, record := range managed {
		if names[strings.ToLower(record.Name)] {
			return nil, fmt.Errorf("web-managed FortiGate %q conflicts with a configured target name", record.Name)
		}
		if previous := scopes[record.URL+"\x00"+record.VDOM]; previous != "" {
			return nil, fmt.Errorf("web-managed FortiGate %q conflicts with configured target %q", record.Name, previous)
		}
		token, readErr := s.readManagedFortiGateCredential(record.CredentialID)
		if readErr != nil {
			return nil, fmt.Errorf("credential for web-managed FortiGate %q is unavailable", record.Name)
		}
		target := managedFortiGateRuntime(record, token)
		if err := target.validate(); err != nil {
			return nil, fmt.Errorf("web-managed FortiGate %q is invalid: %w", record.Name, err)
		}
		targets = append(targets, target)
		names[strings.ToLower(record.Name)] = true
		scopes[record.URL+"\x00"+record.VDOM] = record.Name
	}
	return targets, nil
}

func managedFortiGateRuntime(record managedFortiGate, token string) FortinetTarget {
	return FortinetTarget{
		Name: record.Name, Type: "fortigate", URL: record.URL, VDOM: record.VDOM,
		TokenEnv: "managed:" + record.ID, managedID: record.ID, managedToken: token, managedCAPEM: record.CAPEM,
	}
}

func (s *state) findOperationalFortiGate(id string) (FortinetTarget, error) {
	for _, target := range s.config.FortinetTargets {
		if target.Type == "fortigate" && configuredFortiGateID(target) == id {
			return target, nil
		}
	}
	record, err := s.readManagedFortiGate(id)
	if errors.Is(err, sql.ErrNoRows) {
		return FortinetTarget{}, errManagedFortiGateNotFound
	}
	if err != nil {
		return FortinetTarget{}, fmt.Errorf("read managed FortiGate: %w", err)
	}
	token, err := s.readManagedFortiGateCredential(record.CredentialID)
	if err != nil {
		if os.IsNotExist(err) {
			return FortinetTarget{}, errManagedFortiGateCredentialUnavailable
		}
		return FortinetTarget{}, fmt.Errorf("read managed FortiGate credential: %w", err)
	}
	return managedFortiGateRuntime(record, token), nil
}

func configuredFortiGateID(target FortinetTarget) string {
	sum := sha256.Sum256([]byte(target.Name + "\x00" + target.URL + "\x00" + target.VDOM))
	return "config-" + hex.EncodeToString(sum[:12])
}

func (s *state) managedFortiGateView(record managedFortiGate, tokenConfigured bool) managedFortiGateView {
	return managedFortiGateView{
		ID: record.ID, Revision: record.Revision, Name: record.Name, URL: record.URL, VDOM: record.VDOM,
		Enabled: record.Enabled, ManagedBy: "web", Editable: true,
		TokenConfigured: tokenConfigured, CAConfigured: record.CAPEM != "",
	}
}

func fortiGateAuditMetadata(record managedFortiGate) map[string]any {
	return map[string]any{"id": record.ID, "name": record.Name, "url": record.URL, "vdom": record.VDOM, "revision": record.Revision, "enabled": record.Enabled}
}

func (s *state) managedFortiGateCredentialDir() (string, error) {
	if s.config == nil || strings.TrimSpace(s.config.UserDir) == "" {
		return "", errors.New("user_dir is not configured")
	}
	directory := filepath.Join(s.config.UserDir, ".fortigate-credentials")
	if info, err := os.Lstat(directory); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("credential directory must not be a symbolic link")
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", err
	}
	return directory, nil
}

func (s *state) writeManagedFortiGateCredential(token string) (string, error) {
	id, err := randomFortiGateID(32)
	if err != nil {
		return "", err
	}
	if err := s.queueManagedFortiGateCredentialCleanup(id, time.Now().Add(managedCredentialStageTTL)); err != nil {
		return "", err
	}
	if err := s.writeManagedFortiGateCredentialWithID(id, token); err != nil {
		s.discardManagedFortiGateCredential(id)
		return "", err
	}
	return id, nil
}

func (s *state) queueManagedFortiGateCredentialCleanup(id string, notBefore time.Time) error {
	if !validFortiGateID(id, 32) {
		return errors.New("invalid credential reference")
	}
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO managed_fortigate_credential_cleanup(credential_id, not_before) VALUES(?, ?)
		ON CONFLICT(credential_id) DO UPDATE SET not_before=excluded.not_before`, id, notBefore.Unix())
	return err
}

func (s *state) clearManagedFortiGateCredentialCleanup(id string) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`DELETE FROM managed_fortigate_credential_cleanup WHERE credential_id=?`, id)
	return err
}

func (s *state) discardManagedFortiGateCredential(id string) {
	// Re-queue immediately and let the reference-aware collector decide. This
	// is safe even after an ambiguous database commit result: a credential that
	// became active is preserved and only its marker is cleared.
	if err := s.queueManagedFortiGateCredentialCleanup(id, time.Unix(0, 0)); err != nil {
		log.Printf("queue unused FortiGate credential %q: %v", id, err)
		return
	}
	if err := s.cleanupManagedFortiGateCredentials(); err != nil {
		log.Printf("clean up unused FortiGate credential %q: %v", id, err)
	}
}

func (s *state) cleanupManagedFortiGateCredentials() error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT credential_id FROM managed_fortigate_credential_cleanup WHERE not_before <= ? ORDER BY credential_id`, time.Now().Unix())
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var cleanupErr error
	for _, id := range ids {
		if !validFortiGateID(id, 32) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("invalid queued credential reference %q", id))
			continue
		}
		var references int
		if err := db.QueryRow(`SELECT COUNT(*) FROM managed_fortigate WHERE credential_id=?`, id).Scan(&references); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		if references == 0 {
			if err := s.removeManagedFortiGateCredential(id); err != nil && !os.IsNotExist(err) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove credential %q: %w", id, err))
				continue
			}
		}
		if _, err := db.Exec(`DELETE FROM managed_fortigate_credential_cleanup WHERE credential_id=?`, id); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	return cleanupErr
}

func (s *state) writeManagedFortiGateCredentialWithID(id, token string) error {
	if !validFortiGateID(id, 32) {
		return errors.New("invalid credential reference")
	}
	if _, err := validateManagedFortiGateToken(token); err != nil {
		return err
	}
	directory, err := s.managedFortiGateCredentialDir()
	if err != nil {
		return err
	}
	path := filepath.Join(directory, id)
	if _, err := os.Lstat(path); err == nil {
		return os.ErrExist
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".credential-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write([]byte(token)); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporaryName, path); err != nil {
		return err
	}
	committed = true
	if err := os.Chmod(path, 0o600); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func (s *state) readManagedFortiGateCredential(id string) (string, error) {
	if !validFortiGateID(id, 32) {
		return "", errors.New("invalid credential reference")
	}
	directory, err := s.managedFortiGateCredentialDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, id)
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("credential is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("credential is not a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxManagedFortiGateToken+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxManagedFortiGateToken {
		return "", errors.New("credential exceeds the size limit")
	}
	return validateManagedFortiGateToken(string(data))
}

func (s *state) removeManagedFortiGateCredential(id string) error {
	if !validFortiGateID(id, 32) {
		return errors.New("invalid credential reference")
	}
	directory, err := s.managedFortiGateCredentialDir()
	if err != nil {
		return err
	}
	return os.Remove(filepath.Join(directory, id))
}

func randomFortiGateID(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func validFortiGateID(value string, bytes int) bool {
	if len(value) != bytes*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}

func isSQLiteUniqueError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
