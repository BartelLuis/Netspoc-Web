package backend

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func (s *state) policyDB() (*sql.DB, error) {
	if err := os.MkdirAll(s.config.NetspocData, 0o750); err != nil {
		return nil, fmt.Errorf("create policy data directory: %w", err)
	}
	path := filepath.Join(s.config.NetspocData, "policyweb.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
		CREATE TABLE IF NOT EXISTS policy_draft (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			document TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS policy_publication (
			version TEXT PRIMARY KEY,
			document TEXT NOT NULL,
			published_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS policy_revision (
			version TEXT PRIMARY KEY,
			base_version TEXT NOT NULL,
			document TEXT NOT NULL,
			changes TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			published_at TEXT
		);
		CREATE TABLE IF NOT EXISTS policy_audit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			result TEXT NOT NULL,
			metadata TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL
		);`); err != nil {
		db.Close()
		return nil, err
	}
	columns := []struct{ table, name, definition string }{
		{"policy_draft", "version", "INTEGER NOT NULL DEFAULT 1"},
		{"policy_draft", "updated_by", "TEXT NOT NULL DEFAULT ''"},
		{"policy_revision", "created_by", "TEXT NOT NULL DEFAULT ''"},
		{"policy_revision", "comment", "TEXT NOT NULL DEFAULT ''"},
		{"policy_revision", "change_reference", "TEXT NOT NULL DEFAULT ''"},
		{"policy_revision", "findings", "TEXT NOT NULL DEFAULT '[]'"},
		{"policy_revision", "deployment_plan", "TEXT NOT NULL DEFAULT 'null'"},
		{"policy_revision", "validation", "TEXT NOT NULL DEFAULT 'null'"},
		{"policy_revision", "approved_by", "TEXT NOT NULL DEFAULT ''"},
		{"policy_revision", "rejected_by", "TEXT NOT NULL DEFAULT ''"},
		{"policy_revision", "rejection_comment", "TEXT NOT NULL DEFAULT ''"},
		{"policy_revision", "rejected_at", "TEXT"},
		{"policy_publication", "published_by", "TEXT NOT NULL DEFAULT ''"},
		{"policy_publication", "source_revision", "TEXT NOT NULL DEFAULT ''"},
	}
	for _, column := range columns {
		if err = ensureSQLiteColumn(db, column.table, column.name, column.definition); err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}

func ensureSQLiteColumn(db *sql.DB, table, name, definition string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var columnName, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		if columnName == name {
			return rows.Close()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + name + " " + definition)
	return err
}

var errDraftConflict = errors.New("draft changed since it was loaded")

type draftMetadata struct {
	Version   int64  `json:"draft_version"`
	UpdatedAt string `json:"draft_updated_at"`
	UpdatedBy string `json:"draft_updated_by"`
}

type storedPolicyDraftSnapshot struct {
	Exists    bool
	Document  string
	UpdatedAt string
	Version   int64
	UpdatedBy string
}

func (s *state) snapshotStoredPolicyDraft() (storedPolicyDraftSnapshot, error) {
	db, err := s.policyDB()
	if err != nil {
		return storedPolicyDraftSnapshot{}, err
	}
	defer db.Close()
	var snapshot storedPolicyDraftSnapshot
	err = db.QueryRow(`SELECT document, updated_at, version, updated_by FROM policy_draft WHERE id=1`).Scan(&snapshot.Document, &snapshot.UpdatedAt, &snapshot.Version, &snapshot.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return snapshot, nil
	}
	if err != nil {
		return storedPolicyDraftSnapshot{}, err
	}
	snapshot.Exists = true
	return snapshot, nil
}

func (s *state) restoreStoredPolicyDraft(snapshot storedPolicyDraftSnapshot) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	if !snapshot.Exists {
		_, err = db.Exec(`DELETE FROM policy_draft WHERE id=1`)
		return err
	}
	_, err = db.Exec(`INSERT INTO policy_draft(id, document, updated_at, version, updated_by) VALUES(1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET document=excluded.document, updated_at=excluded.updated_at, version=excluded.version, updated_by=excluded.updated_by`,
		snapshot.Document, snapshot.UpdatedAt, snapshot.Version, snapshot.UpdatedBy)
	return err
}

type revisionMetadata struct {
	CreatedBy       string
	Comment         string
	ChangeReference string
	Findings        []policyFinding
	DeploymentPlan  any
	Validation      any
}

type policyRevisionRecord struct {
	Policy           *editablePolicy
	Version          string
	Base             string
	Status           string
	CreatedBy        string
	Comment          string
	ChangeReference  string
	Findings         []policyFinding
	DeploymentPlan   any
	Validation       any
	ApprovedBy       string
	RejectedBy       string
	RejectionComment string
	Changes          []policyChange
}

type policyRevisionSummary struct {
	Version          string          `json:"version"`
	Base             string          `json:"base"`
	Status           string          `json:"status"`
	CreatedAt        string          `json:"created_at"`
	Changes          []policyChange  `json:"changes"`
	CreatedBy        string          `json:"created_by,omitempty"`
	Comment          string          `json:"comment,omitempty"`
	ChangeReference  string          `json:"change_reference,omitempty"`
	Findings         []policyFinding `json:"findings,omitempty"`
	ApprovedBy       string          `json:"approved_by,omitempty"`
	RejectedBy       string          `json:"rejected_by,omitempty"`
	RejectionComment string          `json:"rejection_comment,omitempty"`
}

func (s *state) storeRevision(version, base string, p *editablePolicy, changes any) error {
	return s.storeRevisionWithMetadata(version, base, p, changes, revisionMetadata{})
}

func (s *state) storeRevisionWithMetadata(version, base string, p *editablePolicy, changes any, meta revisionMetadata) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
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
	_, err = db.Exec(`INSERT INTO policy_revision(version, base_version, document, changes, status, created_at, created_by, comment, change_reference, findings, deployment_plan, validation) VALUES(?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)`, version, base, string(document), string(diff), time.Now().UTC().Format(time.RFC3339Nano), meta.CreatedBy, meta.Comment, meta.ChangeReference, string(findings), string(plan), string(validation))
	return err
}

func (s *state) loadRevision(version string) (*editablePolicy, string, error) {
	record, err := s.loadRevisionRecord(version, true)
	if err != nil {
		return nil, "", err
	}
	return record.Policy, record.Base, nil
}

func (s *state) loadRevisionRecord(version string, pendingOnly bool) (*policyRevisionRecord, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	query := `SELECT document, base_version, status, created_by, comment, change_reference, findings, deployment_plan, validation, approved_by, rejected_by, rejection_comment, changes FROM policy_revision WHERE version = ?`
	if pendingOnly {
		query += ` AND status = 'pending'`
	}
	var document, findings, plan, validation, changes string
	record := &policyRevisionRecord{Version: version}
	if err := db.QueryRow(query, version).Scan(&document, &record.Base, &record.Status, &record.CreatedBy, &record.Comment, &record.ChangeReference, &findings, &plan, &validation, &record.ApprovedBy, &record.RejectedBy, &record.RejectionComment, &changes); err != nil {
		return nil, err
	}
	var p editablePolicy
	if err := json.Unmarshal([]byte(document), &p); err != nil {
		return nil, err
	}
	if findings != "" {
		_ = json.Unmarshal([]byte(findings), &record.Findings)
	}
	if plan != "" {
		_ = json.Unmarshal([]byte(plan), &record.DeploymentPlan)
	}
	if validation != "" {
		_ = json.Unmarshal([]byte(validation), &record.Validation)
	}
	if changes != "" {
		_ = json.Unmarshal([]byte(changes), &record.Changes)
	}
	if record.Changes == nil {
		record.Changes = []policyChange{}
	}
	normalizeEditablePolicy(&p)
	record.Policy = &p
	return record, nil
}

func (s *state) markRevisionPublished(version string) error {
	return s.markRevisionPublishedBy(version, "")
}

func (s *state) markRevisionPublishedBy(version, actor string) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	result, err := db.Exec(`UPDATE policy_revision SET status = 'published', published_at = ?, approved_by = ? WHERE version = ? AND status = 'pending'`, time.Now().UTC().Format(time.RFC3339Nano), actor, version)
	if err == nil {
		if count, _ := result.RowsAffected(); count != 1 {
			return errors.New("revision is not pending")
		}
	}
	return err
}

func (s *state) rejectRevision(version, actor, comment string) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	result, err := db.Exec(`UPDATE policy_revision SET status='rejected', rejected_at=?, rejected_by=?, rejection_comment=? WHERE version=? AND status='pending'`, time.Now().UTC().Format(time.RFC3339Nano), actor, comment, version)
	if err == nil {
		if count, _ := result.RowsAffected(); count != 1 {
			return errors.New("revision is not pending")
		}
	}
	return err
}

func (s *state) listRevisions() ([]policyRevisionSummary, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT version, base_version, status, created_at, changes, created_by, comment, change_reference, findings, approved_by, rejected_by, rejection_comment FROM policy_revision ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []policyRevisionSummary{}
	for rows.Next() {
		var item policyRevisionSummary
		var changes, findings string
		if err := rows.Scan(&item.Version, &item.Base, &item.Status, &item.CreatedAt, &changes, &item.CreatedBy, &item.Comment, &item.ChangeReference, &findings, &item.ApprovedBy, &item.RejectedBy, &item.RejectionComment); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(changes), &item.Changes); err != nil {
			return nil, err
		}
		if item.Changes == nil {
			item.Changes = []policyChange{}
		}
		if findings != "" {
			_ = json.Unmarshal([]byte(findings), &item.Findings)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *state) draftInfo() (draftMetadata, error) {
	db, err := s.policyDB()
	if err != nil {
		return draftMetadata{}, err
	}
	defer db.Close()
	var meta draftMetadata
	err = db.QueryRow(`SELECT version, updated_at, updated_by FROM policy_draft WHERE id=1`).Scan(&meta.Version, &meta.UpdatedAt, &meta.UpdatedBy)
	if err == sql.ErrNoRows {
		return draftMetadata{}, nil
	}
	return meta, err
}

func (s *state) latestPublicationVersion() (string, error) {
	db, err := s.policyDB()
	if err != nil {
		return "", err
	}
	defer db.Close()
	var version string
	err = db.QueryRow(`SELECT version FROM policy_publication ORDER BY published_at DESC LIMIT 1`).Scan(&version)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return version, err
}

func (s *state) latestPublicationSnapshot() (*editablePolicy, string, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, "", err
	}
	defer db.Close()
	var version, document string
	err = db.QueryRow(`SELECT version, document FROM policy_publication ORDER BY published_at DESC LIMIT 1`).Scan(&version, &document)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	var p editablePolicy
	if err := json.Unmarshal([]byte(document), &p); err != nil {
		return nil, "", err
	}
	normalizeEditablePolicy(&p)
	return &p, version, nil
}

// authorizationPolicy returns the immutable policy snapshot used for all
// authorization decisions. The draft is consulted only for a legacy/bootstrap
// installation that has no publication row yet. Database and decode failures
// fail closed instead of silently granting roles from mutable draft data.
func (s *state) authorizationPolicy() *editablePolicy {
	p, version, err := s.latestPublicationSnapshot()
	if err != nil {
		return &editablePolicy{}
	}
	if version != "" && p != nil {
		return p
	}
	return s.readDraft()
}

func (s *state) loadPolicyDraft() (*editablePolicy, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var document string
	err = db.QueryRow(`SELECT document FROM policy_draft WHERE id = 1`).Scan(&document)
	if err == sql.ErrNoRows {
		// One-time migration from the original JSON draft store.
		data, readErr := os.ReadFile(s.draftPath())
		if readErr != nil {
			return &editablePolicy{Name: "policy"}, nil
		}
		var p editablePolicy
		if json.Unmarshal(data, &p) != nil {
			return &editablePolicy{Name: "policy"}, nil
		}
		normalizeEditablePolicy(&p)
		if err := s.storePolicyDraft(db, &p); err != nil {
			return nil, err
		}
		return &p, nil
	}
	if err != nil {
		return nil, err
	}
	var p editablePolicy
	if err := json.Unmarshal([]byte(document), &p); err != nil {
		return nil, fmt.Errorf("decode policy draft: %w", err)
	}
	normalizeEditablePolicy(&p)
	return &p, nil
}

func normalizeEditablePolicy(p *editablePolicy) {
	normalizeCatalog(&p.NamingCatalog)
	if p.FQDNs == nil {
		p.FQDNs = []editableFQDN{}
	}
	for i := range p.Users {
		if p.Users[i].Role == "" {
			if i == 0 {
				p.Users[i].Role = "admin"
			} else {
				p.Users[i].Role = "viewer"
			}
		}
	}
	for i := range p.Services {
		for j := range p.Services[i].Rules {
			rule := &p.Services[i].Rules[j]
			rule.HasUser = strings.ToLower(strings.TrimSpace(rule.HasUser))
			if rule.HasUser == "" {
				rule.HasUser = "src"
			}
			if len(p.TargetContexts) != 0 && !stableIDRE.MatchString(rule.StableRuleID) {
				rule.StableRuleID = newStableRuleID()
				rule.ShortID = ""
			}
		}
	}
}

func (s *state) storePolicyDraft(db *sql.DB, p *editablePolicy) error {
	_, err := s.storePolicyDraftVersion(db, p, "", nil)
	return err
}

func (s *state) storePolicyDraftVersion(db *sql.DB, p *editablePolicy, actor string, expected *int64) (draftMetadata, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return draftMetadata{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := db.Begin()
	if err != nil {
		return draftMetadata{}, err
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRow(`SELECT version FROM policy_draft WHERE id=1`).Scan(&current)
	if err == sql.ErrNoRows {
		if expected != nil && *expected != 0 {
			return draftMetadata{}, errDraftConflict
		}
		current = 1
		_, err = tx.Exec(`INSERT INTO policy_draft(id, document, updated_at, version, updated_by) VALUES(1, ?, ?, ?, ?)`, string(data), now, current, actor)
	} else if err == nil {
		if expected != nil && *expected != current {
			return draftMetadata{}, errDraftConflict
		}
		current++
		_, err = tx.Exec(`UPDATE policy_draft SET document=?, updated_at=?, version=?, updated_by=? WHERE id=1`, string(data), now, current, actor)
	}
	if err != nil {
		return draftMetadata{}, err
	}
	if err = tx.Commit(); err != nil {
		return draftMetadata{}, err
	}
	return draftMetadata{Version: current, UpdatedAt: now, UpdatedBy: actor}, nil
}

func (s *state) storePublication(version string, p *editablePolicy) error {
	return s.storePublicationBy(version, p, "", version)
}

func (s *state) storePublicationBy(version string, p *editablePolicy, actor, sourceRevision string) error {
	return s.finalizePublication(version, p, actor, false)
}

// finalizePublication commits the immutable publication and, for reviewed
// changes, the pending-to-published transition in one SQLite transaction.
func (s *state) finalizePublication(version string, p *editablePolicy, actor string, requirePending bool) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Publication and deployment share a database-level interlock. Checking in
	// this transaction prevents the meaning of "latest published revision"
	// from changing while a confirmed deployment is in flight. Installations
	// that have never initialized deployment logging do not have the lock table
	// yet and retain the normal publication path.
	var lockTable string
	if lockErr := tx.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='policy_deployment_lock'`).Scan(&lockTable); lockErr != nil && !errors.Is(lockErr, sql.ErrNoRows) {
		return lockErr
	} else if lockErr == nil {
		cutoff := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
		var active string
		lockErr = tx.QueryRow(`SELECT deployment_id FROM policy_deployment_lock WHERE id=1 AND acquired_at >= ?`, cutoff).Scan(&active)
		if lockErr == nil && active != publicationLockID(version) {
			return errDeploymentRunning
		}
		if lockErr != nil && !errors.Is(lockErr, sql.ErrNoRows) {
			return lockErr
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.Exec(`INSERT INTO policy_publication(version, document, published_at, published_by, source_revision) VALUES(?, ?, ?, ?, ?)`, version, string(data), now, actor, version); err != nil {
		return err
	}
	if requirePending {
		result, updateErr := tx.Exec(`UPDATE policy_revision SET status='published', published_at=?, approved_by=? WHERE version=? AND status='pending'`, now, actor, version)
		if updateErr != nil {
			return updateErr
		}
		if count, _ := result.RowsAffected(); count != 1 {
			return errors.New("revision is not pending")
		}
	}
	return tx.Commit()
}

func (s *state) loadPublication(version string) (*editablePolicy, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var document string
	if err := db.QueryRow(`SELECT document FROM policy_publication WHERE version=?`, version).Scan(&document); err != nil {
		return nil, err
	}
	var p editablePolicy
	if err := json.Unmarshal([]byte(document), &p); err != nil {
		return nil, err
	}
	normalizeEditablePolicy(&p)
	return &p, nil
}

func (s *state) latestPublication() (*editablePolicy, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var document string
	err = db.QueryRow(`SELECT document FROM policy_publication ORDER BY published_at DESC LIMIT 1`).Scan(&document)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p editablePolicy
	if err := json.Unmarshal([]byte(document), &p); err != nil {
		return nil, err
	}
	return &p, nil
}
