package backend

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func (s *state) policyDB() (*sql.DB, error) {
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
		);`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

type policyRevisionSummary struct {
	Version   string              `json:"version"`
	Base      string              `json:"base"`
	Status    string              `json:"status"`
	CreatedAt string              `json:"created_at"`
	Changes   []map[string]string `json:"changes"`
}

func (s *state) storeRevision(version, base string, p *editablePolicy, changes []map[string]string) error {
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
	_, err = db.Exec(`INSERT INTO policy_revision(version, base_version, document, changes, status, created_at) VALUES(?, ?, ?, ?, 'pending', ?)`, version, base, string(document), string(diff), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *state) loadRevision(version string) (*editablePolicy, string, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, "", err
	}
	defer db.Close()
	var document, base string
	if err := db.QueryRow(`SELECT document, base_version FROM policy_revision WHERE version = ? AND status = 'pending'`, version).Scan(&document, &base); err != nil {
		return nil, "", err
	}
	var p editablePolicy
	if err := json.Unmarshal([]byte(document), &p); err != nil {
		return nil, "", err
	}
	normalizeEditablePolicy(&p)
	return &p, base, nil
}

func (s *state) markRevisionPublished(version string) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`UPDATE policy_revision SET status = 'published', published_at = ? WHERE version = ?`, time.Now().UTC().Format(time.RFC3339Nano), version)
	return err
}

func (s *state) listRevisions() ([]policyRevisionSummary, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT version, base_version, status, created_at, changes FROM policy_revision ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []policyRevisionSummary{}
	for rows.Next() {
		var item policyRevisionSummary
		var changes string
		if err := rows.Scan(&item.Version, &item.Base, &item.Status, &item.CreatedAt, &changes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(changes), &item.Changes); err != nil {
			return nil, err
		}
		if item.Changes == nil {
			item.Changes = []map[string]string{}
		}
		result = append(result, item)
	}
	return result, rows.Err()
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
		}
	}
}

func (s *state) storePolicyDraft(db *sql.DB, p *editablePolicy) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO policy_draft(id, document, updated_at) VALUES(1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET document=excluded.document, updated_at=excluded.updated_at`, string(data), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *state) storePublication(version string, p *editablePolicy) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO policy_publication(version, document, published_at) VALUES(?, ?, ?)`, version, string(data), time.Now().UTC().Format(time.RFC3339Nano))
	return err
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
