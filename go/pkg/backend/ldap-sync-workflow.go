package backend

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const ldapSyncPreviewLifetime = 15 * time.Minute

var (
	errLDAPPreviewInvalid = errors.New("LDAP sync preview is invalid or expired")
	errLDAPPreviewStale   = errors.New("user accounts changed after LDAP sync preview")
)

type storedLDAPSyncPreview struct {
	Token        string
	Actor        string
	UsersVersion int64
	ExpiresAt    string
	Added        int
	Updated      int
	Disabled     int
	Users        []editableUser
}

func ensureLDAPSyncPreviewTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ldap_sync_preview (
		token_hash TEXT PRIMARY KEY,
		actor TEXT NOT NULL,
		draft_version INTEGER NOT NULL,
		document TEXT NOT NULL,
		added INTEGER NOT NULL,
		updated INTEGER NOT NULL,
		disabled INTEGER NOT NULL,
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL
	)`)
	return err
}

func ldapPreviewTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *state) storeLDAPSyncPreview(actor string, usersVersion int64, preview ldapSyncPreview) (storedLDAPSyncPreview, error) {
	document, err := json.Marshal(preview.Users)
	if err != nil {
		return storedLDAPSyncPreview{}, err
	}
	token := randomToken(32)
	now := time.Now().UTC()
	expires := now.Add(ldapSyncPreviewLifetime)
	db, err := s.policyDB()
	if err != nil {
		return storedLDAPSyncPreview{}, err
	}
	defer db.Close()
	if err := ensureLDAPSyncPreviewTable(db); err != nil {
		return storedLDAPSyncPreview{}, err
	}
	actor = strings.ToLower(strings.TrimSpace(actor))
	tx, err := db.Begin()
	if err != nil {
		return storedLDAPSyncPreview{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM ldap_sync_preview WHERE expires_at <= ? OR actor = ?`, now.Format(time.RFC3339Nano), actor); err != nil {
		return storedLDAPSyncPreview{}, err
	}
	if _, err := tx.Exec(`INSERT INTO ldap_sync_preview(token_hash, actor, draft_version, document, added, updated, disabled, created_at, expires_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, ldapPreviewTokenHash(token), actor, usersVersion, string(document), preview.Added, preview.Updated, preview.Disabled,
		now.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano)); err != nil {
		return storedLDAPSyncPreview{}, err
	}
	if err := tx.Commit(); err != nil {
		return storedLDAPSyncPreview{}, err
	}
	return storedLDAPSyncPreview{
		Token: token, Actor: actor, UsersVersion: usersVersion, ExpiresAt: expires.Format(time.RFC3339Nano),
		Added: preview.Added, Updated: preview.Updated, Disabled: preview.Disabled, Users: preview.Users,
	}, nil
}

func (s *state) loadLDAPSyncPreview(actor, token string) (storedLDAPSyncPreview, error) {
	actor = strings.ToLower(strings.TrimSpace(actor))
	token = strings.TrimSpace(token)
	if actor == "" || token == "" {
		return storedLDAPSyncPreview{}, errLDAPPreviewInvalid
	}
	db, err := s.policyDB()
	if err != nil {
		return storedLDAPSyncPreview{}, err
	}
	defer db.Close()
	if err := ensureLDAPSyncPreviewTable(db); err != nil {
		return storedLDAPSyncPreview{}, err
	}
	var result storedLDAPSyncPreview
	var document string
	err = db.QueryRow(`SELECT actor, draft_version, document, added, updated, disabled, expires_at
		FROM ldap_sync_preview WHERE token_hash = ? AND actor = ?`, ldapPreviewTokenHash(token), actor).
		Scan(&result.Actor, &result.UsersVersion, &document, &result.Added, &result.Updated, &result.Disabled, &result.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return storedLDAPSyncPreview{}, errLDAPPreviewInvalid
	}
	if err != nil {
		return storedLDAPSyncPreview{}, err
	}
	expires, err := time.Parse(time.RFC3339Nano, result.ExpiresAt)
	if err != nil || !time.Now().UTC().Before(expires) {
		return storedLDAPSyncPreview{}, errLDAPPreviewInvalid
	}
	if err := json.Unmarshal([]byte(document), &result.Users); err != nil {
		return storedLDAPSyncPreview{}, fmt.Errorf("decode LDAP sync preview: %w", err)
	}
	result.Token = token
	return result, nil
}

func (s *state) consumeLDAPSyncPreview(token string) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	if err := ensureLDAPSyncPreviewTable(db); err != nil {
		return err
	}
	_, err = db.Exec(`DELETE FROM ldap_sync_preview WHERE token_hash = ?`, ldapPreviewTokenHash(strings.TrimSpace(token)))
	return err
}
