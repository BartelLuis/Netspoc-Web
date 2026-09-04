package backend

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

var (
	errAccountConflict     = errors.New("user accounts changed since they were loaded")
	errAccountReferenced   = errors.New("user account is referenced by a policy")
	errLastAccountAdmin    = errors.New("at least one active administrator or developer account is required")
	errAccountUnauthorized = errors.New("user account administrator role required")
)

type accountMutationRequest struct {
	Email        string `json:"email"`
	Role         string `json:"role,omitempty"`
	Revision     int64  `json:"revision,omitempty"`
	UsersVersion *int64 `json:"users_version"`
}

// migratePolicyAccounts is an idempotent, transactional one-time import from
// the latest immutable legacy publication. Mutable drafts and draft files are
// deliberately never authorization sources.
func (s *state) migratePolicyAccounts(db *sql.DB) error {
	var initialized int
	if err := db.QueryRow(`SELECT 1 FROM policy_account_state WHERE id=1`).Scan(&initialized); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var document string
	err := db.QueryRow(`SELECT document FROM policy_publication ORDER BY published_at DESC, version DESC LIMIT 1`).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		document, err = "", nil
	}
	if err != nil {
		return fmt.Errorf("read legacy account catalog: %w", err)
	}
	users := []editableUser{}
	if document != "" {
		var legacy editablePolicy
		if err := json.Unmarshal([]byte(document), &legacy); err != nil {
			return fmt.Errorf("decode legacy account catalog: %w", err)
		}
		users = legacy.Users
	}
	normalized, err := normalizeAccountCatalog(users, false)
	if err != nil {
		return fmt.Errorf("migrate legacy account catalog: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	version := int64(0)
	if len(normalized) != 0 {
		version = 1
	}
	result, err := tx.Exec(`INSERT OR IGNORE INTO policy_account_state(id, version, initialized_at) VALUES(1, ?, ?)`, version, now)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return tx.Commit()
	}
	for _, user := range normalized {
		if _, err := tx.Exec(`INSERT INTO policy_account(email, role, source, directory_id, username, active, revision, created_at, created_by, updated_at, updated_by)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`, user.Email, user.Role, user.Source, user.DirectoryID, user.Username, boolInt(user.Active), user.Revision, now, "migration", now, "migration"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func normalizeAccountCatalog(users []editableUser, requirePrivileged bool) ([]editableUser, error) {
	result := make([]editableUser, 0, len(users))
	emails := map[string]bool{}
	directoryIDs := map[string]bool{}
	hasPrivileged := false
	for i, input := range users {
		email, err := canonicalAccountEmail(input.Email)
		if err != nil {
			return nil, errors.New("invalid user email")
		}
		if emails[email] {
			return nil, fmt.Errorf("duplicate user %q", email)
		}
		emails[email] = true
		role := strings.ToLower(strings.TrimSpace(input.Role))
		if role == "" {
			if i == 0 {
				role = "admin"
			} else {
				role = "viewer"
			}
		}
		if !slices.Contains([]string{policyDeveloperRole, "admin", "editor", "reviewer", "deployer", "viewer"}, role) {
			return nil, fmt.Errorf("user %q has invalid role %q", email, input.Role)
		}
		source := strings.ToLower(strings.TrimSpace(input.Source))
		if source == "" {
			source = "local"
		}
		user := editableUser{Email: email, Role: role, Source: source, Password: "", Revision: input.Revision}
		if user.Revision < 1 {
			user.Revision = 1
		}
		switch source {
		case "local":
			if strings.TrimSpace(input.DirectoryID) != "" {
				return nil, fmt.Errorf("local user %q must not have a directory_id", email)
			}
			user.Active = true
		case "ldap":
			user.DirectoryID = strings.TrimSpace(input.DirectoryID)
			user.Username = strings.TrimSpace(input.Username)
			user.Active = input.Active
			if user.DirectoryID == "" {
				return nil, fmt.Errorf("LDAP user %q requires a directory_id", email)
			}
			if directoryIDs[user.DirectoryID] {
				return nil, fmt.Errorf("LDAP directory_id %q is duplicated", user.DirectoryID)
			}
			directoryIDs[user.DirectoryID] = true
		default:
			return nil, fmt.Errorf("user %q has invalid source %q", email, input.Source)
		}
		if user.Active && (user.Role == "admin" || user.Role == policyDeveloperRole) {
			hasPrivileged = true
		}
		result = append(result, user)
	}
	if requirePrivileged && !hasPrivileged {
		return nil, errLastAccountAdmin
	}
	slices.SortFunc(result, func(a, b editableUser) int { return strings.Compare(a.Email, b.Email) })
	return result, nil
}

func scanAccounts(rows *sql.Rows) ([]editableUser, error) {
	users := []editableUser{}
	for rows.Next() {
		var user editableUser
		var active int
		if err := rows.Scan(&user.Email, &user.Role, &user.Source, &user.DirectoryID, &user.Username, &active, &user.Revision); err != nil {
			return nil, err
		}
		user.Active = active != 0
		users = append(users, user)
	}
	return users, rows.Err()
}

func accountCatalogTx(tx *sql.Tx) ([]editableUser, int64, error) {
	var version int64
	if err := tx.QueryRow(`SELECT version FROM policy_account_state WHERE id=1`).Scan(&version); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(`SELECT email, role, source, directory_id, username, active, revision FROM policy_account ORDER BY email`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	users, err := scanAccounts(rows)
	return users, version, err
}

func (s *state) accountCatalog() ([]editableUser, int64, error) {
	db, err := s.policyDB()
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	users, version, err := accountCatalogTx(tx)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return users, version, nil
}

func (s *state) attachPolicyAccounts(p *editablePolicy) error {
	if p == nil {
		return errors.New("policy is required")
	}
	users, version, err := s.accountCatalog()
	if err != nil {
		p.Users = nil
		p.AccountsVersion = nil
		return err
	}
	p.Users = append([]editableUser(nil), users...)
	p.AccountsVersion = &version
	return nil
}

// fencePolicyAccountsTx turns the account snapshot used to validate owner
// references into a write-transaction precondition. Account mutations update
// the same singleton row, so an account cannot disappear between validation
// and persistence of a draft, revision or publication that references it.
func fencePolicyAccountsTx(tx *sql.Tx, p *editablePolicy) error {
	if p == nil || p.AccountsVersion == nil {
		return nil
	}
	result, err := tx.Exec(`UPDATE policy_account_state SET version=version WHERE id=1 AND version=?`, *p.AccountsVersion)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errAccountConflict
	}
	return nil
}

func (s *state) activeAccount(email string) (editableUser, bool) {
	email, err := canonicalAccountEmail(email)
	if err != nil {
		return editableUser{}, false
	}
	db, err := s.policyDB()
	if err != nil {
		return editableUser{}, false
	}
	defer db.Close()
	var user editableUser
	var active int
	err = db.QueryRow(`SELECT email, role, source, directory_id, username, active, revision FROM policy_account WHERE email=?`, email).
		Scan(&user.Email, &user.Role, &user.Source, &user.DirectoryID, &user.Username, &active, &user.Revision)
	if err != nil || active == 0 {
		return editableUser{}, false
	}
	user.Active = true
	return user, true
}

func (s *state) seedSetupAccountsTx(tx *sql.Tx, users []editableUser, actor string) error {
	if len(users) == 0 {
		return errors.New("initial setup requires an administrator account")
	}
	normalized, err := normalizeAccountCatalog(users, true)
	if err != nil {
		return err
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM policy_account`).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return errors.New("user accounts are already initialized")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, user := range normalized {
		if _, err := tx.Exec(`INSERT INTO policy_account(email, role, source, directory_id, username, active, revision, created_at, created_by, updated_at, updated_by)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`, user.Email, user.Role, user.Source, user.DirectoryID, user.Username, boolInt(user.Active), 1, now, actor, now, actor); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`UPDATE policy_account_state SET version=version+1 WHERE id=1`)
	return err
}

func beginAccountMutation(db *sql.DB, expected int64, actor string) (*sql.Tx, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	result, err := tx.Exec(`UPDATE policy_account_state SET version=version+1 WHERE id=1 AND version=?`, expected)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		tx.Rollback()
		if err != nil {
			return nil, err
		}
		return nil, errAccountConflict
	}
	var role string
	var active int
	err = tx.QueryRow(`SELECT role, active FROM policy_account WHERE email=?`, strings.ToLower(strings.TrimSpace(actor))).Scan(&role, &active)
	if err != nil || active == 0 || (role != "admin" && role != policyDeveloperRole) {
		tx.Rollback()
		return nil, errAccountUnauthorized
	}
	return tx, nil
}

func ensurePrivilegedAccountTx(tx *sql.Tx) error {
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM policy_account WHERE active=1 AND role IN ('admin','developer')`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return errLastAccountAdmin
	}
	return nil
}

func auditAccountMutationTx(tx *sql.Tx, actor, action string, metadata any) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO policy_audit(actor, action, result, metadata, created_at) VALUES(?,?,?,?,?)`,
		strings.ToLower(strings.TrimSpace(actor)), action, "success", string(data), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *state) accountReferencesTx(tx *sql.Tx, email string) ([]string, error) {
	rows, err := tx.Query(`
		SELECT 'draft', document FROM policy_draft WHERE id=1
		UNION ALL
		SELECT 'publication', document FROM policy_publication WHERE version=(SELECT version FROM policy_publication ORDER BY published_at DESC LIMIT 1)
		UNION ALL
		SELECT 'revision:' || version, document FROM policy_revision WHERE status='pending'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	references := []string{}
	for rows.Next() {
		var label, document string
		if err := rows.Scan(&label, &document); err != nil {
			return nil, err
		}
		var policy editablePolicy
		if err := json.Unmarshal([]byte(document), &policy); err != nil {
			return nil, err
		}
		for _, owner := range policy.Owners {
			for _, candidate := range slices.Concat(slices.Clone(owner.Admins), owner.Users, owner.Watchers) {
				if strings.EqualFold(strings.TrimSpace(candidate), email) {
					references = append(references, label+":"+owner.Name)
					break
				}
			}
		}
	}
	slices.Sort(references)
	return slices.Compact(references), rows.Err()
}

func (s *state) createAccount(actor string, request accountMutationRequest) ([]editableUser, int64, error) {
	if request.UsersVersion == nil {
		return nil, 0, errors.New("users_version is required")
	}
	users, err := normalizeAccountCatalog([]editableUser{{Email: request.Email, Role: request.Role, Source: "local", Active: true}}, false)
	if err != nil {
		return nil, 0, err
	}
	user := users[0]
	db, err := s.policyDB()
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	tx, err := beginAccountMutation(db, *request.UsersVersion, actor)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`INSERT INTO policy_account(email, role, source, directory_id, username, active, revision, created_at, created_by, updated_at, updated_by)
		VALUES(?,?, 'local', '', '', 1, 1, ?, ?, ?, ?)`, user.Email, user.Role, now, strings.ToLower(actor), now, strings.ToLower(actor)); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, 0, fmt.Errorf("user %q already exists", user.Email)
		}
		return nil, 0, err
	}
	if err := ensurePrivilegedAccountTx(tx); err != nil {
		return nil, 0, err
	}
	if err := auditAccountMutationTx(tx, actor, "account.create", map[string]any{
		"email": user.Email, "role": user.Role, "users_version": *request.UsersVersion + 1,
	}); err != nil {
		return nil, 0, err
	}
	result, version, err := accountCatalogTx(tx)
	if err != nil {
		return nil, 0, err
	}
	// A deleted and re-created local account must never inherit its old
	// password. Invalidate it before exposing the account; a database commit
	// failure can at worst leave a safely disabled stale credential.
	if err := s.clearAccountCredential(user.Email); err != nil {
		return nil, 0, fmt.Errorf("invalidate previous local credential: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return result, version, nil
}

func (s *state) updateAccount(actor string, request accountMutationRequest) ([]editableUser, int64, error) {
	if request.UsersVersion == nil || request.Revision < 1 {
		return nil, 0, errors.New("users_version and revision are required")
	}
	email, err := canonicalAccountEmail(request.Email)
	if err != nil {
		return nil, 0, err
	}
	role := strings.ToLower(strings.TrimSpace(request.Role))
	if !slices.Contains([]string{policyDeveloperRole, "admin", "editor", "reviewer", "deployer", "viewer"}, role) {
		return nil, 0, fmt.Errorf("user %q has invalid role %q", email, request.Role)
	}
	db, err := s.policyDB()
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	tx, err := beginAccountMutation(db, *request.UsersVersion, actor)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var currentRole string
	if err := tx.QueryRow(`SELECT role FROM policy_account WHERE email=? AND revision=?`, email, request.Revision).Scan(&currentRole); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, errAccountConflict
		}
		return nil, 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.Exec(`UPDATE policy_account SET role=?, revision=revision+1, updated_at=?, updated_by=? WHERE email=? AND revision=?`, role, now, strings.ToLower(actor), email, request.Revision)
	if err != nil {
		return nil, 0, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return nil, 0, errAccountConflict
	}
	if err := ensurePrivilegedAccountTx(tx); err != nil {
		return nil, 0, err
	}
	if err := auditAccountMutationTx(tx, actor, "account.update", map[string]any{
		"email": email, "previous_role": currentRole, "role": role, "users_version": *request.UsersVersion + 1,
	}); err != nil {
		return nil, 0, err
	}
	users, version, err := accountCatalogTx(tx)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return users, version, nil
}

func (s *state) deleteAccount(actor string, request accountMutationRequest) ([]editableUser, int64, error) {
	if request.UsersVersion == nil || request.Revision < 1 {
		return nil, 0, errors.New("users_version and revision are required")
	}
	email, err := canonicalAccountEmail(request.Email)
	if err != nil {
		return nil, 0, err
	}
	db, err := s.policyDB()
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	tx, err := beginAccountMutation(db, *request.UsersVersion, actor)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var source, role string
	if err := tx.QueryRow(`SELECT source, role FROM policy_account WHERE email=? AND revision=?`, email, request.Revision).Scan(&source, &role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, errAccountConflict
		}
		return nil, 0, err
	}
	if source == "ldap" {
		return nil, 0, errors.New("LDAP users are managed by directory sync")
	}
	references, err := s.accountReferencesTx(tx, email)
	if err != nil {
		return nil, 0, err
	}
	if len(references) != 0 {
		return nil, 0, fmt.Errorf("%w: %s", errAccountReferenced, strings.Join(references, ", "))
	}
	result, err := tx.Exec(`DELETE FROM policy_account WHERE email=? AND revision=?`, email, request.Revision)
	if err != nil {
		return nil, 0, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return nil, 0, errAccountConflict
	}
	if err := ensurePrivilegedAccountTx(tx); err != nil {
		return nil, 0, err
	}
	// Clearing before commit fails safely: the account remains present if the
	// database transaction cannot commit, but a removed account can never leave
	// a reusable password artifact behind.
	if err := s.clearAccountCredential(email); err != nil {
		return nil, 0, fmt.Errorf("invalidate local credential: %w", err)
	}
	if err := auditAccountMutationTx(tx, actor, "account.delete", map[string]any{
		"email": email, "role": role, "users_version": *request.UsersVersion + 1,
	}); err != nil {
		return nil, 0, err
	}
	users, version, err := accountCatalogTx(tx)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return users, version, nil
}

func sameAccountIdentity(a, b editableUser) bool {
	return a.Email == b.Email && a.Role == b.Role && a.Source == b.Source &&
		a.DirectoryID == b.DirectoryID && a.Username == b.Username && a.Active == b.Active
}

// applyLDAPAccountPreview commits only directory-owned identity/status fields.
// Local accounts and every existing role must match the actor-bound preview;
// the global version CAS rejects a concurrent role or account mutation.
func (s *state) applyLDAPAccountPreview(actor string, expected int64, previewUsers []editableUser) ([]editableUser, int64, error) {
	next, err := normalizeAccountCatalog(previewUsers, true)
	if err != nil {
		return nil, 0, err
	}
	db, err := s.policyDB()
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	tx, err := beginAccountMutation(db, expected, actor)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	current, _, err := accountCatalogTx(tx)
	if err != nil {
		return nil, 0, err
	}
	currentByEmail := make(map[string]editableUser, len(current))
	for _, user := range current {
		currentByEmail[user.Email] = user
	}
	seen := make(map[string]bool, len(next))
	now := time.Now().UTC().Format(time.RFC3339Nano)
	actor = strings.ToLower(strings.TrimSpace(actor))
	for _, user := range next {
		old, exists := currentByEmail[user.Email]
		if !exists {
			if user.Source != "ldap" {
				return nil, 0, errors.New("LDAP sync may not create local accounts")
			}
			if _, err := tx.Exec(`INSERT INTO policy_account(email, role, source, directory_id, username, active, revision, created_at, created_by, updated_at, updated_by)
				VALUES(?,?,?,?,?,?,1,?,?,?,?)`, user.Email, user.Role, user.Source, user.DirectoryID, user.Username, boolInt(user.Active), now, actor, now, actor); err != nil {
				return nil, 0, err
			}
			seen[user.Email] = true
			continue
		}
		seen[user.Email] = true
		if old.Source != user.Source || old.Role != user.Role {
			return nil, 0, errors.New("LDAP sync may not change account sources or roles")
		}
		if old.Source == "local" {
			if !sameAccountIdentity(old, user) {
				return nil, 0, errors.New("LDAP sync may not change local accounts")
			}
			continue
		}
		if sameAccountIdentity(old, user) {
			continue
		}
		if _, err := tx.Exec(`UPDATE policy_account SET directory_id=?, username=?, active=?, revision=revision+1, updated_at=?, updated_by=? WHERE email=? AND revision=?`,
			user.DirectoryID, user.Username, boolInt(user.Active), now, actor, user.Email, old.Revision); err != nil {
			return nil, 0, err
		}
	}
	for _, old := range current {
		if !seen[old.Email] {
			return nil, 0, errors.New("LDAP sync preview omitted an existing account")
		}
	}
	if err := ensurePrivilegedAccountTx(tx); err != nil {
		return nil, 0, err
	}
	if err := auditAccountMutationTx(tx, actor, "account.ldap_sync", map[string]any{
		"users_version": expected + 1,
	}); err != nil {
		return nil, 0, err
	}
	users, version, err := accountCatalogTx(tx)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return users, version, nil
}

func (s *state) clearAccountCredential(email string) error {
	if s.config == nil || strings.TrimSpace(s.config.UserDir) == "" {
		return nil
	}
	userFile, err := safeUserFile(s.config.UserDir, email)
	if err != nil {
		return err
	}
	err = updateUserStore(userFile, false, func(store *UserStore) (bool, error) {
		if store.Hash == "" {
			return false, nil
		}
		store.Hash = ""
		return true, nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func accountErrorStatus(err error) int {
	switch {
	case errors.Is(err, errAccountConflict), errors.Is(err, errAccountReferenced), errors.Is(err, errLastAccountAdmin):
		return http.StatusConflict
	case errors.Is(err, errAccountUnauthorized):
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
}

func (s *state) adminUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor := strings.ToLower(strings.TrimSpace(getEmailFromSession(r)))
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin") {
		s.audit(actor, "account.access", "denied", nil)
		writeError(w, "User account administrator role required", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet {
		users, version, err := s.accountCatalog()
		if err != nil {
			writeError(w, "User accounts are unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"success": true, "users": users, "users_version": version})
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request accountMutationRequest
	if err := decodeJSONRequest(w, r, 64<<10, &request); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var users []editableUser
	var version int64
	var err error
	action := "account.create"
	switch r.Method {
	case http.MethodPost:
		users, version, err = s.createAccount(actor, request)
	case http.MethodPut:
		action = "account.update"
		users, version, err = s.updateAccount(actor, request)
	case http.MethodDelete:
		action = "account.delete"
		users, version, err = s.deleteAccount(actor, request)
	}
	if err != nil {
		s.audit(actor, action, "failed", map[string]any{"email": strings.ToLower(strings.TrimSpace(request.Email)), "error": err.Error()})
		writeError(w, err.Error(), accountErrorStatus(err))
		return
	}
	writeJSON(w, map[string]any{"success": true, "users": users, "users_version": version})
}
