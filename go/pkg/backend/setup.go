package backend

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	setupRequestLimit      = 16 << 10
	setupPasswordMinRunes  = 12
	setupPasswordMaxRunes  = 256
	setupNameMaxBytes      = 64
	setupClaimLease        = 5 * time.Minute
	defaultSetupPolicyName = "policy"
	defaultSetupOwnerName  = "administration"
)

var (
	errSetupAlreadyClaimed = errors.New("initial setup is already running or completed")
	errSetupAccountExists  = errors.New("local setup account already exists")
)

type setupRequest struct {
	Email                string `json:"email"`
	Password             string `json:"password"`
	PasswordConfirmation string `json:"password_confirmation"`
	PolicyName           string `json:"policy_name,omitempty"`
	OwnerName            string `json:"owner_name,omitempty"`
}

type setupClaim struct {
	ID      string
	Release func()
	Abandon func()
}

type preparedSetupCredential struct {
	UserFile string
	Hash     string
	Digest   string
	Data     []byte
}

type setupPublicationState uint8

const (
	setupPublicationUnknown setupPublicationState = iota
	setupPublicationAbsent
	setupPublicationExact
	setupPublicationMismatch
)

type setupGuardRecord struct {
	ClaimID              string
	ClaimedAt            int64
	CredentialEmail      string
	CredentialDigest     string
	PublicationVersion   string
	PublicationDigest    string
	RollbackDraftVersion int64
}

// setup performs the one-time creation of a local administrator, the initial
// immutable authorization policy and the authenticated browser session. The
// bootstrap token is checked by requireBootstrapToken before this handler is
// entered. No request credential becomes part of policy JSON or an API reply.
func (s *state) setup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.config == nil || strings.TrimSpace(s.config.NetspocData) == "" || strings.TrimSpace(s.config.UserDir) == "" {
		writeError(w, "Setup is unavailable", http.StatusInternalServerError)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, "Content-Type application/json is required", http.StatusUnsupportedMediaType)
		return
	}

	defer r.Body.Close()
	var request setupRequest
	if err := decodeJSONRequest(w, r, setupRequestLimit, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, "Setup request is too large", http.StatusRequestEntityTooLarge)
		} else {
			writeError(w, "Invalid setup request", http.StatusBadRequest)
		}
		return
	}
	email, policy, err := validateSetupRequest(request)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Serializing the initialized check through publication closes the race in
	// which two first-run requests both observe an empty publication store.
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if err := s.reconcileStaleSetupClaim(); err != nil {
		writeError(w, "Setup state could not be recovered", http.StatusInternalServerError)
		return
	}
	version, err := s.latestPublicationVersion()
	if err != nil {
		writeError(w, "Setup state could not be verified", http.StatusInternalServerError)
		return
	}
	if version != "" {
		writeError(w, "Policy administration is already initialized", http.StatusConflict)
		return
	}
	claim, err := s.acquireSetupClaim()
	if errors.Is(err, errSetupAlreadyClaimed) {
		writeError(w, "Policy administration is already being initialized", http.StatusConflict)
		return
	}
	if err != nil {
		writeError(w, "Setup state could not be reserved", http.StatusInternalServerError)
		return
	}
	releaseClaim := true
	defer func() {
		if releaseClaim {
			claim.Release()
		}
	}()

	// Derive the exact document before journaling its digest. Publishing repeats
	// these idempotent normalizations, so a restart can later verify that it is
	// recovering this request rather than an unrelated publication.
	normalizeEditablePolicy(policy)
	if err := prepareManualPolicyNames(policy); err != nil {
		writeError(w, "Initial policy could not be prepared", http.StatusInternalServerError)
		return
	}
	setupVersion := newPolicyVersion()
	policyDigest, err := setupPolicyDigest(policy)
	if err != nil {
		writeError(w, "Initial policy could not be prepared", http.StatusInternalServerError)
		return
	}
	draftSnapshot, err := s.snapshotStoredPolicyDraft()
	if err != nil {
		writeError(w, "Initial policy state could not be recorded", http.StatusInternalServerError)
		return
	}
	rollbackDraftVersion := int64(0)
	if draftSnapshot.Exists {
		rollbackDraftVersion = draftSnapshot.Version
	}

	credential, err := prepareSetupUserPassword(s.config.UserDir, email, request.Password)
	if err == nil {
		err = s.recordSetupClaimCredential(claim.ID, email, credential.Digest, setupVersion, policyDigest, rollbackDraftVersion)
	}
	if err == nil {
		err = createPreparedSetupCredential(credential)
	}
	if errors.Is(err, errSetupAccountExists) {
		// First-run setup must never reset an account created by an operator,
		// including one created concurrently after request validation.
		writeError(w, "A local account already exists for this email", http.StatusConflict)
		return
	}
	if err != nil {
		writeError(w, "Local administrator could not be created", http.StatusInternalServerError)
		return
	}
	retainCredential := false
	defer func() {
		if retainCredential {
			return
		}
		// Remove only the exact hash created by this request. If an operator has
		// changed the password in the meantime, their credential wins.
		rollbackSetupCredential(credential.UserFile, credential.Hash)
	}()

	if err := s.publishSetupPolicyVersion(policy, setupVersion, claim.ID); err != nil {
		publicationState, published := s.inspectSetupPublication(setupVersion, policyDigest)
		switch publicationState {
		case setupPublicationExact:
			// publishPolicyVersion rolls back the compatibility artifacts after
			// any reported commit error. Re-create them only after proving that
			// the exact immutable publication was durably committed.
			retainCredential = true
			if repairErr := s.restoreSetupPublicationArtifacts(setupVersion, policyDigest, rollbackDraftVersion, published); repairErr != nil {
				releaseClaim = false
				claim.Abandon()
				writeError(w, "Initial policy recovery is pending", http.StatusInternalServerError)
				return
			}
		case setupPublicationUnknown:
			// A read/decode failure cannot prove that Commit failed. Preserve
			// both the exact credential and its journal so a later request or
			// process restart can reconcile without locking the administrator out.
			retainCredential = true
			releaseClaim = false
			claim.Abandon()
			writeError(w, "Initial policy state is temporarily unavailable", http.StatusInternalServerError)
			return
		default:
			writeError(w, "Initial policy could not be published", http.StatusInternalServerError)
			return
		}
	}
	retainCredential = true

	s.setLogin(GetGoSession(r), email)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = writeSetupResponse(w, email)
}

func setupPolicyDigest(policy *editablePolicy) (string, error) {
	data, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

// inspectSetupPublication deliberately distinguishes a confirmed absence from
// an unreadable state. Treating an I/O or decode error as absence could delete
// the only credential for a publication that SQLite already committed.
func (s *state) inspectSetupPublication(version, expectedDigest string) (setupPublicationState, *editablePolicy) {
	if !validSetupPublicationVersion(version) || !validSetupCredentialDigest(expectedDigest) {
		return setupPublicationMismatch, nil
	}
	actual, err := s.loadPublication(version)
	if errors.Is(err, sql.ErrNoRows) {
		return setupPublicationAbsent, nil
	}
	if err != nil {
		return setupPublicationUnknown, nil
	}
	actualDigest, err := setupPolicyDigest(actual)
	if err != nil {
		return setupPublicationUnknown, nil
	}
	expected, _ := hex.DecodeString(expectedDigest)
	observed, _ := hex.DecodeString(actualDigest)
	if subtle.ConstantTimeCompare(observed, expected) != 1 {
		return setupPublicationMismatch, actual
	}
	return setupPublicationExact, actual
}

func validSetupPublicationVersion(version string) bool {
	return version != "" && filepath.Base(version) == version && !strings.ContainsAny(version, `/\\`) && len(version) <= 96
}

// restoreSetupPublicationArtifacts repairs the compatibility draft and current
// pointer after an ambiguous SQLite commit. The immutable publication must be
// verified by inspectSetupPublication before calling this function.
func (s *state) restoreSetupPublicationArtifacts(version, expectedDigest string, rollbackDraftVersion int64, policy *editablePolicy) error {
	if policy == nil || rollbackDraftVersion < 0 || !validSetupPublicationVersion(version) || !validSetupCredentialDigest(expectedDigest) {
		return errors.New("invalid setup publication recovery")
	}
	lockID, err := s.acquireSetupRecoveryLock()
	if err != nil {
		return err
	}
	defer s.releaseDeploymentLock(lockID)

	// Re-check beneath the same singleton lock used by publication/deployment.
	// If a newer policy exists, the setup publication is committed but
	// superseded; never point current or the draft backwards to it.
	state, lockedPolicy := s.inspectSetupPublication(version, expectedDigest)
	if state != setupPublicationExact {
		return errors.New("setup publication could not be verified under recovery lock")
	}
	latest, err := s.latestPublicationVersion()
	if err != nil {
		return err
	}
	if latest != version {
		return nil
	}
	policy = lockedPolicy
	versionDir := filepath.Join(s.config.NetspocData, version)
	if info, statErr := os.Stat(versionDir); statErr != nil || !info.IsDir() {
		err = statErr
		if err == nil {
			err = errors.New("publication path is not a directory")
		}
		return fmt.Errorf("verify setup publication files: %w", err)
	}

	current := filepath.Join(s.config.NetspocData, "current")
	currentCorrect := false
	if info, err := os.Lstat(current); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New("current policy pointer is not a symbolic link")
		}
		if target, readErr := os.Readlink(current); readErr == nil && target == version {
			currentCorrect = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := s.ensureSetupPolicyDraft(policy, rollbackDraftVersion); err != nil {
		return fmt.Errorf("restore setup policy draft: %w", err)
	}
	if currentCorrect {
		return nil
	}

	recoveryID, err := newSetupClaimID()
	if err != nil {
		return err
	}
	temporary := filepath.Join(s.config.NetspocData, ".current-setup-recovery-"+recoveryID)
	if err := os.Symlink(version, temporary); err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, current); err != nil {
		return fmt.Errorf("restore current policy pointer: %w", err)
	}
	return nil
}

func (s *state) ensureSetupPolicyDraft(policy *editablePolicy, rollbackDraftVersion int64) error {
	snapshot, err := s.snapshotStoredPolicyDraft()
	if err != nil {
		return err
	}
	if snapshot.Exists {
		var existing editablePolicy
		if json.Unmarshal([]byte(snapshot.Document), &existing) == nil {
			normalizeEditablePolicy(&existing)
			if samePolicyDocument(&existing, policy) {
				return nil
			}
		}
	}
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = s.storePolicyDraftVersion(db, policy, "", &rollbackDraftVersion)
	if errors.Is(err, errDraftConflict) {
		// A newer draft is legitimate administrator work. The setup publication
		// still becomes current, but recovery must never rewind that draft.
		return nil
	}
	return err
}

func (s *state) acquireSetupRecoveryLock() (string, error) {
	recoveryID, err := newSetupClaimID()
	if err != nil {
		return "", err
	}
	lockID := "setup-recovery:" + recoveryID
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
	if _, err := tx.Exec(`INSERT INTO policy_deployment_lock(id, deployment_id, acquired_at) VALUES(1, ?, ?)`,
		lockID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return lockID, nil
}

// createSetupUserPassword is the create-only counterpart of SetUserPassword.
// It uses the same Argon2id encoder, but publishes the credential with
// O_CREATE|O_EXCL so setup can never overwrite an operator-created account.
// The returned hash is used solely for compare-before-remove rollback.
func createSetupUserPassword(userDir, email, password string) (string, string, error) {
	credential, err := prepareSetupUserPassword(userDir, email, password)
	if err != nil {
		return "", "", err
	}
	if err := createPreparedSetupCredential(credential); err != nil {
		return "", "", err
	}
	return credential.UserFile, credential.Hash, nil
}

func prepareSetupUserPassword(userDir, email, password string) (preparedSetupCredential, error) {
	userFile, err := safeUserFile(userDir, email)
	if err != nil {
		return preparedSetupCredential{}, err
	}
	if password == "" {
		return preparedSetupCredential{}, errors.New("password must not be empty")
	}
	hash, err := encodePassword(password)
	if err != nil {
		return preparedSetupCredential{}, err
	}
	data, err := json.Marshal(&UserStore{Hash: hash, SendDiff: []string{}})
	if err != nil {
		return preparedSetupCredential{}, err
	}
	digest := sha256.Sum256(data)
	return preparedSetupCredential{UserFile: userFile, Hash: hash, Digest: hex.EncodeToString(digest[:]), Data: data}, nil
}

func createPreparedSetupCredential(credential preparedSetupCredential) error {
	unlock := lockUserStore(credential.UserFile)
	defer unlock()
	if err := os.MkdirAll(filepath.Dir(credential.UserFile), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(credential.UserFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return errSetupAccountExists
	}
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(credential.UserFile)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(credential.Data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	committed = true
	return nil
}

func rollbackSetupCredential(userFile, setupHash string) {
	unlock := lockUserStore(userFile)
	defer unlock()
	store, err := getUserStoreUnlocked(userFile)
	if err != nil {
		return
	}
	if subtle.ConstantTimeCompare([]byte(store.Hash), []byte(setupHash)) != 1 {
		return
	}
	_ = os.Remove(userFile)
}

func validateSetupRequest(request setupRequest) (string, *editablePolicy, error) {
	email, err := canonicalAccountEmail(request.Email)
	if err != nil {
		return "", nil, errors.New("Invalid account email")
	}
	if !utf8.ValidString(request.Password) {
		return "", nil, errors.New("Password is not valid UTF-8")
	}
	passwordLength := utf8.RuneCountInString(request.Password)
	if passwordLength < setupPasswordMinRunes || passwordLength > setupPasswordMaxRunes {
		return "", nil, errors.New("Password must contain between 12 and 256 characters")
	}
	passwordHash := sha256.Sum256([]byte(request.Password))
	confirmationHash := sha256.Sum256([]byte(request.PasswordConfirmation))
	if subtle.ConstantTimeCompare(passwordHash[:], confirmationHash[:]) != 1 {
		return "", nil, errors.New("Password confirmation does not match")
	}

	policyName := strings.TrimSpace(request.PolicyName)
	if policyName == "" {
		policyName = defaultSetupPolicyName
	}
	ownerName := strings.TrimSpace(request.OwnerName)
	if ownerName == "" {
		ownerName = defaultSetupOwnerName
	}
	if len(policyName) > setupNameMaxBytes || !policyNameRE.MatchString(policyName) {
		return "", nil, errors.New("Invalid policy name")
	}
	if len(ownerName) > setupNameMaxBytes || !policyNameRE.MatchString(ownerName) {
		return "", nil, errors.New("Invalid owner name")
	}

	policy := &editablePolicy{
		Name:     policyName,
		Owners:   []editableOwner{{Name: ownerName, Admins: []string{email}, Users: []string{}, Watchers: []string{}}},
		Users:    []editableUser{{Email: email, Role: "admin", Source: "local", Active: true}},
		Networks: []editableNetwork{},
		FQDNs:    []editableFQDN{},
		Services: []editableService{},
	}
	if err := protectDirectoryUsers(nil, policy); err != nil {
		return "", nil, errors.New("Invalid initial policy")
	}
	protectManualRuleIdentities(nil, policy)
	if err := validateEditablePolicy(policy); err != nil {
		return "", nil, errors.New("Invalid initial policy")
	}
	return email, policy, nil
}

// acquireSetupClaim is a leased database-backed compare-and-set shared by all
// server processes using the same policy store. Publication itself permanently
// closes setup; the short-lived claim only serializes concurrent attempts. A
// lease makes a pre-publication process crash recoverable without allowing an
// active setup request to be stolen.
func (s *state) acquireSetupClaim() (*setupClaim, error) {
	if err := s.reconcileStaleSetupClaim(); err != nil {
		return nil, err
	}
	db, err := s.policyDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err = ensureSetupGuardSchema(db); err != nil {
		return nil, err
	}
	claimID, err := newSetupClaimID()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if _, err = db.Exec(`INSERT INTO policy_setup_guard(id, claim_id, claimed_at) VALUES(1, ?, ?)`, claimID, now); err == nil {
		return s.setupClaimHandle(claimID), nil
	}

	var existingClaim string
	var claimedAt int64
	if queryErr := db.QueryRow(`SELECT claim_id, claimed_at FROM policy_setup_guard WHERE id=1`).Scan(&existingClaim, &claimedAt); queryErr != nil {
		return nil, err
	}
	return nil, errSetupAlreadyClaimed
}

func ensureSetupGuardSchema(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS policy_setup_guard (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		claim_id TEXT NOT NULL,
		claimed_at INTEGER NOT NULL,
		credential_email TEXT NOT NULL DEFAULT '',
		credential_digest TEXT NOT NULL DEFAULT '',
		publication_version TEXT NOT NULL DEFAULT '',
		publication_digest TEXT NOT NULL DEFAULT '',
		rollback_draft_version INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return err
	}
	columns := []struct{ name, definition string }{
		{"claim_id", "TEXT NOT NULL DEFAULT ''"},
		{"claimed_at", "INTEGER NOT NULL DEFAULT 0"},
		{"credential_email", "TEXT NOT NULL DEFAULT ''"},
		{"credential_digest", "TEXT NOT NULL DEFAULT ''"},
		{"publication_version", "TEXT NOT NULL DEFAULT ''"},
		{"publication_digest", "TEXT NOT NULL DEFAULT ''"},
		{"rollback_draft_version", "INTEGER NOT NULL DEFAULT 0"},
	}
	for _, column := range columns {
		if err := ensureSQLiteColumn(db, "policy_setup_guard", column.name, column.definition); err != nil {
			return err
		}
	}
	return nil
}

// reconcileStaleSetupClaim adopts only an expired journal row with a CAS. It
// either repairs the exact committed publication or removes only the exact
// uncommitted credential. Unknown/transient failures retain all metadata and
// make the row immediately retryable.
func (s *state) reconcileStaleSetupClaim() error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	if err := ensureSetupGuardSchema(db); err != nil {
		return err
	}
	var record setupGuardRecord
	err = db.QueryRow(`SELECT claim_id, claimed_at, credential_email, credential_digest, publication_version, publication_digest, rollback_draft_version
		FROM policy_setup_guard WHERE id=1`).Scan(
		&record.ClaimID, &record.ClaimedAt, &record.CredentialEmail, &record.CredentialDigest,
		&record.PublicationVersion, &record.PublicationDigest, &record.RollbackDraftVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if record.ClaimedAt > now-int64(setupClaimLease/time.Second) {
		return nil
	}
	recoveryID, err := newSetupClaimID()
	if err != nil {
		return err
	}
	result, err := db.Exec(`UPDATE policy_setup_guard SET claim_id=?, claimed_at=?
		WHERE id=1 AND claim_id=? AND claimed_at=?`, recoveryID, now, record.ClaimID, record.ClaimedAt)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return nil
	}

	if record.PublicationVersion != "" || record.PublicationDigest != "" {
		state, policy := s.inspectSetupPublication(record.PublicationVersion, record.PublicationDigest)
		switch state {
		case setupPublicationExact:
			if err := s.restoreSetupPublicationArtifacts(record.PublicationVersion, record.PublicationDigest, record.RollbackDraftVersion, policy); err != nil {
				s.abandonSetupClaim(recoveryID)
				return err
			}
			if err := s.deleteSetupClaim(recoveryID); err != nil {
				s.abandonSetupClaim(recoveryID)
				return err
			}
			return nil
		case setupPublicationUnknown:
			s.abandonSetupClaim(recoveryID)
			return errors.New("setup publication state is unavailable")
		}
	}

	if err := cleanupStaleSetupCredential(s.config.UserDir, record.CredentialEmail, record.CredentialDigest); err != nil {
		s.abandonSetupClaim(recoveryID)
		return err
	}
	if err := s.deleteSetupClaim(recoveryID); err != nil {
		s.abandonSetupClaim(recoveryID)
		return err
	}
	return nil
}

func (s *state) abandonSetupClaim(claimID string) {
	db, err := s.policyDB()
	if err != nil {
		return
	}
	defer db.Close()
	_, _ = db.Exec(`UPDATE policy_setup_guard SET claimed_at=0 WHERE id=1 AND claim_id=?`, claimID)
}

func (s *state) deleteSetupClaim(claimID string) error {
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`DELETE FROM policy_setup_guard WHERE id=1 AND claim_id=?`, claimID)
	return err
}

func (s *state) setupClaimHandle(claimID string) *setupClaim {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(setupClaimLease / 3)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				db, err := s.policyDB()
				if err == nil {
					_, _ = db.Exec(`UPDATE policy_setup_guard SET claimed_at=? WHERE id=1 AND claim_id=?`, time.Now().Unix(), claimID)
					_ = db.Close()
				}
			case <-stop:
				return
			}
		}
	}()
	var stopOnce sync.Once
	stopHeartbeat := func() {
		stopOnce.Do(func() { close(stop) })
		<-done
	}
	var releaseOnce sync.Once
	return &setupClaim{
		ID: claimID,
		Release: func() {
			releaseOnce.Do(func() {
				stopHeartbeat()
				_ = s.deleteSetupClaim(claimID)
			})
		},
		Abandon: func() {
			stopHeartbeat()
			s.abandonSetupClaim(claimID)
		},
	}
}

func (s *state) recordSetupClaimCredential(claimID, email, digest, publicationVersion, publicationDigest string, rollbackDraftVersion int64) error {
	if rollbackDraftVersion < 0 || !validSetupCredentialDigest(digest) || !validSetupPublicationVersion(publicationVersion) || !validSetupCredentialDigest(publicationDigest) {
		return errors.New("invalid setup credential digest")
	}
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	result, err := db.Exec(`UPDATE policy_setup_guard
		SET credential_email=?, credential_digest=?, publication_version=?, publication_digest=?, rollback_draft_version=?, claimed_at=?
		WHERE id=1 AND claim_id=?`, email, digest, publicationVersion, publicationDigest, rollbackDraftVersion, time.Now().Unix(), claimID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errSetupAlreadyClaimed
	}
	return nil
}

func (s *state) recordSetupClaimPublication(claimID, publicationVersion, publicationDigest string, rollbackDraftVersion int64) error {
	if rollbackDraftVersion < 0 || !validSetupPublicationVersion(publicationVersion) || !validSetupCredentialDigest(publicationDigest) {
		return errors.New("invalid setup publication journal")
	}
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	result, err := db.Exec(`UPDATE policy_setup_guard
		SET publication_version=?, publication_digest=?, rollback_draft_version=?, claimed_at=?
		WHERE id=1 AND claim_id=?`, publicationVersion, publicationDigest, rollbackDraftVersion, time.Now().Unix(), claimID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errSetupAlreadyClaimed
	}
	return nil
}

func cleanupStaleSetupCredential(userDir, email, digest string) error {
	if email == "" && digest == "" {
		return nil
	}
	if email == "" || !validSetupCredentialDigest(digest) {
		return errors.New("invalid stale setup credential metadata")
	}
	userFile, err := safeUserFile(userDir, email)
	if err != nil {
		return err
	}
	unlock := lockUserStore(userFile)
	defer unlock()
	data, err := os.ReadFile(userFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	actual := sha256.Sum256(data)
	expected, _ := hex.DecodeString(digest)
	if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		return nil
	}
	return os.Remove(userFile)
}

func validSetupCredentialDigest(digest string) bool {
	if len(digest) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size
}

func newSetupClaimID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func writeSetupResponse(w http.ResponseWriter, email string) error {
	// Keep this response intentionally small. In particular, it must never be
	// tempting to include the submitted password or bootstrap token here.
	return json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"initialized":   true,
		"authenticated": true,
		"current_user":  email,
	})
}
