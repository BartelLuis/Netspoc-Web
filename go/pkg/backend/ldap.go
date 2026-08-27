package backend

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type ldapIdentity struct {
	DirectoryID string
	Username    string
	Email       string
}

const (
	ldapSyncPageSize   uint32 = 500
	ldapNetworkTimeout        = 15 * time.Second
)

var errLDAPMaintenanceLogin = errors.New("LDAP login is restricted by maintenance mode")

func dialLDAP(rawURL string) (*ldap.Conn, error) {
	connection, err := ldap.DialURL(rawURL, ldap.DialWithDialer(&net.Dialer{Timeout: ldapNetworkTimeout}))
	if err != nil {
		return nil, err
	}
	connection.SetTimeout(ldapNetworkTimeout)
	return connection, nil
}

func (s *state) ldapEnabled() bool {
	return s.config != nil && s.config.LdapURI != "" && validateLDAPSettings(s.config) == nil
}

func validateLDAPFormatTemplate(name, value string) error {
	if strings.Count(value, "%s") != 1 || strings.Count(value, "%") != 1 {
		return fmt.Errorf("%s must contain exactly one %%s placeholder", name)
	}
	return nil
}

func validateLDAPSettings(c *config) error {
	configured := c.LdapURI != "" || c.LdapDNTemplate != "" || c.LdapBaseDN != "" || c.LdapFilterTemplate != ""
	if !configured {
		return nil
	}
	if c.LdapURI == "" || c.LdapDNTemplate == "" || c.LdapBaseDN == "" || c.LdapFilterTemplate == "" {
		return errors.New("ldap_uri, ldap_dn_template, ldap_base_dn and ldap_filter_template must be configured together")
	}
	u, err := url.Parse(c.LdapURI)
	if err != nil || u.Scheme != "ldaps" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("ldap_uri must be an ldaps:// URL without credentials, query or fragment")
	}
	if err := validateLDAPFormatTemplate("ldap_dn_template", c.LdapDNTemplate); err != nil {
		return err
	}
	if err := validateLDAPFormatTemplate("ldap_filter_template", c.LdapFilterTemplate); err != nil {
		return err
	}
	if (c.LdapBindDNEnv == "") != (c.LdapBindPasswordEnv == "") {
		return errors.New("ldap_bind_dn_env and ldap_bind_password_env must be configured together")
	}
	return nil
}

func ldapBindDN(template, username string) (string, error) {
	if err := validateLDAPFormatTemplate("ldap_dn_template", template); err != nil {
		return "", err
	}
	return fmt.Sprintf(template, ldap.EscapeDN(username)), nil
}

func ldapEntryID(entry *ldap.Entry, attribute string) string {
	raw := entry.GetRawAttributeValue(attribute)
	if len(raw) != 0 {
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return ""
}

func (s *state) ldapAuthenticate(username, password string) (ldapIdentity, error) {
	if !s.ldapEnabled() {
		return ldapIdentity{}, fmt.Errorf("LDAP is not configured")
	}
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return ldapIdentity{}, fmt.Errorf("username and password are required")
	}
	connection, err := dialLDAP(s.config.LdapURI)
	if err != nil {
		return ldapIdentity{}, fmt.Errorf("LDAP connection failed: %w", err)
	}
	defer connection.Close()
	bindDN, err := ldapBindDN(s.config.LdapDNTemplate, username)
	if err != nil {
		return ldapIdentity{}, fmt.Errorf("authentication failed")
	}
	if err := connection.Bind(bindDN, password); err != nil {
		return ldapIdentity{}, fmt.Errorf("authentication failed")
	}
	filter := fmt.Sprintf("("+s.config.LdapFilterTemplate+")", ldap.EscapeFilter(username))
	request := ldap.NewSearchRequest(s.config.LdapBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false, filter,
		[]string{s.config.LdapIDAttr, s.config.LdapUserAttr, s.config.LdapEmailAttr}, nil)
	result, err := connection.Search(request)
	if err != nil {
		return ldapIdentity{}, fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(result.Entries) != 1 {
		return ldapIdentity{}, fmt.Errorf("authentication failed")
	}
	entry := result.Entries[0]
	identity := ldapIdentity{
		DirectoryID: ldapEntryID(entry, s.config.LdapIDAttr),
		Username:    entry.GetAttributeValue(s.config.LdapUserAttr),
		Email:       strings.ToLower(strings.TrimSpace(entry.GetAttributeValue(s.config.LdapEmailAttr))),
	}
	if identity.Username == "" {
		identity.Username = username
	}
	identity.Email, err = canonicalAccountEmail(identity.Email)
	if identity.DirectoryID == "" || err != nil {
		return ldapIdentity{}, fmt.Errorf("LDAP user has no email address")
	}
	return identity, nil
}

func (s *state) ldapUsers() ([]ldapIdentity, error) {
	if !s.ldapEnabled() {
		return nil, fmt.Errorf("LDAP is not configured")
	}
	bindDN, bindPassword := os.Getenv(s.config.LdapBindDNEnv), os.Getenv(s.config.LdapBindPasswordEnv)
	if s.config.LdapBindDNEnv == "" || s.config.LdapBindPasswordEnv == "" || bindDN == "" || bindPassword == "" {
		return nil, fmt.Errorf("LDAP sync credentials are not configured")
	}
	connection, err := dialLDAP(s.config.LdapURI)
	if err != nil {
		return nil, fmt.Errorf("LDAP connection failed: %w", err)
	}
	defer connection.Close()
	if err := connection.Bind(bindDN, bindPassword); err != nil {
		return nil, fmt.Errorf("LDAP sync bind failed: %w", err)
	}
	request := ldap.NewSearchRequest(s.config.LdapBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		s.config.LdapSyncFilter, []string{s.config.LdapIDAttr, s.config.LdapUserAttr, s.config.LdapEmailAttr}, nil)
	// Active Directory enforces MaxPageSize (commonly 1000). A smaller explicit
	// page keeps full-directory syncs reliable without depending on that limit.
	result, err := connection.SearchWithPaging(request, ldapSyncPageSize)
	if err != nil {
		return nil, fmt.Errorf("LDAP sync search failed: %w", err)
	}
	users := make([]ldapIdentity, 0, len(result.Entries))
	for _, entry := range result.Entries {
		identity := ldapIdentity{DirectoryID: ldapEntryID(entry, s.config.LdapIDAttr), Username: entry.GetAttributeValue(s.config.LdapUserAttr), Email: strings.ToLower(strings.TrimSpace(entry.GetAttributeValue(s.config.LdapEmailAttr)))}
		identity.Email, err = canonicalAccountEmail(identity.Email)
		if err == nil && identity.DirectoryID != "" && identity.Username != "" {
			users = append(users, identity)
		}
	}
	return users, nil
}

func findLDAPPolicyUser(p *editablePolicy, identity ldapIdentity) *editableUser {
	for i := range p.Users {
		user := &p.Users[i]
		if user.Source == "ldap" && identity.DirectoryID != "" && user.DirectoryID == identity.DirectoryID {
			return user
		}
	}
	return nil
}

func ldapPolicyLoginUser(p *editablePolicy, identity ldapIdentity, maintenanceActive bool) (*editableUser, error) {
	user := findLDAPPolicyUser(p, identity)
	if user == nil || !user.Active {
		return nil, errors.New("LDAP identity is not active in the authorization policy")
	}
	if maintenanceActive && policyRole(p, user.Email) != "admin" {
		return nil, errLDAPMaintenanceLogin
	}
	return user, nil
}

func (s *state) ldapLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session := GetGoSession(r)
	s.logout(session)
	if err := s.checkAttack(r); err != nil {
		writeHTMLError(w, "Login failed")
		return
	}
	identity, err := s.ldapAuthenticate(r.FormValue("user"), r.FormValue("pass"))
	if err != nil {
		s.setAttack(r)
		writeHTMLError(w, "Login failed")
		return
	}
	maintenanceActive, _ := s.effectiveMaintenance()
	user, err := ldapPolicyLoginUser(s.authorizationPolicy(), identity, maintenanceActive)
	if err != nil {
		if errors.Is(err, errLDAPMaintenanceLogin) {
			writeHTMLError(w, "Das System befindet sich im Wartungsmodus. Die Anmeldung ist nur für Administratoren möglich.")
			return
		}
		s.setAttack(r)
		writeHTMLError(w, "Login failed")
		return
	}
	if err := s.checkEmailAuthorization(user.Email); err != nil {
		s.setAttack(r)
		writeHTMLError(w, "Login failed")
		return
	}
	// Re-read the immutable publication immediately before authentication is
	// committed. A concurrent publication may have disabled the directory ID,
	// changed its source/email/role, or enabled maintenance restrictions.
	maintenanceActive, _ = s.effectiveMaintenance()
	user, err = ldapPolicyLoginUser(s.authorizationPolicy(), identity, maintenanceActive)
	if err != nil {
		if errors.Is(err, errLDAPMaintenanceLogin) {
			writeHTMLError(w, "Das System befindet sich im Wartungsmodus. Die Anmeldung ist nur für Administratoren möglich.")
			return
		}
		s.setAttack(r)
		writeHTMLError(w, "Login failed")
		return
	}
	if err := s.checkEmailAuthorization(user.Email); err != nil {
		s.setAttack(r)
		writeHTMLError(w, "Login failed")
		return
	}
	s.clearAttack(r)
	s.setLogin(session, strings.ToLower(user.Email))
	s.redirectToLandingPage(w)
}

func (s *state) adminLDAPSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := getEmailFromSession(r)
	if !hasPolicyRole(s.authorizationPolicy(), actor, "admin") {
		s.audit(actor, "ldap.sync.confirm", "denied", nil)
		writeError(w, "Policy administrator role required", http.StatusForbidden)
		return
	}
	var request struct {
		Confirm      bool   `json:"confirm"`
		PreviewToken string `json:"preview_token"`
	}
	var current *editablePolicy
	err := decodeJSONRequest(w, r, 1<<20, &request)
	failureStatus := http.StatusBadRequest
	if err == nil && (!request.Confirm || strings.TrimSpace(request.PreviewToken) == "") {
		err = errors.New("confirm=true and preview_token are required")
	}
	var preview storedLDAPSyncPreview
	if err == nil {
		preview, err = s.loadLDAPSyncPreview(actor, request.PreviewToken)
		if err != nil && !errors.Is(err, errLDAPPreviewInvalid) {
			failureStatus = http.StatusInternalServerError
		}
	}
	var meta draftMetadata
	if err == nil {
		meta, err = s.draftInfo()
		if err != nil {
			failureStatus = http.StatusInternalServerError
		}
		if err == nil && meta.Version != preview.DraftVersion {
			err = errLDAPPreviewStale
			failureStatus = http.StatusConflict
		}
	}
	if err == nil {
		current, err = s.loadPolicyDraft()
		if err != nil {
			failureStatus = http.StatusInternalServerError
		}
	}
	if err == nil {
		current.Users = append([]editableUser(nil), preview.Users...)
		err = validateEditablePolicy(current)
	}
	if err == nil {
		expected := preview.DraftVersion
		meta, err = s.saveDraftAs(current, actor, &expected)
		if errors.Is(err, errDraftConflict) {
			failureStatus = http.StatusConflict
		} else if err != nil {
			failureStatus = http.StatusInternalServerError
		}
	}
	if err != nil {
		s.audit(actor, "ldap.sync.confirm", "failed", map[string]any{"error": err.Error()})
		writeError(w, err.Error(), failureStatus)
		return
	}
	if consumeErr := s.consumeLDAPSyncPreview(request.PreviewToken); consumeErr != nil {
		s.audit(actor, "ldap.sync.preview.consume", "failed", map[string]any{"error": consumeErr.Error()})
	}
	s.audit(actor, "ldap.sync.confirm", "success", map[string]any{
		"added": preview.Added, "updated": preview.Updated, "disabled": preview.Disabled, "draft_version": meta.Version,
	})
	writeJSON(w, map[string]any{
		"success": true, "added": preview.Added, "updated": preview.Updated, "disabled": preview.Disabled,
		"users": current.Users, "draft_version": meta.Version, "draft_updated_at": meta.UpdatedAt, "draft_updated_by": meta.UpdatedBy,
	})
}
