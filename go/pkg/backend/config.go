package backend

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// FortinetTarget describes a FortiGate or FortiManager API endpoint. Static
// target secrets are referenced through environment variables. Web-managed
// target secrets use the unexported runtime fields populated by the server-side
// credential store, so neither kind has to be stored in policyweb.conf.
type FortinetTarget struct {
	Name               string            `json:"name"`
	Type               string            `json:"type"`
	URL                string            `json:"url"`
	VDOM               string            `json:"vdom,omitempty"`
	ADOM               string            `json:"adom,omitempty"`
	PolicyPackage      string            `json:"policy_package,omitempty"`
	PolicyInsertBefore string            `json:"policy_insert_before,omitempty"`
	TargetContexts     []string          `json:"target_contexts,omitempty"`
	ZoneInterfaces     map[string]string `json:"zone_interfaces,omitempty"`
	AllowDeploy        bool              `json:"allow_deploy,omitempty"`
	TokenEnv           string            `json:"token_env,omitempty"`
	UsernameEnv        string            `json:"username_env,omitempty"`
	PasswordEnv        string            `json:"password_env,omitempty"`
	CAFile             string            `json:"ca_file,omitempty"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify,omitempty"`
	managedID          string
	managedToken       string
	managedCAPEM       string
}

func (t FortinetTarget) validate() error {
	if strings.TrimSpace(t.Name) == "" || strings.TrimSpace(t.URL) == "" {
		return fmt.Errorf("name and url are required")
	}
	if t.Name != strings.TrimSpace(t.Name) {
		return fmt.Errorf("name must not contain leading or trailing whitespace")
	}
	if utf8.RuneCountInString(t.Name) > 64 {
		return fmt.Errorf("name exceeds the target-name limit of 64 characters")
	}
	for _, character := range t.Name {
		if unicode.IsControl(character) {
			return fmt.Errorf("name must not contain control characters")
		}
	}
	if t.Type != "fortigate" && t.Type != "fortimanager" {
		return fmt.Errorf("type must be fortigate or fortimanager")
	}
	if _, err := normalizedFortinetEndpoint(t.URL); err != nil {
		return fmt.Errorf("url must be an absolute https URL without credentials, query or fragment")
	}
	if t.Type == "fortigate" && t.TokenEnv == "" {
		return fmt.Errorf("token_env is required for FortiGate")
	}
	if t.InsecureSkipVerify {
		return fmt.Errorf("insecure_skip_verify is forbidden for authenticated Fortinet requests")
	}
	if t.Type == "fortimanager" && (t.UsernameEnv == "" || t.PasswordEnv == "") {
		return fmt.Errorf("username_env and password_env are required for FortiManager")
	}
	if t.AllowDeploy && len(t.TargetContexts) == 0 {
		return fmt.Errorf("target_contexts is required when allow_deploy is enabled")
	}
	if len(t.TargetContexts) != 0 && t.Type == "fortigate" && strings.TrimSpace(t.VDOM) == "" {
		return fmt.Errorf("vdom is required for a FortiGate target context")
	}
	if t.Type == "fortigate" && t.VDOM != "" {
		if t.VDOM != strings.TrimSpace(t.VDOM) || t.VDOM == "*" || strings.Contains(t.VDOM, ",") {
			return fmt.Errorf("vdom must identify exactly one FortiGate VDOM")
		}
		if utf8.RuneCountInString(t.VDOM) > 31 {
			return fmt.Errorf("vdom exceeds the FortiOS 7.4 VDOM-name limit of 31 characters")
		}
		for _, character := range t.VDOM {
			if unicode.IsControl(character) {
				return fmt.Errorf("vdom must not contain control characters")
			}
		}
	}
	if t.AllowDeploy && t.Type == "fortigate" {
		if strings.TrimSpace(t.PolicyInsertBefore) == "" {
			return fmt.Errorf("policy_insert_before is required for deterministic FortiGate policy ordering")
		}
		if t.PolicyInsertBefore != strings.TrimSpace(t.PolicyInsertBefore) {
			return fmt.Errorf("policy_insert_before must not contain leading or trailing whitespace")
		}
		for _, character := range t.PolicyInsertBefore {
			if unicode.IsControl(character) {
				return fmt.Errorf("policy_insert_before must not contain control characters")
			}
		}
		if utf8.RuneCountInString(t.PolicyInsertBefore) > 35 {
			return fmt.Errorf("policy_insert_before exceeds the FortiOS 7.4 policy-name limit of 35 characters")
		}
	}
	if len(t.TargetContexts) != 0 && t.Type == "fortimanager" && (strings.TrimSpace(t.ADOM) == "" || strings.TrimSpace(t.PolicyPackage) == "") {
		return fmt.Errorf("adom and policy_package are required for a FortiManager target context")
	}
	if t.AllowDeploy && t.Type == "fortimanager" {
		return fmt.Errorf("FortiManager execution requires an explicit managed-device install target and is currently preview-only")
	}
	for zone, iface := range t.ZoneInterfaces {
		if strings.TrimSpace(zone) == "" || strings.TrimSpace(iface) == "" {
			return fmt.Errorf("zone_interfaces must not contain empty zones or interfaces")
		}
	}
	contexts := make(map[string]bool, len(t.TargetContexts))
	for _, context := range t.TargetContexts {
		context = strings.TrimSpace(context)
		if context == "" || contexts[context] {
			return fmt.Errorf("target_contexts must contain unique, non-empty names")
		}
		contexts[context] = true
	}
	return nil
}

func (t FortinetTarget) httpClient() (*http.Client, error) {
	if t.InsecureSkipVerify {
		return nil, fmt.Errorf("insecure_skip_verify is forbidden for authenticated Fortinet requests")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: t.InsecureSkipVerify} // #nosec G402 -- explicit administrator opt-in
	var certificates [][]byte
	if t.CAFile != "" {
		pemData, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		certificates = append(certificates, pemData)
	}
	if t.managedCAPEM != "" {
		certificates = append(certificates, []byte(t.managedCAPEM))
	}
	if len(certificates) != 0 {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		for _, pemData := range certificates {
			if !pool.AppendCertsFromPEM(pemData) {
				return nil, fmt.Errorf("configured CA data contains no certificates")
			}
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func (t FortinetTarget) apiToken() (string, error) {
	if t.managedToken != "" {
		return t.managedToken, nil
	}
	if t.TokenEnv == "" {
		return "", errors.New("FortiGate API token is not configured")
	}
	if token := os.Getenv(t.TokenEnv); token != "" {
		return token, nil
	}
	return "", fmt.Errorf("environment variable %s is empty", t.TokenEnv)
}

type config struct {
	NetspocData                 string           `json:"netspoc_data"`
	NoreplyAddress              string           `json:"noreply_address"`
	SessionDir                  string           `json:"session_dir"`
	UserDir                     string           `json:"user_dir"`
	SendmailCommand             string           `json:"sendmail_command"`
	MailTransport               string           `json:"mail_transport"`
	SMTPHost                    string           `json:"smtp_host"`
	SMTPPort                    int              `json:"smtp_port"`
	SMTPUsernameEnv             string           `json:"smtp_username_env"`
	SMTPPasswordEnv             string           `json:"smtp_password_env"`
	MailTemplate                string           `json:"mail_template"`
	HTMLTemplate                string           `json:"html_template"`
	PublicBaseURL               string           `json:"public_base_url,omitempty"`
	ExpireLoggedIn              int              `json:"expire_logged_in"`
	BusinessUnits               []string         `json:"business_units"`
	AboutInfoTemplate           string           `json:"about_info_template"`
	FortinetTargets             []FortinetTarget `json:"fortinet_targets,omitempty"`
	FortiGateReadOnly           bool             `json:"-"`
	FortiGatePolicyScanInterval time.Duration    `json:"-"`
	MaintenanceMode             bool             `json:"maintenance_mode,omitempty"`
	MaintenanceMessage          string           `json:"maintenance_message,omitempty"`
	LdapURI                     string           `json:"ldap_uri,omitempty"`
	LdapDNTemplate              string           `json:"ldap_dn_template,omitempty"`
	LdapBaseDN                  string           `json:"ldap_base_dn,omitempty"`
	LdapFilterTemplate          string           `json:"ldap_filter_template,omitempty"`
	LdapSyncFilter              string           `json:"ldap_sync_filter,omitempty"`
	LdapUserAttr                string           `json:"ldap_user_attr,omitempty"`
	LdapEmailAttr               string           `json:"ldap_email_attr,omitempty"`
	LdapIDAttr                  string           `json:"ldap_id_attr,omitempty"`
	LdapBindDNEnv               string           `json:"ldap_bind_dn_env,omitempty"`
	LdapBindPasswordEnv         string           `json:"ldap_bind_password_env,omitempty"`
}

func LoadConfig() *config {
	home, _ := os.UserHomeDir()
	var p string
	if configured := os.Getenv("POLICYWEB_CONFIG"); configured != "" {
		p = configured
	} else if os.Getenv("PW_FRONTEND_TEST") != "" {
		p = filepath.Join(home, "policyweb-test.conf")
	} else {
		p = filepath.Join(home, "policyweb.conf")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		abort("Can't %v", err)
	}

	// Set some defaults
	var c config
	c.SendmailCommand = "/usr/lib/sendmail"
	c.MailTransport = "sendmail"
	c.SMTPPort = 587
	c.MailTemplate = filepath.Join(home, "Netspoc-Web", "go", "pkg", "backend", "mail-templates")
	c.HTMLTemplate = filepath.Join(home, "Netspoc-Web", "go", "pkg", "backend", "html-templates")
	c.ExpireLoggedIn = 480 // 8 hours
	c.LdapUserAttr = "uid"
	c.LdapEmailAttr = "mail"
	c.LdapIDAttr = "entryUUID"
	c.LdapSyncFilter = "(objectClass=person)"
	fortiGateReadOnly, err := fortiGateReadOnlySetting()
	if err != nil {
		abort("Invalid FortiGate read-only setting: %v", err)
	}
	c.FortiGateReadOnly = fortiGateReadOnly
	fortiGatePolicyScanInterval, err := fortiGatePolicyScanIntervalSetting()
	if err != nil {
		abort("Invalid FortiGate policy scan interval: %v", err)
	}
	c.FortiGatePolicyScanInterval = fortiGatePolicyScanInterval

	// Override with config file
	if err := json.Unmarshal(data, &c); err != nil {
		abort("in %q: %v", p, err)
	}
	// Derive this default only after html_template from the configuration has
	// been applied. Otherwise containers keep the pre-config home-directory
	// path and the info dialog remains empty.
	if c.AboutInfoTemplate == "" {
		c.AboutInfoTemplate = filepath.Join(c.HTMLTemplate, "about_info")
	}

	// Check for required config vars.
	if c.NetspocData == "" {
		abort("netspoc_data must be set in %q", p)
	}
	if c.NoreplyAddress == "" {
		abort("noreply_address must be set in %q", p)
	}
	if c.SessionDir == "" {
		abort("session_dir must be set in %q", p)
	}
	if c.UserDir == "" {
		abort("user_dir must be set in %q", p)
	}

	// Check for unexpected config vars. The optional values are those in validKeys
	// that are not explicitly set or checked as mandatory above.
	configMap := make(map[string]interface{})
	if err := json.Unmarshal(data, &configMap); err != nil {
		abort("in %q: %v", p, err)
	}
	validKeys := map[string]bool{
		"netspoc_data":           true,
		"noreply_address":        true,
		"session_dir":            true,
		"user_dir":               true,
		"sendmail_command":       true,
		"mail_transport":         true,
		"smtp_host":              true,
		"smtp_port":              true,
		"smtp_username_env":      true,
		"smtp_password_env":      true,
		"mail_template":          true,
		"html_template":          true,
		"public_base_url":        true,
		"expire_logged_in":       true,
		"business_units":         true,
		"about_info_template":    true,
		"fortinet_targets":       true,
		"maintenance_mode":       true,
		"maintenance_message":    true,
		"ldap_uri":               true,
		"ldap_dn_template":       true,
		"ldap_base_dn":           true,
		"ldap_filter_template":   true,
		"ldap_sync_filter":       true,
		"ldap_user_attr":         true,
		"ldap_email_attr":        true,
		"ldap_id_attr":           true,
		"ldap_bind_dn_env":       true,
		"ldap_bind_password_env": true,
	}
	for k := range configMap {
		if !validKeys[k] {
			abort("Unknown config key %q in %q", k, p)
		}
	}
	fortinetNames := make(map[string]bool, len(c.FortinetTargets))
	fortinetScopes := make(map[string]string, len(c.FortinetTargets))
	for i, target := range c.FortinetTargets {
		if err := target.validate(); err != nil {
			abort("Invalid fortinet_targets[%d]: %v", i, err)
		}
		name := strings.ToLower(strings.TrimSpace(target.Name))
		if fortinetNames[name] {
			abort("Invalid fortinet_targets[%d]: duplicate target name %q", i, target.Name)
		}
		fortinetNames[name] = true
		if len(target.TargetContexts) != 0 {
			scope := target.VDOM
			if target.Type == "fortimanager" {
				scope = target.ADOM + "/" + target.PolicyPackage
			}
			physical := target.Type + "\x00" + deploymentEndpointID(target.URL) + "\x00" + scope
			if previous := fortinetScopes[physical]; previous != "" {
				abort("Invalid fortinet_targets[%d]: target %q duplicates physical scope of %q", i, target.Name, previous)
			}
			fortinetScopes[physical] = target.Name
		}
	}
	ldapConfigured := c.LdapURI != "" || c.LdapDNTemplate != "" || c.LdapBaseDN != "" || c.LdapFilterTemplate != ""
	if ldapConfigured && (c.LdapURI == "" || c.LdapDNTemplate == "" || c.LdapBaseDN == "" || c.LdapFilterTemplate == "") {
		abort("ldap_uri, ldap_dn_template, ldap_base_dn and ldap_filter_template must be configured together")
	}
	if (c.LdapBindDNEnv == "") != (c.LdapBindPasswordEnv == "") {
		abort("ldap_bind_dn_env and ldap_bind_password_env must be configured together")
	}
	if err := validateLDAPSettings(&c); err != nil {
		abort("invalid LDAP configuration: %v", err)
	}
	if c.MailTransport != "sendmail" && c.MailTransport != "smtp" {
		abort("mail_transport must be sendmail or smtp")
	}
	if c.PublicBaseURL != "" {
		publicBaseURL, err := normalizedPublicBaseURL(c.PublicBaseURL)
		if err != nil {
			abort("invalid public_base_url: %v", err)
		}
		c.PublicBaseURL = publicBaseURL
	}
	if c.MailTransport == "smtp" {
		if c.SMTPHost == "" || c.SMTPPort < 1 || c.SMTPPort > 65535 {
			abort("smtp_host and a valid smtp_port are required for SMTP")
		}
		if (c.SMTPUsernameEnv == "") != (c.SMTPPasswordEnv == "") {
			abort("smtp_username_env and smtp_password_env must be configured together")
		}
		if c.SMTPUsernameEnv != "" && (os.Getenv(c.SMTPUsernameEnv) == "" || os.Getenv(c.SMTPPasswordEnv) == "") {
			abort("SMTP credential environment variables are empty")
		}
	}
	return &c
}

const fortiGateReadOnlyEnv = "POLICYWEB_FORTIGATE_READ_ONLY"

const fortiGatePolicyScanIntervalEnv = "POLICYWEB_FORTIGATE_POLICY_SCAN_INTERVAL"

func fortiGateReadOnlySetting() (bool, error) {
	value := strings.TrimSpace(os.Getenv(fortiGateReadOnlyEnv))
	switch strings.ToLower(value) {
	case "":
		return false, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", fortiGateReadOnlyEnv)
	}
}

func fortiGatePolicyScanIntervalSetting() (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(fortiGatePolicyScanIntervalEnv))
	if value == "" || value == "0" {
		return 0, nil
	}
	interval, err := time.ParseDuration(value)
	if err != nil || interval < time.Second || interval > 24*time.Hour {
		return 0, fmt.Errorf("%s must be 0 or a duration between 1s and 24h", fortiGatePolicyScanIntervalEnv)
	}
	return interval, nil
}

// normalizedPublicBaseURL validates the externally visible origin used in
// password-verification emails. It must not be derived from request headers:
// Host and Referer can be attacker-controlled when proxy trust is misconfigured.
func normalizedPublicBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" {
		return "", fmt.Errorf("must be an absolute HTTP(S) origin")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("must not contain credentials, a path, query or fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("HTTP is allowed only for a loopback origin")
		}
	default:
		return "", fmt.Errorf("scheme must be https (or HTTP on loopback)")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Path = "/"
	return u.String(), nil
}
