package backend

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FortinetTarget describes a FortiGate or FortiManager API endpoint. Secrets are
// deliberately referenced through environment variables so they never have to
// be stored in policyweb.conf.
type FortinetTarget struct {
	Name               string `json:"name"`
	Type               string `json:"type"`
	URL                string `json:"url"`
	VDOM               string `json:"vdom,omitempty"`
	ADOM               string `json:"adom,omitempty"`
	TokenEnv           string `json:"token_env,omitempty"`
	UsernameEnv        string `json:"username_env,omitempty"`
	PasswordEnv        string `json:"password_env,omitempty"`
	CAFile             string `json:"ca_file,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

func (t FortinetTarget) validate() error {
	if t.Name == "" || t.URL == "" {
		return fmt.Errorf("name and url are required")
	}
	if t.Type != "fortigate" && t.Type != "fortimanager" {
		return fmt.Errorf("type must be fortigate or fortimanager")
	}
	if !strings.HasPrefix(t.URL, "https://") {
		return fmt.Errorf("url must use https")
	}
	if t.Type == "fortigate" && t.TokenEnv == "" {
		return fmt.Errorf("token_env is required for FortiGate")
	}
	if t.Type == "fortimanager" && (t.UsernameEnv == "" || t.PasswordEnv == "") {
		return fmt.Errorf("username_env and password_env are required for FortiManager")
	}
	return nil
}

func (t FortinetTarget) httpClient() (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: t.InsecureSkipVerify} // #nosec G402 -- explicit administrator opt-in
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 15 * time.Second}, nil
}

type config struct {
	NetspocData        string           `json:"netspoc_data"`
	NoreplyAddress     string           `json:"noreply_address"`
	SessionDir         string           `json:"session_dir"`
	UserDir            string           `json:"user_dir"`
	SendmailCommand    string           `json:"sendmail_command"`
	MailTransport      string           `json:"mail_transport"`
	SMTPHost           string           `json:"smtp_host"`
	SMTPPort           int              `json:"smtp_port"`
	SMTPUsernameEnv    string           `json:"smtp_username_env"`
	SMTPPasswordEnv    string           `json:"smtp_password_env"`
	MailTemplate       string           `json:"mail_template"`
	HTMLTemplate       string           `json:"html_template"`
	ExpireLoggedIn     int              `json:"expire_logged_in"`
	BusinessUnits      []string         `json:"business_units"`
	AboutInfoTemplate  string           `json:"about_info_template"`
	FortinetTargets    []FortinetTarget `json:"fortinet_targets,omitempty"`
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
		"netspoc_data":         true,
		"noreply_address":      true,
		"session_dir":          true,
		"user_dir":             true,
		"sendmail_command":     true,
		"mail_transport":       true,
		"smtp_host":            true,
		"smtp_port":            true,
		"smtp_username_env":    true,
		"smtp_password_env":    true,
		"mail_template":        true,
		"html_template":        true,
		"expire_logged_in":     true,
		"business_units":       true,
		"about_info_template":  true,
		"fortinet_targets":     true,
	}
	for k := range configMap {
		if !validKeys[k] {
			abort("Unknown config key %q in %q", k, p)
		}
	}
	for i, target := range c.FortinetTargets {
		if err := target.validate(); err != nil {
			abort("Invalid fortinet_targets[%d]: %v", i, err)
		}
	}
	if c.MailTransport != "sendmail" && c.MailTransport != "smtp" {
		abort("mail_transport must be sendmail or smtp")
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
