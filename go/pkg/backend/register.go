package backend

import (
	"bufio"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	htmltemplate "html/template"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	texttemplate "text/template"
	"time"
)

var attackFileMu sync.Mutex

func (s *state) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	session := GetGoSession(r)
	email := r.FormValue("email")
	var err error
	email, err = canonicalAccountEmail(email)
	if err != nil {
		writeError(w, "Invalid email", http.StatusBadRequest)
		return
	}
	if !s.localPasswordIdentityAllowed(email) {
		writeError(w, "Account is not eligible for local password authentication", http.StatusForbidden)
		return
	}
	err = s.checkEmailAuthorization(email)
	if err != nil {
		writeError(w, err.Error(), http.StatusForbidden)
		return
	}
	err = s.checkAttack(r)
	if err != nil {
		writeError(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	token := randomToken(32)
	verificationURL, err := s.verificationURL(email, token)
	if err != nil {
		writeError(w, "Password registration is not configured", http.StatusServiceUnavailable)
		return
	}
	registerData := map[string]string{
		"user": email, "token": token}
	session.Put("register", registerData)
	s.setAttack(r)
	ip := GetClientIP(r)
	err = s.sendVerificationEmail(email, verificationURL, ip)
	if err != nil {
		session.Delete("register")
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = s.renderHtmlTemplate(w, "show_passwd", "")
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type pendingRegistration struct {
	Email string
	Token string
}

type verificationConfirmation struct {
	Email string
	Token string
}

func (s *state) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	var reqEmail, reqToken string
	if r.Method == http.MethodGet {
		reqEmail = r.URL.Query().Get("email")
		reqToken = r.URL.Query().Get("token")
	} else {
		if err := r.ParseForm(); err != nil {
			writeError(w, "Invalid verification request", http.StatusBadRequest)
			return
		}
		reqEmail = r.PostForm.Get("email")
		reqToken = r.PostForm.Get("token")
	}
	reqEmail, err := canonicalAccountEmail(reqEmail)
	if err != nil {
		s.renderVerificationFailure(w)
		return
	}

	session := GetGoSession(r)
	registration, ok := pendingRegistrationFromSession(session)
	if !ok || registration.Email != reqEmail || subtle.ConstantTimeCompare([]byte(registration.Token), []byte(reqToken)) != 1 {
		s.renderVerificationFailure(w)
		return
	}

	if r.Method == http.MethodGet {
		if err := s.renderHtmlTemplate(w, "verify_confirm", verificationConfirmation{Email: reqEmail, Token: reqToken}); err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Authorization and account source are checked again at the mutating step:
	// the published policy may have changed after the mail was requested.
	if !s.localPasswordIdentityAllowed(reqEmail) || s.checkEmailAuthorization(reqEmail) != nil {
		s.renderVerificationFailure(w)
		return
	}
	// The password is generated only after possession of the emailed token was
	// proven by this explicit POST. It is never disclosed to the unauthenticated
	// browser that initiated the request.
	password := generatePassword(16, true, true, true)
	hash, err := encodePassword(password)
	if err != nil {
		writeError(w, "Failed to create password", http.StatusInternalServerError)
		return
	}
	if err := s.storePassword(reqEmail, hash); err != nil {
		writeError(w, "Failed to save password", http.StatusInternalServerError)
		return
	}
	session.Delete("register")
	s.clearAttack(r)
	if err := s.renderHtmlTemplate(w, "verify_ok", password); err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
	}
}

func pendingRegistrationFromSession(session *GoSession) (pendingRegistration, bool) {
	if session == nil {
		return pendingRegistration{}, false
	}
	data := session.Get("register")
	var result pendingRegistration
	switch registerData := data.(type) {
	case map[string]string:
		result = pendingRegistration{Email: registerData["user"], Token: registerData["token"]}
	case map[string]any:
		var ok bool
		if result.Email, ok = registerData["user"].(string); !ok {
			return pendingRegistration{}, false
		}
		if result.Token, ok = registerData["token"].(string); !ok {
			return pendingRegistration{}, false
		}
	default:
		return pendingRegistration{}, false
	}
	if result.Email == "" || result.Token == "" {
		return pendingRegistration{}, false
	}
	return result, true
}

func (s *state) renderVerificationFailure(w http.ResponseWriter) {
	if err := s.renderHtmlTemplate(w, "verify_fail", ""); err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *state) verificationURL(email, token string) (string, error) {
	base, err := normalizedPublicBaseURL(s.config.PublicBaseURL)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u = u.ResolveReference(&url.URL{Path: "backend6/verify"})
	query := u.Query()
	query.Set("email", email)
	query.Set("token", token)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (s *state) renderHtmlTemplate(w http.ResponseWriter, p string, data any) error {
	tmplPath := path.Join(s.config.HTMLTemplate, p)
	tmpl, err := htmltemplate.ParseFiles(tmplPath)
	if err != nil {
		return fmt.Errorf("failed to load template %s: %w", tmplPath, err)
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		return fmt.Errorf("failed to render template %s: %w", tmplPath, err)
	}
	return nil
}

func (s *state) storePassword(email, hash string) error {
	userFile, err := safeUserFile(s.config.UserDir, email)
	if err != nil {
		return err
	}
	return updateUserStore(userFile, true, func(store *UserStore) (bool, error) {
		store.Hash = hash
		return true, nil
	})
}

func (s *state) sendEmail(text string) error {
	if s.config.MailTransport == "smtp" {
		return s.sendSMTP(text)
	}
	sendmail := s.config.SendmailCommand
	noreply := s.config.NoreplyAddress

	cmd := exec.Command(sendmail, "-t", "-F", "''", "-f", noreply)
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	_, err = pipe.Write([]byte(text))
	if err != nil {
		return err
	}

	pipe.Close()
	if err := cmd.Wait(); err != nil {
		return err
	}
	return nil
}

func (s *state) sendSMTP(text string) error {
	recipients, err := mailRecipients(text)
	if err != nil {
		return err
	}
	from, err := mail.ParseAddress(s.config.NoreplyAddress)
	if err != nil {
		return fmt.Errorf("invalid noreply_address: %w", err)
	}
	host := s.config.SMTPHost
	addr := fmt.Sprintf("%s:%d", host, s.config.SMTPPort)
	var auth smtp.Auth
	if s.config.SMTPUsernameEnv != "" {
		auth = smtp.PlainAuth("", os.Getenv(s.config.SMTPUsernameEnv), os.Getenv(s.config.SMTPPasswordEnv), host)
	}
	if !strings.Contains(strings.ToLower(text), "\nfrom:") && !strings.HasPrefix(strings.ToLower(text), "from:") {
		text = "From: " + s.config.NoreplyAddress + "\n" + text
	}
	text = stripMailHeader(text, "bcc")
	// SMTP messages use CRLF line endings on the wire.
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
	return smtp.SendMail(addr, auth, from.Address, recipients, []byte(text))
}

func stripMailHeader(text, header string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	result := make([]string, 0, len(lines))
	skipping := false
	inHeaders := true
	prefix := strings.ToLower(header) + ":"
	for _, line := range lines {
		if inHeaders && line == "" {
			inHeaders = false
			skipping = false
		}
		if inHeaders && strings.HasPrefix(strings.ToLower(line), prefix) {
			skipping = true
			continue
		}
		if skipping && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			continue
		}
		skipping = false
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

func mailRecipients(text string) ([]string, error) {
	message, err := mail.ReadMessage(bufio.NewReader(strings.NewReader(text)))
	if err != nil {
		return nil, fmt.Errorf("parse mail headers: %w", err)
	}
	var result []string
	seen := make(map[string]bool)
	for _, header := range []string{"To", "Cc", "Bcc"} {
		addresses, err := message.Header.AddressList(header)
		if err == mail.ErrHeaderNotPresent {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("parse %s header: %w", header, err)
		}
		for _, address := range addresses {
			key := strings.ToLower(address.Address)
			if !seen[key] {
				result = append(result, address.Address)
				seen[key] = true
			}
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("mail has no recipient")
	}
	return result, nil
}

func (s *state) sendVerificationEmail(email, url, ip string) error {
	templatePath := fmt.Sprintf("%s/verify", s.config.MailTemplate)
	text, err := s.getTemplateContent(templatePath, map[string]string{
		"email": email,
		"url":   url,
		"ip":    ip,
	})
	if err != nil {
		return fmt.Errorf("failed to get email template: %w", err)
	}
	err = s.sendEmail(text)
	if err != nil {
		return fmt.Errorf("failed to send email to %s: %w", email, err)
	}
	return nil
}

func (s *state) getTemplateContent(templatePath string, data map[string]string) (string, error) {
	tmpl, err := texttemplate.ParseFiles(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var builder strings.Builder
	err = tmpl.Execute(&builder, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return builder.String(), nil
}

func (s *state) checkEmailAuthorization(email string) error {
	if _, active := s.activeAccount(email); active {
		return nil
	}
	return fmt.Errorf("email %s is not authorized", email)
}

func (s *state) localPasswordIdentityAllowed(email string) bool {
	user, active := s.activeAccount(email)
	return active && user.Source == "local"
}

const (
	letterBytes  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	specialBytes = "!@#$%^&*()_+-=[]{}\\|;':\",.<>/?`~"
	numBytes     = "0123456789"
)

func generatePassword(length int, useLetters bool, useSpecial bool, useNum bool) string {
	alphabet := ""
	classes := []string{}
	if useLetters {
		alphabet += letterBytes
		classes = append(classes, letterBytes)
	}
	if useSpecial {
		alphabet += specialBytes
		classes = append(classes, specialBytes)
	}
	if useNum {
		alphabet += numBytes
		classes = append(classes, numBytes)
	}
	if length <= 0 || alphabet == "" {
		return ""
	}
	b := make([]byte, length)
	i := 0
	for ; i < len(classes) && i < len(b); i++ {
		class := classes[i]
		b[i] = class[secureRandomIndex(len(class))]
	}
	for ; i < len(b); i++ {
		b[i] = alphabet[secureRandomIndex(len(alphabet))]
	}
	for i := len(b) - 1; i > 0; i-- {
		j := secureRandomIndex(i + 1)
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func secureRandomIndex(limit int) int {
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		panic("failed to obtain secure random data")
	}
	return int(n.Int64())
}

func randomToken(length int) string {
	b := make([]byte, length)
	if _, err := cryptorand.Read(b); err != nil {
		panic("failed to obtain secure random data")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *state) readAttackFile(r *http.Request) string {
	// Hashing keeps attacker-controlled address text out of filesystem paths and
	// produces portable names for both IPv4 and IPv6 clients.
	digest := sha256.Sum256([]byte(GetClientIP(r)))
	return filepath.Join(s.config.SessionDir, fmt.Sprintf("attack-%x", digest))
}

func (s *state) readAttackCount(r *http.Request) int {
	file := s.readAttackFile(r)
	data, err := os.ReadFile(file)
	if err != nil {
		return 0
	}
	count, err := strconv.Atoi(string(data))
	if err != nil {
		return 0
	}
	return count
}

func (s *state) storeAttackCount(r *http.Request, count int) error {
	file := s.readAttackFile(r)
	if err := os.WriteFile(file, []byte(strconv.Itoa(count)), 0600); err != nil {
		return err
	}
	// WriteFile preserves the mode of an existing file.
	return os.Chmod(file, 0600)
}

func (s *state) readAttackModified(r *http.Request) (time.Time, error) {
	file := s.readAttackFile(r)
	info, err := os.Stat(file)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func (s *state) setAttack(r *http.Request) {
	attackFileMu.Lock()
	defer attackFileMu.Unlock()
	count := s.readAttackCount(r)
	count++
	_ = s.storeAttackCount(r, count)
}

func (s *state) checkAttack(r *http.Request) error {
	attackFileMu.Lock()
	defer attackFileMu.Unlock()
	count := s.readAttackCount(r)
	if count == 0 {
		return nil
	}
	modified, err := s.readAttackModified(r)
	if err != nil {
		return err
	}
	wait := count * 10
	if wait > 120 {
		wait = 120
	}
	remain := int(time.Until(modified.Add(time.Duration(wait) * time.Second)).Seconds())
	if remain > 0 {
		return fmt.Errorf("wait for %d seconds after wrong password", remain)
	}
	return nil
}

func (s *state) clearAttack(r *http.Request) {
	attackFileMu.Lock()
	defer attackFileMu.Unlock()
	file := s.readAttackFile(r)
	_ = os.Remove(file)
}

// Standard headers list
var requestHeaders = []string{"X-Client-Ip", "X-Forwarded-For",
	"Cf-Connecting-Ip", "Fastly-Client-Ip", "True-Client-Ip",
	"X-Real-Ip", "X-Cluster-Client-Ip", "X-Forwarded",
	"Forwarded-For", "Forwarded"}

// returns IP address string; The IP address if known, defaulting to empty string.
func GetClientIP(r *http.Request) string {
	if trustProxyHeaders() {
		for _, header := range requestHeaders {
			switch header {
			case "X-Forwarded-For": // Load-balancers (AWS ELB) or proxies.
				if host, correctIP := getClientIPFromXForwardedFor(r.Header.Get(header)); correctIP {
					return host
				}
			default:
				if host := r.Header.Get(header); isCorrectIP(host) {
					return host
				}
			}
		}
	}

	//  remote address checks.
	host, _, splitHostPortError := net.SplitHostPort(r.RemoteAddr)
	if splitHostPortError == nil && isCorrectIP(host) {
		return host
	}
	if isCorrectIP(r.RemoteAddr) {
		return r.RemoteAddr
	}
	return ""
}

// returns first known ip address else return empty string
func getClientIPFromXForwardedFor(headers string) (string, bool) {
	if headers == "" {
		return "", false
	}
	// x-forwarded-for may return multiple IP addresses in the format:
	// "client IP, proxy 1 IP, proxy 2 IP"
	// Therefore, the right-most IP address is the IP address of the most recent proxy
	// and the left-most IP address is the IP address of the originating client.
	forwardedIps := strings.Split(headers, ",")
	for _, ip := range forwardedIps {
		// header can contain spaces too, strip those out.
		ip = strings.TrimSpace(ip)
		// make sure we only use this if it's ipv4 (ip:port)
		if splitted := strings.Split(ip, ":"); len(splitted) == 2 {
			ip = splitted[0]
		}
		if isCorrectIP(ip) {
			return ip, true
		}
	}
	return "", false
}

// return true if ip string is valid textual representation of an IP address,
// else returns false
func isCorrectIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
