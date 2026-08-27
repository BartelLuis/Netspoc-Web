package backend

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestGeneratedPasswordUsesRequestedAlphabet(t *testing.T) {
	password := generatePassword(64, true, true, true)
	if len(password) != 64 {
		t.Fatalf("password length = %d", len(password))
	}
	alphabet := letterBytes + specialBytes + numBytes
	for _, char := range password {
		if !strings.ContainsRune(alphabet, char) {
			t.Fatalf("generated character %q is outside requested alphabet", char)
		}
	}
	if !strings.ContainsAny(password, letterBytes) || !strings.ContainsAny(password, specialBytes) || !strings.ContainsAny(password, numBytes) {
		t.Fatalf("generated password does not contain every requested class: %q", password)
	}
}

func TestLoginAttemptThrottleIsEnforced(t *testing.T) {
	t.Setenv("POLICYWEB_TRUST_PROXY_HEADERS", "false")
	s := &state{config: &config{SessionDir: t.TempDir()}}
	r := httptest.NewRequest("POST", "http://policy.example.test/login", nil)
	s.setAttack(r)
	if err := s.checkAttack(r); err == nil {
		t.Fatal("failed login did not activate throttle")
	}
	s.clearAttack(r)
	if err := s.checkAttack(r); err != nil {
		t.Fatalf("cleared throttle remained active: %v", err)
	}
}

func TestClientIPHonorsProxyTrustSetting(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://policy.example.test/login", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")

	t.Setenv("POLICYWEB_TRUST_PROXY_HEADERS", "false")
	if got := GetClientIP(r); got != "192.0.2.10" {
		t.Fatalf("untrusted forwarding header changed client IP to %q", got)
	}
	t.Setenv("POLICYWEB_TRUST_PROXY_HEADERS", "true")
	if got := GetClientIP(r); got != "198.51.100.7" {
		t.Fatalf("trusted forwarding header produced client IP %q", got)
	}
}

func TestAttackFileIsPrivatePortableAndRaceSafe(t *testing.T) {
	t.Setenv("POLICYWEB_TRUST_PROXY_HEADERS", "false")
	s := &state{config: &config{SessionDir: t.TempDir()}}
	r := httptest.NewRequest(http.MethodPost, "http://policy.example.test/login", nil)
	r.RemoteAddr = "[2001:db8::1]:1234"
	name := filepath.Base(s.readAttackFile(r))
	if !strings.HasPrefix(name, "attack-") || len(strings.TrimPrefix(name, "attack-")) != 64 || strings.Contains(name, ":") {
		t.Fatalf("unsafe or non-portable attack filename %q", name)
	}

	const attempts = 16
	var workers sync.WaitGroup
	workers.Add(attempts)
	for range attempts {
		go func() {
			defer workers.Done()
			s.setAttack(r)
		}()
	}
	workers.Wait()
	if got := s.readAttackCount(r); got != attempts {
		t.Fatalf("concurrent attack count = %d, want %d", got, attempts)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(s.readAttackFile(r))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("attack-file permissions = %04o, want 0600", got)
		}
	}
}

func TestRandomTokensDiffer(t *testing.T) {
	first := randomToken(32)
	second := randomToken(32)
	if first == second || len(first) < 40 || len(second) < 40 {
		t.Fatalf("tokens are not independent: %q %q", first, second)
	}
}

func TestVerificationURLUsesOnlyConfiguredPublicOrigin(t *testing.T) {
	s := &state{config: &config{PublicBaseURL: "https://policy.example.test"}}
	got, err := s.verificationURL("user+test@example.test", "token/value")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "policy.example.test" || u.Path != "/backend6/verify" {
		t.Fatalf("unexpected verification URL: %q", got)
	}
	if u.Query().Get("email") != "user+test@example.test" || u.Query().Get("token") != "token/value" {
		t.Fatalf("verification parameters were not encoded safely: %q", got)
	}
}

func TestPublicBaseURLRejectsUnsafeOrigins(t *testing.T) {
	for _, raw := range []string{
		"",
		"javascript:alert(1)",
		"https://user:password@policy.example.test",
		"https://policy.example.test/a/path",
		"https://policy.example.test/?redirect=https://evil.example",
		"http://policy.example.test",
	} {
		if _, err := normalizedPublicBaseURL(raw); err == nil {
			t.Errorf("unsafe public_base_url %q was accepted", raw)
		}
	}
	for _, raw := range []string{"https://policy.example.test", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if _, err := normalizedPublicBaseURL(raw); err != nil {
			t.Errorf("safe public_base_url %q was rejected: %v", raw, err)
		}
	}
}

func TestLocalPasswordIdentityUsesPublishedPolicy(t *testing.T) {
	s := workflowTestState(t)
	published := validEditablePolicy()
	published.Users = append(published.Users, editableUser{
		Email: "directory@example.test", Role: "viewer", Source: "ldap", DirectoryID: "ldap-1", Username: "directory", Active: true,
	})
	if err := s.storePublication("published-auth", published); err != nil {
		t.Fatal(err)
	}

	// A mutable draft must not turn the published LDAP identity into a local
	// password account.
	draft := validEditablePolicy()
	draft.Users = append(draft.Users, editableUser{Email: "directory@example.test", Role: "viewer", Password: "local-password"})
	if _, err := s.saveDraftAs(draft, "admin@example.net", nil); err != nil {
		t.Fatal(err)
	}
	if s.localPasswordIdentityAllowed("directory@example.test") {
		t.Fatal("published LDAP identity was accepted for local password authentication")
	}
	if !s.localPasswordIdentityAllowed("admin@example.net") {
		t.Fatal("published local identity was rejected")
	}

	form := url.Values{"email": {"directory@example.test"}}
	request := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, newSession()))
	recorder := httptest.NewRecorder()
	s.register(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("LDAP local registration status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestVerifyGETOnlyShowsConfirmationAndPOSTStoresPassword(t *testing.T) {
	root := t.TempDir()
	policyDir := filepath.Join(root, "policies")
	if err := writeJSONFile(filepath.Join(policyDir, "current", "email"), map[string][]string{"local@example.test": {"team"}}); err != nil {
		t.Fatal(err)
	}
	templateDir, err := filepath.Abs("html-templates")
	if err != nil {
		t.Fatal(err)
	}
	s := &state{
		config: &config{
			NetspocData:  policyDir,
			UserDir:      filepath.Join(root, "users"),
			SessionDir:   filepath.Join(root, "sessions"),
			HTMLTemplate: templateDir,
		},
		cache: newCache(policyDir, 8),
	}
	// The production "current" path is a symlink to a p... version. Windows
	// test runners commonly lack symlink privileges, so seed the resolved cache
	// entry directly while retaining a real current directory for EvalSymlinks.
	s.cache.getCacheEntry("current").email = map[string][]string{"local@example.test": {"team"}}
	session := newSession()
	session.Put("register", map[string]any{"user": "local@example.test", "token": "test-token"})
	userFile, err := safeUserFile(s.config.UserDir, "local@example.test")
	if err != nil {
		t.Fatal(err)
	}

	query := url.Values{"email": {"local@example.test"}, "token": {"test-token"}}
	getRequest := httptest.NewRequest(http.MethodGet, "/verify?"+query.Encode(), nil)
	getRequest = getRequest.WithContext(context.WithValue(getRequest.Context(), sessionContextKey{}, session))
	getRecorder := httptest.NewRecorder()
	s.verify(getRecorder, getRequest)
	if getRecorder.Code != http.StatusOK || !strings.Contains(strings.ToLower(getRecorder.Body.String()), `method="post"`) {
		t.Fatalf("GET did not render POST confirmation: status=%d body=%s", getRecorder.Code, getRecorder.Body.String())
	}
	if _, err := os.Stat(userFile); !os.IsNotExist(err) {
		t.Fatalf("GET changed the password file: %v", err)
	}
	if session.Get("register") == nil {
		t.Fatal("GET consumed the pending registration")
	}
	if !s.localPasswordIdentityAllowed("local@example.test") {
		t.Fatal("local test identity was rejected by the authorization policy")
	}
	if err := s.checkEmailAuthorization("local@example.test"); err != nil {
		t.Fatalf("local test identity is not authorized: %v", err)
	}

	postRequest := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(query.Encode()))
	postRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRequest = postRequest.WithContext(context.WithValue(postRequest.Context(), sessionContextKey{}, session))
	postRecorder := httptest.NewRecorder()
	s.verify(postRecorder, postRequest)
	if postRecorder.Code != http.StatusOK {
		t.Fatalf("POST confirmation status = %d, body=%s", postRecorder.Code, postRecorder.Body.String())
	}
	password := passwordFromVerificationResponse(t, postRecorder.Body.String())
	store, err := GetUserStore(userFile)
	if err != nil {
		t.Fatal(err)
	}
	if !store.CheckPassword(password) {
		t.Fatal("displayed post-verification password does not match stored hash")
	}
	if session.Get("register") != nil {
		t.Fatal("successful POST retained the pending registration")
	}
}

func passwordFromVerificationResponse(t *testing.T, body string) string {
	t.Helper()
	const marker = `value="`
	start := strings.Index(body, marker)
	if start == -1 {
		t.Fatalf("verification response did not display a password: %s", body)
	}
	start += len(marker)
	end := strings.Index(body[start:], `"`)
	if end == -1 {
		t.Fatalf("verification response contains an unterminated password value: %s", body)
	}
	password := html.UnescapeString(body[start : start+end])
	if len(password) != 16 {
		t.Fatalf("displayed password length = %d, want 16", len(password))
	}
	return password
}

func TestPreVerificationTemplateNeverDisclosesPasswordData(t *testing.T) {
	templateDir, err := filepath.Abs("html-templates")
	if err != nil {
		t.Fatal(err)
	}
	s := &state{config: &config{HTMLTemplate: templateDir}}
	recorder := httptest.NewRecorder()
	const sentinel = "PRE-VERIFICATION-SECRET"
	if err := s.renderHtmlTemplate(recorder, "show_passwd", sentinel); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(recorder.Body.String(), sentinel) {
		t.Fatal("pre-verification response disclosed password material")
	}
}

func TestVerifyRejectsUnsafeMethodAndMalformedSession(t *testing.T) {
	s := &state{config: &config{HTMLTemplate: "html-templates"}}
	request := httptest.NewRequest(http.MethodPut, "/verify", nil)
	recorder := httptest.NewRecorder()
	s.verify(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT verification status = %d", recorder.Code)
	}

	session := newSession()
	session.Put("register", map[string]any{"user": 123})
	if _, ok := pendingRegistrationFromSession(session); ok {
		t.Fatal("malformed registration session was accepted")
	}
}
