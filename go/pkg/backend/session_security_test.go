package backend

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFailedLocalLoginInvalidatesExistingSession(t *testing.T) {
	s := &state{config: &config{SessionDir: t.TempDir()}}
	session := newSession()
	session.Put("email", "admin@example.test")
	session.Put("loggedIn", true)
	before := session.ID

	form := url.Values{"email": {"user@example.test"}, "pass": {"wrong"}}
	r := httptest.NewRequest(http.MethodPost, "http://policy.example.test/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.0.2.10:12345"
	r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, session))
	// Force the handler down a cheap failed-login path after it rotates the
	// session, without depending on templates or account files.
	s.setAttack(r)
	w := httptest.NewRecorder()
	s.loginHandler(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTooManyRequests)
	}
	if session.ID == before || session.Get("email") != nil || session.Get("loggedIn").(bool) {
		t.Fatalf("failed local login preserved authenticated session: %#v", session)
	}
}

func TestSessionRotationDestroysPreviousSession(t *testing.T) {
	store := NewFileSystemSessionStore(t.TempDir())
	manager := &SessionManager{store: store, idleExpiration: time.Hour, absoluteExpiration: 24 * time.Hour, cookieName: "test"}
	session := newSession()
	oldID := session.ID
	if err := store.write(session); err != nil {
		t.Fatal(err)
	}
	manager.rotate(session)
	if session.ID == oldID {
		t.Fatal("session ID was not rotated")
	}
	old, err := store.read(oldID)
	if err != nil {
		t.Fatal(err)
	}
	if old != nil {
		t.Fatal("previous session still exists")
	}
}

func TestConcurrentRequestCannotResurrectLoggedOutSession(t *testing.T) {
	dir := t.TempDir()
	store := NewFileSystemSessionStore(dir)
	manager := &SessionManager{store: store, idleExpiration: time.Hour, absoluteExpiration: 24 * time.Hour, cookieName: "test"}
	session := newSession()
	session.Put("email", "admin@example.test")
	session.Put("loggedIn", true)
	oldID := session.ID
	if err := store.write(session); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://policy.example.test/", nil)
	request.AddCookie(&http.Cookie{Name: "test", Value: oldID})
	// Model an older request that has loaded the authenticated session and is
	// still running when logout arrives.
	releaseOld := manager.lockRequestSession(request)
	stale, err := store.read(oldID)
	if err != nil {
		t.Fatal(err)
	}
	logoutDone := make(chan error)
	go func() {
		releaseLogout := manager.lockRequestSession(request)
		defer releaseLogout()
		current, err := store.read(oldID)
		if err != nil {
			logoutDone <- err
			return
		}
		manager.rotate(current)
		logoutDone <- store.write(current)
	}()

	// Wait until logout is registered as a waiter on the same request lock.
	deadline := time.Now().Add(time.Second)
	for {
		manager.requestMu.Lock()
		waiters := 0
		if entry := manager.requestLocks[oldID]; entry != nil {
			waiters = entry.refs
		}
		manager.requestMu.Unlock()
		if waiters == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("logout request did not reach the session serialization gate")
		}
		time.Sleep(time.Millisecond)
	}
	// The old request completes first. Logout must then read that final state,
	// invalidate it, and leave no old authenticated session behind.
	stale.Put("owner", "late-update")
	if err := store.write(stale); err != nil {
		t.Fatal(err)
	}
	releaseOld()
	if err := <-logoutDone; err != nil {
		t.Fatal(err)
	}
	if restored, err := store.read(oldID); err != nil || restored != nil {
		t.Fatalf("revoked session was resurrected: session=%#v err=%v", restored, err)
	}
}

func TestRevokedSessionCannotBeResurrectedAcrossStores(t *testing.T) {
	dir := t.TempDir()
	primary := NewFileSystemSessionStore(dir)
	// Independent mutexes model two server processes sharing the directory.
	concurrent := NewFileSystemSessionStore(dir)
	manager := &SessionManager{store: primary, idleExpiration: time.Hour, absoluteExpiration: 24 * time.Hour, cookieName: "test"}
	session := newSession()
	session.Put("email", "admin@example.test")
	session.Put("loggedIn", true)
	oldID := session.ID
	if err := primary.write(session); err != nil {
		t.Fatal(err)
	}

	type loadResult struct {
		session *GoSession
		err     error
	}
	loaded := make(chan loadResult)
	allowSave := make(chan struct{})
	saved := make(chan error)
	go func() {
		stale, err := concurrent.read(oldID)
		loaded <- loadResult{session: stale, err: err}
		if err != nil {
			return
		}
		<-allowSave
		saved <- concurrent.write(stale)
	}()
	result := <-loaded
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.session == nil || result.session.Get("loggedIn") != true {
		t.Fatalf("concurrent process did not load authenticated session: %#v", result.session)
	}
	manager.rotate(session)
	close(allowSave)
	if err := <-saved; !errors.Is(err, errSessionRevoked) {
		t.Fatalf("stale process save error = %v, want %v", err, errSessionRevoked)
	}
	if restored, err := primary.read(oldID); err != nil || restored != nil {
		t.Fatalf("revoked session was resurrected: session=%#v err=%v", restored, err)
	}
	if _, err := os.Stat(primary.revokedPath(oldID)); err != nil {
		t.Fatalf("revocation marker missing: %v", err)
	}
}

func TestUnpersistedSessionRotationDoesNotCreateTombstone(t *testing.T) {
	store := NewFileSystemSessionStore(t.TempDir())
	manager := &SessionManager{store: store}
	session := newSession()
	oldID := session.ID
	manager.rotate(session)
	if _, err := os.Stat(store.revokedPath(oldID)); !os.IsNotExist(err) {
		t.Fatalf("unpersisted session created a revocation marker: %v", err)
	}
}

func TestLoginAndLogoutRotateSessionAndClearData(t *testing.T) {
	store := NewFileSystemSessionStore(t.TempDir())
	manager := &SessionManager{store: store, idleExpiration: time.Hour, absoluteExpiration: 24 * time.Hour, cookieName: "test"}
	s := &state{sessionManager: manager}
	session := newSession()
	session.Put("owner", "sensitive-owner")
	if err := store.write(session); err != nil {
		t.Fatal(err)
	}
	beforeLogin := session.ID
	s.setLogin(session, "admin@example.test")
	if session.ID == beforeLogin || session.Get("owner") != nil || !session.Get("loggedIn").(bool) {
		t.Fatalf("unsafe login session state: %#v", session)
	}
	if err := store.write(session); err != nil {
		t.Fatal(err)
	}
	beforeLogout := session.ID
	s.logout(session)
	if session.ID == beforeLogout || session.Get("email") != nil || session.Get("loggedIn").(bool) {
		t.Fatalf("unsafe logout session state: %#v", session)
	}
	old, err := store.read(beforeLogout)
	if err != nil {
		t.Fatal(err)
	}
	if old != nil {
		t.Fatal("authenticated session survived logout")
	}

	// Exercise the same context representation used by request handlers.
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, session))
	if GetGoSession(r) != session {
		t.Fatal("rotated session pointer was not retained in request context")
	}
}

func TestSessionFilesArePrivate(t *testing.T) {
	dir := t.TempDir()
	store := NewFileSystemSessionStore(dir)
	session := newSession()
	if err := store.write(session); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, session.ID))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("session file mode = %v", info.Mode().Perm())
	}
}

func TestSecureSessionCookieDetection(t *testing.T) {
	t.Setenv("POLICYWEB_COOKIE_SECURE", "")
	t.Setenv("POLICYWEB_TRUST_PROXY_HEADERS", "")
	if secureSessionCookie(httptest.NewRequest("GET", "http://example.test/", nil)) {
		t.Fatal("plain HTTP request was treated as secure")
	}
	if !secureSessionCookie(httptest.NewRequest("GET", "https://example.test/", nil)) {
		t.Fatal("TLS request was not treated as secure")
	}
	proxied := httptest.NewRequest("GET", "http://example.test/", nil)
	proxied.Header.Set("X-Forwarded-Proto", "https")
	if secureSessionCookie(proxied) {
		t.Fatal("untrusted forwarded header was accepted")
	}
	t.Setenv("POLICYWEB_TRUST_PROXY_HEADERS", "true")
	if !secureSessionCookie(proxied) {
		t.Fatal("trusted HTTPS proxy was not detected")
	}
}
