package backend

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type GoSession struct {
	CreatedAt      time.Time      `json:"created_at"`
	LastActivityAt time.Time      `json:"last_activity_at"`
	ID             string         `json:"id"`
	Data           map[string]any `json:"data"`
}

type SessionStore interface {
	read(id string) (*GoSession, error)
	write(session *GoSession) error
	destroy(id string) error
	gc(idleExpiration, absoluteExpiration time.Duration) error
}

type SessionManager struct {
	store              SessionStore
	idleExpiration     time.Duration
	absoluteExpiration time.Duration
	cookieName         string
	requestMu          sync.Mutex
	requestLocks       map[string]*sessionRequestLock
}

type sessionRequestLock struct {
	mu   sync.Mutex
	refs int
}

func (m *SessionManager) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serialize the full read/handler/write lifecycle for requests that carry
		// the same session ID. This prevents ordinary session data updates (for
		// example one-time verification tokens) from losing each other.
		release := m.lockRequestSession(r)
		defer release()
		// Start the session
		session, rws := m.start(r)

		// Create a new response writer
		sw := &sessionResponseWriter{
			ResponseWriter: w,
			sessionManager: m,
			request:        rws,
		}

		// Add essential headers
		w.Header().Add("Vary", "Cookie")
		w.Header().Add("Cache-Control", `no-cache="Set-Cookie"`)

		// Call the next handler and pass the new response writer and new request
		next.ServeHTTP(sw, rws)

		// Save the session
		if err := m.save(session); err != nil && !errors.Is(err, errSessionRevoked) {
			log.Printf("Failed to save session: %v", err)
		}

		// Write the session cookie to the response if not already written
		writeCookieIfNecessary(sw)
	})
}

func (m *SessionManager) lockRequestSession(r *http.Request) func() {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil || !validSessionID(cookie.Value) {
		return func() {}
	}
	id := cookie.Value
	m.requestMu.Lock()
	if m.requestLocks == nil {
		m.requestLocks = make(map[string]*sessionRequestLock)
	}
	entry := m.requestLocks[id]
	if entry == nil {
		entry = &sessionRequestLock{}
		m.requestLocks[id] = entry
	}
	entry.refs++
	m.requestMu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		m.requestMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(m.requestLocks, id)
		}
		m.requestMu.Unlock()
	}
}

type sessionResponseWriter struct {
	http.ResponseWriter
	sessionManager *SessionManager
	request        *http.Request
	done           bool
}

func (w *sessionResponseWriter) Write(b []byte) (int, error) {
	writeCookieIfNecessary(w)
	return w.ResponseWriter.Write(b)
}

func (w *sessionResponseWriter) WriteHeader(code int) {
	writeCookieIfNecessary(w)
	w.ResponseWriter.WriteHeader(code)
}

func (w *sessionResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func writeCookieIfNecessary(w *sessionResponseWriter) {
	if w.done {
		return
	}

	session, ok := w.request.Context().Value(sessionContextKey{}).(*GoSession)
	if !ok {
		panic("session not found in request context")
	}

	cookie := &http.Cookie{
		Name:  w.sessionManager.cookieName,
		Value: session.ID,
		//Domain:   "localhost",
		HttpOnly: true,
		Path:     "/",
		Secure:   secureSessionCookie(w.request),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(w.sessionManager.idleExpiration),
		MaxAge:   int(w.sessionManager.idleExpiration / time.Second),
	}

	http.SetCookie(w.ResponseWriter, cookie)

	w.done = true
}

// secureSessionCookie supports TLS termination without trusting forwarded
// headers from arbitrary clients. POLICYWEB_COOKIE_SECURE is an explicit
// override. X-Forwarded-Proto is only considered when
// POLICYWEB_TRUST_PROXY_HEADERS is enabled.
func secureSessionCookie(r *http.Request) bool {
	if configured := strings.TrimSpace(os.Getenv("POLICYWEB_COOKIE_SECURE")); configured != "" {
		secure, err := strconv.ParseBool(configured)
		if err == nil {
			return secure
		}
	}
	if r.TLS != nil {
		return true
	}
	if !trustProxyHeaders() {
		return false
	}
	proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return strings.EqualFold(proto, "https")
}

func trustProxyHeaders() bool {
	trusted, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv("POLICYWEB_TRUST_PROXY_HEADERS")))
	return trusted
}

func GetGoSession(r *http.Request) *GoSession {
	session, ok := r.Context().Value(sessionContextKey{}).(*GoSession)
	if !ok {
		panic("session not found in request context")
	}

	return session
}

func generateSessionId() string {
	id := make([]byte, 32)

	_, err := io.ReadFull(rand.Reader, id)
	if err != nil {
		panic("failed to generate session id")
	}

	return base64.RawURLEncoding.EncodeToString(id)
}

func newSession() *GoSession {
	return &GoSession{
		ID:             generateSessionId(),
		Data:           make(map[string]any),
		CreatedAt:      time.Now(),
		LastActivityAt: time.Now(),
	}
}

func validSessionID(id string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(decoded) == 32
}

// rotate invalidates the previous server-side session and replaces it in
// place, so the request context and response writer immediately use the new
// identifier. Session data is deliberately cleared at authentication
// boundaries to prevent fixation and data from a previous identity leaking.
func (m *SessionManager) rotate(session *GoSession) {
	oldID := session.ID
	if oldID != "" {
		if err := m.store.destroy(oldID); err != nil {
			panic(err)
		}
	}
	*session = *newSession()
}

func (s *GoSession) Get(key string) any {
	return s.Data[key]
}

func (s *GoSession) Put(key string, value any) {
	s.Data[key] = value
}

func (s *GoSession) Delete(key string) {
	delete(s.Data, key)
}

func NewSessionManager(
	store SessionStore,
	gcInterval,
	idleExpiration,
	absoluteExpiration time.Duration,
	cookieName string) *SessionManager {

	m := &SessionManager{
		store:              store,
		idleExpiration:     idleExpiration,
		absoluteExpiration: absoluteExpiration,
		cookieName:         cookieName,
	}

	go m.gc(gcInterval)

	return m
}

func (m *SessionManager) gc(d time.Duration) {
	ticker := time.NewTicker(d)

	for range ticker.C {
		m.store.gc(m.idleExpiration, m.absoluteExpiration)
	}
}

func (m *SessionManager) validate(session *GoSession) bool {
	if time.Since(session.CreatedAt) > m.absoluteExpiration ||
		time.Since(session.LastActivityAt) > m.idleExpiration {

		// Delete the session from the store
		err := m.store.destroy(session.ID)
		if err != nil {
			panic(err)
		}

		return false
	}

	return true
}

type sessionContextKey struct{}

// Retrieves the session by reading the session cookie or generates a new
// one if needed. It then attaches the session to the request using context values.
func (m *SessionManager) start(r *http.Request) (*GoSession, *http.Request) {
	var session *GoSession

	// Read From Cookie
	cookie, err := r.Cookie(m.cookieName)
	if err == nil && validSessionID(cookie.Value) {
		session, err = m.store.read(cookie.Value)
		if err != nil {
			log.Printf("Failed to read session from store: %v", err)
		}
	}

	// Generate a new session
	if session == nil || !m.validate(session) {
		session = newSession()
	}

	// Attach session to context
	ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
	r = r.WithContext(ctx)

	return session, r
}

func (m *SessionManager) save(session *GoSession) error {
	session.LastActivityAt = time.Now()

	err := m.store.write(session)
	if err != nil {
		return err
	}

	return nil
}

// ****************************************************************************
//
// # Implementing a File System Session Store
//
// ****************************************************************************
type FileSystemSessionStore struct {
	mu  sync.RWMutex
	dir string
}

var errSessionRevoked = errors.New("session has been revoked")

const sessionRevocationPrefix = ".revoked-"

func NewFileSystemSessionStore(dir string) *FileSystemSessionStore {
	return &FileSystemSessionStore{
		dir: dir,
	}
}

func (s *FileSystemSessionStore) read(id string) (*GoSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	revoked, err := s.isRevoked(id)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, nil
	}

	filePath := s.filePath(id)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var session GoSession
	err = json.Unmarshal(data, &session)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (s *FileSystemSessionStore) write(session *GoSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	revoked, err := s.isRevoked(session.ID)
	if err != nil {
		return err
	}
	if revoked {
		return errSessionRevoked
	}

	filePath := s.filePath(session.ID)
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	dir := filepath.Dir(filePath)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".session.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmpName, filePath); err != nil {
		return err
	}
	committed = true
	// Correct permissions of session files created by older releases too.
	return os.Chmod(filePath, 0600)
}

func (s *FileSystemSessionStore) destroy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filePath := s.filePath(id)
	if revoked, err := s.isRevoked(id); err != nil {
		return err
	} else if revoked {
		// A marker always wins over any stale data file recreated by an older
		// process during a rolling upgrade.
		err = os.Remove(filePath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			// Fresh request-local IDs are rotated before their first save during
			// login. No other request can hold such a session, so avoid creating
			// an unnecessary, attacker-amplifiable tombstone.
			return nil
		}
		return err
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	// Publish and sync the marker before deleting the session. Another process
	// that loaded the old file can no longer recreate it after this point.
	revokedPath := s.revokedPath(id)
	marker, err := os.OpenFile(revokedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		if syncErr := marker.Sync(); syncErr != nil {
			_ = marker.Close()
			return syncErr
		}
		if closeErr := marker.Close(); closeErr != nil {
			return closeErr
		}
	} else if !os.IsExist(err) {
		return err
	}
	if err := os.Chmod(revokedPath, 0600); err != nil {
		return err
	}
	err = os.Remove(filePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

func (s *FileSystemSessionStore) gc(idleExpiration, absoluteExpiration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	files, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		filePath := s.dir + "/" + file.Name()
		if strings.HasPrefix(file.Name(), sessionRevocationPrefix) {
			info, infoErr := file.Info()
			if infoErr == nil && time.Since(info.ModTime()) > absoluteExpiration {
				_ = os.Remove(filePath)
			}
			continue
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var session GoSession
		err = json.Unmarshal(data, &session)
		if err != nil {
			continue
		}

		if time.Since(session.LastActivityAt) > idleExpiration ||
			time.Since(session.CreatedAt) > absoluteExpiration {
			os.Remove(filePath)
		}
	}

	return nil
}

func (s *FileSystemSessionStore) filePath(id string) string {
	return s.dir + "/" + id
}

func (s *FileSystemSessionStore) revokedPath(id string) string {
	return filepath.Join(s.dir, sessionRevocationPrefix+id)
}

func (s *FileSystemSessionStore) isRevoked(id string) (bool, error) {
	_, err := os.Stat(s.revokedPath(id))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
