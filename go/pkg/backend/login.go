package backend

// login.go - Handles user login

import (
	"errors"
	"net/http"
	"strings"
)

func (s *state) maintenanceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	active, settings := s.effectiveMaintenance()
	message := strings.TrimSpace(settings.Message)
	if active && message == "" {
		message = "Das System befindet sich derzeit im Wartungsmodus. Die Anmeldung ist nur für Administratoren und Developer möglich."
	}
	writeJSON(w, map[string]any{"success": true, "maintenance_mode": active, "message": message})
}

func (s *state) effectiveMaintenance() (bool, maintenanceSettings) {
	active, settings, _ := s.effectiveMaintenanceWithError()
	return active, settings
}

func (s *state) effectiveMaintenanceWithError() (bool, maintenanceSettings, error) {
	if s.config == nil {
		return true, failClosedMaintenanceSettings(), errors.New("maintenance configuration is unavailable")
	}
	return s.maintenanceActive()
}

func maintenanceLoginAllowed(p *editablePolicy, email string) bool {
	role := policyRole(p, strings.ToLower(strings.TrimSpace(email)))
	return role == policyDeveloperRole || role == "admin"
}

func maintenanceRequestAllowed(enabled bool, p *editablePolicy, email string) bool {
	return !enabled || maintenanceLoginAllowed(p, email)
}

func (s *state) setLogin(session *GoSession, email string) {
	s.rotateSession(session)
	session.Put("email", email)
	session.Put("loggedIn", true)
}

func (s *state) logout(session *GoSession) {
	s.rotateSession(session)
	session.Put("loggedIn", false)
}

func (s *state) rotateSession(session *GoSession) {
	if s.sessionManager != nil {
		s.sessionManager.rotate(session)
		return
	}
	// Keep isolated handler tests usable even when they construct state without
	// a session manager.
	*session = *newSession()
}

func (s *state) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session := GetGoSession(r)
	s.logout(session)
	// The ExtJS client performs the navigation after this request completes.
	// Returning JSON avoids an Ajax request following the redirect and trying
	// to parse the login page as store data.
	writeRecords(w, []jsonMap{})
}

func (s *state) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := GetGoSession(r)
	if session == nil {
		writeError(w, "Session not found", http.StatusInternalServerError)
		return
	}
	// A login attempt always starts from an anonymous, rotated session. A
	// failed re-authentication must not leave an earlier login active.
	s.logout(session)
	email := r.FormValue("email")
	email = strings.ToLower(strings.TrimSpace(email))
	if email != "guest" {
		if err := s.checkAttack(r); err != nil {
			writeError(w, "Too many login attempts", http.StatusTooManyRequests)
			return
		}
		canonical, canonicalErr := canonicalAccountEmail(email)
		if canonicalErr != nil {
			s.setAttack(r)
			writeHTMLError(w, "Login failed")
			return
		}
		email = canonical
		if !s.localPasswordIdentityAllowed(email) {
			s.setAttack(r)
			writeHTMLError(w, "Login failed")
			return
		}
		pass := r.FormValue("pass")
		if pass == "" {
			s.setAttack(r)
			writeHTMLError(w, "Login failed")
			return
		}
		userFile, err := safeUserFile(s.config.UserDir, email)
		if err != nil {
			s.setAttack(r)
			writeHTMLError(w, "Login failed")
			return
		}
		ustore, err := GetUserStore(userFile)
		if err != nil {
			s.setAttack(r)
			writeHTMLError(w, "Login failed")
			return
		}
		valid, err := ustore.CheckPasswordAndMigrate(pass, userFile)
		if err != nil {
			s.setAttack(r)
			writeHTMLError(w, "Login failed")
			return
		}
		if !valid {
			s.setAttack(r)
			//writeError(w, "Login failed", http.StatusUnauthorized)
			writeHTMLError(w, "Login failed")
			return
		}
		if err := s.checkEmailAuthorization(email); err != nil {
			s.setAttack(r)
			writeHTMLError(w, "Login failed")
			return
		}
		// Re-evaluate the immutable authorization snapshot after the expensive
		// password check so a concurrent publication cannot switch this identity
		// to LDAP during a local login.
		if !s.localPasswordIdentityAllowed(email) {
			s.setAttack(r)
			writeHTMLError(w, "Login failed")
			return
		}
		s.clearAttack(r)
	}
	maintenanceActive, _ := s.effectiveMaintenance()
	if maintenanceActive {
		p := s.authorizationPolicy()
		if !maintenanceLoginAllowed(p, email) {
			s.logout(session)
			writeHTMLError(w, "Das System befindet sich im Wartungsmodus. Die Anmeldung ist nur für Administratoren und Developer möglich.")
			return
		}
	}
	s.setLogin(session, email)

	// Redirect to referer/app.html.
	s.redirectToLandingPage(w)
}

func (s *state) redirectToLandingPage(w http.ResponseWriter) {
	// Redirect to ../app.html.
	// It is built this way to comply how it was implemented using Perl.
	// It works around the fact that the Redirect function from package http transforms
	// the relative URL into an absolute one, which can cause issues if the Referer
	// header is missing or malformed or modified.
	// The referrer header is modified by mod_proxy in Apache and this causes
	// the http.Redirect function to redirect to the wrong URL.
	// The following three lines are the essence of what is going on in the http.Redirect
	// function, but it doesn't transform the relative URL into an absolute one.
	// And it ignores the GET special cases and the generation of the HTML body for
	// non-GET requests, which is not needed in our case.
	h := w.Header()
	h.Set("Location", "../app.html")
	w.WriteHeader(http.StatusFound)
}

func writeHTMLError(w http.ResponseWriter, errorMsg string) {
	s := &state{
		config: LoadConfig(),
	}
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusInternalServerError)
	err := s.renderHtmlTemplate(w, "error", errorMsg)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
	}
}
