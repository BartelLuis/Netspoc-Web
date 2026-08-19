package backend

// login.go - Handles user login

import (
	"fmt"
	"net/http"
)

func (s *state) setLogin(session *GoSession, email string) {
	session.Put("email", email)
	session.Put("loggedIn", true)
}

func (s *state) logout(session *GoSession) {
	session.Put("loggedIn", false)
}

func (s *state) logoutHandler(w http.ResponseWriter, r *http.Request) {
	session := GetGoSession(r)
	s.logout(session)
	// The ExtJS client performs the navigation after this request completes.
	// Returning JSON avoids an Ajax request following the redirect and trying
	// to parse the login page as store data.
	writeRecords(w, []jsonMap{})
}

func (s *state) loginHandler(w http.ResponseWriter, r *http.Request) {

	session := GetGoSession(r)
	if session == nil {
		writeError(w, "Session not found", http.StatusInternalServerError)
		return
	}
	email := r.FormValue("email")
	if email == "" {
		writeError(w, "Email is required", http.StatusBadRequest)
		return
	}
	if email != "guest" {
		pass := r.FormValue("pass")
		if pass == "" {
			writeError(w, "Password is required", http.StatusBadRequest)
			return
		}
		userFile := fmt.Sprintf("%s/%s", s.config.UserDir, email)
		ustore, err := GetUserStore(userFile)
		if err != nil {
			writeError(w, "Failed to get user store: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if ustore == nil {
			writeError(w, "Empty user store for: "+email, http.StatusUnauthorized)
			return
		}
		if !ustore.CheckPassword(pass) {
			s.setAttack(r)
			//writeError(w, "Login failed", http.StatusUnauthorized)
			writeHTMLError(w, "Login failed")
			return
		}
		s.clearAttack(r)
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
