package backend

import (
	"net/http"
	pathpkg "path"
	"strings"
)

// MainHandlerWithStatic serves the API and authenticated HTML entry points
// through one shared session manager. Other static assets stay public so
// the login and setup pages can load without creating server-side sessions.
func MainHandlerWithStatic(static http.Handler) http.Handler {
	if static == nil {
		static = http.NotFoundHandler()
	}
	api, s := getMux()
	protectedMux := http.NewServeMux()
	protectedMux.Handle("/backend/", http.StripPrefix("/backend", api))
	protectedMux.Handle("/backend6/", http.StripPrefix("/backend6", api))
	protectedMux.Handle("/app.html", s.requireFrontendRoles(static, "admin", "editor", "reviewer", "deployer", "viewer"))
	protectedMux.Handle("/admin.html", s.requireFrontendRoles(static, "admin", "editor", "reviewer", "deployer"))
	protectedMux.Handle("/devices.html", s.requireFrontendRoles(static, "admin", "editor", "reviewer", "deployer"))
	protectedMux.Handle("/requests.html", s.requireFrontendRoles(static, "admin", "editor", "reviewer", "deployer", "viewer"))
	protected := RecoveryHandler(SessionHandler(s, protectedMux))

	root := http.NewServeMux()
	// Container health checks do not need a browser session. Keeping these
	// exact paths outside SessionHandler prevents one session file per probe.
	root.HandleFunc("/backend/healthz", healthz)
	root.HandleFunc("/backend6/healthz", healthz)
	root.Handle("/backend/", protected)
	root.Handle("/backend6/", protected)
	root.Handle("/app.html", protected)
	root.Handle("/admin.html", protected)
	root.Handle("/devices.html", protected)
	root.Handle("/requests.html", protected)
	root.Handle("/", static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if canonical := protectedFrontendCanonicalPath(r.URL.Path); canonical != "" {
			request := r.Clone(r.Context())
			clonedURL := *r.URL
			clonedURL.Path = canonical
			clonedURL.RawPath = ""
			request.URL = &clonedURL
			protected.ServeHTTP(w, request)
			return
		}
		root.ServeHTTP(w, r)
	})
}

// protectedFrontendCanonicalPath recognizes aliases that a case-insensitive
// Windows filesystem may resolve to a protected entry point. The production
// container is Linux, but native Windows runs must enforce the same boundary.
func protectedFrontendCanonicalPath(requestPath string) string {
	requestPath = strings.ReplaceAll(requestPath, `\`, "/")
	cleaned := pathpkg.Clean("/" + strings.TrimLeft(requestPath, "/"))
	base := strings.Trim(cleaned, "/")
	if base == "" || strings.Contains(base, "/") {
		return ""
	}
	if separator := strings.IndexByte(base, ':'); separator >= 0 {
		base = base[:separator]
	}
	base = strings.TrimRight(base, " .")
	lower := strings.ToLower(base)
	switch lower {
	case "app.html":
		return "/app.html"
	case "admin.html":
		return "/admin.html"
	case "devices.html":
		return "/devices.html"
	case "requests.html":
		return "/requests.html"
	}
	for canonical, prefix := range map[string]string{
		"/app.html": "app", "/admin.html": "admin", "/devices.html": "device", "/requests.html": "reques",
	} {
		if windowsShortHTMLAlias(lower, prefix) {
			return canonical
		}
	}
	return ""
}

func windowsShortHTMLAlias(base, prefix string) bool {
	extension := pathpkg.Ext(base)
	if extension != ".htm" && extension != ".html" {
		return false
	}
	stem := strings.TrimSuffix(base, extension)
	tail := strings.TrimPrefix(stem, prefix+"~")
	if tail == stem || tail == "" {
		return false
	}
	for _, character := range tail {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func (s *state) requireFrontendRoles(next http.Handler, roles ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Vary", "Cookie")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !loggedIn(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		actor := getEmailFromSession(r)
		if !hasPolicyRole(s.authorizationPolicy(), actor, roles...) {
			writeError(w, "Policy operations role required", http.StatusForbidden)
			return
		}
		maintenanceActive, _ := s.effectiveMaintenance()
		if !maintenanceRequestAllowed(maintenanceActive, s.authorizationPolicy(), actor) {
			s.logout(GetGoSession(r))
			writeError(w, "Das System befindet sich im Wartungsmodus. Die Anmeldung ist nur für Administratoren und Developer möglich.", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}
