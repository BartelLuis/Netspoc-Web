package backend

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

type state struct {
	*cache
	config         *config
	sessionManager *SessionManager
	setupMu        sync.Mutex
}

func getMux() (*http.ServeMux, *state) {
	cfg := LoadConfig()
	sm := NewSessionManager(
		NewFileSystemSessionStore(cfg.SessionDir),
		30*time.Minute,
		8*time.Hour,
		24*time.Hour,
		"PWGOSESSID",
	)
	s := &state{
		config:         cfg,
		cache:          newCache(cfg.NetspocData, 8),
		sessionManager: sm,
	}
	if err := s.cleanupManagedFortiGateCredentials(); err != nil {
		log.Printf("clean up stale FortiGate credentials during startup: %v", err)
	}
	if err := s.reconcileStaleSetupClaim(); err != nil {
		log.Printf("reconcile interrupted initial setup during startup: %v", err)
	}
	noLoginMux := http.NewServeMux()
	noLoginMux.HandleFunc("/login", s.loginHandler)
	noLoginMux.HandleFunc("/ldap-login", s.ldapLoginHandler)
	noLoginMux.HandleFunc("/maintenance-status", s.maintenanceStatus)
	noLoginMux.HandleFunc("/get_policy", s.getPolicy)
	noLoginMux.HandleFunc("/register", s.register)
	noLoginMux.HandleFunc("/verify", s.verify)
	noLoginMux.HandleFunc("/healthz", healthz)
	noLoginMux.HandleFunc("/admin/status", s.adminStatus)
	noLoginMux.Handle("/setup", requireBootstrapToken(http.HandlerFunc(s.setup)))
	noLoginMux.Handle("/admin/bootstrap", requireBootstrapToken(http.HandlerFunc(s.adminBootstrap)))

	needsLoginMux := http.NewServeMux()
	needsLoginMux.HandleFunc("/get_diff", s.getDiff)
	needsLoginMux.HandleFunc("/get_about_info", s.getAboutInfo)
	needsLoginMux.HandleFunc("/get_diff_mail", s.getDiffMail)
	needsLoginMux.HandleFunc("/set_diff_mail", s.setDiffMail)
	needsLoginMux.HandleFunc("/get_admins", s.getAdmins)
	needsLoginMux.HandleFunc("/get_watchers", s.getWatchers)
	needsLoginMux.HandleFunc("/get_admins_watchers", s.getAdminsWatchers)
	needsLoginMux.HandleFunc("/get_owners", s.getOwners)
	needsLoginMux.HandleFunc("/get_owner", s.getOwner)
	needsLoginMux.HandleFunc("/get_rules", s.getRules)
	needsLoginMux.HandleFunc("/get_users", s.getUsers)
	needsLoginMux.HandleFunc("/get_services_and_rules", s.getServicesAndRules)
	needsLoginMux.HandleFunc("/get_networks", s.getNetworks)
	needsLoginMux.HandleFunc("/get_fqdns", s.getFQDNs)
	needsLoginMux.HandleFunc("/get_network_resources", s.getNetworkResources)
	needsLoginMux.HandleFunc("/get_networks_and_resources", s.getNetworksAndResources)
	needsLoginMux.HandleFunc("/get_history", s.getHistory)
	needsLoginMux.HandleFunc("/get_supervisors", s.getSupervisors)
	needsLoginMux.HandleFunc("/logout", s.logoutHandler)
	needsLoginMux.HandleFunc("/service_list", s.serviceList)
	needsLoginMux.HandleFunc("/set", s.setSessionData)
	needsLoginMux.HandleFunc("/fortinet/status", s.getFortinetStatus)
	needsLoginMux.HandleFunc("/devices/routes", s.getDeviceRoutes)
	needsLoginMux.HandleFunc("/requests", s.policyRequests)
	needsLoginMux.HandleFunc("/requests/context", s.policyRequestContext)
	needsLoginMux.HandleFunc("/admin/fortigates", s.adminFortiGates)
	needsLoginMux.HandleFunc("/admin/fortigates/test", s.adminTestFortiGate)
	needsLoginMux.HandleFunc("/admin/requests", s.adminPolicyRequests)
	needsLoginMux.HandleFunc("/admin/requests/stage", s.adminStagePolicyRequest)
	needsLoginMux.HandleFunc("/admin/requests/reject", s.adminRejectPolicyRequest)
	needsLoginMux.HandleFunc("/admin/policy", s.adminPolicy)
	needsLoginMux.HandleFunc("/admin/users", s.adminUsers)
	needsLoginMux.HandleFunc("/admin/ldap-sync", s.adminLDAPSync)
	needsLoginMux.HandleFunc("/admin/ldap-sync-preview", s.adminLDAPSyncPreview)
	needsLoginMux.HandleFunc("/admin/policy-name-preview", s.adminPolicyNamePreview)
	needsLoginMux.HandleFunc("/admin/diff", s.adminDiff)
	needsLoginMux.HandleFunc("/admin/revision", s.adminRevision)
	needsLoginMux.HandleFunc("/admin/publish", s.adminPublish)
	needsLoginMux.HandleFunc("/admin/stage", s.adminStage)
	needsLoginMux.HandleFunc("/admin/deploy", s.adminDeploy)
	needsLoginMux.HandleFunc("/admin/drift", s.adminDrift)
	needsLoginMux.HandleFunc("/admin/maintenance", s.adminMaintenance)
	needsLoginMux.HandleFunc("/admin/reject", s.adminReject)
	needsLoginMux.HandleFunc("/admin/rollback", s.adminRollback)
	needsLoginMux.HandleFunc("/admin/audit", s.adminAudit)
	needsLoginMux.HandleFunc("/admin/where-used", s.adminWhereUsed)

	defaultMux := http.NewServeMux()
	defaultMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !csrfRequestAllowed(r) {
			writeError(w, "Cross-site request rejected", http.StatusForbidden)
			return
		}
		if loggedIn(r) {
			actor := strings.ToLower(strings.TrimSpace(getEmailFromSession(r)))
			if actor != "guest" {
				if _, active := s.activeAccount(actor); !active {
					s.logout(GetGoSession(r))
				}
			}
		}
		if loggedIn(r) {
			maintenanceActive, _ := s.effectiveMaintenance()
			if !maintenanceRequestAllowed(maintenanceActive, s.authorizationPolicy(), getEmailFromSession(r)) && !maintenanceEndpointExempt(r.URL.Path) {
				s.logout(GetGoSession(r))
				writeError(w, "Das System befindet sich im Wartungsmodus. Die Anmeldung ist nur für Administratoren und Developer möglich.", http.StatusServiceUnavailable)
				return
			}
		}
		if h, pattern := needsLoginMux.Handler(r); pattern != "" {
			if !loggedIn(r) {
				// Should be 401 or 500, but for legacy reasons 200 for now.
				writeError(w, "Login required", http.StatusOK)
				return
			}
			h.ServeHTTP(w, r)
		} else if h, pattern := noLoginMux.Handler(r); pattern != "" {
			h.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	})
	return defaultMux, s
}

func healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jsonMap{"status": "ok"})
}

// requireBootstrapToken protects first-run initialization with a server-side
// secret. Deployments set POLICYWEB_BOOTSTRAP_TOKEN and clients send the exact
// value in X-PolicyWeb-Bootstrap-Token. The token is never written to logs.
func requireBootstrapToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !bootstrapTokenAllowed(r) {
			writeError(w, "Bootstrap authorization required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bootstrapTokenAllowed(r *http.Request) bool {
	expected := os.Getenv("POLICYWEB_BOOTSTRAP_TOKEN")
	provided := r.Header.Get("X-PolicyWeb-Bootstrap-Token")
	if expected == "" || provided == "" {
		return false
	}
	expectedHash := sha256.Sum256([]byte(expected))
	providedHash := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1
}

func maintenanceEndpointExempt(path string) bool {
	switch path {
	case "/login", "/ldap-login", "/logout", "/maintenance-status":
		return true
	default:
		return false
	}
}

func csrfRequestAllowed(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}

	// Fetch Metadata cannot be set by page JavaScript and gives an early,
	// reliable rejection for modern browsers.
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "cross-site":
		return false
	case "same-origin":
		return true
	}

	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		return sameRequestOrigin(r, origin)
	}
	if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
		return sameRequestOrigin(r, referer)
	}
	// ExtJS sends this non-simple header for its legacy POST-based stores. A
	// cross-origin attacker cannot add it without a successful CORS preflight.
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Requested-With")), "XMLHttpRequest") {
		return true
	}

	// Preserve compatibility for non-browser API clients and the historical
	// test backend, which send none of the browser origin metadata. Browser
	// requests carrying cross-site metadata are rejected above.
	return r.Header.Get("Sec-Fetch-Site") == ""
}

func sameRequestOrigin(r *http.Request, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if trustProxyHeaders() {
		forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
		if strings.EqualFold(forwarded, "https") {
			scheme = "https"
		}
	}
	return strings.EqualFold(u.Scheme, scheme) && strings.EqualFold(u.Host, r.Host)
}

func MainHandler() http.Handler {
	mux, s := getMux()
	return RecoveryHandler(SessionHandler(s, mux))
}

func SessionHandler(s *state, h http.Handler) http.Handler {

	sessionManager := s.sessionManager
	if sessionManager == nil {
		abort("No session Manager in SessionHandler", fmt.Sprintf("%v", h))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionManager.Handle(h).ServeHTTP(w, r)
	})
}

func RecoveryHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic serving %s %s: %v\n%s", r.Method, r.URL.Path, err, debug.Stack())
				writeError(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		h.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, errorMsg string, httpStatus int) {
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Type", "text/x-json")
	w.WriteHeader(httpStatus)
	// Flusher is only needed temporarily.
	// TODO: remove this when we have a better way to handle HTTP Status
	// and encoding.
	/*
		flusher, ok := w.(http.Flusher)
		if !ok {
			errorMsg = "Error: http.Flusher not supported"
			abort(errorMsg)
		}
	*/
	data := jsonMap{
		"success": false,
		"msg":     errorMsg,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	enc.Encode(data)
	//flusher.Flush()
}

func abort(format string, args ...interface{}) {
	msg := fmt.Sprintf(format+"\n", args...)
	panic(msg)
}
