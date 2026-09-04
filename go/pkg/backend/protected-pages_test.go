package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func frontendPageRequest(method, email string, logged bool) *http.Request {
	request := httptest.NewRequest(method, "/admin.html?embedded=1", nil)
	session := newSession()
	session.Put("loggedIn", logged)
	if email != "" {
		session.Put("email", email)
	}
	return request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, session))
}

func TestProtectedFrontendPagesRequireSessionAndOperationsRole(t *testing.T) {
	s := managedFortiGateTestState(t,
		editableUser{Email: "developer@example.net", Role: policyDeveloperRole},
		editableUser{Email: "editor@example.net", Role: "editor"},
		editableUser{Email: "reviewer@example.net", Role: "reviewer"},
		editableUser{Email: "deployer@example.net", Role: "deployer"},
		editableUser{Email: "viewer@example.net", Role: "viewer"},
	)
	served := 0
	page := s.requireFrontendRoles(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		_, _ = w.Write([]byte("protected-page-sentinel"))
	}), "admin", "editor", "reviewer", "deployer")

	anonymous := httptest.NewRecorder()
	page.ServeHTTP(anonymous, frontendPageRequest(http.MethodGet, "", false))
	if anonymous.Code != http.StatusFound || anonymous.Header().Get("Location") != "/" || strings.Contains(anonymous.Body.String(), "sentinel") {
		t.Fatalf("anonymous page response = %d location=%q body=%q", anonymous.Code, anonymous.Header().Get("Location"), anonymous.Body.String())
	}

	for _, email := range []string{"viewer@example.net", "unknown@example.net"} {
		response := httptest.NewRecorder()
		page.ServeHTTP(response, frontendPageRequest(http.MethodGet, email, true))
		if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "sentinel") {
			t.Errorf("unauthorized %s response = %d body=%q", email, response.Code, response.Body.String())
		}
	}

	for _, email := range []string{"admin@example.net", "developer@example.net", "editor@example.net", "reviewer@example.net", "deployer@example.net"} {
		response := httptest.NewRecorder()
		page.ServeHTTP(response, frontendPageRequest(http.MethodGet, email, true))
		if response.Code != http.StatusOK || response.Body.String() != "protected-page-sentinel" {
			t.Errorf("authorized %s response = %d body=%q", email, response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "private, no-store" || response.Header().Get("Vary") != "Cookie" {
			t.Errorf("authorized %s cache headers = %#v", email, response.Header())
		}
	}
	if served != 5 {
		t.Fatalf("protected page handler called %d times, want 5", served)
	}
}

func TestProtectedFrontendPagesAllowOnlySafeReadMethods(t *testing.T) {
	s := managedFortiGateTestState(t)
	page := s.requireFrontendRoles(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "admin")
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response := httptest.NewRecorder()
		page.ServeHTTP(response, frontendPageRequest(method, "admin@example.net", true))
		if response.Code != http.StatusNoContent {
			t.Errorf("%s response = %d, want 204", method, response.Code)
		}
	}
	response := httptest.NewRecorder()
	page.ServeHTTP(response, frontendPageRequest(http.MethodPost, "admin@example.net", true))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST response = %d, want 405", response.Code)
	}
}

func TestHealthCheckIsPublicReadOnlyAndDoesNotSetSessionCookie(t *testing.T) {
	response := httptest.NewRecorder()
	healthz(response, httptest.NewRequest(http.MethodGet, "/backend/healthz", nil))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Body.String(), `"status":"ok"`) {
		t.Fatalf("health response = %d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
	if response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("health check created a session cookie: %q", response.Header().Get("Set-Cookie"))
	}

	response = httptest.NewRecorder()
	healthz(response, httptest.NewRequest(http.MethodPost, "/backend/healthz", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST health response = %d, want 405", response.Code)
	}
}

func TestProtectedFrontendCanonicalPathCatchesFilesystemAliases(t *testing.T) {
	tests := map[string]string{
		"/app.html":               "/app.html",
		"/APP.HTML":               "/app.html",
		"//Admin.Html":            "/admin.html",
		"/folder/../devices.html": "/devices.html",
		`\ADMIN.HTML`:             "/admin.html",
		"/admin.html. ":           "/admin.html",
		"/admin.html::$DATA":      "/admin.html",
		"/ADMIN~1.HTM":            "/admin.html",
		"/DEVICE~2.HTM":           "/devices.html",
		"/REQUES~1.HTM":           "/requests.html",
		"/APP~1.HTM":              "/app.html",
	}
	for requestPath, expected := range tests {
		if actual := protectedFrontendCanonicalPath(requestPath); actual != expected {
			t.Errorf("protectedFrontendCanonicalPath(%q) = %q, want %q", requestPath, actual, expected)
		}
	}
	for _, requestPath := range []string{"/", "/index.html", "/resources/app.html", "/admin.html.txt", "/administration.html"} {
		if actual := protectedFrontendCanonicalPath(requestPath); actual != "" {
			t.Errorf("public path %q mapped to %q", requestPath, actual)
		}
	}
}
