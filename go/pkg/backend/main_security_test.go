package backend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecoveryHandlerDoesNotExposePanicDetails(t *testing.T) {
	const secret = "password=never-return-this"
	h := RecoveryHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(secret)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://policy.example.test/private", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	body := w.Body.String()
	if strings.Contains(body, secret) || strings.Contains(body, "goroutine ") || strings.Contains(body, "main_security_test.go") {
		t.Fatalf("panic details leaked to client: %s", body)
	}
	if !strings.Contains(body, "Internal server error") {
		t.Fatalf("generic error missing: %s", body)
	}
}
