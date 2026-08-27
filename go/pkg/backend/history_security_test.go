package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func seedPolicyDirectory(t *testing.T, directory, version, owner string, changed bool) {
	t.Helper()
	ownerDirectory := filepath.Join(directory, "owner", owner)
	if err := os.MkdirAll(ownerDirectory, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "POLICY"), []byte("# "+version+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if changed {
		if err := os.WriteFile(filepath.Join(ownerDirectory, "CHANGED"), []byte("[]\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func historySecurityState(t *testing.T) *state {
	t.Helper()
	root := t.TempDir()
	seedPolicyDirectory(t, filepath.Join(root, "current"), "p-current", "team", false)
	if err := writeJSONFile(filepath.Join(root, "current", "email"), map[string][]string{"reader@example.net": {"team"}}); err != nil {
		t.Fatal(err)
	}
	seedPolicyDirectory(t, filepath.Join(root, "p-allowed"), "p-allowed", "team", false)
	seedPolicyDirectory(t, filepath.Join(root, "p-other-owner"), "p-other-owner", "other", false)
	seedPolicyDirectory(t, filepath.Join(root, "history", "2026-08-25"), "2026-08-25", "team", true)
	s := &state{config: &config{NetspocData: root}, cache: newCache(root, 8)}
	// Production resolves current to its p... symlink target. Windows test
	// runners commonly cannot create symlinks, so seed that resolved cache slot.
	s.cache.getCacheEntry("current").email = map[string][]string{"reader@example.net": {"team"}}
	return s
}

func authenticatedHistoryRequest(method, target string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	session := newSession()
	session.Put("loggedIn", true)
	session.Put("email", "reader@example.net")
	return request.WithContext(context.WithValue(request.Context(), sessionContextKey{}, session))
}

func TestPolicyVersionResolutionUsesOwnerAllowlist(t *testing.T) {
	s := historySecurityState(t)
	for _, version := range []string{"p-current", "p-allowed", "2026-08-25"} {
		request := authenticatedHistoryRequest(http.MethodGet, "/?active_owner=team&history="+version)
		recorder := httptest.NewRecorder()
		if !s.requireOwnerAccess(recorder, request, "team") {
			t.Fatalf("allowed version %q was rejected: status=%d body=%s", version, recorder.Code, recorder.Body.String())
		}
		if got := s.getHistoryParamOrCurrentPolicy(request); got != version {
			t.Fatalf("resolved version = %q, want %q", got, version)
		}
	}

	for _, version := range []string{"p-other-owner", `p..\..\secrets`, "../secrets", "p-unlisted"} {
		request := authenticatedHistoryRequest(http.MethodGet, "/?active_owner=team&history="+version)
		recorder := httptest.NewRecorder()
		if s.requireOwnerAccess(recorder, request, "team") {
			t.Fatalf("unavailable version %q passed the owner gate", version)
		}
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("unavailable version %q status = %d", version, recorder.Code)
		}
	}
}

func TestDiffRejectsUnlistedVersionBeforeCacheAccess(t *testing.T) {
	s := historySecurityState(t)
	request := authenticatedHistoryRequest(http.MethodGet, "/get_diff?active_owner=team&version=p..%5c..%5csecrets")
	recorder := httptest.NewRecorder()
	s.getDiff(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("traversal diff status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestGetOwnerRejectsUnresolvedHistoryBeforeLoadingCache(t *testing.T) {
	s := historySecurityState(t)
	request := authenticatedHistoryRequest(http.MethodGet, "/get_owner?history=p-unlisted")
	recorder := httptest.NewRecorder()
	s.getOwner(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unlisted owner-history status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}
