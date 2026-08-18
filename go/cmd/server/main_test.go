package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSPAFileServer(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("policyweb"), 0600); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	spaFiles(dir).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "policyweb" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestSPAFileServerRejectsTraversal(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.URL.Path = "/../secret"
	spaFiles(t.TempDir()).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}
