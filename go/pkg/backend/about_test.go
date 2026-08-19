package backend

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetAboutInfoUsesConfiguredRepository(t *testing.T) {
	dir := t.TempDir()
	template := filepath.Join(dir, "about_info")
	if err := os.WriteFile(template, []byte(`Version [% policy_web_version %] https://github.com/BartelLuis/Netspoc-Web`), 0600); err != nil {
		t.Fatal(err)
	}
	s := &state{config: &config{AboutInfoTemplate: template}}
	w := httptest.NewRecorder()
	s.getAboutInfo(w, httptest.NewRequest("GET", "/get_about_info", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "BartelLuis/Netspoc-Web") || strings.Contains(w.Body.String(), "[%") {
		t.Fatalf("unexpected info response: code=%d body=%q", w.Code, w.Body.String())
	}
}
