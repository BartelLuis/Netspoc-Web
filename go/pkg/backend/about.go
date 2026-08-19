package backend

import (
	"net/http"
	"os"
	"runtime/debug"
	"strings"
)

func policyWebVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "Entwicklung"
}

func (s *state) getAboutInfo(w http.ResponseWriter, _ *http.Request) {
	content, err := os.ReadFile(s.config.AboutInfoTemplate)
	if err != nil {
		writeError(w, "Info-Vorlage kann nicht geladen werden: "+err.Error(), http.StatusInternalServerError)
		return
	}
	html := strings.ReplaceAll(string(content), "[% policy_web_version %]", policyWebVersion())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}
