package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hknutzen/Netspoc-Web/go/pkg/backend"
)

func main() {
	port := os.Getenv("LISTENPORT")
	if port == "" {
		panic("LISTENPORT must be set")
	}
	listen := os.Getenv("LISTENADDRESS") + ":" + port
	handler := backend.MainHandler()
	if staticDir := os.Getenv("STATIC_DIR"); staticDir != "" {
		mux := http.NewServeMux()
		mux.Handle("/backend/", http.StripPrefix("/backend", handler))
		mux.Handle("/backend6/", http.StripPrefix("/backend6", handler))
		mux.Handle("/", spaFiles(staticDir))
		handler = mux
	}
	log.Printf("Listening on %s", listen)
	log.Fatal(http.ListenAndServe(listen, handler))
}

// spaFiles serves the legacy web application while preventing directory
// traversal and falling back to index.html for its root route.
func spaFiles(dir string) http.Handler {
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		files.ServeHTTP(w, r)
	})
}
