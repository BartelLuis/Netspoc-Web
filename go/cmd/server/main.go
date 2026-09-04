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
	var handler http.Handler
	if staticDir := os.Getenv("STATIC_DIR"); staticDir != "" {
		handler = backend.MainHandlerWithStatic(spaFiles(staticDir))
	} else {
		handler = backend.MainHandler()
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
