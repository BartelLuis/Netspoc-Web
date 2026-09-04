package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hknutzen/Netspoc-Web/go/pkg/backend"
)

func main() {
	port := os.Getenv("LISTENPORT")
	if port == "" {
		panic("LISTENPORT must be set")
	}
	listen := os.Getenv("LISTENADDRESS") + ":" + port
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var handler http.Handler
	if staticDir := os.Getenv("STATIC_DIR"); staticDir != "" {
		handler = backend.MainHandlerWithStaticContext(ctx, spaFiles(staticDir))
	} else {
		handler = backend.MainHandlerContext(ctx)
	}
	server := &http.Server{Addr: listen, Handler: handler}
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
		}
	}()
	log.Printf("Listening on %s", listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
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
