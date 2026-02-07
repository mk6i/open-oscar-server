package http

import (
	_ "embed"
	"net/http"
)

//go:embed admin.html
var adminHTML []byte

// adminUIHandler serves the embedded admin UI HTML page.
func adminUIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(adminHTML)
}
