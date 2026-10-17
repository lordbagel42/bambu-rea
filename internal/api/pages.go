package api

import (
	_ "embed"
	"net/http"
)

//go:embed pages/docs.html
var docsHTML []byte

//go:embed pages/login.html
var loginHTML []byte

// handleDocs serves the Scalar API reference, which reads /openapi.json.
func (s *Server) handleDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(docsHTML)
}

// handleLoginPage serves the self-contained sign-in and API-key page.
func (s *Server) handleLoginPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(loginHTML)
}
