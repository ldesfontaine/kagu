package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders_AreSetOnEveryResponse(t *testing.T) {
	server := newTestServer(t)
	want := map[string]string{
		"Content-Security-Policy": contentSecurityPolicy,
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "same-origin",
	}
	for _, path := range []string{"/", "/machines", "/api/session", "/api/nope", "/favicon.svg"} {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		for header, value := range want {
			if got := recorder.Header().Get(header); got != value {
				t.Errorf("%s: %s = %q, want %q", path, header, got, value)
			}
		}
	}
}

func TestCSP_ForbidsInlineStylesAndScripts(t *testing.T) {
	for _, forbidden := range []string{"'unsafe-inline'", "'unsafe-eval'", "http:", "https:"} {
		if strings.Contains(contentSecurityPolicy, forbidden) {
			t.Errorf("CSP contains %s", forbidden)
		}
	}
}

// Vite doit sortir une page sans script ni style en ligne, sinon la CSP
// la casse en silence.
func TestCSP_IndexHasNoInlineScriptOrStyle(t *testing.T) {
	server := newTestServer(t)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	body := recorder.Body.String()
	for _, forbidden := range []string{"<script>", "<style", "onload=", "javascript:"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("index.html contains %s", forbidden)
		}
	}
}

// R-D5-17 : en HTTPS, serve pose lui-même HSTS et COOP ; en http://, aucun
// HSTS (il enfermerait localhost en HTTPS pendant un an).
func TestR_D5_17(t *testing.T) {
	cases := []struct {
		name      string
		publicURL string
		wantHSTS  string
		wantCOOP  string
	}{
		{"https", "https://cloud.exemple.fr", "max-age=31536000", "same-origin"},
		{"https en majuscules", "HTTPS://cloud.exemple.fr/", "max-age=31536000", "same-origin"},
		{"http", "http://localhost:8080", "", ""},
		{"sans public_url", "", "", ""},
		{"schéma sans séparateur", "https.exemple.fr", "", ""},
		{"https ailleurs dans l'adresse", "http://exemple.fr/?next=https://x", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server := newTestServer(t)
			server.publicURL = c.publicURL
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
			if got := recorder.Header().Get("Strict-Transport-Security"); got != c.wantHSTS {
				t.Errorf("Strict-Transport-Security = %q, want %q", got, c.wantHSTS)
			}
			if got := recorder.Header().Get("Cross-Origin-Opener-Policy"); got != c.wantCOOP {
				t.Errorf("Cross-Origin-Opener-Policy = %q, want %q", got, c.wantCOOP)
			}
		})
	}
}
