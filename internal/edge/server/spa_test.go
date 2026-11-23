package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/edge/server/servertest"
	"github.com/ldesfontaine/kagu/internal/edge/store/storetest"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

func get(server *Server, path string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

// Le front est une seule page : toute adresse sans extension la reçoit,
// jamais en cache, et son routeur décide. Un fichier absent reste un 404.
func TestSPA_ServesIndexForEveryClientRoute(t *testing.T) {
	servertest.RequireFront(t)
	server := newTestServer(t)
	for _, path := range []string{"/", "/machines", "/taches/abc", "/rien-ici"} {
		recorder := get(server.Server, path)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `<div id="root">`) {
			t.Errorf("%s: %d", path, recorder.Code)
		}
		if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control %q", path, got)
		}
	}
	if got := get(server.Server, "/rien.png"); got.Code != http.StatusNotFound {
		t.Errorf("missing file: %d", got.Code)
	}
	if got := get(server.Server, "/index.html"); got.Code != http.StatusOK || got.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("index.html by name: %d %q", got.Code, got.Header().Get("Cache-Control"))
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/machines", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST on a page: %d", recorder.Code)
	}
}

// Le front ne connaît pas le nom du produit : ses pages le demandent par
// {{product}} et le serveur le pose à la livraison, dans le titre et dans la
// balise que lit l'écran d'erreur de démarrage.
func TestSPA_PagesCarryTheProductName(t *testing.T) {
	servertest.RequireFront(t)
	server := newTestServer(t)
	storetest.PublishedProject(t, server.db, "statut")
	for _, path := range []string{"/", "/statut/statut"} {
		body := get(server.Server, path).Body.String()
		for _, want := range []string{"<title>" + brand.ProductName + "</title>", `content="` + brand.ProductName + `"`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: %s missing from the page", path, want)
			}
		}
		if strings.Contains(body, "{{product}}") {
			t.Errorf("%s: placeholder left in the page", path)
		}
	}
}

// Une page demandée par son nom de fichier ne passe pas à côté de la
// substitution : index.html devient la page, statut.html un 404.
func TestSPA_HTMLFilesByName_NeverServedRaw(t *testing.T) {
	server := newTestServer(t)
	for _, path := range []string{"/index.html", "/statut.html"} {
		got := get(server.Server, path)
		if strings.Contains(got.Body.String(), "{{product}}") {
			t.Errorf("%s: raw page served (%d)", path, got.Code)
		}
	}
	if got := get(server.Server, "/statut.html"); got.Code != http.StatusNotFound {
		t.Errorf("/statut.html: %d, want 404", got.Code)
	}
}

func TestExpandProductName_ReplacesEveryMarker(t *testing.T) {
	got := string(expandProductName([]byte("<title>{{product}}</title>{{product}}")))
	if got != "<title>"+brand.ProductName+"</title>"+brand.ProductName {
		t.Errorf("expandProductName = %q", got)
	}
}

// Les fichiers de dist portent leur empreinte dans leur nom : cache
// immuable ; ce qui vient de public/ (favicon, theme.js) se revalide.
func TestSPA_AssetsAreImmutableAndPublicFilesRevalidated(t *testing.T) {
	servertest.RequireFront(t)
	server := newTestServer(t)
	assets := listAssets(t, server.Server)
	if len(assets) == 0 {
		t.Fatal("no asset in dist: run make front")
	}
	for _, name := range assets {
		recorder := get(server.Server, "/"+name)
		if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != immutableYear {
			t.Errorf("%s: %d %q", name, recorder.Code, recorder.Header().Get("Cache-Control"))
		}
	}
	// Le navigateur demande /favicon.ico de lui-même : il reçoit le signe
	// de la marque, jamais un 404.
	icon := get(server.Server, "/favicon.ico")
	if icon.Code != http.StatusOK || !strings.HasPrefix(icon.Header().Get("Content-Type"), "image/svg+xml") {
		t.Errorf("favicon.ico: %d %q", icon.Code, icon.Header().Get("Content-Type"))
	}
	for _, name := range []string{"/favicon.svg", "/theme.js"} {
		recorder := get(server.Server, name)
		if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("%s: %d %q", name, recorder.Code, recorder.Header().Get("Cache-Control"))
		}
	}
}

// Les deux polices de la direction artistique sont embarquées et servies
// avec leur type MIME, sans quoi certains navigateurs refusent le fichier.
func TestSPA_FontsAreEmbeddedAndServedAsWoff2(t *testing.T) {
	servertest.RequireFront(t)
	server := newTestServer(t)
	fonts := 0
	for _, name := range listAssets(t, server.Server) {
		if !strings.HasSuffix(name, ".woff2") {
			continue
		}
		fonts++
		recorder := get(server.Server, "/"+name)
		if got := recorder.Header().Get("Content-Type"); got != "font/woff2" {
			t.Errorf("%s: Content-Type %q", name, got)
		}
		if !strings.HasPrefix(recorder.Body.String(), "wOF2") {
			t.Errorf("%s: not a woff2 file", name)
		}
	}
	if fonts != 2 {
		t.Fatalf("%d fonts embedded, want Geist and Geist Mono", fonts)
	}
}

func listAssets(t *testing.T, server *Server) []string {
	t.Helper()
	var assets []string
	err := fs.WalkDir(server.app, "assets", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			assets = append(assets, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return assets
}

// R-A2-13 : seule la route du front sert un fichier compilé sans session, et
// elle juge le chemin encodé. Un %2F ne fait jamais passer une route /api/…
// pour un fichier du front.
func TestR_A2_13(t *testing.T) {
	servertest.RequireFront(t)
	server := newFirstSetupServer(t)
	server.enableNative(t)

	anonymous := func(target string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Host = "localhost"
		recorder := httptest.NewRecorder()
		server.Server.ServeHTTP(recorder, request)
		return recorder
	}

	if got := anonymous("/theme.js"); got.Code != http.StatusOK {
		t.Errorf("/theme.js: %d, want 200", got.Code)
	}
	for _, target := range []string{
		"/api/machines/..%2F..%2Ftheme.js",
		"/api/machines/..%2f..%2ftheme.js",
		"/api/machines/%2E%2E%2Ftheme.js",
		"/api/counts%2F..%2Ftheme.js",
	} {
		got := anonymous(target)
		if got.Code != http.StatusBadRequest && got.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 400 or 401", target, got.Code)
		}
		if strings.Contains(got.Body.String(), "localStorage") || got.Header().Get("Cache-Control") == "no-cache" {
			t.Errorf("%s served the compiled file", target)
		}
	}
	// Un fichier compilé nommé hors du front reste fermé : la route /api/ sans
	// %2F demande la session.
	if got := anonymous("/api/counts"); got.Code != http.StatusUnauthorized {
		t.Errorf("/api/counts: %d, want 401", got.Code)
	}
	// Le refus du %2F ne dépend pas de la session.
	for _, signedIn := range []bool{false, true} {
		request := httptest.NewRequest(http.MethodGet, "/api/machines/..%2F..%2Ftheme.js", nil)
		request.Host = "localhost"
		if signedIn {
			signInRequest(server.Server, request, testUsername, testPassword)
		}
		recorder := httptest.NewRecorder()
		server.Server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("signed in %v: %d, want 400", signedIn, recorder.Code)
		}
	}
}
