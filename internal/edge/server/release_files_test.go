package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/release/releasetest"
)

// R-B1-12 : la bibliothèque sert, sans session ni jeton, les trois fichiers
// d'une version importée tels qu'importés, et rien d'autre ; un binaire
// changé depuis l'import n'est pas servi.
func TestReleaseFiles_ServeTheVerifiedFilesWithoutASession(t *testing.T) {
	server := newTestServer(t)
	public, private, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	server.releases = release.NewLibrary(server.state, release.Keys{Current: public})
	dir := releasetest.Write(t, private, "v1.0.0", releasetest.Binaries("v1.0.0", "amd64"))
	if _, err := server.releases.Import(dir); err != nil {
		t.Fatal(err)
	}
	get := func(path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder
	}
	for _, name := range []string{brand.ReleaseSumsFile, brand.ReleaseSignatureFile, release.BinaryName("amd64")} {
		want, _ := os.ReadFile(filepath.Join(dir, name))
		if got := get("/releases/v1.0.0/" + name); got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), want) {
			t.Errorf("%s: %d", name, got.Code)
		}
	}
	for _, path := range []string{"/releases/v1.0.0/" + release.BinaryName("arm64"), "/releases/v9.9.9/" + brand.ReleaseSumsFile, "/releases/latest/" + brand.ReleaseSumsFile, "/releases/v1.0.0/server.key"} {
		if got := get(path); got.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, got.Code)
		}
	}
	if err := server.state.WriteFile("releases/v1.0.0/"+release.BinaryName("amd64"), []byte("changed"), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := get("/releases/v1.0.0/" + release.BinaryName("amd64")); got.Code == http.StatusOK {
		t.Fatal("a changed binary was served")
	}
}
