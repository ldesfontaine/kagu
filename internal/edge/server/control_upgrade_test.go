package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/release/releasetest"
)

// importBody est le corps de releases/import pour ce dossier.
func importBody(t *testing.T, folder string) string {
	t.Helper()
	body, err := json.Marshal(releaseImportRequest{Folder: folder})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// trustReleasesSignedBy donne au serveur une bibliothèque qui ne croit que
// cette clé : celle que serve tient de son binaire, ici tirée par le test.
func (ts *testServer) trustReleasesSignedBy(t *testing.T, trusted release.PublicKey) {
	t.Helper()
	ts.releases = release.NewLibrary(ts.state, release.Keys{Current: trusted})
}

// R-B2-1 : serve revérifie avec ses propres clés le dossier que root lui
// nomme. Signé par une clé étrangère, il est refusé et rien n'est écrit sous
// releases/ ; signé par la sienne, il entre dans la bibliothèque.
func TestR_B2_1_ImportRefusesAReleaseNotSignedByTheEmbeddedKeys(t *testing.T) {
	ts := newTestServer(t)
	trustedPublic, trustedPrivate, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, strangerPrivate, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	binaries := releasetest.Binaries("v0.0.2", "amd64", "arm64")
	foreign := releasetest.Write(t, strangerPrivate, "v0.0.2", binaries)
	const importPath = "/control/admin/releases/import"

	got := callControl(ts, http.MethodPost, importPath, importBody(t, foreign), rootUID)
	requireRefusal(t, got, http.StatusConflict, "release.no_trusted_key")

	ts.trustReleasesSignedBy(t, trustedPublic)
	got = callControl(ts, http.MethodPost, importPath, importBody(t, foreign), rootUID)
	requireRefusal(t, got, http.StatusUnprocessableEntity, "release.wrong_key")
	if _, err := ts.state.Stat(brand.ReleasesDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a foreign release left something in the state: %v", err)
	}

	got = callControl(ts, http.MethodPost, importPath, importBody(t, filepath.Base(foreign)), rootUID)
	requireRefusal(t, got, http.StatusUnprocessableEntity, "release.folder_not_absolute")
	got = callControl(ts, http.MethodPost, importPath, importBody(t, filepath.Join(foreign, "absent")), rootUID)
	requireRefusal(t, got, http.StatusUnprocessableEntity, "release.folder_unreadable")

	signed := releasetest.Write(t, trustedPrivate, "v0.0.2", binaries)
	got = callControl(ts, http.MethodPost, importPath, importBody(t, signed), rootUID)
	if got.Code != http.StatusOK {
		t.Fatalf("a release signed by the trusted key: %d %s", got.Code, got.Body.String())
	}
	var imported releaseImportResponse
	decodeAPI(t, got, &imported)
	if imported.Version != "v0.0.2" || len(imported.Binaries) != 2 {
		t.Fatalf("imported %+v", imported)
	}
	if _, err := ts.state.Stat(path.Join(brand.ReleasesDir, "v0.0.2", brand.ReleaseSumsFile)); err != nil {
		t.Fatalf("the release is not in the library: %v", err)
	}
}

// R-B2-2 : serve copie sa base sous son propre compte. La copie naît en 0600
// (umask ouvert compris), à serve, est une base entière ; la quatrième efface
// la plus ancienne, et rien de partiel ne reste.
func TestR_B2_2_PreUpgradeCopyIsWrittenUnderTheServiceAccount(t *testing.T) {
	ts := newTestServer(t)
	previous := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(previous) })

	versions := []string{"v0.0.1", "v0.0.2", "v0.0.3", "v0.0.4"}
	start := time.Now().Add(-time.Hour)
	for index, running := range versions {
		ts.version = running
		got := callControl(ts, http.MethodPost, "/control/admin/backup/pre-upgrade", ``, rootUID)
		if got.Code != http.StatusCreated {
			t.Fatalf("copy under %s: %d %s", running, got.Code, got.Body.String())
		}
		var copied upgradeCopyResponse
		decodeAPI(t, got, &copied)
		name := path.Join(brand.UpgradeDir, brand.UpgradeCopyPrefix+running+".db")
		if copied.Path != filepath.Join(ts.state.Name(), name) {
			t.Fatalf("path %q, want %s under the state", copied.Path, name)
		}
		requireServiceOwnedPrivateFile(t, ts.state, name)
		requireWholeDatabase(t, copied.Path)
		// Une copie par minute : l'ordre des copies ne tient pas à la
		// finesse de l'horloge du disque.
		at := start.Add(time.Duration(index) * time.Minute)
		if err := ts.state.Chtimes(name, at, at); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := fs.ReadDir(ts.state.FS(), brand.UpgradeDir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, entry := range entries {
		left = append(left, entry.Name())
	}
	want := []string{"avant-v0.0.2.db", "avant-v0.0.3.db", "avant-v0.0.4.db"}
	if len(left) != len(want) || left[0] != want[0] || left[1] != want[1] || left[2] != want[2] {
		t.Fatalf("upgrade folder holds %v, want %v", left, want)
	}
	info, err := ts.state.Stat(brand.UpgradeDir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("upgrade folder %v %v, want 0700", info, err)
	}
}

// requireServiceOwnedPrivateFile : le fichier est en 0600, au compte qui fait
// tourner serve (ici, celui du test).
func requireServiceOwnedPrivateFile(t *testing.T, state *os.Root, name string) {
	t.Helper()
	info, err := state.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode %v, want 0600", name, info.Mode().Perm())
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		t.Fatalf("%s is not owned by the service account: %+v", name, info.Sys())
	}
}

// requireWholeDatabase : la copie s'ouvre seule, intègre, avec le schéma.
func requireWholeDatabase(t *testing.T, file string) {
	t.Helper()
	copied, err := sql.Open("sqlite", "file:"+file+"?"+url.Values{"mode": {"ro"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer copied.Close()
	var integrity string
	if err := copied.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity_check = %q %v", integrity, err)
	}
	var migrations int
	if err := copied.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&migrations); err != nil || migrations == 0 {
		t.Fatalf("the copy has no schema: %d %v", migrations, err)
	}
}

// health rend la version que serve fait tourner, à root seul.
func TestControlHealth_SaysTheRunningVersion(t *testing.T) {
	ts := newTestServer(t)
	got := callControl(ts, http.MethodGet, "/control/admin/health", ``, rootUID)
	if got.Code != http.StatusOK {
		t.Fatalf("health: %d %s", got.Code, got.Body.String())
	}
	var health healthResponse
	decodeAPI(t, got, &health)
	if health.Version != "v0.0.1" {
		t.Fatalf("health %+v", health)
	}
}
