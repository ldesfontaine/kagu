package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldesfontaine/opencloud/internal/domain/alert"
	"github.com/ldesfontaine/opencloud/internal/edge/store/storetest"
	"github.com/ldesfontaine/opencloud/internal/fact/machine"
	"github.com/ldesfontaine/opencloud/internal/fact/probe"
	"github.com/ldesfontaine/opencloud/internal/kit/brand"
	"github.com/ldesfontaine/opencloud/internal/view/manifest"
)

// databaseBytes lit la base et son journal tels qu'ils sont sur le disque :
// un mot de passe « effacé » qui reste dans une page libre y serait encore.
func databaseBytes(t *testing.T, stateDir string) []byte {
	t.Helper()
	var all []byte
	for _, suffix := range []string{"", "-wal"} {
		content, err := os.ReadFile(filepath.Join(stateDir, brand.DatabaseFile+suffix))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		all = append(all, content...)
	}
	return all
}

// R-D5-19 : une base d'avant, avec « https://u:hunter2zz@h/ » : après la
// migration, le mot de passe n'est plus dans la base ni dans l'export ; l'utilisateur
// reste, la sonde est en pause avec son historique, une alerte la dit.
func TestR_D5_19(t *testing.T) {
	server := newTestServer(t)
	ctx := context.Background()
	legacy := storetest.InsertProbe(t, server.db, "00000000000000a1", probe.Definition{
		Name: "api", Kind: probe.KindHTTP, Target: "https://u:hunter2zz@h.example.org/", MachineID: machine.LocalID,
	}, testNow)

	if _, err := server.probes.RemoveTargetPasswords(ctx); err != nil {
		t.Fatal(err)
	}

	got, err := server.db.GetProbe(ctx, legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Target != "https://u@h.example.org/" || !got.IsPaused() {
		t.Fatalf("attendu la cible sans mot de passe, utilisateur gardé, en pause: %q %q", got.Target, got.Status)
	}
	exported, err := server.exportedDirectory(ctx, manifest.ExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(exported), "hunter2zz") || !strings.Contains(string(exported), "u@h.example.org") {
		t.Fatalf("l'export doit garder l'utilisateur et jamais le mot de passe:\n%s", exported)
	}
	open, err := server.alerts.List(ctx, alert.StatusOpen)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].Kind != alert.KindProbePasswordRemoved || open[0].Object.ID != legacy.ID {
		t.Fatalf("attendu une alerte « mot de passe retiré » sur la sonde: %+v", open)
	}
	// Fermée proprement, la base reporte son journal dans le fichier : c'est
	// ce que laisse un arrêt du serveur.
	if err := server.db.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(databaseBytes(t, server.state.Name()), []byte("hunter2zz")) {
		t.Fatal("le mot de passe est encore dans la base")
	}
}

// Sans la migration, l'export masque quand même : un mot de passe encore en
// base ne sort jamais, pour une personne comme pour un jeton.
func TestR_D5_19_ExportMasksAPasswordTheMigrationHasNotReached(t *testing.T) {
	server := newTestServer(t)
	storetest.InsertProbe(t, server.db, "00000000000000a1", probe.Definition{
		Name: "api", Kind: probe.KindHTTP, Target: "https://u:hunter2zz@h.example.org/", MachineID: machine.LocalID,
	}, testNow)

	exported, err := server.exportedDirectory(context.Background(), manifest.ExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(exported), "hunter2zz") {
		t.Fatalf("l'export ne doit jamais porter le mot de passe:\n%s", exported)
	}
}
