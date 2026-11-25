package server

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/release/releasetest"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// e2eAgentScenePath est la route du seul serveur de parcours (jamais du vrai
// serveur) qui pose une scène de la colonne « Agent » et du bandeau de version
// importée (web/e2e/colonne-agent.spec.ts). Sans elle, les données fictives
// n'ont pas de bibliothèque : aucun agent n'est en retard, aucune version n'est
// importée, et les autres parcours n'en voient rien.
const e2eAgentScenePath = "/__e2e/agent-update-scene"

// Les scènes, à jouer dans cet ordre (un import ne se défait pas) :
//   - current : le serveur en v0.0.1, seule importée ; chaque agent, en
//     v0.0.1, est à jour et annonce tout.
//   - imported : v0.0.2 importée au-dessus : le bandeau.
//   - behind : le serveur en v0.0.2, v0.0.3 importée ; tous les agents en
//     retard, vps-paris-1 sans docker.deploy, la machine Kagu sans
//     quatre genres.
//   - reset : plus de bibliothèque, les genres de chacun rendus.
type e2eAgentScene struct {
	ts       *testServer
	library  *release.Library
	versions map[string]string
}

// e2eWithAgentScene prépare les dossiers des trois versions (signés d'une clé
// tirée ici) et rend le serveur du parcours, la route des scènes en tête.
func e2eWithAgentScene(t *testing.T, ts *testServer, next http.Handler) http.Handler {
	t.Helper()
	public, private, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	scene := &e2eAgentScene{ts: ts, library: release.NewLibrary(ts.state, release.Keys{Current: public}), versions: map[string]string{}}
	for _, version := range []string{"v0.0.1", "v0.0.2", "v0.0.3"} {
		scene.versions[version] = releasetest.Write(t, private, version, releasetest.Binaries(version, "amd64", "arm64"))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != e2eAgentScenePath || r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		var body struct {
			Scene string `json:"scene"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := scene.play(r.Context(), body.Scene); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (scene *e2eAgentScene) play(ctx context.Context, name string) error {
	full := agentwire.AnnouncedKinds()
	kinds := map[string]machine.OrderKinds{remoteID: full, machine.LocalID: full}
	switch name {
	case "current":
		if err := scene.importVersion("v0.0.1"); err != nil {
			return err
		}
		scene.ts.actions.SetReleases(scene.library, "v0.0.1")
	case "imported":
		if err := scene.importVersion("v0.0.2"); err != nil {
			return err
		}
	case "behind":
		if err := scene.importVersion("v0.0.3"); err != nil {
			return err
		}
		scene.ts.actions.SetReleases(scene.library, "v0.0.2")
		kinds[remoteID] = kindsWithout(full, agentwire.KindDockerDeploy)
		kinds[machine.LocalID] = kindsWithout(full, agentwire.KindDockerDeploy, agentwire.KindDockerUpdate, agentwire.KindDockerRollback, agentwire.KindAgentPing)
	case "reset":
		// Une version illisible coupe la bibliothèque : l'état des données fictives.
		scene.ts.actions.SetReleases(scene.library, "")
	default:
		return fmt.Errorf("unknown scene %q", name)
	}
	for machineID, announced := range kinds {
		found, err := scene.ts.machines.Get(ctx, machineID)
		if err != nil {
			return err
		}
		if err := scene.ts.machines.NoteOrderKinds(ctx, found.Agent.ID, announced.Format()); err != nil {
			return err
		}
	}
	return nil
}

func (scene *e2eAgentScene) importVersion(version string) error {
	_, err := scene.library.Import(scene.versions[version])
	return err
}

func kindsWithout(kinds machine.OrderKinds, dropped ...agentwire.Kind) machine.OrderKinds {
	kept := maps.Clone(kinds)
	for _, kind := range dropped {
		delete(kept, string(kind))
	}
	return kept
}
