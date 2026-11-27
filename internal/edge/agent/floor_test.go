package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/release/releasetest"
	"github.com/ldesfontaine/kagu/internal/kit/rollback"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// publishWithFloor est publish pour une version de releasetest qui porte un
// plancher dans son commentaire de confiance signé.
func (b *updateBench) publishWithFloor(t *testing.T, version, floor string) published {
	t.Helper()
	dir := releasetest.WriteWithFloor(t, b.private, version, floor, map[string][]byte{archBinary: []byte("the binary of " + version)})
	files := map[string]string{}
	for _, name := range []string{archBinary, brand.ReleaseSumsFile, brand.ReleaseSignatureFile} {
		content, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- un fichier du test.
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(content)
	}
	return published{
		server: &parcelServer{files: files},
		params: agentwire.AgentUpdateParams{Version: version, Parcel: "colis1", Binary: archBinary, Files: listed(files)},
	}
}

// runs fait tourner version : son binaire dans bin/, le lien current dessus.
func (b *updateBench) runs(t *testing.T, version string) {
	t.Helper()
	b.installPrevious(t, version)
	if err := b.stateDir.Remove("bin/current"); err != nil {
		t.Fatal(err)
	}
	if err := b.stateDir.Symlink("kagu-"+version, "bin/current"); err != nil {
		t.Fatal(err)
	}
	b.updater.version = version
}

// updatedPastTheFloor : v1.0.0 tournait, v1.0.1 au plancher floor est
// installée ; c'est elle qui tourne désormais, v1.0.0 en previous.
func updatedPastTheFloor(t *testing.T, floor string) *updateBench {
	t.Helper()
	b := newUpdateBench(t, "v1.0.0")
	b.runs(t, "v1.0.0")
	if err := b.update(t, b.publishWithFloor(t, "v1.0.1", floor)); err != nil {
		t.Fatal(err)
	}
	if b.link(t, "current") != "kagu-v1.0.1" || b.link(t, "previous") != "kagu-v1.0.0" {
		t.Fatalf("current %s, previous %s", b.link(t, "current"), b.link(t, "previous"))
	}
	b.updater.version = "v1.0.1"
	return b
}

func (b *updateBench) noted(t *testing.T) string {
	t.Helper()
	text, err := b.stateDir.ReadFile(brand.AgentReleaseFloorFile)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

func (b *updateBench) confirm(t *testing.T) {
	t.Helper()
	outcome := newUpdateOutcome(b.stateDir, b.updater.version, newActionResults(), slog.New(slog.DiscardHandler))
	outcome.confirm()
	if _, err := rollback.Load(b.stateDir); !errors.Is(err, rollback.ErrNoMarker) {
		t.Fatalf("not confirmed: %v", err)
	}
}

// R-B2-11, W-M7 : v1.0.1 au plancher v1.0.1 tourne, v1.0.0 en previous :
// agent.rollback est refusé below_floor, rien ne bascule ; agent.update vers
// v1.0.0 aussi, below_floor plutôt que downgrade.
func TestR_B2_11_RollbackBelowTheFloorIsRefused(t *testing.T) {
	b := updatedPastTheFloor(t, "v1.0.1")
	if noted := b.noted(t); noted != "v1.0.1\n" {
		t.Fatalf("floor noted %q", noted)
	}
	pending, err := rollback.Load(b.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	b.checked = nil

	err = b.updater.rollback(context.Background(), "run2")
	if reason := reasonOf(t, err); reason != agentwire.ReasonBelowFloor {
		t.Fatalf("reason %s", reason)
	}
	var refused *orderError
	if !errors.As(err, &refused) || !refused.untouched {
		t.Fatal("refused after a write")
	}
	if b.link(t, "current") != "kagu-v1.0.1" || b.link(t, "previous") != "kagu-v1.0.0" || len(b.checked) != 0 || b.restarted != 0 {
		t.Fatalf("current %s, previous %s, checked %v", b.link(t, "current"), b.link(t, "previous"), b.checked)
	}
	if marker, err := rollback.Load(b.stateDir); err != nil || marker != pending {
		t.Fatalf("marker %+v, %v", marker, err)
	}

	if reason := reasonOf(t, b.update(t, b.publishWithFloor(t, "v1.0.0", ""))); reason != agentwire.ReasonBelowFloor {
		t.Fatalf("update below the floor: reason %s", reason)
	}
	if b.link(t, "current") != "kagu-v1.0.1" {
		t.Fatalf("current %s", b.link(t, "current"))
	}
}

// R-B2-11, W-M7 : une fois v1.0.1 confirmée, le binaire v1.0.0, sous son
// plancher, n'est plus dans bin/ ; le lien previous reste, et le retour est
// toujours refusé below_floor.
func TestR_B2_11_ConfirmationErasesAPreviousBelowTheFloor(t *testing.T) {
	b := updatedPastTheFloor(t, "v1.0.1")
	b.confirm(t)
	if _, err := b.stateDir.Lstat("bin/kagu-v1.0.0"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the binary below the floor is still there: %v", err)
	}
	if _, err := b.stateDir.Lstat("bin/kagu-v1.0.1"); err != nil {
		t.Fatalf("the running binary: %v", err)
	}
	if reason := reasonOf(t, b.updater.rollback(context.Background(), "run3")); reason != agentwire.ReasonBelowFloor {
		t.Fatalf("reason %s", reason)
	}
}

// Une version au plancher plus bas que sa précédente, ou sans plancher, se
// confirme comme avant : la précédente reste, le retour passe.
func TestAgentUpdate_APreviousAtOrAboveTheFloorIsKept(t *testing.T) {
	for _, floor := range []string{"", "v1.0.0"} {
		t.Run("floor "+floor, func(t *testing.T) {
			b := updatedPastTheFloor(t, floor)
			b.confirm(t)
			if _, err := b.stateDir.Lstat("bin/kagu-v1.0.0"); err != nil {
				t.Fatalf("the previous binary was erased: %v", err)
			}
			if err := b.updater.rollback(context.Background(), "run2"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Le plancher ne fait que monter : une version suivante au plancher plus bas,
// ou sans plancher, ne l'abaisse pas, et il tient pour le binaire d'avant.
func TestAgentUpdate_TheFloorNeverGoesDown(t *testing.T) {
	b := updatedPastTheFloor(t, "v1.0.1")
	b.confirm(t)
	if err := b.update(t, b.publishWithFloor(t, "v1.0.2", "")); err != nil {
		t.Fatal(err)
	}
	b.updater.version = "v1.0.2"
	if noted := b.noted(t); noted != "v1.0.1\n" {
		t.Fatalf("floor noted %q", noted)
	}
	if err := b.update(t, b.publishWithFloor(t, "v1.0.3", "v1.0.0")); err != nil {
		t.Fatal(err)
	}
	if noted := b.noted(t); noted != "v1.0.1\n" {
		t.Fatalf("floor lowered to %q", noted)
	}
}

// Un plancher noté illisible ne se devine pas : le retour et la mise à jour
// sont refusés below_floor, rien ne bouge.
func TestAgentRollback_AnUnreadableFloorRefusesEverything(t *testing.T) {
	b := updatedPastTheFloor(t, "")
	if err := b.stateDir.WriteFile(brand.AgentReleaseFloorFile, []byte("1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if reason := reasonOf(t, b.updater.rollback(context.Background(), "run2")); reason != agentwire.ReasonBelowFloor {
		t.Fatalf("rollback: reason %s", reason)
	}
	if reason := reasonOf(t, b.update(t, b.publishWithFloor(t, "v1.0.2", ""))); reason != agentwire.ReasonBelowFloor {
		t.Fatalf("update: reason %s", reason)
	}
	if b.link(t, "current") != "kagu-v1.0.1" {
		t.Fatalf("current %s", b.link(t, "current"))
	}
}

// Le plancher ne vient que de la version signée : un commentaire de
// confiance dont on a changé le plancher ne passe pas la signature, et rien
// n'est noté.
func TestAgentUpdate_AChangedFloorDoesNotPassTheSignature(t *testing.T) {
	b := newUpdateBench(t, "v1.0.0")
	b.runs(t, "v1.0.0")
	published := b.publishWithFloor(t, "v1.0.1", "v1.0.1")
	signature := published.server.files[brand.ReleaseSignatureFile]
	published.server.files[brand.ReleaseSignatureFile] = string(bytes.Replace([]byte(signature), []byte("floor:v1.0.1"), []byte("floor:v1.0.0"), 1))
	published.params.Files = listed(published.server.files)
	if reason := reasonOf(t, b.update(t, published)); reason != agentwire.ReasonSignatureInvalid {
		t.Fatalf("reason %s", reason)
	}
	if noted := b.noted(t); noted != "" {
		t.Fatalf("floor noted %q", noted)
	}
}

// guardChild est un agent qui s'arrête aussitôt, sans erreur : le lanceur
// n'a qu'à juger le marqueur avant de le lancer.
type guardChild struct{}

func (guardChild) Wait() rollback.Exit { return rollback.Exit{Code: 0} }
func (guardChild) Stop()               {}
func (guardChild) Hangup()             {}

// runGuardAt fait tourner le lanceur stable une fois, à l'instant now.
func (b *updateBench) runGuardAt(t *testing.T, now time.Time) {
	t.Helper()
	bin, err := b.stateDir.OpenRoot(brand.AgentBinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer bin.Close()
	guard := rollback.NewGuard(b.stateDir, bin, filepath.Join(b.state, brand.AgentBinDir, brand.AgentCurrentLink), []string{"agent"}, slog.New(slog.DiscardHandler))
	guard.Now = func() time.Time { return now }
	guard.Launch = func(string, []string, []string) (rollback.Child, error) { return guardChild{}, nil }
	if code := guard.Run(context.Background()); code != 0 {
		t.Fatalf("guard exit code %d", code)
	}
}

// R-B2-11, ARB-7 : une montée vers une version plancher qui n'est pas
// confirmée revient seule, par le lanceur, à la version d'où elle est partie,
// même sous le plancher ; le plancher noté à l'installation reste, ferme
// agent.rollback, et le binaire d'avant n'est pas effacé.
func TestR_B2_11_AnUnconfirmedUpdateReturnsToTheLaunchingVersion(t *testing.T) {
	b := updatedPastTheFloor(t, "v1.0.1")
	b.updater.now = time.Now
	b.runGuardAt(t, time.Now().Add(rollback.GracePeriod+time.Minute))

	if marker, err := rollback.Load(b.stateDir); err != nil || marker.State != rollback.StateRolledBack {
		t.Fatalf("marker %+v, %v", marker, err)
	}
	if current := b.link(t, "current"); current != "kagu-v1.0.0" {
		t.Fatalf("current %s, want the launching version", current)
	}
	b.updater.version = "v1.0.0"
	if noted := b.noted(t); noted != "v1.0.1\n" {
		t.Fatalf("floor noted %q", noted)
	}
	// previous est ici la version qui tourne : le plancher se juge avant.
	err := b.updater.rollback(context.Background(), "run2")
	if reason := reasonOf(t, err); reason != agentwire.ReasonBelowFloor {
		t.Fatalf("rollback: reason %s", reason)
	}
	var refused *orderError
	if !errors.As(err, &refused) || !refused.untouched {
		t.Fatal("refused after a write")
	}
	if marker, err := rollback.Load(b.stateDir); err != nil || marker.State != rollback.StateRolledBack {
		t.Fatalf("the refused rollback changed the marker: %+v, %v", marker, err)
	}
	if _, err := b.stateDir.Lstat("bin/kagu-v1.0.0"); err != nil {
		t.Fatalf("the launching binary was erased: %v", err)
	}
}
