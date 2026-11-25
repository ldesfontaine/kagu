package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ldesfontaine/kagu/internal/domain/alert"
	"github.com/ldesfontaine/kagu/internal/edge/store"
	"github.com/ldesfontaine/kagu/internal/edge/store/storetest"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/fact/probe"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

type countingCompactor struct {
	calls int
	err   error
}

func (c *countingCompactor) Compact(context.Context) error {
	c.calls++
	return c.err
}

// openWithLegacyProbe rend une base où la machine Kagu existe et où une
// sonde porte encore « hunter2zz » dans sa cible.
func openWithLegacyProbe(t *testing.T, logger *slog.Logger) (string, *store.DB) {
	t.Helper()
	root, db := storetest.OpenWithStateDir(t)
	storetest.EnsureLocalMachine(t, machine.New(db, machine.NewSessions(), logger))
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	// Une ligne déjà effacée par une version d'avant `secure_delete` : le
	// reste est dans la page, seul le compactage le retire. Des sondes
	// remplissent la base pour que la sonde d'avant soit sur une autre page.
	storetest.InsertProbe(t, db, "00000000000000a2", probe.Definition{
		Name: "old", Kind: probe.KindHTTP, Target: "https://u:staleOldPw99@old.example.org/", MachineID: machine.LocalID,
	}, at)
	for i := range 60 {
		storetest.InsertProbe(t, db, fmt.Sprintf("00000000000001%02x", i), probe.Definition{
			Name: fmt.Sprintf("site-%02d", i), Kind: probe.KindHTTP, Target: fmt.Sprintf("https://site-%02d.example.org/health", i), MachineID: machine.LocalID,
		}, at)
	}
	storetest.InsertProbe(t, db, "00000000000000a1", probe.Definition{
		Name: "api", Kind: probe.KindHTTP, Target: "https://u:hunter2zz@h.example.org/", MachineID: machine.LocalID,
	}, at)
	deleteWithoutSecureDelete(t, root.Name(), "00000000000000a2")
	return root.Name(), db
}

// deleteWithoutSecureDelete rejoue ce que faisait une version d'avant : une
// connexion sans secure_delete efface la sonde, sa ligne reste lisible dans
// la page.
func deleteWithoutSecureDelete(t *testing.T, stateDir, probeID string) {
	t.Helper()
	old, err := sql.Open("sqlite", "file:"+filepath.Join(stateDir, brand.DatabaseFile)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	var enabled int
	if err := old.QueryRow(`PRAGMA secure_delete`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("the old connection must not erase securely: %d %v", enabled, err)
	}
	if _, err := old.Exec(`DELETE FROM probes WHERE id = ?`, probeID); err != nil {
		t.Fatal(err)
	}
}

func quietLogger(output io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(output, nil))
}

// databaseBytes lit la base et son -wal tels qu'ils sont sur le disque, base
// ouverte : c'est ce que laisse le serveur qui sert.
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

// R-D5-19 : après le démarrage, l'ancien mot de passe n'est ni dans le fichier
// de base ni dans le -wal ; un second démarrage ne compacte pas.
func TestR_D5_19_StartupLeavesNoPasswordInTheFiles(t *testing.T) {
	ctx := context.Background()
	logger := quietLogger(io.Discard)
	stateDir, db := openWithLegacyProbe(t, logger)
	for _, leftover := range []string{"hunter2zz", "staleOldPw99"} {
		if !bytes.Contains(databaseBytes(t, stateDir), []byte(leftover)) {
			t.Fatalf("the fixture must start with %q on disk", leftover)
		}
	}
	probes := probe.New(db, logger)

	removeLegacyProbePasswords(ctx, probes, alert.New(db, logger), db, logger)

	for _, leftover := range []string{"hunter2zz", "staleOldPw99"} {
		if bytes.Contains(databaseBytes(t, stateDir), []byte(leftover)) {
			t.Fatalf("%q is still in the database file or its -wal", leftover)
		}
	}
}

func TestRemoveLegacyProbePasswords_CompactsOnceThenNoMore(t *testing.T) {
	ctx := context.Background()
	logger := quietLogger(io.Discard)
	_, db := openWithLegacyProbe(t, logger)
	probes := probe.New(db, logger)
	compactor := &countingCompactor{}

	removeLegacyProbePasswords(ctx, probes, alert.New(db, logger), compactor, logger)
	removeLegacyProbePasswords(ctx, probes, alert.New(db, logger), compactor, logger)

	if compactor.calls != 1 {
		t.Fatalf("the first start compacts, the second finds nothing to remove: %d compactions", compactor.calls)
	}
}

func TestRemoveLegacyProbePasswords_NothingToRemoveNeverCompacts(t *testing.T) {
	_, db := storetest.OpenWithStateDir(t)
	logger := quietLogger(io.Discard)
	compactor := &countingCompactor{}

	removeLegacyProbePasswords(context.Background(), probe.New(db, logger), alert.New(db, logger), compactor, logger)

	if compactor.calls != 0 {
		t.Fatalf("no password removed, no compaction: %d", compactor.calls)
	}
}

// Un VACUUM qui échoue se journalise avec sa cause ; le démarrage continue.
func TestRemoveLegacyProbePasswords_CompactionFailureIsLoggedAndStartupGoesOn(t *testing.T) {
	var logs bytes.Buffer
	logger := quietLogger(&logs)
	_, db := openWithLegacyProbe(t, logger)
	compactor := &countingCompactor{err: errors.New("disk full")}

	removeLegacyProbePasswords(context.Background(), probe.New(db, logger), alert.New(db, logger), compactor, logger)

	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "disk full") {
		t.Fatalf("expected an error log with the cause:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "hunter2zz") {
		t.Fatal("the log must not carry the password")
	}
}

// TU-22 : de 4229874 à 621466e, une alerte probe_down écrivait la cible brute
// dans alerts.details. La résolution garde la ligne 90 jours : le démarrage
// la nettoie et compacte, même quand aucune sonde ne porte plus de mot de passe.
func TestRemoveLegacyProbePasswords_RedactsOldProbeDownAlertTarget(t *testing.T) {
	ctx := context.Background()
	logger := quietLogger(io.Discard)
	stateDir, db := openWithLegacyProbe(t, logger)
	at := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	if _, err := db.InsertAlert(ctx, alert.Alert{
		Kind: alert.KindProbeDown, Severity: alert.SeverityDanger, Status: alert.StatusResolved,
		Object:    alert.Object{Kind: alert.ObjectProbe, ID: "00000000000000a1", Name: "api"},
		MachineID: machine.LocalID,
		Details:   alert.Details{Target: "https://u:alertOldPw77@h.example.org/", Reason: "timeout"},
		OpenedAt:  at, UpdatedAt: at, ResolvedAt: at.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	removeLegacyProbePasswords(ctx, probe.New(db, logger), alert.New(db, logger), db, logger)

	if bytes.Contains(databaseBytes(t, stateDir), []byte("alertOldPw77")) {
		t.Fatal("le mot de passe est encore dans alerts.details, le fichier de base ou son -wal après le démarrage")
	}
	alerts, err := db.ListAlerts(ctx, alert.Filter{Kind: alert.KindProbeDown})
	if err != nil || len(alerts) != 1 {
		t.Fatalf("alertes: %v, %v", alerts, err)
	}
	if got := alerts[0].Details.Target; got != "https://u:…@h.example.org/" {
		t.Fatalf("la cible de l'alerte garde son utilisateur sans son mot de passe: %q", got)
	}
}
