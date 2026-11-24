package store

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/seal"
)

// E01-11 : une base d'avant garde des noms d'hôte que la règle d'aujourd'hui
// refuse (un espace, un caractère de contrôle) et une version à saut de ligne.
// La 050 les rejuge une fois : la valeur refusée est effacée, son refus se lit
// sur la machine, avant comme après un redémarrage ; la machine reste suivie ;
// un nom valable annoncé au ré-enrôlement efface le refus.
func TestE01_11_AStoredNameTheRuleRefusesIsReportedAndNeverShown(t *testing.T) {
	ctx := context.Background()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	spaced, control, valid := newMachineID(t), newMachineID(t), newMachineID(t)
	writeBaseBefore050(t, root, map[string][2]string{
		spaced:  {"web essai", "v0.0.1"},
		control: {"web\x1b[2Jessai", "v0.0.1\n"},
		valid:   {"nas-1.lan", "v0.0.1"},
	})
	refusedBytes := []string{"web essai", "\x1b[2J", "\\u001b[2J", "v0.0.1\n", "v0.0.1\\n"}

	logs := &bytes.Buffer{}
	db, machines := startOn(t, root, logs)
	wantRefused := map[string][]string{
		spaced:  {machine.ReportFieldHostname},
		control: {machine.ReportFieldHostname, machine.ReportFieldVersion},
		valid:   nil,
	}
	expectRefusals(t, machines, wantRefused, refusedBytes)
	kept, err := machines.Get(ctx, valid)
	if err != nil || kept.Hostname != "nas-1.lan" || kept.Agent.Version != "v0.0.1" {
		t.Fatalf("une valeur que la règle accepte reste : %+v %v", kept.Machine, err)
	}
	if got := count(t, db, `SELECT COUNT(*) FROM machines WHERE hostname LIKE 'web%'`); got != 0 {
		t.Fatalf("%d noms refusés encore en base", got)
	}

	// La machine reste suivie : son agent ouvre son flux, elle est en ligne.
	stored, err := machines.Get(ctx, spaced)
	if err != nil {
		t.Fatal(err)
	}
	session, err := machines.Connect(ctx, stored.Machine, "192.0.2.10", "v0.0.1", "", "", "", "")
	if err != nil {
		t.Fatalf("la machine au nom refusé ne se connecte plus : %v", err)
	}
	if online, _ := machines.Get(ctx, spaced); !online.Online {
		t.Fatal("la machine au nom refusé n'est pas en ligne")
	}
	machines.Disconnect(session)

	// Redémarrage : la 050 ne repasse pas, le refus reste.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, machines = startOn(t, root, logs)
	expectRefusals(t, machines, wantRefused, refusedBytes)

	// Un agent d'avant, qui ne dit ni version ni système, n'annonce rien de
	// valable : le refus reste.
	silent, err := machines.Get(ctx, control)
	if err != nil {
		t.Fatal(err)
	}
	session, err = machines.Connect(ctx, silent.Machine, "192.0.2.11", "", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	machines.Disconnect(session)
	if err := machines.NoteSystem(ctx, control, ""); err != nil {
		t.Fatal(err)
	}
	expectRefusals(t, machines, wantRefused, refusedBytes)

	// L'agent annonce un nom valable en se ré-enrôlant : le refus s'efface.
	cleartext, _, err := machines.CreateReenrollToken(ctx, spaced, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = machines.Enroll(ctx, machine.Enrollment{
		MachineID: spaced, PublicKey: newKey(t), Token: cleartext,
		Hostname: "web-essai", OS: "Debian GNU/Linux 13", Arch: "amd64", AgentVersion: "v0.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantRefused[spaced] = nil
	expectRefusals(t, machines, wantRefused, refusedBytes)
	if renamed, _ := machines.Get(ctx, spaced); renamed.Hostname != "web-essai" {
		t.Fatalf("nom d'hôte %q après le ré-enrôlement", renamed.Hostname)
	}
	for _, refused := range refusedBytes {
		if strings.Contains(logs.String(), refused) {
			t.Fatalf("le journal porte %q :\n%s", refused, logs.String())
		}
	}
}

func newMachineID(t *testing.T) string {
	t.Helper()
	id, err := machine.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// writeBaseBefore050 écrit, sous root, une base jouée jusqu'à la 049 et ses
// machines : par identifiant, le nom d'hôte et la version de l'agent.
func writeBaseBefore050(t *testing.T, root *os.Root, reported map[string][2]string) {
	t.Helper()
	ctx := context.Background()
	handle, err := openHandle(root)
	if err != nil {
		t.Fatal(err)
	}
	before := &DB{sql: handle}
	defer before.Close()
	exec(t, before, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`)
	names, err := migrationFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if version := migrationVersion(name); version < 50 {
			if err := before.apply(ctx, name, version); err != nil {
				t.Fatal(err)
			}
		}
	}
	for id, said := range reported {
		agentID, err := machine.NewAgentID()
		if err != nil {
			t.Fatal(err)
		}
		exec(t, before, `INSERT INTO machines (id, name, hostname, os, arch, created_at) VALUES (?, ?, ?, 'Debian', 'amd64', 1)`,
			id, "m-"+strings.ToLower(id[:8]), said[0])
		exec(t, before, `INSERT INTO agents (id, machine_id, public_key, version, enrolled_at) VALUES (?, ?, ?, ?, 1)`,
			agentID, id, newKey(t), said[1])
	}
}

// startOn ouvre la base comme serve au démarrage, migrations comprises, et
// le composant des machines par-dessus.
func startOn(t *testing.T, root *os.Root, logs *bytes.Buffer) (*DB, *machine.Service) {
	t.Helper()
	db, err := Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	db.SetSealer(seal.Generate())
	t.Cleanup(func() { db.Close() })
	return db, machine.New(db, machine.NewSessions(), slog.New(slog.NewTextHandler(logs, nil)))
}

// expectRefusals lit chaque machine comme la fiche : les refus attendus, et
// aucun octet refusé dans ce qui en sort.
func expectRefusals(t *testing.T, machines *machine.Service, want map[string][]string, refusedBytes []string) {
	t.Helper()
	statuses, err := machines.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range statuses {
		if expected, known := want[status.ID]; known && !slices.Equal(status.ReportRejected, expected) {
			t.Errorf("machine %s : refus %v, %v attendus", status.ID, status.ReportRejected, expected)
		}
	}
	shown, err := json.Marshal(statuses)
	if err != nil {
		t.Fatal(err)
	}
	for _, refused := range refusedBytes {
		if bytes.Contains(shown, []byte(refused)) {
			t.Fatalf("la lecture des machines porte %q : %s", refused, shown)
		}
	}
}
