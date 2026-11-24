package store

import (
	"context"
	"testing"
)

// La 049 recopie dans un ordre et un silence d'avant le libellé de leur
// ligne d'audit (le compte d'une session), à condition qu'elle nomme le même
// acteur ; l'acteur enregistré ne bouge pas.
func TestMigration049_OldRowsTakeTheAccountFromTheirAuditLine(t *testing.T) {
	ctx := context.Background()
	db := openEmpty(t)
	names, err := migrationFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if version := migrationVersion(name); version < 49 {
			if err := db.apply(ctx, name, version); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, run := range []string{"run-session", "run-other-actor", "run-no-audit"} {
		exec(t, db, `INSERT INTO action_runs (id, action, machine_name, state, not_after, seq, requested_by, requested_at)
			VALUES (?, 'agent.ping', 'nas', 'succeeded', 10, 1, 'operator:5e55105e55105e55', 1)`, run)
	}
	exec(t, db, `INSERT INTO mutes (id, starts_at, ends_at, created_by, created_at) VALUES (7, 1, 10, 'operator:5e55105e55105e55', 1)`)
	audit := `INSERT INTO audit_events (at, actor_kind, actor_name, actor_label, action, object_kind, object_id) VALUES (1, 'operator', ?, 'lucas', ?, ?, ?)`
	exec(t, db, audit, "5e55105e55105e55", "action.order", "action", "run-session")
	exec(t, db, audit, "a0a0a0a0a0a0a0a0", "action.order", "action", "run-other-actor")
	exec(t, db, audit, "5e55105e55105e55", "mute.create", "mute", "7")

	if err := db.apply(ctx, "049_requester_label.sql", 49); err != nil {
		t.Fatal(err)
	}

	for run, want := range map[string]string{"run-session": "lucas", "run-other-actor": "", "run-no-audit": ""} {
		if got := text(t, db, `SELECT requested_by_label FROM action_runs WHERE id = ?`, run); got != want {
			t.Errorf("%s: label %q, want %q", run, got, want)
		}
	}
	if kept := count(t, db, `SELECT COUNT(*) FROM action_runs WHERE requested_by = 'operator:5e55105e55105e55'`); kept != 3 {
		t.Fatalf("the recorded actor changed: %d rows kept it", kept)
	}
	if got := text(t, db, `SELECT created_by_label || '/' || created_by FROM mutes WHERE id = 7`); got != "lucas/operator:5e55105e55105e55" {
		t.Fatalf("mute %q", got)
	}
}
