package store

import (
	"context"
	"testing"
)

// La 058 élargit les états d'une sonde à « suspended » (essai E03-09), garde
// la sonde, son histoire et son certificat, et refuse toujours un état hors
// liste ; supprimer la sonde emporte encore son histoire.
func TestMigration058_AddsTheSuspendedStateAndKeepsTheProbes(t *testing.T) {
	ctx := context.Background()
	db := openEmpty(t)
	names, err := migrationFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if version := migrationVersion(name); version < 58 {
			if err := db.apply(ctx, name, version); err != nil {
				t.Fatal(err)
			}
		}
	}
	exec(t, db, `INSERT INTO machines (id, name, created_at) VALUES ('m1', 'vps', 1)`)
	exec(t, db, `INSERT INTO probes (id, name, kind, target, machine_id, status, interval_seconds, timeout_seconds, failure_threshold, recovery_threshold, last_reason, created_at, revised_at)
		VALUES ('p1', 'nas', 'tcp', '10.0.0.2:443', 'm1', 'down', 60, 10, 3, 2, 'lan', 1, 1500)`)
	exec(t, db, `INSERT INTO probe_results (probe_id, checked_at, outcome, duration_ms) VALUES ('p1', 1, 'down', 5)`)
	exec(t, db, `INSERT INTO probe_certificates (probe_id, not_before, not_after, fingerprint, chain_valid, hostname_match) VALUES ('p1', 1, 2, 'ab', 1, 1)`)
	if _, err := db.sql.Exec(`UPDATE probes SET status = 'suspended' WHERE id = 'p1'`); err == nil {
		t.Fatal("suspended accepted before the migration")
	}

	if err := db.apply(ctx, "058_probe_suspended.sql", 58); err != nil {
		t.Fatal(err)
	}

	if kept := count(t, db, `SELECT COUNT(*) FROM probes WHERE id = 'p1' AND status = 'down' AND last_reason = 'lan' AND target = '10.0.0.2:443' AND revised_at = 1500`); kept != 1 {
		t.Fatal("the migration lost or changed the probe")
	}
	if kept := count(t, db, `SELECT COUNT(*) FROM probe_results WHERE probe_id = 'p1'`) + count(t, db, `SELECT COUNT(*) FROM probe_certificates WHERE probe_id = 'p1'`); kept != 2 {
		t.Fatal("the migration lost the history or the certificate of the probe")
	}
	exec(t, db, `UPDATE probes SET status = 'suspended' WHERE id = 'p1'`)
	if _, err := db.sql.Exec(`UPDATE probes SET status = 'perdue' WHERE id = 'p1'`); err == nil {
		t.Fatal("a state outside the list is accepted")
	}
	if indexes := count(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('probes_machine', 'probes_service')`); indexes != 2 {
		t.Fatalf("%d indexes of probes, 2 expected", indexes)
	}
	exec(t, db, `DELETE FROM probes WHERE id = 'p1'`)
	if left := count(t, db, `SELECT COUNT(*) FROM probe_results`); left != 0 {
		t.Fatal("deleting the probe left its history")
	}
}
