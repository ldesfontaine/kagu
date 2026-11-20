package store

import (
	"context"
	"testing"
)

// La 043 élargit les états d'une demande à « lapsed », garde les lignes et
// l'effacement par cascade avec le jeton, et refuse toujours un état hors liste.
func TestMigration043_AddsTheLapsedStateAndKeepsTheRows(t *testing.T) {
	ctx := context.Background()
	db := openEmpty(t)
	names, err := migrationFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if version := migrationVersion(name); version < 43 {
			if err := db.apply(ctx, name, version); err != nil {
				t.Fatal(err)
			}
		}
	}
	exec(t, db, `INSERT INTO api_tokens (id, token_hash, token_prefix, scope, name, created_at) VALUES ('tok', 'h', 'p', 'write', 'agent', 1)`)
	exec(t, db, `INSERT INTO verb_requests (id, verb, object_name, params, body, token_id, token_name, on_behalf_of, state, created_at, expires_at)
		VALUES ('r1', 'machine.delete', 'nas', '{"id":"m1"}', '', 'tok', 'agent', 'alice', 'confirmed', 100, 1000)`)
	if _, err := db.sql.Exec(`UPDATE verb_requests SET state = 'lapsed' WHERE id = 'r1'`); err == nil {
		t.Fatal("lapsed accepted before the migration")
	}

	if err := db.apply(ctx, "043_verb_request_lapsed.sql", 43); err != nil {
		t.Fatal(err)
	}

	if kept := count(t, db, `SELECT COUNT(*) FROM verb_requests WHERE id = 'r1' AND state = 'confirmed' AND params = '{"id":"m1"}'`); kept != 1 {
		t.Fatal("the migration lost or changed a row")
	}
	exec(t, db, `UPDATE verb_requests SET state = 'lapsed' WHERE id = 'r1'`)
	if _, err := db.sql.Exec(`UPDATE verb_requests SET state = 'perdue' WHERE id = 'r1'`); err == nil {
		t.Fatal("a state outside the list is accepted")
	}
	exec(t, db, `DELETE FROM api_tokens WHERE id = 'tok'`)
	if requests := count(t, db, `SELECT COUNT(*) FROM verb_requests`); requests != 0 {
		t.Fatal("revoking the token left its request")
	}
}
