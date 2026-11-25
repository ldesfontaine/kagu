package store

import (
	"context"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
)

// La 059 (essai E03-08) : la raison d'une politique refusée se garde et se
// relit ; la base refuse une raison hors de l'ensemble fermé et un détail
// plus long que ce que l'agent envoie ; un rapport sans raison l'efface.
func TestMigration059_KeepsTheRefusalAndRefusesTheRest(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	exec(t, db, `INSERT INTO machines (id, name, hostname, created_at) VALUES ('web', 'web-1', 'web', 1)`)
	exec(t, db, `INSERT INTO agents (id, machine_id, public_key, version, enrolled_at) VALUES ('agt_1', 'web', zeroblob(32), 'v0.0.1', 2)`)

	refused := agentpolicy.Refusal{Reason: agentpolicy.RefusedUnknownKey, Detail: "foo"}
	if err := db.RecordPolicy(ctx, "agt_1", agentpolicy.SourceRefused, "", refused); err != nil {
		t.Fatal(err)
	}
	found, err := db.GetMachine(ctx, "web")
	if err != nil || found.Agent.PolicyRefusal != refused {
		t.Fatalf("read back %+v %v", found.Agent.PolicyRefusal, err)
	}
	for _, wrong := range []agentpolicy.Refusal{{Reason: "because"}, {Reason: agentpolicy.RefusedMode, Detail: strings.Repeat("a", 129)}} {
		if err := db.RecordPolicy(ctx, "agt_1", agentpolicy.SourceRefused, "", wrong); err == nil {
			t.Errorf("%+v written", wrong)
		}
	}
	if err := db.RecordPolicy(ctx, "agt_1", agentpolicy.SourcePolicy, strings.Repeat("ab", 32), agentpolicy.Refusal{}); err != nil {
		t.Fatal(err)
	}
	if found, _ := db.GetMachine(ctx, "web"); found.Agent.PolicyRefusal != (agentpolicy.Refusal{}) {
		t.Fatalf("a held policy kept %+v", found.Agent.PolicyRefusal)
	}
}
