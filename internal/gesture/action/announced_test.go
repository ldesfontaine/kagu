package action_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Un ordre d'un genre que l'agent n'a pas annoncé est refusé avant tout :
// aucun run écrit, rien de signé ni de mis en file, rien dans l'audit. Le refus
// dit « Mettre à jour l'agent » (action.agent_outdated). Seul ce que l'agent
// annonce compte : un agent qui n'annonce rien ne reçoit rien, agent.update
// compris.
func TestR_B2_8_AnOrderOfAKindNotAnnouncedIsRefusedBeforeSending(t *testing.T) {
	cases := map[string]struct {
		announced string
		refused   []agentwire.Kind
		sent      []agentwire.Kind
	}{
		"ping only": {
			announced: "agent.ping@1",
			refused:   []agentwire.Kind{agentwire.KindDockerDeploy, agentwire.KindAgentUpdate, agentwire.KindResticBackup},
			sent:      []agentwire.Kind{agentwire.KindAgentPing},
		},
		"another kind only": {
			announced: "docker.deploy@1",
			refused:   []agentwire.Kind{agentwire.KindAgentPing},
		},
		"nothing announced": {
			refused: agentwire.OrderKinds(),
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBench(t)
			if err := b.machines.NoteOrderKinds(context.Background(), b.agentID, c.announced); err != nil {
				t.Fatal(err)
			}
			for _, kind := range c.refused {
				_, err := b.service.Send(operator(), machineID, kind, nil)
				if key, _ := refusal.KeyOf(err); !errors.Is(err, action.ErrAgentOutdated) || key != "action.agent_outdated" {
					t.Errorf("%s: %v (key %q)", kind, err, key)
				}
			}
			events, err := b.db.ListAuditEvents(context.Background(), audit.Query{Limit: 10, ObjectKind: audit.ObjectAction})
			if runs := b.runs(t); len(runs) != 0 || len(b.pusher.sent) != 0 || err != nil || len(events) != 0 {
				t.Fatalf("a refused order left a trace: %d runs, %d sent, %d audited, %v", len(runs), len(b.pusher.sent), len(events), err)
			}
			for _, kind := range c.sent {
				if run, err := b.service.Send(operator(), machineID, kind, nil); err != nil || run.State != action.StateSent {
					t.Errorf("%s, announced: %+v, %v", kind, run, err)
				}
			}
		})
	}
}
