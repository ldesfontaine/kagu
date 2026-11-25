package action_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// grantedRight écrit un droit comme l'agent le rapporte : un droit borné
// porte sa portée.
func grantedRight(name string) string {
	scopes := map[string]string{
		agentpolicy.CapabilityBackupReceive: "/srv/backups",
		agentpolicy.CapabilityBackupProduce: agentpolicy.ProducerProxmoxVzdump,
		agentpolicy.CapabilityFilesWrite:    "/srv/files",
		agentpolicy.CapabilityResticTarget:  "/srv/restic",
	}
	if scope, bounded := scopes[name]; bounded {
		return name + "=" + scope
	}
	return name
}

// everyRightBut rend tous les droits sauf missing.
func everyRightBut(missing string) string {
	var granted []string
	for _, name := range agentpolicy.CapabilityNames() {
		if name != missing {
			granted = append(granted, grantedRight(name))
		}
	}
	return strings.Join(granted, ",")
}

// Le serveur pré-juge un ordre avec le droit que le registre déclare pour son
// genre, et lui seul : un agent qui a tous les droits sauf celui-là ne reçoit
// rien ; un agent qui n'a que celui-là reçoit l'ordre.
func TestR_A1_14_TheServerPrejudgesWithTheRegistry(t *testing.T) {
	var alone []agentwire.Kind
	for _, kind := range agentwire.OrderKinds() {
		spec, _ := agentwire.SpecOf(kind)
		// L'exception d'ARB-1, déclarée sur le genre : TestARB1_ARightRequestLeavesWithoutTheRight
		// l'éprouve. Elle ne vaut que pour right.request (R-DROIT-4).
		if spec.AgentJudgesAlone {
			alone = append(alone, kind)
			continue
		}
		// observe est toujours tenu (agentpolicy.NormalizeCapabilities) : il ne
		// peut pas manquer.
		if spec.Right != agentpolicy.CapabilityObserve {
			missing := newBenchReporting(t, everyRightBut(spec.Right))
			if _, err := missing.service.Send(operator(), machineID, kind, nil); !errors.Is(err, action.ErrRightMissing) {
				t.Errorf("%s without %s: %v", kind, spec.Right, err)
			}
			if len(missing.pusher.sent) != 0 {
				t.Errorf("%s without %s: %d orders left", kind, spec.Right, len(missing.pusher.sent))
			}
		}
		holding := newBenchReporting(t, grantedRight(spec.Right))
		if _, err := holding.service.Send(operator(), machineID, kind, nil); err != nil {
			t.Errorf("%s with only %s: %v", kind, spec.Right, err)
		}
	}
	if !slices.Equal(alone, []agentwire.Kind{agentwire.KindRightRequest}) {
		t.Errorf("kinds the server does not prejudge: %v, want right.request alone", alone)
	}
	// Une observation n'est pas au registre : aucun droit ne la fait partir
	// comme un ordre.
	every := newBenchReporting(t, everyRightBut(""))
	if _, err := every.service.Send(operator(), machineID, agentwire.KindLogs, nil); !errors.Is(err, action.ErrUnknownKind) {
		t.Errorf("an observation sent as an order: %v", err)
	}
}

// R-A3-5 : le serveur pré-juge avec l'échéance que l'agent rapporte. Un droit
// qui échoit avant not_after de l'ordre ne suffit pas ; un droit qui tient
// jusque-là, si. Le droit terminal.host, de la politique seule, se lit
// dans ce que l'agent rapporte.
func TestPrejudge_ARightThatLapsesBeforeNotAfterIsRefused(t *testing.T) {
	b := newBenchReporting(t, "agent.update,terminal.host=root")
	target, err := b.db.GetMachine(context.Background(), machineID)
	if err != nil {
		t.Fatal(err)
	}
	if !agentpolicy.HasCapability(target.Agent.Capabilities, agentpolicy.CapabilityTerminalHost) {
		t.Fatalf("terminal.host reported but not kept: %v", target.Agent.Capabilities)
	}
	notAfter := benchNow.Add(action.OrderLifetime)
	report := func(until time.Time) {
		t.Helper()
		if err := b.db.RecordRightsUntil(context.Background(), target.Agent.ID, map[string]time.Time{agentpolicy.CapabilityAgentUpdate: until}); err != nil {
			t.Fatal(err)
		}
	}
	report(notAfter.Add(-time.Second))
	if _, err := b.service.Send(operator(), machineID, agentwire.KindAgentUpdate, nil); !errors.Is(err, action.ErrRightMissing) {
		t.Fatalf("a right lapsing before not_after: %v", err)
	}
	if len(b.pusher.sent) != 0 {
		t.Fatalf("%d orders left", len(b.pusher.sent))
	}
	report(notAfter)
	if _, err := b.service.Send(operator(), machineID, agentwire.KindAgentUpdate, nil); err != nil {
		t.Fatalf("a right held through not_after: %v", err)
	}
}

// ARB-1 : « Demander ce droit à la machine » envoie right.request même quand
// l'agent a rapporté ne pas tenir le droit : un seul ordre part, signé, de ce
// genre et d'aucun autre, avec le droit demandé. Un droit qu'agentpolicy ne
// connaît pas, ou une valeur hors de la liste des producteurs, ne fait partir
// rien.
func TestARB1_ARightRequestLeavesWithoutTheRight(t *testing.T) {
	b := newBenchReporting(t, agentpolicy.CapabilityObserve)
	run, err := b.service.RequestRight(operator(), machineID, agentpolicy.CapabilityDockerDeploy, "")
	if err != nil || run.Kind != agentwire.KindRightRequest || run.State != action.StateSent {
		t.Fatalf("request: %+v %v", run, err)
	}
	if len(b.pusher.sent) != 1 {
		t.Fatalf("%d orders left, want one", len(b.pusher.sent))
	}
	sent := b.pusher.sent[0]
	if sent.Kind != agentwire.KindRightRequest || sent.Order == nil || len(sent.Order.Signature) == 0 {
		t.Fatalf("sent %+v", sent)
	}
	var body agentwire.OrderBody
	if err := json.Unmarshal(sent.Order.Body, &body); err != nil {
		t.Fatal(err)
	}
	if string(body.Params) != `{"right":"docker.deploy"}` {
		t.Fatalf("params %s", body.Params)
	}
	// Le même agent, sans le droit, ne reçoit pas l'ordre qu'il protège.
	if _, err := b.service.Send(operator(), machineID, agentwire.KindDockerRollback, nil); !errors.Is(err, action.ErrRightMissing) {
		t.Fatalf("docker.rollback without its right: %v", err)
	}
	refused := map[string][2]string{
		"unknown right":  {"shell.exec", ""},
		"path value":     {agentpolicy.CapabilityFilesWrite, "/etc"},
		"other producer": {agentpolicy.CapabilityBackupProduce, "dd"},
	}
	for name, asked := range refused {
		if _, err := b.service.RequestRight(operator(), machineID, asked[0], asked[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(b.pusher.sent) != 1 {
		t.Fatalf("%d orders left, want only the request", len(b.pusher.sent))
	}
}
