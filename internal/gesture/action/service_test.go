package action_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/store"
	"github.com/ldesfontaine/kagu/internal/edge/store/storetest"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

const machineID = "11111111-2222-4333-8444-555555555555"

var benchNow = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

// pusher tient lieu du flux de l'agent : il regarde la base au moment où
// l'ordre part, et peut refuser de le porter.
type pusher struct {
	db       *store.DB
	refuse   error
	sent     []agentwire.Command
	atSend   []action.Run
	auditing int
}

func (p *pusher) Command(_ string, command agentwire.Command) error {
	if p.refuse != nil {
		return p.refuse
	}
	p.sent = append(p.sent, command)
	runs, err := p.db.ListActionRuns(context.Background(), action.Query{Limit: 10})
	if err != nil {
		return err
	}
	p.atSend = runs
	events, err := p.db.ListAuditEvents(context.Background(), audit.Query{Limit: 10, ObjectKind: audit.ObjectAction})
	if err != nil {
		return err
	}
	p.auditing = len(events)
	return nil
}

type bench struct {
	db       *store.DB
	service  *action.Service
	machines *machine.Service
	agentID  string
	pusher   *pusher
	now      time.Time
}

// newBench enrôle une machine, ouvre la session de son agent (elle est en
// ligne) et branche le composant comme serve le fait. L'agent n'a pas
// encore rapporté ses droits.
func newBench(t *testing.T) *bench {
	t.Helper()
	return newBenchReporting(t, "")
}

// newBenchReporting fait de même avec un agent qui rapporte ces droits à
// l'ouverture de son flux.
func newBenchReporting(t *testing.T, rights string) *bench {
	t.Helper()
	return newBenchLogging(t, rights, slog.New(slog.DiscardHandler))
}

// newBenchLogging garde en plus le journal du service, pour les tests qui
// y cherchent ce qui ne doit pas s'y trouver.
func newBenchLogging(t *testing.T, rights string, logger *slog.Logger) *bench {
	t.Helper()
	db := storetest.Open(t)
	b := &bench{db: db, now: benchNow}
	clock := func() time.Time { return b.now }
	machines := machine.New(db, machine.NewSessions(), logger)
	machines.SetClock(clock)
	enrolled := storetest.EnrollMachine(t, machines, machineID, "vps-paris-1")
	session, err := machines.Connect(context.Background(), enrolled, "192.0.2.1", "v0.0.1", rights, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	storetest.AnnounceKinds(t, machines, enrolled.Agent.ID)
	b.machines, b.agentID = machines, enrolled.Agent.ID
	t.Cleanup(func() { machines.Disconnect(session) })
	journal := audit.New(db, logger)
	b.pusher = &pusher{db: db}
	b.service = action.New(db, machines, logger)
	b.service.SetClock(clock)
	b.service.SetAuditor(journal)
	b.service.SetKey(action.GenerateKey())
	b.service.SetCommander(b.pusher)
	return b
}

func operator() context.Context {
	return audit.WithActor(context.Background(), audit.Operator("lucas"))
}

func (b *bench) runs(t *testing.T) []action.Run {
	t.Helper()
	runs, err := b.db.ListActionRuns(context.Background(), action.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	return runs
}

// states rend l'état de chaque run, par identifiant.
func (b *bench) states(t *testing.T) map[string]action.State {
	t.Helper()
	states := map[string]action.State{}
	for _, run := range b.runs(t) {
		states[run.ID] = run.State
	}
	return states
}

// Le run est écrit, marqué envoyé et journalisé avant que l'ordre ne parte :
// le flux le trouve déjà en base.
func TestPing_WritesAndJournalsTheRunBeforeSending(t *testing.T) {
	b := newBench(t)
	run, err := b.service.Ping(operator(), machineID)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.pusher.sent) != 1 || b.pusher.sent[0].Kind != agentwire.KindAgentPing || b.pusher.sent[0].Order == nil {
		t.Fatalf("sent %+v", b.pusher.sent)
	}
	if len(b.pusher.atSend) != 1 || b.pusher.atSend[0].ID != run.ID || b.pusher.atSend[0].State != action.StateSent {
		t.Fatalf("at send time the base held %+v", b.pusher.atSend)
	}
	if b.pusher.auditing != 1 {
		t.Fatalf("%d audit events at send time", b.pusher.auditing)
	}
	if run.RequestedBy != "operator:lucas" || run.Seq != 1 || !run.NotAfter.Equal(benchNow.Add(action.OrderLifetime)) {
		t.Fatalf("run %+v", run)
	}
}

// Un ordre que le flux ne prend pas finit failed, undelivered : la trace
// dit qu'il n'est jamais parti.
func TestPing_UndeliveredOrderFails(t *testing.T) {
	b := newBench(t)
	b.pusher.refuse = machine.ErrBusy
	run, err := b.service.Ping(operator(), machineID)
	if err != nil {
		t.Fatal(err)
	}
	stored := b.runs(t)
	if run.State != action.StateFailed || len(stored) != 1 || stored[0].State != action.StateFailed || stored[0].Reason != action.ReasonUndelivered || stored[0].FinishedAt.IsZero() {
		t.Fatalf("run %+v, stored %+v", run, stored)
	}
}

// Ce qui attend encore son agent après not_after expire ; ce qui a reçu sa
// réponse ne bouge plus, même rapporté après.
func TestExpire_EndsWhatWaitsPastItsDeadline(t *testing.T) {
	b := newBench(t)
	waiting, err := b.service.Ping(operator(), machineID)
	if err != nil {
		t.Fatal(err)
	}
	answered, err := b.service.Ping(operator(), machineID)
	if err != nil {
		t.Fatal(err)
	}
	report := agentwire.ActionReport{Results: []agentwire.ActionResult{{RunID: answered.ID, State: agentwire.ActionSucceeded}}}
	if err := b.service.Record(context.Background(), machineID, report); err != nil {
		t.Fatal(err)
	}
	b.now = benchNow.Add(action.OrderLifetime)
	if err := b.service.Expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Les deux runs ont le même instant : la liste ne dit pas lequel vient
	// d'abord, on les lit par identifiant.
	if states := b.states(t); states[waiting.ID] != action.StateSent {
		t.Fatalf("not yet past the deadline: %+v", states)
	}
	b.now = benchNow.Add(action.OrderLifetime + time.Second)
	if err := b.service.Expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if states := b.states(t); states[waiting.ID] != action.StateExpired || states[answered.ID] != action.StateSucceeded {
		t.Fatalf("states %+v", states)
	}
	// Une réponse arrivée après l'expiration ne la défait pas.
	late := agentwire.ActionReport{Results: []agentwire.ActionResult{{RunID: waiting.ID, State: agentwire.ActionSucceeded}}}
	if err := b.service.Record(context.Background(), machineID, late); err != nil {
		t.Fatal(err)
	}
	for _, run := range b.runs(t) {
		if run.ID == waiting.ID && run.State != action.StateExpired {
			t.Fatalf("late answer moved %+v", run)
		}
	}
}

// Un rapport hors des bornes du protocole est refusé en entier.
func TestRecord_RefusesAReportOutsideTheProtocol(t *testing.T) {
	b := newBench(t)
	run, err := b.service.Ping(operator(), machineID)
	if err != nil {
		t.Fatal(err)
	}
	long := make([]agentwire.OutputLine, agentwire.MaxOutputLines+1)
	for index := range long {
		long[index] = agentwire.OutputLine{Stream: "stdout", Line: "x"}
	}
	manySteps := make([]step.Step, agentwire.MaxActionSteps+1)
	for index := range manySteps {
		manySteps[index] = step.Step{Key: step.EnrollDocker, State: step.StateDone, At: benchNow}
	}
	for name, result := range map[string]agentwire.ActionResult{
		"state from the server": {RunID: run.ID, State: "expired"},
		"no run":                {State: agentwire.ActionSucceeded},
		"reason on two lines":   {RunID: run.ID, State: agentwire.ActionRefused, Reason: "a\nb"},
		"too much output":       {RunID: run.ID, State: agentwire.ActionSucceeded, Output: long},
		"unknown stream":        {RunID: run.ID, State: agentwire.ActionSucceeded, Output: []agentwire.OutputLine{{Stream: "tty", Line: "x"}}},
		"too many steps":        {RunID: run.ID, State: agentwire.ActionSucceeded, Steps: manySteps},
		"step without a key":    {RunID: run.ID, State: agentwire.ActionSucceeded, Steps: []step.Step{{Key: "docker", State: step.StateDone, At: benchNow}}},
		"step in no state":      {RunID: run.ID, State: agentwire.ActionSucceeded, Steps: []step.Step{{Key: step.EnrollDocker, State: "queued", At: benchNow}}},
		"step detail too long":  {RunID: run.ID, State: agentwire.ActionSucceeded, Steps: []step.Step{{Key: step.EnrollDocker, State: step.StateDone, Detail: strings.Repeat("x", step.MaxDetailRunes+1), At: benchNow}}},
	} {
		err := b.service.Record(context.Background(), machineID, agentwire.ActionReport{Results: []agentwire.ActionResult{result}})
		if !errors.Is(err, action.ErrReportInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if runs := b.runs(t); runs[0].State != action.StateSent {
		t.Fatalf("a refused report moved the run: %+v", runs)
	}
}

// Un faux agent coche trois étapes d'un run, rapport après rapport : la
// lecture du run les rend dans l'ordre où il les a cochées, le détail passé
// par untrusted.Strip. Le run fini, une étape rapportée plus tard ne s'écrit
// pas.
func TestRecord_StepsOfARunComeBackInOrder(t *testing.T) {
	b := newBench(t)
	run, err := b.service.Ping(operator(), machineID)
	if err != nil {
		t.Fatal(err)
	}
	at := benchNow.Add(time.Second)
	system := step.Step{Key: step.EnrollSystem, State: step.StateDone, Detail: "Debian 12, amd64", At: at}
	docker := step.Step{Key: step.EnrollDocker, State: step.StateRunning, At: at}
	reports := []agentwire.ActionResult{
		{RunID: run.ID, State: agentwire.ActionAccepted, Steps: []step.Step{system, docker}},
		{RunID: run.ID, State: agentwire.ActionAccepted, Steps: []step.Step{
			system,
			{Key: step.EnrollDocker, State: step.StateDone, Detail: "27.3.1\x1b[2J", At: at},
			{Key: step.EnrollRestic, State: step.StateRunning, At: at},
		}},
		{RunID: run.ID, State: agentwire.ActionSucceeded, Steps: []step.Step{
			system,
			{Key: step.EnrollDocker, State: step.StateDone, Detail: "27.3.1\x1b[2J", At: at},
			{Key: step.EnrollRestic, State: step.StateSkipped, At: at},
		}},
		{RunID: run.ID, State: agentwire.ActionSucceeded, Steps: []step.Step{{Key: step.EnrollReady, State: step.StateDone, At: at}}},
	}
	for _, reported := range reports {
		if err := b.service.Record(context.Background(), machineID, agentwire.ActionReport{Results: []agentwire.ActionResult{reported}}); err != nil {
			t.Fatal(err)
		}
	}
	read, err := b.db.GetActionRun(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, one := range read.Steps {
		got = append(got, string(one.Key)+" "+string(one.State)+" "+one.Detail)
	}
	want := []string{"step.enroll.system done Debian 12, amd64", "step.enroll.docker done 27.3.1\ufffd[2J", "step.enroll.restic skipped "}
	if read.State != action.StateSucceeded || !slices.Equal(got, want) || !read.Steps[0].At.Equal(at) {
		t.Fatalf("run %s, steps %q", read.State, got)
	}
}

// Sans clé, rien ne part : une commande hors ligne, qui ne la charge pas,
// n'envoie aucun ordre.
func TestPing_WithoutAKeySendsNothing(t *testing.T) {
	b := newBench(t)
	b.service.SetKey(nil)
	if _, err := b.service.Ping(operator(), machineID); !errors.Is(err, action.ErrNoServerKey) {
		t.Fatalf("got %v", err)
	}
	if runs := b.runs(t); len(runs) != 0 {
		t.Fatalf("runs %+v", runs)
	}
}

// Le serveur n'envoie pas un ordre dont il sait que le droit manque : refus
// immédiat, sans run ni journal. Tant que l'agent n'a rien rapporté, c'est
// lui qui juge ; avec le droit, l'ordre part.
func TestSend_RefusesAnOrderWhoseRightTheAgentDidNotReport(t *testing.T) {
	observing := newBenchReporting(t, "observe")
	if _, err := observing.service.Send(operator(), machineID, agentwire.KindAgentUpdate, nil); !errors.Is(err, action.ErrRightMissing) {
		t.Fatalf("right missing: %v", err)
	}
	if runs := observing.runs(t); len(runs) != 0 || len(observing.pusher.sent) != 0 {
		t.Fatalf("written or sent: %+v %+v", runs, observing.pusher.sent)
	}
	if _, err := observing.service.Ping(operator(), machineID); err != nil {
		t.Fatalf("ping needs observe only: %v", err)
	}
	for _, rights := range []string{"", "observe,agent.update"} {
		b := newBenchReporting(t, rights)
		run, err := b.service.Send(operator(), machineID, agentwire.KindAgentUpdate, nil)
		if err != nil || run.State != action.StateSent {
			t.Fatalf("rights %q: %+v %v", rights, run, err)
		}
	}
	if _, err := observing.service.Send(operator(), machineID, "shell.exec", nil); !errors.Is(err, action.ErrUnknownKind) {
		t.Fatalf("unknown kind: %v", err)
	}
}

// Un refus de l'agent se journalise, sous l'agent, avec sa raison.
func TestRecord_JournalsARefusalByTheAgent(t *testing.T) {
	b := newBench(t)
	run, err := b.service.Ping(operator(), machineID)
	if err != nil {
		t.Fatal(err)
	}
	refused := agentwire.ActionReport{Results: []agentwire.ActionResult{{RunID: run.ID, State: agentwire.ActionRefused, Reason: agentwire.RightMissing("agent.update")}}}
	agentCtx := audit.WithActor(context.Background(), audit.Agent(machineID))
	if err := b.service.Record(agentCtx, machineID, refused); err != nil {
		t.Fatal(err)
	}
	events, err := b.db.ListAuditEvents(context.Background(), audit.Query{Limit: 10, ObjectKind: audit.ObjectAction})
	if err != nil || len(events) != 2 || events[0].Action != audit.ActionRefused || events[0].Actor.Kind != audit.ActorAgent ||
		events[0].Details["reason"] != "right_missing:agent.update" || events[0].ObjectID != run.ID || events[0].Details["kind"] != "agent.ping" {
		t.Fatalf("events %+v %v", events, err)
	}
	// Rejoué, le refus ne se journalise pas deux fois.
	if err := b.service.Record(agentCtx, machineID, refused); err != nil {
		t.Fatal(err)
	}
	if events, _ := b.db.ListAuditEvents(context.Background(), audit.Query{Limit: 10, ObjectKind: audit.ObjectAction}); len(events) != 2 {
		t.Fatalf("a replayed refusal was journaled again: %+v", events)
	}
}

// Pendant une rotation, aucun ordre ne livre la neuve (R-A3-9) : le serveur
// n'écrit même plus agent.server_key. Un agent resté sur la clé précédente
// reçoit ses ordres signés par elle ; une fois que root a collé « trust set »
// et qu'il redit la neuve, par la neuve.
func TestRotation_SignsWithTheKeyTheAgentAccepts(t *testing.T) {
	b := newBench(t)
	ctx := operator()
	old := action.GenerateKey()
	rotated, err := old.Rotated()
	if err != nil {
		t.Fatal(err)
	}
	b.service.SetKey(rotated)
	if _, err := b.service.Send(ctx, machineID, agentwire.Kind("agent.server_key"), nil); !errors.Is(err, action.ErrUnknownKind) || len(b.pusher.sent) != 0 {
		t.Fatalf("agent.server_key was written: %v %+v", err, b.pusher.sent)
	}
	host, err := b.db.GetMachine(ctx, machineID)
	if err != nil {
		t.Fatal(err)
	}
	for _, accepted := range []*action.Key{old, rotated} {
		if err := b.db.RecordServerKey(ctx, host.Agent.ID, accepted.Fingerprint()); err != nil {
			t.Fatal(err)
		}
		if _, err := b.service.Ping(ctx, machineID); err != nil {
			t.Fatal(err)
		}
		order := b.pusher.sent[len(b.pusher.sent)-1].Order
		if order.Key != accepted.Fingerprint() ||
			!ed25519.Verify(accepted.PublicKey(), agentwire.OrderSigningBytes(agentwire.OrderVersion, order.Body), order.Signature) {
			t.Fatalf("the order is not signed by the key the agent accepts (%s): %+v", accepted.Fingerprint(), order)
		}
	}
}
