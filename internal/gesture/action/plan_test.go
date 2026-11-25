package action_test

import (
	"context"
	"slices"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// R-B2-9 : un agent plus ancien n'est jamais « à jour », qu'il soit hors
// ligne, non migré ou prêt ; ce qui lui manque est ce que le serveur sait
// envoyer et qu'il n'a pas annoncé.
func TestR_B2_9_AnOlderAgentIsNeverShownUpToDate(t *testing.T) {
	ctx := context.Background()
	b := readyBench(t) // vps-paris-1, v0.0.1, serveur v0.0.2
	b.machines.Disconnect(b.session)
	b.addMachine(t, otherMachineID, "not-migrated", "v0.0.1", false)
	partial := b.addMachine(t, "33333333-4444-4555-8666-777777777777", "no-deploy", "v0.0.1", true)
	withoutDeploy := agentwire.AnnouncedKinds()
	delete(withoutDeploy, string(agentwire.KindDockerDeploy))
	if err := b.machines.NoteOrderKinds(ctx, partial.Agent.ID, withoutDeploy.Format()); err != nil {
		t.Fatal(err)
	}
	legacy := b.addMachine(t, "44444444-5555-4666-8777-888888888888", "legacy", "v0.0.1", true)
	if err := b.machines.NoteProtocol(ctx, legacy.Agent.ID, agentwire.LegacyProtocolVersion); err != nil {
		t.Fatal(err)
	}
	if err := b.machines.NoteOrderKinds(ctx, legacy.Agent.ID, ""); err != nil {
		t.Fatal(err)
	}
	b.addMachine(t, "55555555-6666-4777-8888-999999999999", "current", "v0.0.2", true)
	b.addMachine(t, "66666666-7777-4888-8999-aaaaaaaaaaaa", "newer", "v0.0.9", true)

	plan, err := b.service.UpdatePlan(operator())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]action.PlanEntry{}
	for _, entry := range plan {
		got[entry.MachineName] = entry
	}
	for _, name := range []string{"vps-paris-1", "not-migrated", "no-deploy", "legacy"} {
		if entry := got[name]; entry.UpToDate || !entry.Behind {
			t.Errorf("%s, older than the server, shown up to date: %+v", name, entry)
		}
	}
	for _, name := range []string{"current", "newer"} {
		if entry := got[name]; !entry.UpToDate || entry.Behind || len(entry.Missing) != 0 {
			t.Errorf("%s: %+v", name, entry)
		}
	}
	if missing := got["no-deploy"].Missing; !slices.Equal(missing, []string{string(agentwire.KindDockerDeploy)}) {
		t.Errorf("no-deploy misses %v", missing)
	}
	// Un agent du protocole 2 ne reçoit qu'agent.update (R-B2-8).
	var allButUpdate []string
	for _, kind := range agentwire.OrderKinds() {
		if kind != agentwire.KindAgentUpdate {
			allButUpdate = append(allButUpdate, string(kind))
		}
	}
	if missing := got["legacy"].Missing; !slices.Equal(missing, allButUpdate) {
		t.Errorf("legacy misses %v", missing)
	}
	// Hors ligne, il reste en retard ; sa raison reste celle de la fiche.
	if entry := got["vps-paris-1"]; entry.Online || entry.Blocked != action.OfferOffline {
		t.Errorf("offline %+v", entry)
	}
}

// Sans bibliothèque, rien ne se compare : ni « à jour » ni « en retard ».
func TestStandingOf_WithoutReleasesSaysNeitherUpToDateNorBehind(t *testing.T) {
	b := newUpdateBench(t, updateOptions{rights: "observe,agent.update", agentVersion: "v0.0.1", arch: "amd64"})
	target, err := b.machines.Get(context.Background(), machineID)
	if err != nil {
		t.Fatal(err)
	}
	if standing := b.service.StandingOf(target.Agent); standing.UpToDate || standing.Behind || len(standing.Missing) != 0 {
		t.Fatalf("standing %+v", standing)
	}
	if standing := b.service.StandingOf(machine.Agent{}); standing.UpToDate || standing.Behind || standing.Missing != nil {
		t.Fatalf("no agent %+v", standing)
	}
}

// Le bandeau : une version importée plus récente que le serveur, et elle
// seule ; la version qui tourne, importée, n'en fait pas.
func TestImportedAhead_NamesOnlyANewerImportedVersion(t *testing.T) {
	b := newUpdateBench(t, updateOptions{rights: "observe,agent.update", agentVersion: "v0.0.1", arch: "amd64"})
	if ahead, err := b.service.ImportedAhead(); err != nil || ahead != "" {
		t.Fatalf("without releases: %q %v", ahead, err)
	}
	b.publishBoth(t, "v0.0.2")
	b.service.SetReleases(b.library, "v0.0.2")
	if ahead, err := b.service.ImportedAhead(); err != nil || ahead != "" {
		t.Fatalf("the running version is imported: %q %v", ahead, err)
	}
	b.publishBoth(t, "v0.0.1")
	b.publishBoth(t, "v0.1.0")
	if ahead, err := b.service.ImportedAhead(); err != nil || ahead != "v0.1.0" {
		t.Fatalf("a newer import: %q %v", ahead, err)
	}
	b.service.SetReleases(b.library, "v0.1.0")
	if ahead, err := b.service.ImportedAhead(); err != nil || ahead != "" {
		t.Fatalf("once installed: %q %v", ahead, err)
	}
}
