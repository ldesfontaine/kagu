package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// pendingBench est un agent passé à la politique, observe seul, sur un faux
// système : root y lit la liste et y pose les droits.
func pendingBench(t *testing.T) *migratedBench {
	t.Helper()
	b := migrate(t, newOrderBench(t))
	b.opts.System = newRecordingSystem()
	return b
}

// refuseDeploy envoie un ordre docker.deploy signé par signer, de rang seq.
func (b *migratedBench) refuseDeploy(t *testing.T, seq int64, signer ed25519.PrivateKey) agentwire.ActionResult {
	t.Helper()
	body := order(seq)
	body.Kind = agentwire.KindDockerDeploy
	body.NotAfter = b.clock.now.Add(time.Minute).Unix()
	return b.send(t, body, signer)
}

// pendingNames lit la liste comme root et rend les droits à poser.
func (b *migratedBench) pendingNames(t *testing.T) []string {
	t.Helper()
	pending, err := ReadPendingRightsAsRoot(b.opts)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range pending.Grantable {
		names = append(names, entry.Text())
	}
	return names
}

// R-A3-15 (E03-07) : un droit que l'agent refuse à un ordre jugé entre dans
// sa liste, écrite en 0600 dans son état.
func TestR_A3_15_E03_07_ARefusedRightIsNotedByTheAgent(t *testing.T) {
	b := pendingBench(t)
	if result := b.refuseDeploy(t, 1, b.private); result.Reason != agentwire.RightMissing(agentpolicy.CapabilityDockerDeploy) {
		t.Fatalf("deploy %+v", result)
	}
	if names := b.pendingNames(t); !slices.Equal(names, []string{"docker.deploy"}) {
		t.Fatalf("pending %v, want docker.deploy", names)
	}
	info, err := b.stateDir.Stat(pendingRightsFile)
	if err != nil || info.Mode().Perm() != pendingRightsMode {
		t.Fatalf("pending file %v %v", info, err)
	}
	// Un second refus garde une entrée, à l'heure du dernier.
	b.clock.advance(time.Hour)
	b.refuseDeploy(t, 2, b.private)
	entries, err := readPendingRights(b.stateDir)
	if err != nil || len(entries) != 1 || !entries[0].RefusedAt.Equal(b.clock.now) {
		t.Fatalf("entries %+v %v", entries, err)
	}
}

// Rien de ce que le serveur dit sans signature valable n'écrit dans la liste :
// un ordre mal signé, pour un autre agent, rejoué ou périmé est refusé avant
// le jugement du droit. Un ordre qui passe n'y écrit rien non plus.
func TestR_A3_15_E03_07_OnlyAJudgedRefusalIsNoted(t *testing.T) {
	b := pendingBench(t)
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if result := b.refuseDeploy(t, 1, stranger); result.Reason != agentwire.ReasonBadSignature {
		t.Fatalf("forged %+v", result)
	}
	otherAgent := order(2)
	otherAgent.Kind, otherAgent.AgentID = agentwire.KindDockerDeploy, "agt_other"
	if result := b.send(t, otherAgent, b.private); result.Reason != agentwire.ReasonWrongAgent {
		t.Fatalf("other agent %+v", result)
	}
	expired := order(3)
	expired.Kind, expired.NotAfter = agentwire.KindDockerDeploy, b.clock.now.Add(-time.Second).Unix()
	if result := b.send(t, expired, b.private); result.Reason != agentwire.ReasonExpired {
		t.Fatalf("expired %+v", result)
	}
	if result := b.pingAt(t, 4, b.private); result.State != agentwire.ActionSucceeded {
		t.Fatalf("ping %+v", result)
	}
	if names := b.pendingNames(t); len(names) != 0 {
		t.Fatalf("pending %v, want none", names)
	}
	if _, err := b.stateDir.Stat(pendingRightsFile); err == nil {
		t.Fatal("the pending file was written")
	}
}

// Une entrée vaut 24 h après le dernier refus ; une entrée datée du futur ne
// vaut pas.
func TestR_A3_15_E03_07_AnEntryOlderThan24hIsIgnored(t *testing.T) {
	b := pendingBench(t)
	b.refuseDeploy(t, 1, b.private)
	b.clock.advance(pendingRightLife - time.Second)
	if names := b.pendingNames(t); !slices.Equal(names, []string{"docker.deploy"}) {
		t.Fatalf("pending before 24 h %v", names)
	}
	b.clock.advance(time.Second)
	if names := b.pendingNames(t); len(names) != 0 {
		t.Fatalf("pending after 24 h %v, want none", names)
	}
	future := PendingRight{Name: agentpolicy.CapabilityDockerDeploy, RefusedAt: b.clock.now.Add(time.Hour)}
	if future.live(b.clock.now) {
		t.Fatal("an entry from the future is live")
	}
}

// Au plafond, le plus ancien refus tombe.
func TestR_A3_15_E03_07_TheOldestEntryFallsAtTheCeiling(t *testing.T) {
	b := pendingBench(t)
	for index := range maxPendingRights + 1 {
		entry := PendingRight{Name: fmt.Sprintf("right-%02d", index), RefusedAt: b.clock.now.Add(time.Duration(index-maxPendingRights) * time.Minute)}
		if err := b.runner.updatePendingRights(func(rights []PendingRight) []PendingRight { return append(rights, entry) }); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := readPendingRights(b.stateDir)
	if err != nil || len(entries) != maxPendingRights {
		t.Fatalf("%d entries %v, want %d", len(entries), err, maxPendingRights)
	}
	if entries[0].Name != "right-01" || entries[len(entries)-1].Name != fmt.Sprintf("right-%02d", maxPendingRights) {
		t.Fatalf("kept %s … %s, the oldest must fall", entries[0].Name, entries[len(entries)-1].Name)
	}
}

// grant --pending pose par le chemin de grant, avec sa trace ; le droit posé
// sort de la liste à la relecture de la politique, et n'y entre plus.
func TestR_A3_15_E03_07_GrantPendingGoesThroughGrant(t *testing.T) {
	b := pendingBench(t)
	b.refuseDeploy(t, 1, b.private)
	var trace []string
	b.opts.Audit = func(message string) error {
		trace = append(trace, message)
		return nil
	}
	pending, err := ReadPendingRightsAsRoot(b.opts)
	if err != nil {
		t.Fatal(err)
	}
	change, err := GrantPending(b.opts, pending.Grantable, accept)
	if err != nil || !slices.Equal(change.Added, []string{"docker.deploy"}) {
		t.Fatalf("change %+v %v", change, err)
	}
	if len(trace) != 1 || !strings.HasPrefix(trace[0], "policy grant +[docker.deploy] -[]") {
		t.Fatalf("audit %q", trace)
	}
	b.runner.currentPolicy()
	if entries, err := readPendingRights(b.stateDir); err != nil || len(entries) != 0 {
		t.Fatalf("a granted right stays pending: %+v %v", entries, err)
	}
	b.runner.notePendingRight(judgedOrder{}, agentwire.RightMissing(agentpolicy.CapabilityDockerDeploy))
	if entries, _ := readPendingRights(b.stateDir); len(entries) != 0 {
		t.Fatalf("a held right entered the list: %+v", entries)
	}
}

// Une valeur ne se note que lue hors du serveur : un producteur de la liste
// fermée. Sans elle, root choisit la valeur ; rien ne se pose seul.
func TestR_A3_15_E03_07_OnlyAClosedValueIsNoted(t *testing.T) {
	b := pendingBench(t)
	known := judgedOrder{Order: agentwire.Order{Kind: agentwire.KindBackupProduce, Params: agentwire.BackupProduceParams{Producer: agentpolicy.ProducerProxmoxVzdump}}}
	b.runner.notePendingRight(known, agentwire.RightMissing(agentpolicy.CapabilityBackupProduce))
	if names := b.pendingNames(t); !slices.Equal(names, []string{"backup.produce=proxmox-vzdump"}) {
		t.Fatalf("pending %v", names)
	}
	b.runner.notePendingRight(judgedOrder{}, agentwire.RightMissing(agentpolicy.CapabilityResticTarget))
	pending, err := ReadPendingRightsAsRoot(b.opts)
	if err != nil || len(pending.NeedsValue) != 1 || pending.NeedsValue[0].Name != agentpolicy.CapabilityResticTarget {
		t.Fatalf("needs value %+v %v", pending, err)
	}
	if got := missingValueOf(judgedOrder{Order: agentwire.Order{Params: agentwire.BackupProduceParams{Producer: "rm-rf"}}}, agentpolicy.CapabilityBackupProduce); got != "" {
		t.Fatalf("an unknown producer was noted: %q", got)
	}
}

// Le fichier est écrit par le compte de l'agent : root n'y lit qu'un droit
// connu, d'une valeur bien formée. Ce que l'agent n'a pas refusé ne se pose
// jamais.
func TestR_A3_15_E03_07_AnUnknownOrHostileEntryIsNeverGranted(t *testing.T) {
	b := pendingBench(t)
	now := b.clock.now
	hostile := []PendingRight{
		{Name: "docker.deploy; curl x | sh", RefusedAt: now},
		{Name: agentpolicy.CapabilityFilesWrite, Value: "/srv; curl x | sh", RefusedAt: now},
		{Name: "root", RefusedAt: now},
	}
	if err := b.runner.updatePendingRights(func(rights []PendingRight) []PendingRight { return append(rights, hostile...) }); err != nil {
		t.Fatal(err)
	}
	pending, err := ReadPendingRightsAsRoot(b.opts)
	if err != nil || len(pending.Grantable) != 0 || len(pending.NeedsValue) != 0 {
		t.Fatalf("pending %+v %v, want nothing", pending, err)
	}
	if _, err := ReadPendingRightsAsRoot(PolicyOptions{StateDir: b.opts.StateDir, StatePath: b.opts.StatePath, EUID: 1000}); err == nil {
		t.Fatal("a non-root account read the list")
	}
}
