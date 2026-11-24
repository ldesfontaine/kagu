package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// La clé du serveur dans la politique (fiche A3, R-A3-14, N-M2) : root la
// remplace par « trust set », ou garde l'ancienne un temps borné par « trust
// add … -keep-old ». Aucun ordre ne la change (R-A3-9).

// legacyPolicyPlace rend un dossier de politique qui n'existe pas encore,
// sous un parent en 0755 au compte du test : une machine d'avant la
// politique, que « policy migrate » fera passer.
func legacyPolicyPlace(t *testing.T) PolicyPlace {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	return PolicyPlace{Dir: filepath.Join(parent, "policy"), Owner: fsx.Owner{UID: os.Getuid(), GID: os.Getgid()}}
}

// bootID est le démarrage des bancs : l'horloge monotone du banc avance avec
// l'heure, sauf quand un test la fait diverger.
const bootID = "9a6c1d2e-0b7f-4e3a-8c5d-1f2e3a4b5c6d"

// benchClock est l'horloge d'un banc : l'heure affichée et le temps écoulé
// depuis le démarrage, que le test avance ou recule séparément.
type benchClock struct {
	now    time.Time
	uptime time.Duration
}

func (c *benchClock) read() agentpolicy.Clock {
	return agentpolicy.Clock{Now: c.now, Boot: bootID, Uptime: c.uptime}
}

// advance fait passer le temps : l'heure et l'horloge monotone ensemble.
func (c *benchClock) advance(duration time.Duration) {
	c.now, c.uptime = c.now.Add(duration), c.uptime+duration
}

// migratedBench est un banc d'ordres passé à la politique par « policy
// migrate », comme une machine d'avant la v2 : le runner lit la politique,
// root la change par opts, et les deux partagent clock.
type migratedBench struct {
	*orderBench
	opts  PolicyOptions
	clock *benchClock
}

func migrate(t *testing.T, b *orderBench) *migratedBench {
	t.Helper()
	if _, err := UpdateIdentity(b.stateDir, nil, func(identity *Identity) error {
		identity.PolicyFormat = agentpolicy.FormatVersion
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	clock := &benchClock{now: orderNow, uptime: time.Hour}
	opts := PolicyOptions{StateDir: b.stateDir, StatePath: b.stateDir.Name(), Place: legacyPolicyPlace(t), EUID: 0, Clock: clock.read}
	if _, err := MigratePolicy(opts, accept); err != nil {
		t.Fatal(err)
	}
	b.runner.policyPlace = opts.Place
	b.runner.now = func() time.Time { return clock.now }
	b.runner.monotonic = func() (string, time.Duration) { return bootID, clock.uptime }
	b.runner.identity, _ = LoadIdentity(b.stateDir)
	return &migratedBench{orderBench: b, opts: opts, clock: clock}
}

// trustKey joue « agent trust <verb> server-key <clé> », accepté.
func (b *migratedBench) trustKey(t *testing.T, verb string, key ed25519.PublicKey, keepOld time.Duration) PolicyChange {
	t.Helper()
	change, err := Trust(b.opts, TrustRequest{Verb: verb, Kind: agentpolicy.TrustServerKey, Value: base64.StdEncoding.EncodeToString(key), KeepOld: keepOld}, accept)
	if err != nil {
		t.Fatal(err)
	}
	return change
}

// pingAt envoie un ping de rang seq, valable une minute à l'heure du banc.
func (b *migratedBench) pingAt(t *testing.T, seq int64, signer ed25519.PrivateKey) agentwire.ActionResult {
	t.Helper()
	body := order(seq)
	body.NotAfter = b.clock.now.Add(time.Minute).Unix()
	return b.send(t, body, signer)
}

func newServerKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

// R-A3-14 et N-M2 : après « trust set server-key <neuve> », un ordre signé par
// l'ancienne est refusé bad_signature, à l'ordre suivant, sans redémarrage ;
// la neuve signe, et c'est elle que l'agent redit au serveur.
func TestR_A3_14_TrustSetReplacesTheKey(t *testing.T) {
	b := migrate(t, newOrderBench(t))
	if result := b.pingAt(t, 1, b.private); result.State != agentwire.ActionSucceeded {
		t.Fatalf("the migrated key no longer signs: %+v", result)
	}
	newPublic, newPrivate := newServerKey(t)
	change := b.trustKey(t, TrustSet, newPublic, 0)
	if len(change.After.ServerKeys) != 1 || !newPublic.Equal(ed25519.PublicKey(change.After.ServerKeys[0].Key)) {
		t.Fatalf("after set: %+v", change.After.ServerKeys)
	}
	if result := b.pingAt(t, 2, b.private); result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonBadSignature {
		t.Fatalf("the old key still signs: %+v", result)
	}
	if result := b.pingAt(t, 3, newPrivate); result.State != agentwire.ActionSucceeded {
		t.Fatalf("the new key does not sign: %+v", result)
	}
	if accepted := b.runner.currentPolicy().AcceptedServerKey(); !newPublic.Equal(ed25519.PublicKey(accepted)) {
		t.Fatalf("the agent reports %x", accepted)
	}
}

// R-DROIT-9 : remplacer la clé laisse tomber l'ancienne, même gardée un temps
// par un -keep-old encore en cours : « set » ne laisse qu'une clé.
func TestR_DROIT_9_ReplacingTheKeyDropsTheOldOne(t *testing.T) {
	b := migrate(t, newOrderBench(t))
	middle, middlePrivate := newServerKey(t)
	b.trustKey(t, TrustAdd, middle, time.Hour)
	last, lastPrivate := newServerKey(t)
	change := b.trustKey(t, TrustSet, last, 0)
	if len(change.After.ServerKeys) != 1 {
		t.Fatalf("set kept %d keys", len(change.After.ServerKeys))
	}
	for seq, signer := range []ed25519.PrivateKey{b.private, middlePrivate} {
		if result := b.pingAt(t, int64(seq+1), signer); result.Reason != agentwire.ReasonBadSignature {
			t.Fatalf("a replaced key still signs: %+v", result)
		}
	}
	if result := b.pingAt(t, 3, lastPrivate); result.State != agentwire.ActionSucceeded {
		t.Fatalf("the last key does not sign: %+v", result)
	}
}

// R-A3-14 : « add server-key » sans -keep-old est refusé, sans rien écrire :
// garder deux clés sans échéance est la faille N-M2. La durée va de 5 min à
// 7 jours ; « set » ne prend pas de -keep-old.
func TestR_A3_14_AddServerKeyWithoutKeepOldIsRefused(t *testing.T) {
	b := migrate(t, newOrderBench(t))
	newPublic, _ := newServerKey(t)
	value := base64.StdEncoding.EncodeToString(newPublic)
	before, err := os.ReadFile(filepath.Join(b.opts.Place.Dir, policyFile))
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string]struct {
		request TrustRequest
		want    error
	}{
		"add without keep-old": {TrustRequest{Verb: TrustAdd, Kind: agentpolicy.TrustServerKey, Value: value}, ErrKeepOldRequired},
		"keep-old too short":   {TrustRequest{Verb: TrustAdd, Kind: agentpolicy.TrustServerKey, Value: value, KeepOld: 4 * time.Minute}, agentpolicy.ErrDurationOutOfBounds},
		"keep-old too long":    {TrustRequest{Verb: TrustAdd, Kind: agentpolicy.TrustServerKey, Value: value, KeepOld: 7*24*time.Hour + time.Second}, agentpolicy.ErrDurationOutOfBounds},
		"set with keep-old":    {TrustRequest{Verb: TrustSet, Kind: agentpolicy.TrustServerKey, Value: value, KeepOld: time.Hour}, ErrKeepOldServerKeyOnly},
		"keep-old on anchor":   {TrustRequest{Verb: TrustAdd, Kind: anchor.BackupGuest, Value: "101", KeepOld: time.Hour}, ErrKeepOldServerKeyOnly},
		"remove the key":       {TrustRequest{Verb: TrustRemove, Kind: agentpolicy.TrustServerKey, Value: value}, ErrTrustUnknownVerb},
		"set an anchor":        {TrustRequest{Verb: TrustSet, Kind: anchor.BackupGuest, Value: "101"}, ErrTrustUnknownVerb},
		"not a key":            {TrustRequest{Verb: TrustSet, Kind: agentpolicy.TrustServerKey, Value: "c2hvcnQ="}, agentpolicy.ErrServerKeyInvalid},
		"key already accepted": {TrustRequest{Verb: TrustAdd, Kind: agentpolicy.TrustServerKey, Value: base64.StdEncoding.EncodeToString(b.private.Public().(ed25519.PublicKey)), KeepOld: time.Hour}, agentpolicy.ErrServerKeyAlreadyAccepted},
	}
	for name, c := range refused {
		if _, err := Trust(b.opts, c.request, func(PolicyChange) error { t.Fatalf("%s: asked", name); return nil }); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if after, _ := os.ReadFile(filepath.Join(b.opts.Place.Dir, policyFile)); string(after) != string(before) {
		t.Fatalf("a refused trust wrote the policy:\n%s", after)
	}
}

// N-M2 : après « trust add server-key <neuve> -keep-old 5m » (la durée la plus
// courte), un ordre signé par l'ancienne passe, puis est refusé cinq minutes
// plus tard, sans serveur : l'agent la retire seul, et ne redit qu'une clé.
func TestR_A3_14_KeepOldLapsesAfterItsDuration(t *testing.T) {
	b := migrate(t, newOrderBench(t))
	newPublic, newPrivate := newServerKey(t)
	change := b.trustKey(t, TrustAdd, newPublic, agentpolicy.MinDuration)
	kept := change.After.ServerKeys[1]
	if !kept.Until.Equal(orderNow.Add(5*time.Minute)) || kept.Granted.Boot != bootID || kept.Granted.Uptime != time.Hour {
		t.Fatalf("kept key %+v", kept)
	}
	if result := b.pingAt(t, 1, b.private); result.State != agentwire.ActionSucceeded {
		t.Fatalf("the kept key does not sign: %+v", result)
	}
	if result := b.pingAt(t, 2, newPrivate); result.State != agentwire.ActionSucceeded {
		t.Fatalf("the new key does not sign: %+v", result)
	}
	if keys := b.runner.currentPolicy().ServerKeys; len(keys) != 2 {
		t.Fatalf("two keys during the keep-old, got %d", len(keys))
	}
	b.clock.advance(5*time.Minute - time.Second)
	if result := b.pingAt(t, 3, b.private); result.State != agentwire.ActionSucceeded {
		t.Fatalf("the kept key lapsed early: %+v", result)
	}
	b.clock.advance(time.Second)
	if result := b.pingAt(t, 4, b.private); result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonBadSignature {
		t.Fatalf("the kept key still signs after its five minutes: %+v", result)
	}
	if result := b.pingAt(t, 5, newPrivate); result.State != agentwire.ActionSucceeded {
		t.Fatalf("the new key: %+v", result)
	}
	if keys := b.runner.currentPolicy().ServerKeys; len(keys) != 1 || !newPublic.Equal(ed25519.PublicKey(keys[0])) {
		t.Fatalf("the agent reports %d keys", len(keys))
	}
}

// QA-12 : la clé gardée tombe aussi quand l'horloge affichée recule (NTP n'est
// pas authentifié) : cinq minutes d'horloge monotone suffisent.
func TestR_A3_14_KeepOldLapsesWhenTheClockGoesBack(t *testing.T) {
	b := migrate(t, newOrderBench(t))
	newPublic, _ := newServerKey(t)
	b.trustKey(t, TrustAdd, newPublic, agentpolicy.MinDuration)
	b.clock.uptime += 5 * time.Minute
	b.clock.now = b.clock.now.Add(-time.Hour)
	if result := b.pingAt(t, 1, b.private); result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonBadSignature {
		t.Fatalf("a clock moved back kept the old key alive: %+v", result)
	}
}

// R-A3-9 : l'ordre agent.server_key n'existe plus. Signé par la clé acceptée,
// il est refusé unknown_kind et la clé ne change ni dans la politique ni dans
// identity.json.
func TestR_A3_9_ServerKeyOrderIsUnknownKind(t *testing.T) {
	for name, bench := range map[string]func(t *testing.T) *orderBench{
		"identity": newOrderBench,
		"policy":   func(t *testing.T) *orderBench { return migrate(t, newOrderBench(t)).orderBench },
	} {
		b := bench(t)
		newPublic, newPrivate := newServerKey(t)
		before := b.runner.currentPolicy().AcceptedServerKey()
		body := order(1)
		body.Kind = agentwire.Kind("agent.server_key")
		body.Params = []byte(`{"public_key":"` + base64.StdEncoding.EncodeToString(newPublic) + `"}`)
		if result := b.send(t, body, b.private); result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonUnknownKind {
			t.Fatalf("%s: %+v", name, result)
		}
		if after := b.runner.currentPolicy().AcceptedServerKey(); !slices.Equal(before, after) || len(after) == 0 {
			t.Fatalf("%s: the accepted key changed", name)
		}
		if result := b.send(t, order(2), newPrivate); result.Reason != agentwire.ReasonBadSignature {
			t.Fatalf("%s: the delivered key signs: %+v", name, result)
		}
	}
}

// R-A3-16 : sur une machine installée avec la politique (son dossier existe),
// la politique effacée et identity.json réécrit avec docker.deploy, l'agent
// n'applique que observe : ni les droits, ni les ancres, ni la clé
// d'identity.json.
func TestR_A3_16_AV2MachineNeverReadsIdentityRights(t *testing.T) {
	b := migrate(t, newOrderBench(t))
	if err := os.Remove(filepath.Join(b.opts.Place.Dir, policyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateIdentity(b.stateDir, nil, func(identity *Identity) error {
		identity.Rights = []string{"observe", "docker.deploy"}
		identity.Anchors = map[string][]string{anchor.BackupGuest: {"101"}}
		identity.ServerKey = b.private.Public().(ed25519.PublicKey)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.runner.identity, _ = LoadIdentity(b.stateDir)
	applied := b.runner.currentPolicy()
	if applied.Source != agentpolicy.SourceRefused || agentpolicy.FormatCapabilities(applied.Rights) != agentpolicy.CapabilityObserve ||
		len(applied.ServerKeys) != 0 || len(applied.Anchors) != 0 {
		t.Fatalf("a v2 machine read identity.json: %+v", applied)
	}
	if result := b.pingAt(t, 1, b.private); result.Reason != agentwire.ReasonServerKeyMissing {
		t.Fatalf("an order passed on identity.json: %+v", result)
	}
	// Un dossier sans fichier ne se remplit pas non plus par « agent grant » : la
	// première politique part d'observe seul.
	change, err := GrantRights(b.opts, []agentpolicy.Capability{{Name: agentpolicy.CapabilityProbeLAN}}, accept)
	if err != nil || !change.First || agentpolicy.FormatCapabilities(change.After.Rights) != "observe,probe.lan" || len(change.After.ServerKeys) != 0 {
		t.Fatalf("grant on an empty directory: %+v %v", change, err)
	}
}

// « policy migrate » recopie à l'identique droits, ancres et clé épinglée, puis
// les efface d'identity.json ; il crée le dossier de la politique. Relancé, il
// ne change rien. Avant lui, grant et trust refusent sans rien créer.
func TestMigratePolicy_CopiesRightsAnchorsAndKeyThenErasesThem(t *testing.T) {
	b := newOrderBenchWithRights(t, []string{"observe", "docker.deploy", "files.write=/srv/a:/srv/b"})
	anchors := map[string][]string{anchor.BackupGuest: {"101", "102"}, anchor.ResticTargetCert: {"ab"}}
	b.trust(t, anchors)
	if _, err := UpdateIdentity(b.stateDir, nil, func(identity *Identity) error {
		identity.PolicyFormat = agentpolicy.FormatVersion
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	legacy, err := LoadIdentity(b.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	opts := PolicyOptions{StateDir: b.stateDir, StatePath: b.stateDir.Name(), Place: legacyPolicyPlace(t), EUID: 0}
	if _, err := GrantRights(opts, nil, accept); !errors.Is(err, ErrNotMigrated) {
		t.Fatalf("grant before migrate: %v", err)
	}
	if _, err := Trust(opts, TrustRequest{Verb: TrustAdd, Kind: anchor.BackupGuest, Value: "103"}, accept); !errors.Is(err, ErrNotMigrated) {
		t.Fatalf("trust before migrate: %v", err)
	}
	if _, err := os.Lstat(opts.Place.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused command created the policy directory: %v", err)
	}

	// Refusé à la question, il ne crée rien : la machine reste d'avant la
	// politique, et l'agent lit encore identity.json.
	declined := errors.New("declined")
	if _, err := MigratePolicy(opts, func(PolicyChange) error { return declined }); !errors.Is(err, declined) {
		t.Fatalf("declined migrate: %v", err)
	}
	if _, err := os.Lstat(opts.Place.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a declined migrate created the policy directory: %v", err)
	}

	var shown PolicyChange
	if _, err := MigratePolicy(opts, func(change PolicyChange) error { shown = change; return nil }); err != nil {
		t.Fatal(err)
	}
	if !shown.First || len(shown.Added) != 3 {
		t.Fatalf("every copied right is shown: %+v", shown)
	}
	stored := (&policyBench{opts: opts}).stored(t)
	if agentpolicy.FormatCapabilities(stored.Rights) != agentpolicy.FormatCapabilities(legacy.Capabilities()) || stored.MachineID != orderMachineID ||
		!equalValues(stored.Anchors, anchors) || len(stored.ServerKeys) != 1 || !slices.Equal(stored.ServerKeys[0].Key, legacy.ServerKey) {
		t.Fatalf("the policy is not a copy of identity.json: %+v", stored)
	}
	erased, err := LoadIdentity(b.stateDir)
	if err != nil || erased.Rights != nil || erased.Anchors != nil || erased.ServerKey != nil || erased.MachineID != orderMachineID || erased.PrivateKey == nil && legacy.PrivateKey != nil {
		t.Fatalf("identity.json after migrate: %+v %v", erased, err)
	}
	if info, err := os.Stat(opts.Place.Dir); err != nil || info.Mode().Perm() != policyDirMode {
		t.Fatalf("policy directory: %v %v", info, err)
	}
	again, err := MigratePolicy(opts, func(PolicyChange) error { t.Fatal("asked twice"); return nil })
	if err != nil || again.Changed() {
		t.Fatalf("a second migrate: %+v %v", again, err)
	}
}
