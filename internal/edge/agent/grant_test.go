package agent

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
)

// policyBench est un agent enrôlé, au binaire qui lit la politique, et un
// dossier de politique vide ; le test y joue root (EUID 0) sans l'être.
type policyBench struct {
	opts PolicyOptions
}

func newPolicyBench(t *testing.T, rights ...string) *policyBench {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stateDir.Close() })
	identity := Identity{MachineID: "m-grant", Rights: rights, PolicyFormat: agentpolicy.FormatVersion}
	if err := SaveIdentity(stateDir, identity); err != nil {
		t.Fatal(err)
	}
	place := testPolicyPlace(t)
	return &policyBench{opts: PolicyOptions{StateDir: stateDir, StatePath: dir, Place: place, EUID: 0}}
}

// accept est la réponse « o » à la question.
func accept(PolicyChange) error { return nil }

func (b *policyBench) grant(t *testing.T, text string) PolicyChange {
	t.Helper()
	granted, err := agentpolicy.ParseCapabilities(text)
	if err != nil {
		t.Fatal(err)
	}
	change, err := GrantRights(b.opts, granted, accept)
	if err != nil {
		t.Fatal(err)
	}
	return change
}

func (b *policyBench) stored(t *testing.T) agentpolicy.Document {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(b.opts.Place.Dir, policyFile))
	if err != nil {
		t.Fatal(err)
	}
	document, err := agentpolicy.Decode(content)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// R-A3-1 : la politique écrite est à root (le compte de place.Owner, root sur
// une machine), lisible du groupe de l'agent et de lui seul, inscriptible par
// personne d'autre que root ; son dossier est à root, en 0755. Le compte de
// l'agent ne peut donc ni l'écrire, ni la remplacer, ni l'effacer.
func TestR_A3_1_TheAgentAccountCannotWriteThePolicy(t *testing.T) {
	b := newPolicyBench(t)
	if err := os.Remove(b.opts.Place.Dir); err != nil {
		t.Fatal(err)
	}
	if _, err := MigratePolicy(b.opts, accept); err != nil {
		t.Fatal(err)
	}
	b.grant(t, "probe.lan")
	info, err := os.Lstat(filepath.Join(b.opts.Place.Dir, policyFile))
	if err != nil {
		t.Fatal(err)
	}
	raw := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 {
		t.Fatalf("policy mode %s, want -rw-r-----", info.Mode())
	}
	if int(raw.Uid) != b.opts.Place.Owner.UID || int(raw.Gid) != b.opts.Place.Owner.GID {
		t.Fatalf("policy owned by %d:%d, want %+v", raw.Uid, raw.Gid, b.opts.Place.Owner)
	}
	dirInfo, err := os.Stat(b.opts.Place.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o755 {
		t.Fatalf("policy dir mode %s, want drwxr-xr-x", dirInfo.Mode())
	}
	// Sur une machine, le fichier est à root et au groupe du compte de l'agent,
	// qui possède son état : jamais à ce compte.
	system, err := SystemPolicyPlace(b.opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	stateInfo, err := os.Stat(b.opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if system.Owner.UID != 0 || system.Owner.GID != int(stateInfo.Sys().(*syscall.Stat_t).Gid) || system.Dir != "/etc/opencloud-agent" {
		t.Fatalf("system place %+v", system)
	}
}

// R-A3-3 : deux gestes en même temps se suivent sous le verrou : chacun relit
// ce que l'autre a écrit, aucun droit ne se perd, et le fichier reste entier.
func TestR_A3_3_TwoGrantsAreSerialized(t *testing.T) {
	rights := []string{
		agentpolicy.CapabilityProbeLAN, agentpolicy.CapabilityObserveEnv, agentpolicy.CapabilityAgentUpdate,
		agentpolicy.CapabilityDockerDeploy, agentpolicy.CapabilityDockerUpdate, agentpolicy.CapabilityProxmoxPower,
		agentpolicy.CapabilityProxmoxSnapshot, agentpolicy.CapabilityResticProduce, agentpolicy.CapabilityResticDocker,
		agentpolicy.CapabilityResticVerify, agentpolicy.CapabilityResticBrowse, agentpolicy.CapabilityResticRestore,
	}
	for round := range 3 {
		b := newPolicyBench(t)
		var wg sync.WaitGroup
		failures := make(chan error, len(rights))
		for _, right := range rights {
			wg.Go(func() {
				if _, err := GrantRights(b.opts, []agentpolicy.Capability{{Name: right}}, accept); err != nil {
					failures <- err
				}
			})
		}
		wg.Wait()
		close(failures)
		for err := range failures {
			t.Fatalf("round %d: %v", round, err)
		}
		stored := b.stored(t)
		for _, right := range rights {
			if !agentpolicy.HasCapability(stored.Rights, right) {
				t.Fatalf("round %d: %s lost, stored %s", round, right, agentpolicy.FormatCapabilities(stored.Rights))
			}
		}
	}
}

// R-DROIT-1 : seul root écrit la politique ; un autre compte est refusé avant
// toute lecture, et rien n'est créé, pas même le dossier.
func TestR_DROIT_1_OnlyRootWritesThePolicy(t *testing.T) {
	b := newPolicyBench(t)
	if err := os.Remove(b.opts.Place.Dir); err != nil {
		t.Fatal(err)
	}
	b.opts.EUID = 1000
	asked := false
	ask := func(PolicyChange) error {
		asked = true
		return nil
	}
	if _, err := GrantRights(b.opts, []agentpolicy.Capability{{Name: agentpolicy.CapabilityDockerDeploy}}, ask); !errors.Is(err, ErrTrustNotRoot) {
		t.Fatalf("grant: %v", err)
	}
	if _, err := RevokeRights(b.opts, []string{agentpolicy.CapabilityDockerDeploy}, ask); !errors.Is(err, ErrTrustNotRoot) {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := ReadPolicyAsRoot(b.opts); !errors.Is(err, ErrTrustNotRoot) {
		t.Fatalf("rights: %v", err)
	}
	if _, err := os.Stat(b.opts.Place.Dir); !errors.Is(err, fs.ErrNotExist) || asked {
		t.Fatalf("a refused command touched the policy: %v, asked %v", err, asked)
	}
}

// La première politique d'un dossier sans fichier part d'observe seul : un
// droit que le compte de l'agent aurait glissé dans son identité n'y entre
// pas (R-A3-16). La question le dit première.
func TestGrantRights_TheFirstPolicyStartsFromObserveOnly(t *testing.T) {
	b := newPolicyBench(t, "docker.deploy")
	var shown PolicyChange
	change, err := GrantRights(b.opts, []agentpolicy.Capability{{Name: agentpolicy.CapabilityProbeLAN}}, func(change PolicyChange) error {
		shown = change
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !shown.First || len(shown.Removed) != 0 || len(shown.Added) != 1 || shown.Added[0] != "probe.lan" {
		t.Fatalf("shown %+v", shown)
	}
	if change.After.MachineID != "m-grant" || agentpolicy.FormatCapabilities(b.stored(t).Rights) != "observe,probe.lan" {
		t.Fatalf("stored %+v", b.stored(t))
	}
	// La suivante ne montre que ce qu'elle change.
	revoked, err := RevokeRights(b.opts, []string{agentpolicy.CapabilityProbeLAN}, func(change PolicyChange) error {
		shown = change
		return nil
	})
	if err != nil || shown.First || len(shown.Added) != 0 || len(shown.Removed) != 1 || shown.Removed[0] != "probe.lan" || !revoked.Changed() {
		t.Fatalf("revoke %+v %v", shown, err)
	}
}

// Refusée, la question laisse la politique telle quelle ; un geste qui ne
// change rien ne pose pas de question et n'écrit rien.
func TestGrantRights_NothingIsWrittenWithoutConsent(t *testing.T) {
	b := newPolicyBench(t)
	declined := errors.New("declined")
	if _, err := GrantRights(b.opts, []agentpolicy.Capability{{Name: agentpolicy.CapabilityProbeLAN}}, func(PolicyChange) error { return declined }); !errors.Is(err, declined) {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.opts.Place.Dir, policyFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("declined grant wrote: %v", err)
	}
	b.grant(t, "probe.lan")
	change, err := GrantRights(b.opts, []agentpolicy.Capability{{Name: agentpolicy.CapabilityProbeLAN}}, func(PolicyChange) error {
		t.Fatal("asked about nothing")
		return nil
	})
	if err != nil || change.Changed() {
		t.Fatalf("%+v %v", change, err)
	}
}

// Sur une politique qu'on ne lit pas, ou mal gardée, on n'écrit rien : root
// la corrige ou l'efface d'abord. Sur un agent qui ne lit pas encore la
// politique non plus : le retrait resterait sans effet.
func TestGrantRights_RefusesWhatItCannotTrust(t *testing.T) {
	b := newPolicyBench(t)
	writePolicyFile(t, b.opts.Place, "version = [", policyMode)
	if _, err := GrantRights(b.opts, nil, accept); !errors.Is(err, agentpolicy.ErrUnreadable) {
		t.Fatalf("unreadable: %v", err)
	}
	writePolicyFile(t, b.opts.Place, policyGranting(t, "m-grant", "observe"), 0o666)
	var unsafe *UnsafeStateError
	if _, err := RevokeRights(b.opts, []string{agentpolicy.CapabilityProbeLAN}, accept); !errors.As(err, &unsafe) {
		t.Fatalf("world writable: %v", err)
	}
	old := newPolicyBench(t)
	if _, err := UpdateIdentity(old.opts.StateDir, nil, func(identity *Identity) error {
		identity.PolicyFormat = 0
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := GrantRights(old.opts, nil, accept); !errors.Is(err, ErrAgentTooOld) {
		t.Fatalf("old agent: %v", err)
	}
	if _, err := RevokeRights(b.opts, []string{agentpolicy.CapabilityObserve}, accept); err == nil {
		t.Fatal("observe revoked")
	}
}

// Le binaire qui lit la politique le note dans l'identité au démarrage, sans
// toucher aux ancres posées par root : « agent grant » le lit avant d'écrire.
func TestNotePolicyFormat_TheAgentSaysItReadsThePolicy(t *testing.T) {
	b := newPolicyBench(t)
	if _, err := UpdateIdentity(b.opts.StateDir, nil, func(identity *Identity) error {
		identity.PolicyFormat = 0
		identity.Anchors = map[string][]string{"backup.guest": {"101"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stale, err := LoadIdentity(b.opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	stale.Anchors = nil
	noted := notePolicyFormat(b.opts.StateDir, stale, slog.New(slog.DiscardHandler))
	stored, err := LoadIdentity(b.opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if noted.PolicyFormat != agentpolicy.FormatVersion || stored.PolicyFormat != agentpolicy.FormatVersion || len(stored.Anchors["backup.guest"]) != 1 {
		t.Fatalf("noted %d, stored %+v", noted.PolicyFormat, stored)
	}
}
