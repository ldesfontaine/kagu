package agent

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/fact/probe"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/testkit"
	"github.com/ldesfontaine/kagu/internal/kit/wait/waittest"
)

// noPolicy : un dossier de politique qui n'existe pas ; les droits viennent
// d'identity.json, comme chez une machine qui n'a jamais connu « agent grant ».
var noPolicy = PolicyPlace{Dir: "/nonexistent/" + policyFile}

// testPolicyPlace rend un dossier de politique vide, en 0755, au compte du
// test : il y joue root.
func testPolicyPlace(t *testing.T) PolicyPlace {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "policy")
	if err := os.Mkdir(dir, policyDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	return PolicyPlace{Dir: dir, Owner: fsx.Owner{UID: os.Getuid(), GID: os.Getgid()}}
}

// writePolicyFile écrit le fichier de la politique tel quel, avec ce mode.
func writePolicyFile(t *testing.T, place PolicyPlace, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(place.Dir, policyFile)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// policyGranting écrit une politique lisible pour la machine m avec ces droits.
func policyGranting(t *testing.T, machineID string, rights string) string {
	t.Helper()
	capabilities, err := agentpolicy.ParseCapabilities(rights)
	if err != nil {
		t.Fatal(err)
	}
	content, err := agentpolicy.Encode(agentpolicy.Document{MachineID: machineID, Rights: capabilities})
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func identityWith(t *testing.T, rights ...string) Identity {
	t.Helper()
	return Identity{MachineID: "m", Rights: rights}
}

// Une politique lisible et bien gardée fait foi : ses droits, sa machine, son
// empreinte ; sans elle, les droits d'identity.json (source identity).
func TestReadPolicy_ThePolicyWinsOverTheIdentity(t *testing.T) {
	place := testPolicyPlace(t)
	identity := identityWith(t, "docker.deploy")
	applied, err := readPolicy(place, identity)
	if err != nil || applied.Source != agentpolicy.SourceIdentity || !agentpolicy.HasCapability(applied.Rights, agentpolicy.CapabilityDockerDeploy) {
		t.Fatalf("without a file: %+v %v", applied, err)
	}
	content := policyGranting(t, "m-policy", "probe.lan")
	writePolicyFile(t, place, content, policyMode)
	applied, err = readPolicy(place, identity)
	if err != nil || applied.Source != agentpolicy.SourcePolicy || applied.MachineID != "m-policy" || applied.Digest != agentpolicy.Digest([]byte(content)) {
		t.Fatalf("with a file: %+v %v", applied, err)
	}
	if agentpolicy.FormatCapabilities(applied.Rights) != "observe,probe.lan" {
		t.Fatalf("rights %s", agentpolicy.FormatCapabilities(applied.Rights))
	}
	if applied, _ := readPolicy(noPolicy, identity); applied.Source != agentpolicy.SourceIdentity {
		t.Fatalf("absent directory: %+v", applied)
	}
}

// R-A3-6 : une politique illisible, qui n'est pas à root, ou qu'un autre compte
// peut écrire ne laisse que observe, et le rapporte (source refused) ; rien
// ne s'élargit, ni vers les droits d'identity.json ni vers ceux d'avant.
func TestR_A3_6_AWorldWritablePolicyLeavesObserveOnly(t *testing.T) {
	identity := identityWith(t, "docker.deploy", "probe.lan")
	granting := policyGranting(t, "m", "docker.deploy,probe.lan")
	refusedOnly := func(t *testing.T, place PolicyPlace) {
		t.Helper()
		applied, err := readPolicy(place, identity)
		if err == nil || applied.Source != agentpolicy.SourceRefused || agentpolicy.FormatCapabilities(applied.Rights) != agentpolicy.CapabilityObserve || applied.Digest != "" {
			t.Fatalf("%+v %v", applied, err)
		}
	}
	t.Run("0666", func(t *testing.T) {
		place := testPolicyPlace(t)
		writePolicyFile(t, place, granting, 0o666)
		refusedOnly(t, place)
	})
	t.Run("group writable", func(t *testing.T) {
		place := testPolicyPlace(t)
		writePolicyFile(t, place, granting, 0o660)
		refusedOnly(t, place)
	})
	t.Run("another owner", func(t *testing.T) {
		place := testPolicyPlace(t)
		writePolicyFile(t, place, granting, policyMode)
		// Le fichier est au compte du test ; la politique attend un autre compte.
		place.Owner.UID++
		refusedOnly(t, place)
	})
	t.Run("a directory others can write", func(t *testing.T) {
		place := testPolicyPlace(t)
		writePolicyFile(t, place, granting, policyMode)
		if err := os.Chmod(place.Dir, 0o777); err != nil {
			t.Fatal(err)
		}
		refusedOnly(t, place)
	})
	t.Run("a link", func(t *testing.T) {
		place := testPolicyPlace(t)
		target := filepath.Join(t.TempDir(), "elsewhere.toml")
		if err := os.WriteFile(target, []byte(granting), policyMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(place.Dir, policyFile)); err != nil {
			t.Fatal(err)
		}
		refusedOnly(t, place)
	})
	t.Run("unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root lit un fichier en 0000")
		}
		place := testPolicyPlace(t)
		writePolicyFile(t, place, granting, 0o000)
		refusedOnly(t, place)
	})
	for name, content := range map[string]string{
		"not toml":       "version = [",
		"unknown key":    granting + "\nextra = 1\n",
		"other version":  strings.Replace(granting, "version = 1", "version = 2", 1),
		"unknown right":  granting + "\n[[right]]\nname = 'everything'\n",
		"right twice":    granting + "\n[[right]]\nname = 'probe.lan'\n",
		"no machine":     strings.Replace(granting, "machine_id = 'm'", "", 1),
		"bad path value": granting + "\n[[right]]\nname = 'files.write'\nvalue = 'relative'\n",
	} {
		t.Run(name, func(t *testing.T) {
			place := testPolicyPlace(t)
			writePolicyFile(t, place, content, policyMode)
			refusedOnly(t, place)
		})
	}
	t.Run("nothing widens on a later error", func(t *testing.T) {
		place := testPolicyPlace(t)
		writePolicyFile(t, place, granting, policyMode)
		runner := newOrderRunner(nil, identity, place, "v0.0.1", "", newActionResults(), slog.New(slog.DiscardHandler))
		if !agentpolicy.HasCapability(runner.rights(), agentpolicy.CapabilityDockerDeploy) {
			t.Fatalf("rights %v", runner.rights())
		}
		if err := os.Chmod(filepath.Join(place.Dir, policyFile), 0o666); err != nil {
			t.Fatal(err)
		}
		applied, _ := runner.currentPolicy()
		if applied.Source != agentpolicy.SourceRefused || agentpolicy.FormatCapabilities(runner.rights()) != agentpolicy.CapabilityObserve {
			t.Fatalf("%+v", applied)
		}
		select {
		case <-runner.policyChanged:
		default:
			t.Fatal("the change was not signalled: the stream would keep reporting the old rights")
		}
	})
}

// Un état mal gardé n'a que observe, même quand la politique est bonne.
func TestReadPolicy_ANarrowedStateKeepsObserveOnly(t *testing.T) {
	place := testPolicyPlace(t)
	writePolicyFile(t, place, policyGranting(t, "m", "docker.deploy"), policyMode)
	identity := identityWith(t)
	identity.narrowed = true
	applied, err := readPolicy(place, identity)
	if err != nil || applied.Source != agentpolicy.SourcePolicy || agentpolicy.FormatCapabilities(applied.Rights) != agentpolicy.CapabilityObserve {
		t.Fatalf("%+v %v", applied, err)
	}
}

// La machine que la politique nomme est celle que le juge attend : un ordre
// pour la machine de l'identité est refusé si root a écrit une autre machine.
func TestOrderRunner_JudgesWithTheMachineOfThePolicy(t *testing.T) {
	place := testPolicyPlace(t)
	writePolicyFile(t, place, policyGranting(t, "m-other", "observe"), policyMode)
	runner := newOrderRunner(nil, identityWith(t), place, "v0.0.1", "", newActionResults(), slog.New(slog.DiscardHandler))
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if got := runner.policy().MachineID; got != "m-other" {
		t.Fatalf("machine %q", got)
	}
}

// R-A3-4 : la politique se relit à SIGHUP et toutes les quinze secondes, flux
// coupé ou non ; probe.lan suit sans redémarrage. Le banc relance une vraie
// boucle d'agent contre un vrai serveur : la sonde vers la boucle locale passe
// avec le droit, tombe sur sa raison quand root le retire, et l'agent rapporte
// le changement en rouvrant son flux.
func TestR_A3_4_ProbeLANFollowsThePolicyWithoutRestart(t *testing.T) {
	target := testkit.AcceptingLoopback(t)
	b := newBench(t)
	token, _, err := b.machines.CreateToken(context.Background(), "vps-policy-1", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}
	enrolling := b.options(token)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, enrolling) }()
	enrolled := b.waitFor(t, "vps-policy-1", func(s machine.Status) bool { return s.Online })
	cancel()
	<-done

	writePolicyFile(t, b.policy, policyGranting(t, enrolled.ID, "probe.lan"), policyMode)
	created, err := b.probes.Create(context.Background(), probe.Definition{
		Name: "service local", Kind: probe.KindTCP, Target: target, MachineID: enrolled.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	hangups := make(chan os.Signal, 1)
	running := b.options("")
	running.Hangups = hangups
	ctx, cancel = context.WithCancel(context.Background())
	defer func() {
		cancel()
		<-done
	}()
	go func() { done <- Run(ctx, running) }()
	b.waitForProbe(t, created.ID, func(found probe.Probe) bool { return found.Status == probe.StatusUp })

	writePolicyFile(t, b.policy, policyGranting(t, enrolled.ID, "observe"), policyMode)
	hangups <- syscall.SIGHUP
	b.waitFor(t, "vps-policy-1", func(s machine.Status) bool {
		return s.Online && s.Agent.PolicySource == agentpolicy.SourcePolicy && !agentpolicy.HasCapability(s.Agent.Capabilities, agentpolicy.CapabilityProbeLAN)
	})
	// La sonde changée repart tout de suite, sur le même agent.
	slower := probe.Definition{Name: "service local", Kind: probe.KindTCP, Target: target, MachineID: enrolled.ID, Interval: 2 * time.Minute}
	if _, err := b.probes.Update(context.Background(), created.ID, slower); err != nil {
		t.Fatal(err)
	}
	b.waitForProbe(t, created.ID, func(found probe.Probe) bool { return found.LastReason == probe.ReasonLAN })
}

// Sans signal, la relecture toutes les quinze secondes suffit : ici, à
// l'intervalle du banc.
func TestWatchPolicy_RereadsOnItsInterval(t *testing.T) {
	place := testPolicyPlace(t)
	writePolicyFile(t, place, policyGranting(t, "m", "probe.lan"), policyMode)
	runner := newOrderRunner(nil, identityWith(t), place, "v0.0.1", "", newActionResults(), slog.New(slog.DiscardHandler))
	allowsLAN := runner.allows(agentpolicy.CapabilityProbeLAN)
	if !allowsLAN() {
		t.Fatal("probe.lan not applied")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.watchPolicy(ctx, nil, 10*time.Millisecond)
	writePolicyFile(t, place, policyGranting(t, "m", "observe"), policyMode)
	waittest.Until(t, "probe.lan to close", func() bool { return !allowsLAN() })
}
