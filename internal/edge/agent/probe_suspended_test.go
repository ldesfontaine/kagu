package agent

import (
	"context"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/domain/alert"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/fact/probe"
	"github.com/ldesfontaine/kagu/internal/kit/testkit"
)

// E03-09 (R-A3-4 inchangée) : root retire probe.lan à un agent qui tourne ; la
// sonde vers le réseau local passe « suspendue », sans alerte, même au seuil
// d'un échec, et l'agent note le droit refusé pour « grant --pending ». root
// le rend : la sonde reprend seule, sans redémarrer l'agent ni toucher à la
// sonde, et le droit sort des droits en attente.
func TestE03_09_RevokeSuspendsTheProbeWithoutAlertAndGrantResumesIt(t *testing.T) {
	target := testkit.AcceptingLoopback(t)
	b := newBench(t)
	alerts := alert.New(b.db, b.logger)
	b.probes.SetAlerter(alerts)
	token, _, err := b.machines.CreateToken(context.Background(), "vps-lan-2", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, b.options(token)) }()
	enrolled := b.waitFor(t, "vps-lan-2", func(s machine.Status) bool { return s.Online })
	cancel()
	<-done

	if err := os.Mkdir(b.policy.Dir, policyDirMode); err != nil {
		t.Fatal(err)
	}
	writePolicyFile(t, b.policy, policyGranting(t, enrolled.ID, "probe.lan"), policyMode)
	definition := probe.Definition{Name: "service local", Kind: probe.KindTCP, Target: target, MachineID: enrolled.ID, FailureThreshold: 1}
	created, err := b.probes.Create(context.Background(), definition)
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

	// root pose la politique et le signale ; un intervalle changé relance la
	// sonde tout de suite, sans remettre son état à zéro.
	setRights := func(rights string, holdsLAN bool, interval time.Duration) {
		t.Helper()
		writePolicyFile(t, b.policy, policyGranting(t, enrolled.ID, rights), policyMode)
		hangups <- syscall.SIGHUP
		b.waitFor(t, "vps-lan-2", func(s machine.Status) bool {
			return s.Online && agentpolicy.HasCapability(s.Agent.Capabilities, agentpolicy.CapabilityProbeLAN) == holdsLAN
		})
		definition.Interval = interval
		if _, err := b.probes.Update(context.Background(), created.ID, definition); err != nil {
			t.Fatal(err)
		}
	}
	setRights("observe", false, 2*time.Minute)
	suspended := b.waitForProbe(t, created.ID, func(found probe.Probe) bool { return found.Status == probe.StatusSuspended })
	if right, ok := suspended.MissingRight(); !ok || right != agentpolicy.CapabilityProbeLAN {
		t.Fatalf("missing right %q %v", right, ok)
	}
	if every := allAlerts(t, alerts); len(every) != 0 {
		t.Fatalf("the suspension opened %d alerts: %+v", len(every), every)
	}
	if !slices.Contains(pendingNames(t, b), agentpolicy.CapabilityProbeLAN) {
		t.Fatal("the agent did not note probe.lan for grant --pending")
	}

	setRights("probe.lan", true, 3*time.Minute)
	b.waitForProbe(t, created.ID, func(found probe.Probe) bool { return found.Status == probe.StatusUp })
	if every := allAlerts(t, alerts); len(every) != 0 {
		t.Fatalf("the resumption opened %d alerts: %+v", len(every), every)
	}
	if slices.Contains(pendingNames(t, b), agentpolicy.CapabilityProbeLAN) {
		t.Fatal("probe.lan is held again and still pending")
	}
}

func allAlerts(t *testing.T, alerts *alert.Engine) []alert.Alert {
	t.Helper()
	every, err := alerts.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	return every
}

// pendingNames lit les droits en attente de l'agent du banc, comme root.
func pendingNames(t *testing.T, b *bench) []string {
	t.Helper()
	return grantablePendingRights(t, PolicyOptions{StateDir: b.stateDir, StatePath: b.stateDir.Name(), Place: b.policy, EUID: 0})
}
