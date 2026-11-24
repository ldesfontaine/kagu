package agent

import (
	"context"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/fact/probe"
	"github.com/ldesfontaine/kagu/internal/kit/testkit"
	"github.com/ldesfontaine/kagu/internal/kit/wait/waittest"
)

// probeOnLoopback enrôle un agent avec ces droits, lui donne une sonde TCP
// vers un écouteur de la boucle locale, le relance (le jeu de sondes arrive à
// l'ouverture du flux) et rend la sonde une fois son premier essai rapporté.
// narrowed relance l'agent sur un état jugé mal gardé : il n'a plus qu'observe.
func probeOnLoopback(t *testing.T, rights string, narrowed bool) probe.Probe {
	t.Helper()
	target := testkit.AcceptingLoopback(t)
	b := newBench(t)
	granted, err := agentpolicy.ParseCapabilities(rights)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := b.machines.CreateToken(context.Background(), "vps-lan-1", machine.RoleGeneric, granted)
	if err != nil {
		t.Fatal(err)
	}
	enrolling := b.options(token)
	enrolling.Rights = granted
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, enrolling) }()
	enrolled := b.waitFor(t, "vps-lan-1", func(s machine.Status) bool { return s.Online })
	cancel()
	<-done
	b.waitFor(t, "vps-lan-1", func(s machine.Status) bool { return !s.Online })

	created, err := b.probes.Create(context.Background(), probe.Definition{
		Name: "service local", Kind: probe.KindTCP, Target: target, MachineID: enrolled.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	restarted := b.options("")
	if narrowed {
		restarted.UnsafeState = &UnsafeStateError{Path: "/var/lib/opencloud", UID: 999, Mode: dir0755}
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer func() {
		cancel()
		<-done
	}()
	go func() { done <- Run(ctx, restarted) }()
	return b.waitForProbe(t, created.ID, nil)
}

// waitForProbe attend que la sonde ait rapporté un essai, et, quand want est
// dit, un essai qui lui convient.
func (b *bench) waitForProbe(t *testing.T, id string, want func(probe.Probe) bool) probe.Probe {
	t.Helper()
	var checked probe.Probe
	waittest.Until(t, "the probe to report a result", func() bool {
		found, err := b.db.GetProbe(context.Background(), id)
		if err != nil || found.LastCheckedAt.IsZero() || (want != nil && !want(found)) {
			return false
		}
		checked = found
		return true
	})
	return checked
}

// Le réseau local ne s'ouvre aux sondes que par probe.lan : sans lui, la
// sonde vers la boucle locale tombe avec sa raison ; avec lui, elle répond.
// Un agent enrôlé avant le droit (observe seul) est dans le premier cas, et
// un état mal gardé (observe seul aussi) ferme le réseau local même quand le
// fichier porte le droit.
func TestRun_ProbesFollowTheLANRight(t *testing.T) {
	cases := []struct {
		name     string
		rights   string
		narrowed bool
		status   probe.Status
		reason   probe.Reason
	}{
		{"agent enrolled before the right", "observe", false, probe.StatusDown, probe.ReasonLAN},
		{"another right is not this one", "observe,agent.update", false, probe.StatusDown, probe.ReasonLAN},
		{"with probe.lan", "observe,probe.lan", false, probe.StatusUp, probe.ReasonNone},
		{"right on disk but state unsafe", "observe,probe.lan", true, probe.StatusDown, probe.ReasonLAN},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := probeOnLoopback(t, tc.rights, tc.narrowed)
			if got.Status != tc.status || got.LastReason != tc.reason {
				t.Fatalf("status %s reason %q, want %s %q", got.Status, got.LastReason, tc.status, tc.reason)
			}
		})
	}
}
