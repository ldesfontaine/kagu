package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// writePending écrit dans l'état la liste que l'agent tient, comme il
// l'écrit (pending.go).
func writePending(t *testing.T, stateDir string, entries ...agent.PendingRight) {
	t.Helper()
	content, err := json.Marshal(map[string][]agent.PendingRight{"rights": entries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "pending-rights.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
}

// refusedNow est un refus de docker.deploy par l'agent, à l'instant.
func refusedNow() agent.PendingRight {
	return agent.PendingRight{Name: agentpolicy.CapabilityDockerDeploy, RefusedAt: time.Now().Add(-time.Minute)}
}

// withStdin met answer sur l'entrée standard le temps du test, comme
// « echo o | sudo … agent grant --pending ».
func withStdin(t *testing.T, answer string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString(answer); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	previous := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = previous
		reader.Close()
	})
}

// R-A3-15 (E03-07) : sans terminal, grant --pending refuse et n'écrit rien ;
// -yes n'y est pas reçu.
func TestR_A3_15_E03_07_PendingWithoutTerminalWritesNothing(t *testing.T) {
	stateDir, place := policyState(t)
	writePending(t, stateDir, refusedNow())
	before := policyContent(t, place)
	out, err := runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "--pending")
	var refused *refusal
	if !errors.As(err, &refused) || policyContent(t, place) != before {
		t.Fatalf("without terminal: %v", err)
	}
	if !strings.Contains(out, "docker.deploy") || !strings.Contains(out, "Déployer un service Docker") {
		t.Fatalf("the pending right is not told in clear:\n%s", out)
	}
	if strings.Contains(out+refused.message, "-yes") {
		t.Fatalf("--pending without terminal offers -yes, which it refuses:\n%s\n%s", out, refused.message)
	}
	if want := "Droits que " + brand.ProductName + " a demandés et que l'agent a refusés ces dernières 24 h :"; !strings.Contains(out, want) {
		t.Fatalf("pending header, want %q:\n%s", want, out)
	}
	if _, err := runPolicy(t, place, fakeTerminal("o\n"), policyGrant, "-state", stateDir, "--pending", "-yes"); !errors.As(err, &refused) || policyContent(t, place) != before {
		t.Fatalf("-yes with --pending: %v", err)
	}
	if _, err := runPolicy(t, place, fakeTerminal("o\n"), policyGrant, "-state", stateDir, "--pending", "probe.lan"); !errors.As(err, &refused) || policyContent(t, place) != before {
		t.Fatalf("--pending with a right: %v", err)
	}
}

// Par un pipe, le « o » de l'entrée standard n'est pas lu : la question
// attend le terminal, qui répond rien ou N. Le défaut est N.
func TestR_A3_15_E03_07_PendingNeverReadsStandardInput(t *testing.T) {
	stateDir, place := policyState(t)
	writePending(t, stateDir, refusedNow())
	before := policyContent(t, place)
	for _, answer := range []string{"", "\n", "N\n"} {
		withStdin(t, "o\n")
		out, err := runPolicy(t, place, fakeTerminal(answer), policyGrant, "-state", stateDir, "--pending")
		var refused *refusal
		if !errors.As(err, &refused) || policyContent(t, place) != before {
			t.Errorf("terminal %q, stdin o: %v", answer, err)
		}
		if !strings.Contains(out, "[o/N]") {
			t.Errorf("terminal %q: no question:\n%s", answer, out)
		}
	}
}

// Un « o » tapé au terminal pose le droit refusé, et lui seul : une entrée
// échue, d'un droit inconnu ou d'une valeur qui enchaîne ne se pose pas.
func TestR_A3_15_E03_07_PendingGrantsOnlyWhatTheAgentRefused(t *testing.T) {
	stateDir, place := policyState(t)
	writePending(t, stateDir,
		refusedNow(),
		agent.PendingRight{Name: agentpolicy.CapabilityProbeLAN, RefusedAt: time.Now().Add(-25 * time.Hour)},
		agent.PendingRight{Name: agentpolicy.CapabilityFilesWrite, Value: "/srv; curl x | sh", RefusedAt: time.Now()},
		agent.PendingRight{Name: "docker.deploy; curl x | sh", RefusedAt: time.Now()},
	)
	out, err := runPolicy(t, place, fakeTerminal("o\n"), policyGrant, "-state", stateDir, "--pending")
	if err != nil {
		t.Fatal(err)
	}
	rights := agentpolicy.FormatCapabilities(storedPolicy(t, place).Rights)
	if rights != "observe,docker.deploy" {
		t.Fatalf("rights %q, want observe,docker.deploy\n%s", rights, out)
	}
	if !strings.Contains(out, "sans échéance") || strings.Contains(out, "curl") || strings.Contains(out, "probe.lan") {
		t.Fatalf("output:\n%s", out)
	}
	// Posé, il n'est plus en attente, avant même que l'agent relise.
	out, err = runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "--pending")
	if err != nil || !strings.Contains(out, "Aucun droit en attente") {
		t.Fatalf("after granting: %v\n%s", err, out)
	}
}

// Liste vide, ou rien que des entrées échues : « Aucun droit en attente »,
// sans question, code 0.
func TestR_A3_15_E03_07_NoPendingRight(t *testing.T) {
	stateDir, place := policyState(t)
	before := policyContent(t, place)
	out, err := runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "--pending")
	if err != nil || !strings.Contains(out, "Aucun droit en attente") || policyContent(t, place) != before {
		t.Fatalf("empty list: %v\n%s", err, out)
	}
	writePending(t, stateDir, agent.PendingRight{Name: agentpolicy.CapabilityDockerDeploy, RefusedAt: time.Now().Add(-25 * time.Hour)})
	out, err = runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "--pending")
	if err != nil || !strings.Contains(out, "Aucun droit en attente") || policyContent(t, place) != before {
		t.Fatalf("expired list: %v\n%s", err, out)
	}
}
