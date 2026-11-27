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
	"github.com/ldesfontaine/kagu/internal/kit/lang"
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
	// L'avertissement nomme « --yes » pour l'interdire : ce n'est pas une offre.
	warning := testCatalog(t).Get("rights.paste_only_pending")
	if strings.Contains(strings.ReplaceAll(out, warning, "")+refused.message, "-yes") {
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

// R-DROIT-8 (ARB-1) : la sortie de grant --pending porte, avant la question,
// la phrase de l'écran (une seule clé), avec le nom et la commande de la marque.
func TestR_DROIT_8_PendingOutputCarriesThePasteWarning(t *testing.T) {
	stateDir, place := policyState(t)
	writePending(t, stateDir, refusedNow())
	out, _ := runPolicy(t, place, fakeTerminal("\n"), policyGrant, "-state", stateDir, "--pending")
	catalogs, err := lang.Load()
	if err != nil {
		t.Fatal(err)
	}
	// La phrase validée par Lucas (ARB-4), lue dans le catalogue : la sortie
	// et l'écran disent la même.
	want := catalogs.For(lang.Default).Get("rights.paste_only_pending")
	if !strings.HasPrefix(want, "Une ligne de droits venue de "+brand.ProductName+" ") {
		t.Fatalf("the catalog lost the validated warning: %q", want)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("no warning in the --pending output, want %q:\n%s", want, out)
	}
	if strings.Index(out, want) > strings.Index(out, "[o/N]") {
		t.Fatalf("the warning comes after the question:\n%s", out)
	}
}

// R-A3-15 (ARB-3) : grant --pending lit tout droit que la politique connaît,
// ceux de la politique seule compris. Chaque droit demandé s'imprime avec sa
// phrase de risque et son échéance avant [o/N] (2 h et « égal de root » pour
// terminal.host) ; Entrée seule ne pose rien, « o » au terminal pose ce qui
// était imprimé.
func TestR_A3_15_ARB3_PendingPrintsAndGrantsEveryRequestedRight(t *testing.T) {
	text := testCatalog(t)
	for _, requested := range []struct{ right, granted string }{
		{agentpolicy.CapabilityDockerDeploy, "docker.deploy"},
		{agentpolicy.CapabilityResticProduce, "restic.produce"},
		{agentpolicy.CapabilityTerminalContainer, "terminal.container"},
		{agentpolicy.CapabilityNetworkPrivate, "network.private=1"},
		{agentpolicy.CapabilityTerminalHost, "terminal.host=root"},
	} {
		t.Run(requested.right, func(t *testing.T) {
			stateDir, place := policyState(t)
			writePending(t, stateDir, agent.PendingRight{Name: requested.right, RefusedAt: time.Now().Add(-time.Minute)})
			before := policyContent(t, place)
			out, err := runPolicy(t, place, fakeTerminal("\n"), policyGrant, "-state", stateDir, "--pending")
			var refused *refusal
			if !errors.As(err, &refused) || policyContent(t, place) != before {
				t.Fatalf("Enter alone: %v\n%s", err, out)
			}
			question := strings.Index(out, "[o/N]")
			if question < 0 {
				t.Fatalf("no question:\n%s", out)
			}
			printed := out[:question]
			term := text.Get("agent.pending_permanent")
			if requested.right == agentpolicy.CapabilityTerminalHost {
				term = strings.TrimSuffix(text.Get("agent.pending_until"), "%s")
			}
			if !strings.Contains(printed, "  "+requested.granted+" : ") || !strings.Contains(printed, term) {
				t.Fatalf("the pending line of %s (%q) is not printed:\n%s", requested.granted, term, out)
			}
			if risk := agentpolicy.NoticeOf(agentpolicy.Capability{Name: requested.right}).RiskKey; risk != "" && !strings.Contains(printed, text.Format(risk)) {
				t.Fatalf("no risk sentence %q:\n%s", risk, out)
			}

			out, err = runPolicy(t, place, fakeTerminal("o\n"), policyGrant, "-state", stateDir, "--pending")
			stored := storedPolicy(t, place)
			if err != nil || agentpolicy.FormatCapabilities(stored.Rights) != "observe,"+requested.granted {
				t.Fatalf("o: %v %q\n%s", err, agentpolicy.FormatCapabilities(stored.Rights), out)
			}
			expiry, bounded := stored.Expiries[requested.right]
			if bounded != (requested.right == agentpolicy.CapabilityTerminalHost) || bounded && expiry.Until.Sub(expiry.Granted.Now) != 2*time.Hour {
				t.Fatalf("term %+v", stored.Expiries)
			}
		})
	}
}
