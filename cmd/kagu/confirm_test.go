package main

import (
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
)

// rightsCommand est une commande qui change les droits ou la confiance de
// l'agent (R-DROIT-8) : l'état où elle se lance, et comment la lancer avec ce
// terminal et ces drapeaux en plus.
type rightsCommand struct {
	name    string
	pending bool
	state   func(t *testing.T) (stateDir string, place agent.PolicyPlace)
	run     func(t *testing.T, stateDir string, place agent.PolicyPlace, terminal terminalOpener, extra ...string) (string, error)
}

// rightsCommands sont les sept commandes d'E03-07b.
func rightsCommands() []rightsCommand {
	grant := func(words ...string) func(*testing.T, string, agent.PolicyPlace, terminalOpener, ...string) (string, error) {
		return func(t *testing.T, stateDir string, place agent.PolicyPlace, terminal terminalOpener, extra ...string) (string, error) {
			return runPolicy(t, place, terminal, words[0], append(append([]string{"-state", stateDir}, extra...), words[1:]...)...)
		}
	}
	withProbeLAN := func(t *testing.T) (string, agent.PolicyPlace) { return policyState(t, agentpolicy.CapabilityProbeLAN) }
	withPending := func(t *testing.T) (string, agent.PolicyPlace) {
		stateDir, place := policyState(t)
		writePending(t, stateDir, refusedNow())
		return stateDir, place
	}
	newKey := base64.StdEncoding.EncodeToString(fixedServerKey)
	return []rightsCommand{
		{name: "grant", state: func(t *testing.T) (string, agent.PolicyPlace) { return policyState(t) }, run: grant(policyGrant, agentpolicy.CapabilityProbeLAN)},
		{name: "grant --set manage", state: func(t *testing.T) (string, agent.PolicyPlace) { return policyState(t) }, run: grant(policyGrant, "--set", "manage")},
		{name: "grant --set observe", state: func(t *testing.T) (string, agent.PolicyPlace) {
			return policyState(t, agentpolicy.CapabilityDockerDeploy)
		}, run: grant(policyGrant, "--set", "observe")},
		{name: "revoke", state: withProbeLAN, run: grant(policyRevoke, agentpolicy.CapabilityProbeLAN)},
		{name: "grant --pending", pending: true, state: withPending, run: grant(policyGrant, "--pending")},
		{
			name:  "policy migrate",
			state: func(t *testing.T) (string, agent.PolicyPlace) { return legacyState(t, agentpolicy.CapabilityProbeLAN) },
			run: func(t *testing.T, stateDir string, place agent.PolicyPlace, terminal terminalOpener, extra ...string) (string, error) {
				return runMigrate(t, place, terminal, append([]string{policyMigrate, "-state", stateDir}, extra...)...)
			},
		},
		{
			name:  "trust set",
			state: func(t *testing.T) (string, agent.PolicyPlace) { return policyState(t) },
			run: func(t *testing.T, stateDir string, place agent.PolicyPlace, terminal terminalOpener, extra ...string) (string, error) {
				args := append(append([]string{"-state", stateDir}, extra...), "set", agentpolicy.TrustServerKey, newKey)
				return runTrust(t, place, terminal, 0, args...)
			},
		},
	}
}

// fixedServerKey est la clé neuve que « trust set » pose.
var fixedServerKey = []byte("0123456789abcdef0123456789abcdef")

// documentOf lit une politique écrite ; vide : celle d'avant la politique.
func documentOf(t *testing.T, content string) agentpolicy.Document {
	t.Helper()
	if content == "" {
		return agentpolicy.Document{}
	}
	document, err := agentpolicy.Decode([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// changeLines rend les lignes « + » et « - » que la commande doit imprimer
// pour passer de before à after : droits, ancres, et clés du serveur par leur
// empreinte (« + SHA256:… »).
func changeLines(before, after agentpolicy.Document) []string {
	var lines []string
	added := func(sign string, was, now []string) {
		for _, item := range now {
			if !slices.Contains(was, item) {
				lines = append(lines, sign+item)
			}
		}
	}
	rights := func(document agentpolicy.Document) []string {
		var texts []string
		for _, right := range document.Rights {
			texts = append(texts, agentpolicy.FormatCapabilities([]agentpolicy.Capability{right}))
		}
		return texts
	}
	anchors := func(document agentpolicy.Document) []string {
		var texts []string
		for kind, values := range document.Anchors {
			for _, value := range values {
				texts = append(texts, kind+" "+value)
			}
		}
		return texts
	}
	keys := func(document agentpolicy.Document) []string {
		var texts []string
		for _, key := range document.ServerKeys {
			texts = append(texts, ident.KeyFingerprint(key.Key))
		}
		return texts
	}
	for _, facts := range []func(agentpolicy.Document) []string{rights, anchors, keys} {
		added("+ ", facts(before), facts(after))
		added("- ", facts(after), facts(before))
	}
	return lines
}

// printedLines rend les lignes « + » et « - » de la sortie ; une clé du
// serveur s'y dit par son empreinte seule.
func printedLines(out string) []string {
	var lines []string
	for line := range strings.SplitSeq(out, "\n") {
		if !strings.HasPrefix(line, "  + ") && !strings.HasPrefix(line, "  - ") {
			continue
		}
		sign, rest := line[2:4], line[4:]
		for field := range strings.FieldsSeq(rest) {
			if strings.HasPrefix(field, "SHA256:") {
				rest = field
			}
		}
		lines = append(lines, sign+rest)
	}
	return lines
}

// assertPrintedIsWritten vérifie que la commande a imprimé exactement ce qui
// a changé entre before et after, et rien d'autre.
func assertPrintedIsWritten(t *testing.T, name, out string, before, after agentpolicy.Document) {
	t.Helper()
	want, got := changeLines(before, after), printedLines(out)
	if len(want) == 0 {
		t.Fatalf("%s: nothing changed:\n%s", name, out)
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("%s: printed %q, written %q", name, got, want)
	}
}

// assertAsked vérifie que la question est posée, après ce qui change.
func assertAsked(t *testing.T, name, out string) {
	t.Helper()
	asked := strings.Index(out, testCatalog(t).Get("agent.confirm"))
	if asked < 0 || !changeBefore(out, asked) {
		t.Errorf("%s: the change is not printed before the question:\n%s", name, out)
	}
}

// changeBefore dit si une ligne « + » ou « - » est imprimée avant at.
func changeBefore(out string, at int) bool {
	return strings.Contains(out[:at], "\n  + ") || strings.Contains(out[:at], "\n  - ") ||
		strings.HasPrefix(out, "  + ") || strings.HasPrefix(out, "  - ")
}

// R-DROIT-8, R-A3-15 (E03-07b, condition de Lucas du 25/11/2026) : chacune des
// sept commandes imprime ce qui change avant [o/N] ; Entrée seule, une
// réponse par le pipe et l'absence de terminal ne changent rien ; « o » au
// terminal change exactement ce qui était imprimé.
func TestE03_07b_EveryRightsCommandAsksAtTheKeyboard(t *testing.T) {
	for _, command := range rightsCommands() {
		stateDir, place := command.state(t)
		before := policyContent(t, place)
		out, err := command.run(t, stateDir, place, fakeTerminal("\n"))
		var refused *refusal
		if !errors.As(err, &refused) || policyContent(t, place) != before {
			t.Errorf("%s, Enter: %v", command.name, err)
		}
		assertAsked(t, command.name, out)
		declined := printedLines(out)

		withStdin(t, "o\n")
		if _, err := command.run(t, stateDir, place, noTerminal); !errors.As(err, &refused) || policyContent(t, place) != before {
			t.Errorf("%s, piped o without terminal: %v", command.name, err)
		}

		out, err = command.run(t, stateDir, place, fakeTerminal("o\n"))
		if err != nil {
			t.Errorf("%s, o: %v", command.name, err)
			continue
		}
		if !slices.Equal(printedLines(out), declined) {
			t.Errorf("%s: o printed %q, Enter %q", command.name, printedLines(out), declined)
		}
		assertPrintedIsWritten(t, command.name, out, documentOf(t, before), documentOf(t, policyContent(t, place)))
	}
}

// Lucas, 25/11/2026 : -yes ne vaut que sans terminal. Avec un terminal, la
// commande dit que -yes est ignoré, imprime ce qui change, pose [o/N], et
// Entrée ne change rien. Sans terminal, -yes change exactement ce qui est
// imprimé. grant --pending refuse -yes dans les deux cas.
func TestYesOnlyWithoutTerminal_TheQuestionIsAskedWithATerminal(t *testing.T) {
	notice := testCatalog(t).Get("agent.confirm_yes_ignored")
	for _, command := range rightsCommands() {
		stateDir, place := command.state(t)
		before := policyContent(t, place)
		out, err := command.run(t, stateDir, place, fakeTerminal("\n"), "-yes")
		var refused *refusal
		if !errors.As(err, &refused) || policyContent(t, place) != before {
			t.Errorf("%s, terminal, -yes, Enter: %v", command.name, err)
		}
		if command.pending {
			if refused == nil || refused.message != testCatalog(t).Get("agent.pending_no_yes") {
				t.Errorf("--pending -yes with a terminal: %v", err)
			}
		} else {
			if at := strings.Index(out, notice); at < 0 || changeBefore(out, at) {
				t.Errorf("%s: the notice is not printed before the change:\n%s", command.name, out)
			}
			assertAsked(t, command.name, out)
		}

		out, err = command.run(t, stateDir, place, noTerminal, "-yes")
		if command.pending {
			if !errors.As(err, &refused) || policyContent(t, place) != before {
				t.Errorf("--pending -yes without terminal: %v", err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s, no terminal, -yes: %v", command.name, err)
			continue
		}
		if strings.Contains(out, notice) {
			t.Errorf("%s: the notice without terminal:\n%s", command.name, out)
		}
		assertPrintedIsWritten(t, command.name, out, documentOf(t, before), documentOf(t, policyContent(t, place)))
	}
}
