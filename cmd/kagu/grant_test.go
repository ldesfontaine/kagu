package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
)

// legacyState écrit un agent enrôlé d'avant la politique, dont le binaire la
// lit, avec ces droits et une clé du serveur, et rend son état et le dossier
// de politique (absent) où la commande écrira, au compte du test.
func legacyState(t *testing.T, rights ...string) (stateDir string, place agent.PolicyPlace) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir = filepath.Join(parent, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	identity := agent.Identity{
		MachineID: "m", Language: lang.French, Rights: rights, PolicyFormat: agentpolicy.FormatVersion,
		ServerKey: testServerPublicKey(t), Anchors: map[string][]string{anchor.BackupGuest: {"5012"}},
	}
	if err := agent.SaveIdentity(root, identity); err != nil {
		t.Fatal(err)
	}
	place = agent.PolicyPlace{Dir: filepath.Join(parent, "policy"), Owner: fsx.Owner{UID: os.Getuid(), GID: os.Getgid()}}
	return stateDir, place
}

// testServerPublicKey tire une clé publique Ed25519 de serveur.
func testServerPublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

// policyState est legacyState passé à la politique par « policy migrate ».
func policyState(t *testing.T, rights ...string) (stateDir string, place agent.PolicyPlace) {
	t.Helper()
	stateDir, place = legacyState(t, rights...)
	if _, err := runMigrate(t, place, noTerminal, "migrate", "-state", stateDir, "-yes"); err != nil {
		t.Fatal(err)
	}
	return stateDir, place
}

// runPolicy lance la commande en root (euid 0) avec ce terminal.
func runPolicy(t *testing.T, place agent.PolicyPlace, terminal terminalOpener, verb string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	placer := func(*os.Root) (agent.PolicyPlace, error) { return place, nil }
	err := runAgentPolicy(verb, args, policyCommand{out: &out, openTerminal: terminal, euid: 0, place: placer})
	return out.String(), err
}

// runMigrate lance « agent policy … » en root avec ce terminal.
func runMigrate(t *testing.T, place agent.PolicyPlace, terminal terminalOpener, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	placer := func(*os.Root) (agent.PolicyPlace, error) { return place, nil }
	err := runAgentPolicyMigrate(args, policyCommand{out: &out, openTerminal: terminal, euid: 0, place: placer})
	return out.String(), err
}

// policyContent rend le fichier de la politique, vide s'il n'existe pas.
func policyContent(t *testing.T, place agent.PolicyPlace) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(place.Dir, "policy.toml"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return string(content)
}

// N-M3, R-A3-15 : sans terminal ni -yes, grant et revoke refusent et
// n'écrivent rien ; avec un terminal qui répond « N », Entrée ou autre chose,
// non plus. Ce qui change est dit avant la question.
func TestR_A3_15_GrantWithoutConsentWritesNothing(t *testing.T) {
	stateDir, place := policyState(t, "docker.deploy")
	before := policyContent(t, place)
	out, err := runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "probe.lan")
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "-yes") || policyContent(t, place) != before {
		t.Fatalf("without terminal: %v", err)
	}
	if !strings.Contains(out, "+ probe.lan") || strings.Contains(out, "docker.deploy") {
		t.Fatalf("the change is not told before refusing:\n%s", out)
	}
	for _, answer := range []string{"N\n", "\n", "non\n", ""} {
		out, err := runPolicy(t, place, fakeTerminal(answer), policyGrant, "-state", stateDir, "probe.lan")
		if !errors.As(err, &refused) || policyContent(t, place) != before {
			t.Errorf("answer %q: %v", answer, err)
		}
		if !strings.Contains(out, "+ probe.lan") || !strings.Contains(out, "[o/N]") {
			t.Errorf("answer %q: change and question missing:\n%s", answer, out)
		}
	}
	if _, err := runPolicy(t, place, noTerminal, policyRevoke, "-state", stateDir, "docker.deploy"); !errors.As(err, &refused) || policyContent(t, place) != before {
		t.Fatalf("revoke without terminal: %v", err)
	}
}

// Un « o », ou -yes, écrit ; rights le relit, avec sa source et son empreinte.
func TestRunAgentPolicy_GrantRevokeAndRights(t *testing.T) {
	stateDir, place := policyState(t)
	if _, err := runPolicy(t, place, fakeTerminal("o\n"), policyGrant, "-state", stateDir, "files.write=/srv/a", "probe.lan"); err != nil {
		t.Fatal(err)
	}
	if _, err := runPolicy(t, place, noTerminal, policyRevoke, "-state", stateDir, "-yes", "probe.lan"); err != nil {
		t.Fatal(err)
	}
	out, err := runPolicy(t, place, noTerminal, policyRights, "-state", stateDir)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(place.Dir, "policy.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, agentpolicy.Digest(content)) || !strings.Contains(out, "files.write=/srv/a") || strings.Contains(out, "probe.lan") {
		t.Fatalf("rights:\n%s", out)
	}
	out, err = runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "files.write=/srv/a")
	if err != nil || !strings.Contains(out, "Rien ne change") {
		t.Fatalf("nothing to change: %v\n%s", err, out)
	}
}

// Les refus se disent dans la langue de l'opérateur, sans rien écrire : un
// compte qui n'est pas root, un droit inconnu, observe retiré, l'usage.
func TestRunAgentPolicy_RefusalsWriteNothing(t *testing.T) {
	stateDir, place := policyState(t)
	before := policyContent(t, place)
	var out bytes.Buffer
	placer := func(*os.Root) (agent.PolicyPlace, error) { return place, nil }
	err := runAgentPolicy(policyGrant, []string{"-state", stateDir, "-yes", "probe.lan"}, policyCommand{out: &out, openTerminal: noTerminal, euid: 1000, place: placer})
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "root") {
		t.Fatalf("not root: %v", err)
	}
	cases := []struct {
		args []string
		want string
	}{
		{[]string{policyGrant, "-state", stateDir, "-yes", "everything"}, "n'existe pas"},
		{[]string{policyGrant, "-state", stateDir, "-yes", "files.write=relative"}, "absolu"},
		{[]string{policyRevoke, "-state", stateDir, "-yes", "observe"}, "ne se retire pas"},
		{[]string{policyGrant, "-state", stateDir}, "Usage"},
		{[]string{policyRevoke, "-state", stateDir}, "Usage"},
		{[]string{policyRights, "-state", stateDir, "extra"}, "Usage"},
		{[]string{policyRevoke, "-state", stateDir, "-yes", "probe.lan", "--for", "5m"}, "Usage"},
		{[]string{policyGrant, "-state", stateDir, "-yes", "probe.lan", "--for", "4m"}, "de 5m à 168h"},
		{[]string{policyGrant, "-state", stateDir, "-yes", "probe.lan", "--for", "169h"}, "de 5m à 168h"},
		{[]string{policyGrant, "-state", stateDir, "-yes", "probe.lan", "--for", "toujours"}, "de 5m à 168h"},
		{[]string{policyGrant, "-state", stateDir, "-yes", "terminal.host=Root"}, "nom de compte Unix"},
		{[]string{policyGrant, "-state", stateDir, "-yes", "service.free"}, "n'existe pas"},
	}
	for _, tc := range cases {
		_, err := runPolicy(t, place, noTerminal, tc.args[0], tc.args[1:]...)
		if !errors.As(err, &refused) || !strings.Contains(refused.message, tc.want) {
			t.Errorf("%v: %v", tc.args, err)
		}
	}
	if policyContent(t, place) != before {
		t.Fatal("a refused command wrote the policy")
	}
}

// N-M6, R-A3-12 : « grant terminal.host » pose terminal.host=root pour deux
// heures, et dit, avant la question, que l'agent devient l'égal de root au
// premier terminal, et comment choisir un autre compte. --for change la
// durée, où qu'il soit sur la ligne ; --for permanent la retire.
func TestN_M6_GrantHostTerminalTellsItsRiskAndTakesTwoHours(t *testing.T) {
	stateDir, place := policyState(t)
	out, err := runPolicy(t, place, fakeTerminal("o\n"), policyGrant, "-state", stateDir, "terminal.host")
	if err != nil {
		t.Fatal(err)
	}
	risk := "l'agent devient l'égal de root"
	question := strings.Index(out, "[o/N]")
	for _, want := range []string{"+ terminal.host=root", "terminal.host   jusqu'au", risk, "Un autre compte : sudo opencloud agent grant terminal.host=<compte> --for 2h"} {
		if index := strings.Index(out, want); index < 0 || index > question {
			t.Errorf("%q not said before the question:\n%s", want, out)
		}
	}
	document, err := agentpolicy.Decode([]byte(policyContent(t, place)))
	if err != nil {
		t.Fatal(err)
	}
	expiry := document.Expiries[agentpolicy.CapabilityTerminalHost]
	if agentpolicy.FormatCapabilities(document.Rights) != "observe,terminal.host=root" || expiry.Until.Sub(expiry.Granted.Now) != 2*time.Hour || expiry.Granted.Boot == "" {
		t.Fatalf("policy:\n%s", policyContent(t, place))
	}

	out, err = runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "terminal.host=admin", "-yes", "--for", "5m")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, risk) || strings.Contains(out, "Un autre compte") {
		t.Fatalf("another account still tells the risk, not the other account line:\n%s", out)
	}
	document, _ = agentpolicy.Decode([]byte(policyContent(t, place)))
	if expiry := document.Expiries[agentpolicy.CapabilityTerminalHost]; expiry.Until.Sub(expiry.Granted.Now) != 5*time.Minute {
		t.Fatalf("--for 5m:\n%s", policyContent(t, place))
	}
	out, err = runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "-yes", "--for", "permanent", "terminal.host=admin")
	if err != nil || !strings.Contains(out, "terminal.host   sans échéance") || strings.Contains(policyContent(t, place), "until") {
		t.Fatalf("--for permanent: %v\n%s\n%s", err, out, policyContent(t, place))
	}
}
