package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
)

// policyState écrit un agent enrôlé dont le binaire lit la politique, et rend
// son état et le dossier de politique (absent) où la commande écrira, au
// compte du test.
func policyState(t *testing.T, rights ...string) (stateDir string, place agent.PolicyPlace) {
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
	identity := agent.Identity{MachineID: "m", Language: lang.French, Rights: rights, PolicyFormat: agentpolicy.FormatVersion}
	if err := agent.SaveIdentity(root, identity); err != nil {
		t.Fatal(err)
	}
	place = agent.PolicyPlace{Dir: filepath.Join(parent, "policy"), Owner: fsx.Owner{UID: os.Getuid(), GID: os.Getgid()}}
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

func policyWritten(place agent.PolicyPlace) bool {
	_, err := os.Stat(filepath.Join(place.Dir, "policy.toml"))
	return !errors.Is(err, fs.ErrNotExist)
}

// N-M3, R-A3-15 : sans terminal ni -yes, grant et revoke refusent et
// n'écrivent rien ; avec un terminal qui répond « N », Entrée ou autre chose,
// non plus. Ce qui change est dit avant la question.
func TestR_A3_15_GrantWithoutConsentWritesNothing(t *testing.T) {
	stateDir, place := policyState(t, "docker.deploy")
	out, err := runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "probe.lan")
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "-yes") || policyWritten(place) {
		t.Fatalf("without terminal: %v, written %v", err, policyWritten(place))
	}
	if !strings.Contains(out, "+ probe.lan") || !strings.Contains(out, "+ docker.deploy") {
		t.Fatalf("the change is not told before refusing:\n%s", out)
	}
	for _, answer := range []string{"N\n", "\n", "non\n", ""} {
		out, err := runPolicy(t, place, fakeTerminal(answer), policyGrant, "-state", stateDir, "probe.lan")
		if !errors.As(err, &refused) || policyWritten(place) {
			t.Errorf("answer %q: %v", answer, err)
		}
		if !strings.Contains(out, "+ probe.lan") || !strings.Contains(out, "[o/N]") {
			t.Errorf("answer %q: change and question missing:\n%s", answer, out)
		}
	}
	if _, err := runPolicy(t, place, noTerminal, policyRevoke, "-state", stateDir, "docker.deploy"); !errors.As(err, &refused) || policyWritten(place) {
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
	}
	for _, tc := range cases {
		_, err := runPolicy(t, place, noTerminal, tc.args[0], tc.args[1:]...)
		if !errors.As(err, &refused) || !strings.Contains(refused.message, tc.want) {
			t.Errorf("%v: %v", tc.args, err)
		}
	}
	if policyWritten(place) {
		t.Fatal("a refused command wrote the policy")
	}
}
