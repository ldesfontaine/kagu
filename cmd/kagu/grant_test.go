package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

// runPolicy lance la commande en root (euid 0) avec ce terminal, sur un
// système qui ne pose rien.
func runPolicy(t *testing.T, place agent.PolicyPlace, terminal terminalOpener, verb string, args ...string) (string, error) {
	t.Helper()
	return runPolicyOn(t, place, &quietSystem{}, terminal, verb, args...)
}

// runPolicyOn est runPolicy sur ce système.
func runPolicyOn(t *testing.T, place agent.PolicyPlace, system agent.System, terminal terminalOpener, verb string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	placer := func(*os.Root) (agent.PolicyPlace, error) { return place, nil }
	err := runAgentPolicy(verb, args, policyCommand{out: &out, openTerminal: terminal, euid: 0, place: placer, system: system})
	return out.String(), err
}

// quietSystem est une machine avec un groupe docker, sans drop-in, qui note
// ce qu'on lui fait poser sans rien lancer ; server : la machine du serveur ;
// noDocker : pas de groupe docker ; member : le compte de l'agent y est ;
// dropIn : le drop-in des droits écrit.
type quietSystem struct {
	server   bool
	noDocker bool
	member   bool
	dropIn   []byte
	laid     []string
}

func (s *quietSystem) GroupExists(string) (bool, error)     { return !s.noDocker, nil }
func (s *quietSystem) InGroup(string, string) (bool, error) { return s.member, nil }
func (*quietSystem) DropIns() ([]string, error)             { return nil, nil }
func (*quietSystem) Proxmox() bool                          { return false }
func (s *quietSystem) ServerMachine() bool                  { return s.server }
func (s *quietSystem) Run(name string, args ...string) error {
	s.laid = append(s.laid, name+" "+strings.Join(args, " "))
	if name == "usermod" {
		s.member = true
	}
	return nil
}
func (s *quietSystem) MakeFolder(path string, _ fs.FileMode, _ fsx.Owner) error {
	s.laid = append(s.laid, "folder "+path)
	return nil
}
func (s *quietSystem) ReadDropIn(string) ([]byte, error) {
	if s.dropIn == nil {
		return nil, fs.ErrNotExist
	}
	return s.dropIn, nil
}
func (s *quietSystem) WriteDropIn(name string, content []byte) error {
	s.laid = append(s.laid, "write "+name+" "+string(content))
	s.dropIn = content
	return nil
}
func (s *quietSystem) RemoveDropIn(name string) error {
	s.laid = append(s.laid, "remove "+name)
	s.dropIn = nil
	return nil
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
	// Une seule machine : le drop-in écrit par le premier grant y reste.
	system := &quietSystem{}
	if _, err := runPolicyOn(t, place, system, fakeTerminal("o\n"), policyGrant, "-state", stateDir, "files.write=/srv/a", "probe.lan"); err != nil {
		t.Fatal(err)
	}
	if _, err := runPolicyOn(t, place, system, noTerminal, policyRevoke, "-state", stateDir, "-yes", "probe.lan"); err != nil {
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
	out, err = runPolicyOn(t, place, system, noTerminal, policyGrant, "-state", stateDir, "files.write=/srv/a")
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
		{[]string{policyGrant, "-state", stateDir, "-yes", "network.private=0"}, "nombre de pairs"},
		{[]string{policyGrant, "-state", stateDir, "-yes", "--set", "admin"}, "observe, manage ou root"},
		{[]string{policyGrant, "-state", stateDir, "-yes", "--set", "manage", "probe.lan"}, "Usage"},
		{[]string{policyGrant, "-state", stateDir, "-yes", "--set", "root", "--for", "2h"}, "Usage"},
		{[]string{policyRevoke, "-state", stateDir, "-yes", "--set", "observe"}, "Usage"},
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
	for _, want := range []string{"+ terminal.host=root", "terminal.host   jusqu'au", risk, "Un autre compte : sudo kagu agent grant terminal.host=<compte> --for 2h"} {
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

// R-A3-5, N-F5 : sur une machine dont l'horloge monotone ne se lit pas,
// « grant --for », la durée de terminal.host et « trust add … -keep-old »
// sont refusés par leur phrase, avant la question ; rien n'est écrit.
// --for permanent passe.
func TestR_A3_5_GrantForIsRefusedWithoutTheMonotonicClock(t *testing.T) {
	stateDir, place := policyState(t)
	before := policyContent(t, place)
	wallClockOnly := func() agentpolicy.Clock { return agentpolicy.Clock{Now: time.Now()} }
	catalogs, err := lang.Load()
	if err != nil {
		t.Fatal(err)
	}
	want := catalogs.For(lang.French).Get("agent.policy_no_monotonic_clock")
	run := func(verb string, args ...string) (string, error) {
		var out bytes.Buffer
		placer := func(*os.Root) (agent.PolicyPlace, error) { return place, nil }
		command := policyCommand{out: &out, openTerminal: noTerminal, euid: 0, place: placer, system: &quietSystem{}, clock: wallClockOnly}
		var err error
		if verb == "trust" {
			err = runAgentTrust(args, command)
		} else {
			err = runAgentPolicy(verb, args, command)
		}
		return out.String(), err
	}
	newer := base64.StdEncoding.EncodeToString(testServerPublicKey(t))
	for _, args := range [][]string{
		{policyGrant, "-state", stateDir, "-yes", "observe.env", "--for", "1h"},
		{policyGrant, "-state", stateDir, "-yes", "terminal.host"},
		{"trust", "-state", stateDir, "-yes", "add", agentpolicy.TrustServerKey, newer, "-keep-old", "1h"},
	} {
		out, err := run(args[0], args[1:]...)
		var refused *refusal
		if !errors.As(err, &refused) || refused.message != want || strings.Contains(out, "[o/N]") {
			t.Errorf("%v: %v\n%s", args, err, out)
		}
		if policyContent(t, place) != before {
			t.Fatalf("%v wrote the policy:\n%s", args, policyContent(t, place))
		}
	}
	if _, err := run(policyGrant, "-state", stateDir, "-yes", "terminal.host", "--for", "permanent"); err != nil {
		t.Fatalf("--for permanent: %v", err)
	}
}

// N-M3, R-A3-15 : grant --set liste, avant la question, chaque droit posé et
// retiré, l'échéance de celui qui la perd, et ce qu'il fait aussi sur le
// système ; « N », Entrée, ou pas de terminal sans -yes : rien n'est écrit,
// rien n'est posé.
func TestR_A3_15_GrantSetPrintsEachRightBeforeAsking(t *testing.T) {
	stateDir, place := policyState(t)
	if _, err := runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "-yes", "terminal.host", "observe.env"); err != nil {
		t.Fatal(err)
	}
	before := policyContent(t, place)
	for _, terminal := range []terminalOpener{fakeTerminal("N\n"), fakeTerminal("\n"), noTerminal} {
		system := &quietSystem{}
		out, err := runPolicyOn(t, place, system, terminal, policyGrant, "-state", stateDir, "--set", "manage")
		var refused *refusal
		if !errors.As(err, &refused) || policyContent(t, place) != before || len(system.laid) != 0 {
			t.Fatalf("declined: %v, laid %q", err, system.laid)
		}
		question := strings.Index(out, "[o/N]")
		if question < 0 {
			question = len(out)
		}
		said := out[:question]
		for _, want := range []string{
			"+ probe.lan", "+ agent.update", "+ docker.deploy", "+ docker.update", "+ files.write=/srv/workspace",
			"+ restic.produce", "+ restic.docker", "+ restic.restore", "+ terminal.container", "- terminal.host=root",
			"groupe docker pour", "dossier /srv/workspace", "droits.conf écrit", "systemctl daemon-reload, puis relance",
		} {
			if !strings.Contains(said, want) {
				t.Errorf("%q not said before the question:\n%s", want, out)
			}
		}
		if strings.Contains(said, "observe.env") {
			t.Errorf("a right outside the sets is said changed:\n%s", out)
		}
	}
	// Un droit posé par le jeu qui perd son échéance la dit.
	if _, err := runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "-yes", "--set", "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "-yes", "terminal.host", "--for", "1h"); err != nil {
		t.Fatal(err)
	}
	out, err := runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "-yes", "--set", "root")
	if err != nil || !strings.Contains(out, "terminal.host   sans échéance") {
		t.Fatalf("the lost expiry is not said: %v\n%s", err, out)
	}
}

// R-A3-12 : « Gérer » met le compte de l'agent dans le groupe docker, et la
// commande le dit « vaut root » avant la question, une fois ; le jeu posé,
// le groupe, le dossier, le drop-in et la relance sont faits, et dits.
func TestR_A3_12_ManageSaysItIsWorthRoot(t *testing.T) {
	stateDir, place := policyState(t)
	system := &quietSystem{}
	out, err := runPolicyOn(t, place, system, fakeTerminal("o\n"), policyGrant, "-state", stateDir, "--set", "manage")
	if err != nil {
		t.Fatal(err)
	}
	risk := "le compte de l'agent vaut root sur la machine."
	question := strings.Index(out, "[o/N]")
	if index := strings.Index(out, risk); index < 0 || index > question || strings.Count(out, risk) != 1 {
		t.Fatalf("worth root not said once before the question:\n%s", out)
	}
	if len(system.laid) != 5 || !strings.HasPrefix(system.laid[0], "usermod -aG docker ") || !strings.Contains(out, "✓ systemctl daemon-reload") {
		t.Fatalf("laid %q\n%s", system.laid, out)
	}
	// Observer ne le dit pas.
	out, err = runPolicy(t, place, noTerminal, policyGrant, "-state", stateDir, "-yes", "--set", "observe")
	if err != nil || strings.Contains(out, risk) {
		t.Fatalf("observe: %v\n%s", err, out)
	}
}

// R-DROIT-5 : sur la machine du serveur, « Gérer en root » se dit avant
// d'être posé : qui entre dans l'interface y devient root. Ailleurs, ou
// quand la machine y est déjà, la phrase ne vient pas.
func TestR_DROIT_5_RootSetOnTheKaguMachineSaysItBeforeLaying(t *testing.T) {
	stateDir, place := policyState(t)
	sentence := "qui entre dans l'interface devient root sur cette machine"
	elsewhere, err := runPolicyOn(t, place, &quietSystem{}, fakeTerminal("N\n"), policyGrant, "-state", stateDir, "--set", "root")
	var refused *refusal
	if !errors.As(err, &refused) || strings.Contains(elsewhere, sentence) {
		t.Fatalf("away from the server: %v\n%s", err, elsewhere)
	}
	server := &quietSystem{server: true}
	out, err := runPolicyOn(t, place, server, fakeTerminal("o\n"), policyGrant, "-state", stateDir, "--set", "root")
	if err != nil {
		t.Fatal(err)
	}
	if index := strings.Index(out, sentence); index < 0 || index > strings.Index(out, "[o/N]") {
		t.Fatalf("not said before the question:\n%s", out)
	}
	again, err := runPolicyOn(t, place, server, noTerminal, policyGrant, "-state", stateDir, "-yes", "probe.lan", "observe.env")
	if err != nil || strings.Contains(again, sentence) {
		t.Fatalf("said again on a machine already in root: %v\n%s", err, again)
	}
}

// E03-10 : « Gérer » posé sans Docker ne promet pas le groupe ; la même
// commande le redit manquant sans rien demander ; Docker installé, elle
// refait le plan, droits inchangés : le groupe et la relance sont dits avant
// la question, rien n'est posé sur « N », tout l'est sur « o », et la sortie
// ne dit pas « Rien ne change ».
func TestE03_10_GrantSetLaysTheDockerGroupWhenOnlyThePrerequisitesDiffer(t *testing.T) {
	stateDir, place := policyState(t)
	system := &quietSystem{noDocker: true}
	out, err := runPolicyOn(t, place, system, noTerminal, policyGrant, "-state", stateDir, "-yes", "--set", "manage")
	if err != nil || !strings.Contains(out, "pas de groupe docker") || strings.Contains(out, "groupe docker pour") || strings.Contains(out, "entre dans le groupe docker") {
		t.Fatalf("without docker: %v\n%s", err, out)
	}
	system.laid = nil
	out, err = runPolicyOn(t, place, system, noTerminal, policyGrant, "-state", stateDir, "--set", "manage")
	if err != nil || !strings.Contains(out, "Rien ne change") || !strings.Contains(out, "pas de groupe docker") || strings.Contains(out, "[o/N]") || len(system.laid) != 0 {
		t.Fatalf("still without docker: %v, laid %q\n%s", err, system.laid, out)
	}

	system.noDocker = false
	before := policyContent(t, place)
	for _, terminal := range []terminalOpener{fakeTerminal("N\n"), noTerminal} {
		out, err = runPolicyOn(t, place, system, terminal, policyGrant, "-state", stateDir, "--set", "manage")
		var refused *refusal
		if !errors.As(err, &refused) || len(system.laid) != 0 || system.member || policyContent(t, place) != before {
			t.Fatalf("declined: %v, laid %q", err, system.laid)
		}
		for _, want := range []string{"La politique ne change pas.", "groupe docker pour", "systemctl daemon-reload, puis relance"} {
			if !strings.Contains(out, want) {
				t.Errorf("%q not said before the refusal:\n%s", want, out)
			}
		}
	}

	out, err = runPolicyOn(t, place, system, fakeTerminal("o\n"), policyGrant, "-state", stateDir, "--set", "manage")
	question := strings.Index(out, "[o/N]")
	if err != nil || question < strings.Index(out, "groupe docker pour") || strings.Contains(out, "Rien ne change") || !strings.Contains(out, "✓ groupe docker pour") || policyContent(t, place) != before {
		t.Fatalf("accepted: %v\n%s", err, out)
	}
	if len(system.laid) != 3 || !strings.HasPrefix(system.laid[0], "usermod -aG docker ") || system.laid[1] != "systemctl daemon-reload" {
		t.Fatalf("laid %q", system.laid)
	}
}
