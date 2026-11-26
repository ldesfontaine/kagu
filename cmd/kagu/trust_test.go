package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// runTrust lance « agent trust » avec ce terminal, sous ce compte.
func runTrust(t *testing.T, place agent.PolicyPlace, terminal terminalOpener, euid int, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	placer := func(*os.Root) (agent.PolicyPlace, error) { return place, nil }
	err := runAgentTrust(args, policyCommand{out: &out, openTerminal: terminal, euid: euid, place: placer})
	return out.String(), err
}

func TestRunAgentTrust_AUsageErrorIsARefusalThatListsTheTypes(t *testing.T) {
	stateDir, place := policyState(t)
	for _, arguments := range [][]string{{}, {"frobnicate"}, {"add"}, {"add", "backup.guest"}, {"list", "extra"}, {"remove", "a", "b", "c"}} {
		_, err := runTrust(t, place, noTerminal, 0, append([]string{"-state", stateDir}, arguments...)...)
		var refused *refusal
		if !errors.As(err, &refused) || !strings.Contains(refused.message, "backup.recipient, backup.guest, restic.target-cert") {
			t.Errorf("%v: %v", arguments, err)
		}
	}
}

// Sans être root, la commande refuse sans rien écrire : elle change ce que
// l'agent accepte d'exécuter.
func TestRunAgentTrust_RefusesAnAccountThatIsNotRoot(t *testing.T) {
	stateDir, place := policyState(t)
	before := policyContent(t, place)
	_, err := runTrust(t, place, noTerminal, 1000, "-state", stateDir, "-yes", "add", anchor.BackupGuest, "101")
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "root") {
		t.Fatalf("err %v", err)
	}
	if policyContent(t, place) != before {
		t.Fatal("a refused command wrote")
	}
}

func TestPrintAnchors_SeparatesNoneFromUnreadable(t *testing.T) {
	var out bytes.Buffer
	state := anchor.FromFile(map[string][]string{anchor.BackupGuest: {"101", "102"}, anchor.ResticTargetCert: {"nope"}})
	printAnchors(&out, testCatalog(t), state)
	text := out.String()
	for _, want := range []string{"backup.recipient\taucune posée", "backup.guest\t101 102", "restic.target-cert\tillisible"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q missing from:\n%s", want, text)
		}
	}
}

func TestSplitTrustArguments(t *testing.T) {
	cases := map[string]struct {
		arguments []string
		verb      string
		ok        bool
	}{
		"list":   {[]string{"list"}, "list", true},
		"add":    {[]string{"add", "backup.guest", "101"}, "add", true},
		"remove": {[]string{"remove", "backup.guest", "101"}, "remove", true},
		"set":    {[]string{"set", "server-key", "k", "-keep-old", "1h"}, "set", true},
		"short":  {[]string{"add", "backup.guest"}, "", false},
		"long":   {[]string{"list", "x"}, "", false},
		"none":   {nil, "", false},
		"verb":   {[]string{"drop", "a", "b"}, "", false},
	}
	for name, c := range cases {
		request, ok := splitTrustArguments(c.arguments)
		if request.Verb != c.verb || ok != c.ok {
			t.Errorf("%s: %q %v", name, request.Verb, ok)
		}
	}
}

func TestParseAnchorFlags_JudgesEveryTypeOfTheRegistry(t *testing.T) {
	values := map[string]*string{}
	for _, kind := range anchor.Kinds() {
		empty := ""
		values[kind.Name] = &empty
	}
	if anchors, bad := parseAnchorFlags(values); bad != nil || len(anchors) != 0 {
		t.Fatalf("no flag: %v %v", anchors, bad)
	}
	good, wrong := "101,102", "0101"
	values[anchor.BackupGuest] = &good
	if anchors, bad := parseAnchorFlags(values); bad != nil || len(anchors[anchor.BackupGuest]) != 2 {
		t.Fatalf("good: %v %v", anchors, bad)
	}
	values[anchor.BackupGuest] = &wrong
	if _, bad := parseAnchorFlags(values); bad == nil || bad.Name != anchor.BackupGuest {
		t.Fatalf("a malformed value must name its type: %v", bad)
	}
}

func noTerminal() (io.ReadCloser, error) { return nil, errors.New("no tty") }

func fakeTerminal(answer string) terminalOpener {
	return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(answer)), nil }
}

// storedPolicy lit la politique écrite.
func storedPolicy(t *testing.T, place agent.PolicyPlace) agentpolicy.Document {
	t.Helper()
	document, err := agentpolicy.Decode([]byte(policyContent(t, place)))
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// R-A3-15, R-DROIT-8 : sans terminal ni -yes la commande refuse et n'écrit
// rien ; avec un terminal qui répond « N », Entrée ou autre chose, non plus.
// Le changement est dit avant la question.
func TestR_A3_15(t *testing.T) {
	fingerprint := strings.Repeat("ab", 32)
	stateDir, place := policyState(t)
	before := policyContent(t, place)
	out, err := runTrust(t, place, noTerminal, 0, "-state", stateDir, "add", anchor.ResticTargetCert, fingerprint)
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "-yes") || policyContent(t, place) != before {
		t.Errorf("without terminal: %v", err)
	}
	if !strings.Contains(out, "+ "+anchor.ResticTargetCert+" "+fingerprint) || !strings.Contains(out, fingerprint[:16]+")") {
		t.Errorf("the change is not told before refusing:\n%s", out)
	}
	for _, answer := range []string{"N\n", "\n", "non\n", ""} {
		out, err := runTrust(t, place, fakeTerminal(answer), 0, "-state", stateDir, "add", anchor.BackupGuest, "101")
		if !errors.As(err, &refused) || policyContent(t, place) != before {
			t.Errorf("answer %q: %v", answer, err)
		}
		if !strings.Contains(out, "+ backup.guest 101") || !strings.Contains(out, "[o/N]") {
			t.Errorf("answer %q: change and question missing:\n%s", answer, out)
		}
	}
	out, err = runTrust(t, place, noTerminal, 0, "-state", stateDir, "remove", anchor.BackupGuest, "312")
	if !errors.As(err, &refused) || !strings.Contains(out, "- backup.guest 312") || policyContent(t, place) != before {
		t.Errorf("remove without terminal: %v\n%s", err, out)
	}
}

// Un « o » passe la question : l'ancre est posée dans la politique. Le test
// joue root par l'argument euid.
func TestR_DROIT_8(t *testing.T) {
	stateDir, place := policyState(t)
	if _, err := runTrust(t, place, fakeTerminal("o\n"), 0, "-state", stateDir, "add", anchor.BackupGuest, "101"); err != nil {
		t.Fatal(err)
	}
	if got := storedPolicy(t, place).Anchors[anchor.BackupGuest]; len(got) != 2 || got[1] != "101" {
		t.Fatalf("stored %v", got)
	}
	if _, err := runTrust(t, place, noTerminal, 0, "-state", stateDir, "add", "nope", "x"); err == nil || !strings.Contains(err.Error(), "inconnu") {
		t.Fatalf("unknown type: %v", err)
	}
	out, err := runTrust(t, place, noTerminal, 0, "-state", stateDir, "list")
	if err != nil || !strings.Contains(out, "backup.guest\t312 101") || !strings.Contains(out, agentpolicy.TrustServerKey+"\tSHA256:") {
		t.Fatalf("list: %v\n%s", err, out)
	}
}

// N-M3 : « trust set server-key » imprime l'empreinte de l'ancienne et de la
// nouvelle clé, avant la question, et renvoie à « secrets server-key » sur la
// machine du serveur. « add server-key » sans -keep-old est refusé et
// propose « set » ; avec, il dit l'échéance de l'ancienne.
func TestR_A3_15_TrustSetPrintsBothFingerprints(t *testing.T) {
	stateDir, place := policyState(t)
	old := storedPolicy(t, place).ServerKeys[0].Key
	fresh := testServerPublicKey(t)
	value := base64.StdEncoding.EncodeToString(fresh)
	before := policyContent(t, place)

	out, err := runTrust(t, place, noTerminal, 0, "-state", stateDir, "add", agentpolicy.TrustServerKey, value)
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "agent trust set server-key "+value) || policyContent(t, place) != before {
		t.Fatalf("add without -keep-old: %v", err)
	}
	if strings.Contains(out, "[o/N]") {
		t.Fatalf("asked before refusing:\n%s", out)
	}

	out, err = runTrust(t, place, fakeTerminal("o\n"), 0, "-state", stateDir, "set", agentpolicy.TrustServerKey, value)
	if err != nil {
		t.Fatal(err)
	}
	question := strings.Index(out, "[o/N]")
	for _, want := range []string{"- clé du serveur   " + agentwire.KeyFingerprint(old), "+ clé du serveur   " + agentwire.KeyFingerprint(fresh), brand.Command + " secrets server-key"} {
		if index := strings.Index(out, want); index < 0 || index > question {
			t.Errorf("%q is not told before the question:\n%s", want, out)
		}
	}
	if keys := storedPolicy(t, place).ServerKeys; len(keys) != 1 || !fresh.Equal(ed25519.PublicKey(keys[0].Key)) {
		t.Fatalf("stored keys %+v", keys)
	}

	newer := base64.StdEncoding.EncodeToString(testServerPublicKey(t))
	out, err = runTrust(t, place, noTerminal, 0, "-state", stateDir, "add", agentpolicy.TrustServerKey, newer, "-keep-old", "1h", "-yes")
	if err != nil || !strings.Contains(out, agentwire.KeyFingerprint(fresh)+"   gardée jusqu'au") {
		t.Fatalf("add -keep-old: %v\n%s", err, out)
	}
	if keys := storedPolicy(t, place).ServerKeys; len(keys) != 2 || keys[1].Until.IsZero() {
		t.Fatalf("stored keys %+v", keys)
	}
}

// grant et trust refusent sur une machine d'avant la politique, sans rien
// créer, et donnent la ligne « policy migrate ».
func TestRunAgentTrust_BeforeMigrateGivesTheMigrateLine(t *testing.T) {
	stateDir, place := legacyState(t)
	_, err := runTrust(t, place, noTerminal, 0, "-state", stateDir, "-yes", "add", anchor.BackupGuest, "101")
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, agentpolicy.MigrateLine()) {
		t.Fatalf("trust before migrate: %v", err)
	}
	if _, err := os.Stat(place.Dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the policy directory was created: %v", err)
	}
}

// Un compte sans privilège est refusé avant la question : le terminal n'est
// même pas ouvert.
func TestR_DROIT_8_NonRootIsRefusedBeforeTheQuestion(t *testing.T) {
	opened := false
	spy := func() (io.ReadCloser, error) {
		opened = true
		return io.NopCloser(strings.NewReader("o\n")), nil
	}
	stateDir, place := policyState(t)
	before := policyContent(t, place)
	out, err := runTrust(t, place, spy, 1000, "-state", stateDir, "add", anchor.BackupGuest, "101")
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "root") {
		t.Fatalf("err %v", err)
	}
	if opened || strings.Contains(out, "[o/N]") || policyContent(t, place) != before {
		t.Fatalf("asked a non-root account: opened=%v out=%q", opened, out)
	}
}
