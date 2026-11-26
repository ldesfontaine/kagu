package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
)

// « agent policy migrate » dit tout ce qu'il recopie avant la question (les
// droits, les ancres, l'empreinte de la clé du serveur) ; sans terminal ni
// -yes il n'écrit rien et ne crée pas le dossier ; avec -yes il écrit la
// politique et efface d'identity.json ce qu'il a recopié.
func TestRunAgentPolicyMigrate_TellsWhatItCopiesThenErasesIt(t *testing.T) {
	stateDir, place := legacyState(t, "docker.deploy")
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	legacy, err := agent.LoadIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	out, err := runMigrate(t, place, noTerminal, "migrate", "-state", stateDir)
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "-yes") {
		t.Fatalf("without terminal: %v", err)
	}
	for _, want := range []string{"+ docker.deploy", "+ " + anchor.BackupGuest + " 312", "+ clé du serveur   " + ident.KeyFingerprint(legacy.ServerKey)} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is not told:\n%s", want, out)
		}
	}
	if policyContent(t, place) != "" {
		t.Fatal("a refused migrate wrote the policy")
	}
	if kept, _ := agent.LoadIdentity(root); len(kept.ServerKey) == 0 || len(kept.Rights) == 0 {
		t.Fatalf("a refused migrate erased identity.json: %+v", kept)
	}

	if _, err := runMigrate(t, place, noTerminal, "migrate", "-state", stateDir, "-yes"); err != nil {
		t.Fatal(err)
	}
	stored := storedPolicy(t, place)
	if len(stored.ServerKeys) != 1 || string(stored.ServerKeys[0].Key) != string(legacy.ServerKey) || stored.Anchors[anchor.BackupGuest][0] != "312" {
		t.Fatalf("stored %+v", stored)
	}
	erased, err := agent.LoadIdentity(root)
	if err != nil || erased.Rights != nil || erased.Anchors != nil || erased.ServerKey != nil {
		t.Fatalf("identity.json keeps %+v %v", erased, err)
	}
	if _, err := os.Stat(filepath.Join(place.Dir, "policy.toml")); err != nil {
		t.Fatal(err)
	}
	out, err = runMigrate(t, place, noTerminal, "migrate", "-state", stateDir)
	if err != nil || !strings.Contains(out, "Rien ne change") {
		t.Fatalf("a second migrate: %v\n%s", err, out)
	}
	for _, args := range [][]string{{}, {"move"}, {"migrate", "extra"}} {
		if _, err := runMigrate(t, place, noTerminal, args...); !errors.As(err, &refused) || !strings.Contains(refused.message, "policy migrate") {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// Essai E03-08 : « agent rights » dit la raison du refus dans les mots de
// l'onglet Droits, en français, la clé inconnue nommée ; la commande qui
// corrige suit quand elle existe.
func TestE03_08_AgentRightsSaysWhyThePolicyIsRefused(t *testing.T) {
	text := testCatalog(t)
	for _, c := range []struct {
		refused agentpolicy.Refusal
		want    []string
	}{
		{agentpolicy.Refusal{Reason: agentpolicy.RefusedUnknownKey, Detail: "foo"}, []string{"Politique refusée", "clé inconnue, « foo »"}},
		{agentpolicy.Refusal{Reason: agentpolicy.RefusedOwner, Detail: agentpolicy.FilePath()}, []string{"n'appartient pas à root", "sudo chown root " + agentpolicy.FilePath()}},
		{agentpolicy.Refusal{Reason: agentpolicy.RefusedMode, Detail: agentpolicy.FilePath()}, []string{"autre compte que root", "sudo chmod 640 " + agentpolicy.FilePath()}},
	} {
		var out strings.Builder
		printPolicyRefusal(&out, text, c.refused, errors.New("agent policy is unreadable: strict mode"))
		for _, want := range c.want {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%+v: %q lacks %q", c.refused, out.String(), want)
			}
		}
		if strings.Contains(out.String(), "strict mode") || strings.Contains(out.String(), "%!") {
			t.Errorf("%+v: %q", c.refused, out.String())
		}
	}
}
