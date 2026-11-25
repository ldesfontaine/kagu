package machine

import (
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// Les textes que la préparation écrit en root se collent entre apostrophes,
// dans une ligne : ni apostrophe, ni retour à la ligne, ni caractère que le
// shell lirait autrement qu'une lettre.
func TestProduceTexts_AreSafeInsideSingleQuotes(t *testing.T) {
	texts := map[string][]string{
		"wrapper": VzdumpWrapperLines(), "sudoers": SudoersRuleLines(), "drop-in": ProduceDropInLines(),
	}
	for name, lines := range texts {
		if len(lines) == 0 {
			t.Errorf("%s: no line", name)
		}
		for _, line := range lines {
			if strings.ContainsAny(line, "'\n\r\x00") {
				t.Errorf("%s: %q cannot go inside single quotes", name, line)
			}
		}
	}
}

// Le script, la règle et le drop-in disent ce que la documentation dit : le
// script lance vzdump sous systemd-run, la règle ne nomme que lui, le drop-in
// desserre NoNewPrivileges et rien d'autre.
func TestProduceTexts_SayExactlyWhatTheDocumentationSays(t *testing.T) {
	wantWrapper := []string{
		"#!/bin/sh",
		"# " + brand.ProductName + " : vzdump hors du bac à sable de l agent, sur ordre de l agent.",
		`exec /usr/bin/systemd-run --pipe --wait --collect --quiet /usr/bin/vzdump "$@"`,
	}
	if got := VzdumpWrapperLines(); !slices.Equal(got, wantWrapper) {
		t.Errorf("wrapper %q, want %q", got, wantWrapper)
	}
	wantRule := []string{"kagu-agent ALL=(root) NOPASSWD: /usr/local/sbin/kagu-vzdump"}
	if got := SudoersRuleLines(); !slices.Equal(got, wantRule) {
		t.Errorf("rule %q, want %q", got, wantRule)
	}
	wantDropIn := []string{"[Service]", "NoNewPrivileges=false"}
	if got := ProduceDropInLines(); !slices.Equal(got, wantDropIn) {
		t.Errorf("drop-in %q, want %q", got, wantDropIn)
	}
	if ProduceDropInFile != "/etc/systemd/system/kagu-agent.service.d/produce.conf" || SudoersFile != "/etc/sudoers.d/kagu-agent" || ProduceDir != "/var/lib/kagu-agent/produce" {
		t.Errorf("paths: %s %s %s", ProduceDropInFile, SudoersFile, ProduceDir)
	}
}
