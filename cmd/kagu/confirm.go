package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
)

// terminalOpener rend le terminal de l'opérateur. Dans « curl … | sudo sh »,
// l'entrée standard est le script : la réponse se lit sur /dev/tty, jamais
// dessus. Un test y met un faux terminal.
type terminalOpener func() (io.ReadCloser, error)

func openControllingTerminal() (io.ReadCloser, error) {
	return os.Open("/dev/tty")
}

// isYes dit si la réponse est un accord ; Entrée ou tout autre mot est un non.
func isYes(answer string) bool {
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "o", "oui", "y", "yes":
		return true
	}
	return false
}

// confirmChange est la question des commandes root qui changent les droits
// ou la confiance de l'agent (grant, grant --set, revoke, policy migrate,
// trust) : elle imprime ce qui change, puis demande [o/N] au clavier, N par
// défaut (R-DROIT-8, R-A3-15). Le terminal s'ouvre d'abord : -yes ne vaut que
// sans lui (script, cloud-init). Avec un terminal, -yes est ignoré, la
// commande le dit et pose la question (Lucas, 25/11/2026). Sans terminal ni
// -yes, elle refuse : rien ne s'écrit jamais sans accord.
func confirmChange(out io.Writer, openTerminal terminalOpener, yes bool, text lang.Catalog) func(agent.PolicyChange) error {
	return func(change agent.PolicyChange) error {
		return confirmOnTerminal(out, openTerminal, yes, text, func() { printPolicyChange(out, text, change) })
	}
}

// confirmOnTerminal imprime ce qui change (describe), puis demande [o/N] au
// clavier ; -yes ne vaut que sans terminal, et sans terminal ni -yes rien ne
// se fait. La règle de confirmChange, pour qui dit le changement autrement
// (join).
func confirmOnTerminal(out io.Writer, openTerminal terminalOpener, yes bool, text lang.Catalog, describe func()) error {
	terminal, err := openTerminal()
	if err != nil {
		describe()
		if yes {
			return nil
		}
		return &refusal{message: text.Get("agent.confirm_needs_tty")}
	}
	defer terminal.Close()
	if yes {
		fmt.Fprintln(out, text.Get("agent.confirm_yes_ignored"))
	}
	describe()
	return askOn(out, terminal, text)
}

// askOnTerminal pose la question sur le terminal de contrôle ; sans terminal
// elle refuse avec le message de needsTerminalKey, que chaque commande choisit
// selon ce qu'elle accepte (-yes ou non).
func askOnTerminal(out io.Writer, openTerminal terminalOpener, text lang.Catalog, needsTerminalKey string) error {
	terminal, err := openTerminal()
	if err != nil {
		return &refusal{message: text.Get(needsTerminalKey)}
	}
	defer terminal.Close()
	return askOn(out, terminal, text)
}

// askOn demande [o/N] et lit la réponse sur ce terminal ; tout sauf un
// accord est un refus.
func askOn(out io.Writer, terminal io.Reader, text lang.Catalog) error {
	fmt.Fprint(out, text.Get("agent.confirm"))
	answer, _ := bufio.NewReader(terminal).ReadString('\n')
	if !isYes(answer) {
		return &refusal{message: text.Get("agent.confirm_declined")}
	}
	return nil
}
