package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ldesfontaine/opencloud/internal/lang"
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

// confirmChange est la question des commandes root qui écrivent : l'appelant
// a déjà imprimé ce qui change. Avec -yes elle ne demande rien ; sans -yes et
// sans terminal elle refuse, sans quoi rien ne s'écrit jamais sans accord.
func confirmChange(out io.Writer, openTerminal terminalOpener, yes bool, text lang.Catalog) error {
	if yes {
		return nil
	}
	terminal, err := openTerminal()
	if err != nil {
		return &refusal{message: text.Get("agent.confirm_needs_tty")}
	}
	defer terminal.Close()
	fmt.Fprint(out, text.Get("agent.confirm"))
	answer, _ := bufio.NewReader(terminal).ReadString('\n')
	if !isYes(answer) {
		return &refusal{message: text.Get("agent.confirm_declined")}
	}
	return nil
}
