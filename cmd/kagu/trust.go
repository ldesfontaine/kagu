package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"strings"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
)

// opencloud agent trust list | add <type> <valeur> | remove <type> <valeur> :
// les ancres de confiance locales de l'agent (internal/fact/anchor). Seule voie qui
// les change après l'installation ; réservée à root. Le message d'un
// changement est écrit au journal du système (journald, via /dev/log).
func runAgentTrust(args []string, out io.Writer, openTerminal terminalOpener, euid int) error {
	flags := flag.NewFlagSet("agent trust", flag.ContinueOnError)
	stateDir := flags.String("state", defaultAgentStateDir, "répertoire d'état de l'agent")
	yes := flags.Bool("yes", false, "confirme sans poser la question (obligatoire sans terminal)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	catalogs, err := lang.Load()
	if err != nil {
		return err
	}
	text := catalogs.For(lang.Default)
	rest := flags.Args()
	verb, kindName, value, ok := splitTrustArguments(rest)
	if !ok {
		return &refusal{message: text.Format("agent.trust_usage", brand.AgentCurrentPath, strings.Join(anchor.Names(), ", "))}
	}
	root, err := openStateDir(*stateDir)
	if err != nil {
		return explainStateDirError(err, *stateDir, agent.CurrentAccount(), text)
	}
	defer root.Close()
	// L'identité connaît la langue choisie à l'installation.
	if identity, loadErr := agent.LoadIdentity(root); loadErr == nil && identity.Language != "" {
		text = catalogs.For(identity.Language)
	}
	if verb != agent.TrustList {
		// Un compte sans privilège est refusé sans qu'on lui pose la question.
		if err := agent.RequireTrustRoot(euid); err != nil {
			return explainTrustError(err, kindName, text)
		}
		if err := confirmTrustChange(out, openTerminal, *yes, text, verb, kindName, value); err != nil {
			return err
		}
	}
	result, err := agent.Trust(agent.TrustOptions{
		StateDir: root, StatePath: *stateDir, EUID: euid, Audit: auditToSystemJournal,
	}, verb, kindName, value)
	if err != nil {
		return explainTrustError(err, kindName, text)
	}
	printTrust(out, text, verb, kindName, value, result)
	return nil
}

// confirmTrustChange dit ce qu'« add » ou « remove » va changer, puis demande
// l'accord avant que quoi que ce soit s'écrive.
func confirmTrustChange(out io.Writer, openTerminal terminalOpener, yes bool, text lang.Catalog, verb, kindName, value string) error {
	kind, known := anchor.Lookup(kindName)
	if !known {
		return explainTrustError(agent.ErrTrustUnknownKind, kindName, text)
	}
	key := "agent.trust_change_add"
	if verb == agent.TrustRemove {
		key = "agent.trust_change_remove"
	}
	fmt.Fprintln(out, text.Format(key, kindName, value))
	if kind.Name == anchor.ResticTargetCert && kind.Valid(value) {
		fmt.Fprintln(out, text.Format("agent.trust_change_fingerprint", shortFingerprint(value)))
	}
	return confirmChange(out, openTerminal, yes, text)
}

// shortFingerprint garde les seize premiers caractères d'une empreinte
// hexadécimale : de quoi la comparer à l'œil, pas de quoi la reconnaître seule.
func shortFingerprint(fingerprint string) string {
	return fingerprint[:16]
}

// splitTrustArguments lit « list », ou « add|remove <type> <valeur> ».
func splitTrustArguments(arguments []string) (verb, kindName, value string, ok bool) {
	switch {
	case len(arguments) == 1 && arguments[0] == agent.TrustList:
		return agent.TrustList, "", "", true
	case len(arguments) == 3 && (arguments[0] == agent.TrustAdd || arguments[0] == agent.TrustRemove):
		return arguments[0], arguments[1], arguments[2], true
	}
	return "", "", "", false
}

func printTrust(out io.Writer, text lang.Catalog, verb, kindName, value string, result agent.TrustResult) {
	switch verb {
	case agent.TrustList:
		printAnchors(out, text, result)
	case agent.TrustAdd:
		fmt.Fprintln(out, text.Format("agent.trust_done_add", kindName, value))
	case agent.TrustRemove:
		fmt.Fprintln(out, text.Format("agent.trust_done_remove", kindName, value))
	}
	if result.AuditError != nil {
		fmt.Fprintln(os.Stderr, text.Format("agent.trust_audit_failed", result.AuditError.Error()))
	}
}

// printAnchors écrit un type par ligne, dans l'ordre du registre : ses valeurs,
// « aucune » ou « illisible ». Les deux derniers états se distinguent.
func printAnchors(out io.Writer, text lang.Catalog, result agent.TrustResult) {
	for _, kind := range anchor.Kinds() {
		switch {
		case result.State.Unreadable[kind.Name]:
			fmt.Fprintf(out, "%s\t%s\n", kind.Name, text.Get("agent.trust_list_unreadable"))
		case len(result.State.Values[kind.Name]) == 0:
			fmt.Fprintf(out, "%s\t%s\n", kind.Name, text.Get("agent.trust_list_none"))
		default:
			fmt.Fprintf(out, "%s\t%s\n", kind.Name, strings.Join(result.State.Values[kind.Name], " "))
		}
	}
}

func explainTrustError(err error, kindName string, text lang.Catalog) error {
	var unsafe *agent.UnsafeStateError
	switch {
	case errors.Is(err, agent.ErrTrustNotRoot):
		return &refusal{message: text.Get("agent.trust_root_only")}
	case errors.Is(err, agent.ErrTrustUnknownKind):
		return &refusal{message: text.Format("agent.trust_unknown_kind", kindName, strings.Join(anchor.Names(), ", "))}
	case errors.Is(err, agent.ErrTrustUnknownVerb):
		return &refusal{message: text.Format("agent.trust_usage", brand.AgentCurrentPath, strings.Join(anchor.Names(), ", "))}
	case errors.Is(err, agent.ErrNotEnrolled):
		return &refusal{message: text.Get("agent.not_enrolled")}
	case errors.As(err, &unsafe):
		return &refusal{message: text.Format("agent.trust_unsafe", unsafe.Error())}
	case errors.Is(err, anchor.ErrUnreadable):
		return &refusal{message: text.Format("agent.trust_value_invalid", kindName)}
	case errors.Is(err, anchor.ErrTooMany):
		return &refusal{message: text.Format("agent.trust_full", kindName)}
	case errors.Is(err, anchor.ErrStoredUnreadable):
		return &refusal{message: text.Format("agent.trust_stored_unreadable", kindName)}
	case errors.Is(err, anchor.ErrAbsent):
		return &refusal{message: text.Format("agent.trust_absent", kindName)}
	}
	return err
}

// auditToSystemJournal écrit le changement au journal du système : /dev/log,
// que journald lit, sous le nom de l'agent et la facilité « authpriv ».
func auditToSystemJournal(message string) error {
	writer, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_AUTHPRIV, brand.AgentAccount)
	if err != nil {
		return err
	}
	defer writer.Close()
	return writer.Notice(message)
}
