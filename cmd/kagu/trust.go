package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"slices"
	"strings"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
)

// kagu agent trust list | add <type> <valeur> | remove <type> <valeur>
// | set server-key <clé> | add server-key <clé> -keep-old <durée> : les ancres
// de confiance locales de l'agent (internal/fact/anchor) et la clé du serveur
// qu'il accepte, dans sa politique. Seule voie qui les change après
// l'installation ; réservée à root. Ce qui change est dit, puis demandé
// [o/N] (R-A3-15) ; le message du changement est écrit au journal du système
// (journald, via /dev/log).
func runAgentTrust(args []string, command policyCommand) error {
	flags := flag.NewFlagSet("agent trust", flag.ContinueOnError)
	stateDir := flags.String("state", defaultAgentStateDir, "répertoire d'état de l'agent")
	yes := flags.Bool("yes", false, "sans terminal seulement (script, cloud-init) : confirme sans poser la question ; avec un terminal, la question est posée")
	keepOld := flags.Duration("keep-old", 0, "add server-key : garde l'ancienne clé acceptée cette durée (5m à 168h)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	catalogs, err := lang.Load()
	if err != nil {
		return err
	}
	text := catalogs.For(lang.Default)
	request, ok := splitTrustArguments(flags.Args())
	// Les drapeaux se donnent aussi après les mots : « add server-key <clé>
	// -keep-old 1h ».
	if ok && request.Verb != agent.TrustList {
		if err := flags.Parse(flags.Args()[3:]); err != nil {
			return err
		}
		ok = flags.NArg() == 0
	}
	if !ok {
		return &refusal{message: trustUsage(text)}
	}
	request.KeepOld = *keepOld
	root, err := openStateDir(*stateDir)
	if err != nil {
		return explainStateDirError(err, *stateDir, agent.CurrentAccount(), text)
	}
	defer root.Close()
	// L'identité connaît la langue choisie à l'installation.
	if identity, loadErr := agent.LoadIdentity(root); loadErr == nil && identity.Language != "" {
		text = catalogs.For(identity.Language)
	}
	// Un compte sans privilège est refusé sans qu'on lui pose la question.
	if err := agent.RequireTrustRoot(command.euid); err != nil {
		return explainTrustError(err, request, text)
	}
	place, err := command.place(root)
	if err != nil {
		return err
	}
	opts := agent.PolicyOptions{StateDir: root, StatePath: *stateDir, Place: place, EUID: command.euid, Audit: auditToSystemJournal, Clock: command.clock}
	if request.Verb == agent.TrustList {
		report, err := agent.ReadPolicyAsRoot(opts)
		if err != nil {
			return explainTrustError(err, request, text)
		}
		printTrustList(command.out, text, report.Applied)
		return nil
	}
	change, err := agent.Trust(opts, request, confirmChange(command.out, command.openTerminal, *yes, text))
	if err != nil {
		return explainTrustError(err, request, text)
	}
	printPolicyDone(command.out, text, change)
	return nil
}

func trustUsage(text lang.Catalog) string {
	return text.Format("agent.trust_usage", brand.Command, strings.Join(anchor.Names(), ", "))
}

// splitTrustArguments lit « list », ou « add|remove|set <type> <valeur> »
// suivi de drapeaux.
func splitTrustArguments(arguments []string) (agent.TrustRequest, bool) {
	switch {
	case len(arguments) == 1 && arguments[0] == agent.TrustList:
		return agent.TrustRequest{Verb: agent.TrustList}, true
	case len(arguments) >= 3 && slices.Contains([]string{agent.TrustAdd, agent.TrustRemove, agent.TrustSet}, arguments[0]):
		return agent.TrustRequest{Verb: arguments[0], Kind: arguments[1], Value: arguments[2]}, true
	}
	return agent.TrustRequest{}, false
}

// printTrustList écrit les clés du serveur acceptées, puis les ancres.
func printTrustList(out io.Writer, text lang.Catalog, applied agent.AppliedPolicy) {
	if len(applied.ServerKeys) == 0 {
		fmt.Fprintf(out, "%s\t%s\n", agentpolicy.TrustServerKey, text.Get("agent.trust_list_none"))
	}
	for _, key := range applied.ServerKeys {
		fmt.Fprintf(out, "%s\t%s\n", agentpolicy.TrustServerKey, ident.KeyFingerprint(key))
	}
	printAnchors(out, text, anchor.FromFile(applied.Anchors))
}

// printAnchors écrit un type par ligne, dans l'ordre du registre : ses valeurs,
// « aucune » ou « illisible ». Les deux derniers états se distinguent.
func printAnchors(out io.Writer, text lang.Catalog, state anchor.State) {
	for _, kind := range anchor.Kinds() {
		switch {
		case state.Unreadable[kind.Name]:
			fmt.Fprintf(out, "%s\t%s\n", kind.Name, text.Get("agent.trust_list_unreadable"))
		case len(state.Values[kind.Name]) == 0:
			fmt.Fprintf(out, "%s\t%s\n", kind.Name, text.Get("agent.trust_list_none"))
		default:
			fmt.Fprintf(out, "%s\t%s\n", kind.Name, strings.Join(state.Values[kind.Name], " "))
		}
	}
}

func explainTrustError(err error, request agent.TrustRequest, text lang.Catalog) error {
	kindName := request.Kind
	var unsafe *agent.UnsafeStateError
	switch {
	case errors.Is(err, agent.ErrTrustNotRoot):
		return &refusal{message: text.Get("agent.trust_root_only")}
	case errors.Is(err, agent.ErrTrustUnknownKind):
		return &refusal{message: text.Format("agent.trust_unknown_kind", kindName, strings.Join(anchor.Names(), ", "))}
	case errors.Is(err, agent.ErrTrustUnknownVerb), errors.Is(err, agent.ErrKeepOldServerKeyOnly):
		return &refusal{message: trustUsage(text)}
	case errors.Is(err, agent.ErrKeepOldRequired):
		return &refusal{message: text.Format("agent.trust_keep_old_required", agentpolicy.AgentLine("trust", agent.TrustSet, agentpolicy.TrustServerKey, request.Value))}
	case errors.Is(err, agentpolicy.ErrDurationOutOfBounds):
		return &refusal{message: text.Get("agent.trust_keep_old_bounds")}
	case errors.Is(err, agentpolicy.ErrNoMonotonicClock):
		return explainPolicyError(err, text)
	case errors.Is(err, agentpolicy.ErrServerKeyInvalid):
		return &refusal{message: text.Get("agent.trust_server_key_invalid")}
	case errors.Is(err, agentpolicy.ErrNoServerKeyToKeep):
		return &refusal{message: text.Get("agent.trust_no_server_key_to_keep")}
	case errors.Is(err, agentpolicy.ErrServerKeyAlreadyAccepted):
		return &refusal{message: text.Get("agent.trust_server_key_already")}
	case errors.Is(err, agent.ErrNotMigrated):
		return &refusal{message: text.Format("agent.policy_not_migrated", agentpolicy.MigrateLine())}
	case errors.Is(err, agent.ErrAgentTooOld):
		return &refusal{message: text.Get("agent.policy_agent_too_old")}
	case errors.Is(err, agentpolicy.ErrUnreadable):
		return &refusal{message: text.Format("agent.policy_unreadable", err.Error())}
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
