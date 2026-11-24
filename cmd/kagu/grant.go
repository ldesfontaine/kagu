package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	kitrefusal "github.com/ldesfontaine/kagu/internal/kit/refusal"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// opencloud agent rights | grant <droit>[=valeur]… [--for <durée>|permanent]
// | revoke <droit>… : la politique de l'agent (fiche A3), root seul. grant et
// revoke disent ce qui change, demandent [o/N] (R-A3-15), écrivent la
// politique d'un coup sous son verrou et tracent le changement au journal du
// système (journald).

// Les verbes de la politique, à côté de « trust ».
const (
	policyRights = "rights"
	policyGrant  = "grant"
	policyRevoke = "revoke"
)

// policyPlacer rend où la politique s'écrit pour cet état d'agent ; un test y
// met un dossier et un compte à lui.
type policyPlacer func(stateDir *os.Root) (agent.PolicyPlace, error)

// policyCommand est ce qu'une commande de la politique reçoit, ses arguments
// à part : où elle écrit, le terminal de la question, le compte qui la lance
// et où vit la politique.
type policyCommand struct {
	out          io.Writer
	openTerminal terminalOpener
	euid         int
	place        policyPlacer
}

func runAgentPolicy(verb string, args []string, command policyCommand) error {
	flags := flag.NewFlagSet("agent policy", flag.ContinueOnError)
	stateDir := flags.String("state", defaultAgentStateDir, "répertoire d'état de l'agent")
	yes := flags.Bool("yes", false, "confirme sans poser la question (obligatoire sans terminal)")
	forTerm := flags.String("for", "", "grant : la durée des droits posés, de 5m à 168h, ou permanent")
	names, err := parseWordsAndFlags(flags, args)
	if err != nil {
		return err
	}
	catalogs, err := lang.Load()
	if err != nil {
		return err
	}
	text := catalogs.For(lang.Default)
	if (verb == policyRights) != (len(names) == 0) || (verb != policyGrant && *forTerm != "") {
		return &refusal{message: text.Format("agent.policy_usage", brand.Command)}
	}
	term, err := agentpolicy.ParseTerm(*forTerm)
	if err != nil {
		return &refusal{message: text.Get("agent.policy_for_bounds")}
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
	// Un compte sans privilège est refusé avant tout : ni question ni lecture.
	if err := agent.RequireTrustRoot(command.euid); err != nil {
		return explainPolicyError(err, text)
	}
	place, err := command.place(root)
	if err != nil {
		return err
	}
	opts := agent.PolicyOptions{StateDir: root, StatePath: *stateDir, Place: place, EUID: command.euid, Audit: auditToSystemJournal}
	if verb == policyRights {
		report, err := agent.ReadPolicyAsRoot(opts)
		if err != nil {
			return explainPolicyError(err, text)
		}
		printPolicyReport(command.out, text, place, report)
		return nil
	}
	confirm := func(change agent.PolicyChange) error {
		printPolicyChange(command.out, text, change)
		return confirmChange(command.out, command.openTerminal, *yes, text)
	}
	change, err := changeRights(verb, opts, names, term, confirm)
	if err != nil {
		return explainPolicyError(err, text)
	}
	printPolicyDone(command.out, text, change)
	return nil
}

// parseWordsAndFlags lit les drapeaux où qu'ils soient : « grant
// terminal.host --for 2h » comme « grant --for 2h terminal.host ». Rend les
// mots dans leur ordre.
func parseWordsAndFlags(flags *flag.FlagSet, args []string) ([]string, error) {
	var words []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		if flags.NArg() == 0 {
			return words, nil
		}
		words = append(words, flags.Arg(0))
		args = flags.Args()[1:]
	}
}

// changeRights joue grant ou revoke. Les droits se lisent avant d'ouvrir la
// politique : un droit mal écrit ne prend pas le verrou.
func changeRights(verb string, opts agent.PolicyOptions, names []string, term agentpolicy.Term, confirm func(agent.PolicyChange) error) (agent.PolicyChange, error) {
	if verb == policyRevoke {
		return agent.RevokeRights(opts, names, confirm)
	}
	granted, err := agentpolicy.ParsePolicyRights(strings.Join(names, agentpolicy.RightSeparator))
	if err != nil {
		return agent.PolicyChange{}, err
	}
	return agent.GrantRights(opts, granted, term, confirm)
}

// printPolicyChange dit, avant la question, chaque droit, chaque ancre et
// chaque clé du serveur posés et retirés (R-A3-15).
func printPolicyChange(out io.Writer, text lang.Catalog, change agent.PolicyChange) {
	if change.First {
		fmt.Fprintln(out, text.Get("agent.policy_first"))
	}
	fmt.Fprintln(out, text.Get("agent.policy_change"))
	for _, right := range change.Added {
		fmt.Fprintf(out, "  + %s\n", right)
	}
	for _, right := range change.Removed {
		fmt.Fprintf(out, "  - %s\n", right)
	}
	printExpiryChanges(out, text, change.Before, change.After)
	printRightNotices(out, text, change)
	printAnchorChanges(out, change.Before.Anchors, change.After.Anchors)
	printServerKeyChanges(out, text, change.Before.ServerKeys, change.After.ServerKeys)
}

// printExpiryChanges dit l'échéance de chaque droit qui en prend une, ou qui
// perd la sienne (R-A3-5, R-A3-15).
func printExpiryChanges(out io.Writer, text lang.Catalog, before, after agentpolicy.Document) {
	for _, right := range after.Rights {
		was, now := before.Expiries[right.Name], after.Expiries[right.Name]
		switch {
		case !now.Until.IsZero() && !now.Until.Equal(was.Until):
			fmt.Fprintln(out, text.Format("agent.policy_right_until", right.Name, now.Until.Local().Format(time.DateTime)))
		case now.Until.IsZero() && !was.Until.IsZero():
			fmt.Fprintln(out, text.Format("agent.policy_right_permanent", right.Name))
		}
	}
}

// printRightNotices dit, pour chaque droit posé, la phrase de son risque et,
// posé sous le compte par défaut, la ligne qui le pose sous un autre
// (R-A3-12, N-M6) : avant la question.
func printRightNotices(out io.Writer, text lang.Catalog, change agent.PolicyChange) {
	for _, right := range change.After.Rights {
		if !slices.Contains(change.Added, agentpolicy.FormatCapabilities([]agentpolicy.Capability{right})) {
			continue
		}
		notice := agentpolicy.NoticeOf(right)
		if notice.RiskKey != "" {
			fmt.Fprintln(out, text.Get(notice.RiskKey))
		}
		if notice.OtherAccount {
			term := agentpolicy.TermPermanent
			if expiry := change.After.Expiries[right.Name]; !expiry.Until.IsZero() {
				term = agentpolicy.FormatTerm(expiry.Until.Sub(expiry.Granted.Now))
			}
			fmt.Fprintln(out, text.Format("agent.policy_other_account", brand.Command, right.Name, term))
		}
	}
}

// printAnchorChanges dit chaque ancre posée et retirée, type par type ; une
// empreinte de certificat se dit aussi en court, pour la comparer à l'œil.
func printAnchorChanges(out io.Writer, before, after map[string][]string) {
	for _, kind := range anchor.Kinds() {
		for _, value := range after[kind.Name] {
			if !slices.Contains(before[kind.Name], value) {
				fmt.Fprintf(out, "  + %s %s%s\n", kind.Name, value, shortFingerprintOf(kind, value))
			}
		}
		for _, value := range before[kind.Name] {
			if !slices.Contains(after[kind.Name], value) {
				fmt.Fprintf(out, "  - %s %s%s\n", kind.Name, value, shortFingerprintOf(kind, value))
			}
		}
	}
}

func shortFingerprintOf(kind anchor.Kind, value string) string {
	if kind.Name != anchor.ResticTargetCert || !kind.Valid(value) {
		return ""
	}
	return " (" + value[:16] + ")"
}

// printServerKeyChanges dit l'empreinte de chaque clé du serveur retirée,
// posée ou gardée avec son échéance, puis renvoie à la machine du serveur
// pour comparer l'empreinte de la neuve : jamais à l'écran, qu'un serveur
// compromis écrit (R-A3-15).
func printServerKeyChanges(out io.Writer, text lang.Catalog, before, after []agentpolicy.ServerKey) {
	held := func(keys []agentpolicy.ServerKey, key []byte) bool {
		return slices.ContainsFunc(keys, func(other agentpolicy.ServerKey) bool { return slices.Equal(other.Key, key) })
	}
	for _, key := range before {
		if !held(after, key.Key) {
			fmt.Fprintln(out, text.Format("agent.trust_server_key_removed", agentwire.KeyFingerprint(key.Key)))
		}
	}
	var added []string
	for _, key := range after {
		fingerprint := agentwire.KeyFingerprint(key.Key)
		switch {
		case !held(before, key.Key):
			added = append(added, fingerprint)
			fmt.Fprintln(out, text.Format("agent.trust_server_key_added", fingerprint))
		case !key.Until.IsZero():
			fmt.Fprintln(out, text.Format("agent.trust_server_key_kept", fingerprint, key.Until.Local().Format(time.DateTime)))
		}
	}
	for _, fingerprint := range added {
		fmt.Fprintln(out, text.Format("agent.trust_server_key_compare", fingerprint))
	}
}

func printPolicyDone(out io.Writer, text lang.Catalog, change agent.PolicyChange) {
	if !change.Changed() {
		fmt.Fprintln(out, text.Get("agent.policy_unchanged"))
		return
	}
	fmt.Fprintln(out, text.Get("agent.policy_done"))
	if change.AuditError != nil {
		fmt.Fprintln(os.Stderr, text.Format("agent.trust_audit_failed", change.AuditError.Error()))
	}
}

// printPolicyReport écrit d'où viennent les droits, puis un droit par ligne.
func printPolicyReport(out io.Writer, text lang.Catalog, place agent.PolicyPlace, report agent.PolicyReport) {
	applied := report.Applied
	switch applied.Source {
	case agentpolicy.SourcePolicy:
		fmt.Fprintln(out, text.Format("agent.policy_source_policy", place.Dir+"/"+brand.AgentPolicyFile, applied.Digest))
	case agentpolicy.SourceIdentity:
		fmt.Fprintln(out, text.Format("agent.policy_source_identity", agentpolicy.MigrateLine()))
	case agentpolicy.SourceRefused:
		fmt.Fprintln(out, text.Format("agent.policy_source_refused", report.Refused.Error()))
	}
	for _, capability := range applied.Rights {
		fmt.Fprintln(out, agentpolicy.FormatCapabilities([]agentpolicy.Capability{capability}))
	}
}

func explainPolicyError(err error, text lang.Catalog) error {
	var unsafe *agent.UnsafeStateError
	switch {
	case errors.Is(err, agent.ErrTrustNotRoot):
		return &refusal{message: text.Get("agent.policy_root_only")}
	case errors.Is(err, agent.ErrAgentTooOld):
		return &refusal{message: text.Get("agent.policy_agent_too_old")}
	case errors.Is(err, agent.ErrNotMigrated):
		return &refusal{message: text.Format("agent.policy_not_migrated", agentpolicy.MigrateLine())}
	case errors.Is(err, agent.ErrNotEnrolled):
		return &refusal{message: text.Get("agent.not_enrolled")}
	case errors.Is(err, agentpolicy.ErrRevokeObserve):
		return &refusal{message: text.Get("agent.policy_revoke_observe")}
	case errors.As(err, &unsafe):
		return &refusal{message: text.Format("agent.policy_unsafe", unsafe.Error())}
	case errors.Is(err, agentpolicy.ErrUnreadable):
		return &refusal{message: text.Format("agent.policy_unreadable", err.Error())}
	case errors.Is(err, agentpolicy.ErrCapabilityUnknown), errors.Is(err, agentpolicy.ErrCapabilityPath), errors.Is(err, agentpolicy.ErrCapabilityScope),
		errors.Is(err, agentpolicy.ErrCapabilityAccount):
		// Un droit mal écrit se dit avec la phrase de son refus.
		key, _ := kitrefusal.KeyOf(err)
		return &refusal{message: text.Get(key)}
	}
	return err
}
