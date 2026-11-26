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

// kagu agent rights | grant <droit>[=valeur]… [--for <durée>|permanent]
// | grant --set observe|manage|root | grant --pending | revoke <droit>… : la politique de
// l'agent (fiche A3), root seul. grant et revoke disent ce qui change, et ce
// qu'ils font aussi sur le système, demandent [o/N] (R-A3-15), écrivent la
// politique d'un coup sous son verrou, tracent le changement au journal du
// système (journald), puis posent ce que les droits demandent (R-A3-8).

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
// à part : où elle écrit, le terminal de la question, le compte qui la lance,
// où vit la politique, le système que grant prépare et l'horloge où une
// échéance se pose (nil : la machine).
type policyCommand struct {
	out          io.Writer
	openTerminal terminalOpener
	euid         int
	place        policyPlacer
	system       agent.System
	clock        func() agentpolicy.Clock
}

func runAgentPolicy(verb string, args []string, command policyCommand) error {
	flags := flag.NewFlagSet("agent policy", flag.ContinueOnError)
	stateDir := flags.String("state", defaultAgentStateDir, "répertoire d'état de l'agent")
	yes := flags.Bool("yes", false, "sans terminal seulement (script, cloud-init) : confirme sans poser la question ; avec un terminal, la question est posée")
	forTerm := flags.String("for", "", "grant : la durée des droits posés, de 5m à 168h, ou permanent")
	setName := flags.String("set", "", "grant : remplace les droits des jeux par ceux de observe, manage ou root")
	pending := flags.Bool("pending", false, "grant : pose les droits que l'agent a refusés ces dernières 24 h, après un « o » tapé au clavier")
	names, err := parseWordsAndFlags(flags, args)
	if err != nil {
		return err
	}
	catalogs, err := lang.Load()
	if err != nil {
		return err
	}
	text := catalogs.For(lang.Default)
	withSet := *setName != ""
	bare := verb == policyRights || withSet || *pending
	if bare != (len(names) == 0) || (verb != policyGrant && (*forTerm != "" || withSet || *pending)) || (withSet && *forTerm != "") || (*pending && (withSet || *forTerm != "")) {
		return &refusal{message: text.Format("agent.policy_usage", brand.Command)}
	}
	// --pending ne se confirme qu'au clavier : -yes poserait ce que l'agent a
	// noté sans que personne ne l'ait lu (R-A3-15).
	if *pending && *yes {
		return &refusal{message: text.Get("agent.pending_no_yes")}
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
	opts := agent.PolicyOptions{StateDir: root, StatePath: *stateDir, Place: place, EUID: command.euid, Audit: auditToSystemJournal, System: command.system, Clock: command.clock}
	if verb == policyRights {
		report, err := agent.ReadPolicyAsRoot(opts)
		if err != nil {
			return explainPolicyError(err, text)
		}
		printPolicyReport(command.out, text, place, report)
		return nil
	}
	if *pending {
		return grantPending(command, opts, text)
	}
	change, err := changeRights(verb, opts, names, *setName, term, confirmChange(command.out, command.openTerminal, *yes, text))
	return finishPolicyChange(command.out, text, change, err)
}

// finishPolicyChange dit ce qu'un geste a écrit et posé, ou pourquoi il s'est
// arrêté.
func finishPolicyChange(out io.Writer, text lang.Catalog, change agent.PolicyChange, err error) error {
	var partial *agent.PrerequisiteError
	if errors.As(err, &partial) {
		printPolicyDone(out, text, partial.Change)
		key := "agent.prerequisites_failed"
		if !partial.Change.Changed() {
			key = "agent.prerequisites_failed_same"
		}
		return &refusal{message: text.Format(key, partial.Err.Error())}
	}
	if err != nil {
		return explainPolicyError(err, text)
	}
	printPolicyDone(out, text, change)
	return nil
}

// grantPending joue « grant --pending » (R-DROIT-8, R-A3-15) : les droits que
// l'agent a lui-même refusés ces dernières 24 h, dits en clair, posés par le
// chemin de grant après un « o » lu sur le terminal de contrôle, jamais sur
// l'entrée standard : la ligne a pu arriver par un pipe. Sans terminal, rien
// ne s'écrit.
func grantPending(command policyCommand, opts agent.PolicyOptions, text lang.Catalog) error {
	pending, err := agent.ReadPendingRightsAsRoot(opts)
	if err != nil {
		return explainPolicyError(err, text)
	}
	for _, entry := range pending.NeedsValue {
		fmt.Fprintln(command.out, text.Format("agent.pending_needs_value", entry.Name, rightLabel(text, entry.Name), brand.Command))
	}
	if len(pending.Grantable) == 0 {
		if len(pending.NeedsValue) == 0 {
			fmt.Fprintln(command.out, text.Get("agent.pending_none"))
		}
		return nil
	}
	confirm := func(change agent.PolicyChange) error {
		printPendingRights(command.out, text, pending.Grantable, change)
		printPolicyChange(command.out, text, change)
		return askOnTerminal(command.out, command.openTerminal, text, "agent.pending_needs_tty")
	}
	change, err := agent.GrantPending(opts, pending.Grantable, confirm)
	return finishPolicyChange(command.out, text, change, err)
}

// printPendingRights dit chaque droit en attente que le geste pose : son nom
// et sa valeur, ce qu'il permet, l'échéance que grant lui donne, le dernier
// refus de l'agent.
func printPendingRights(out io.Writer, text lang.Catalog, pending []agent.PendingRight, change agent.PolicyChange) {
	fmt.Fprintln(out, text.Get("agent.pending_header"))
	fmt.Fprintln(out, text.Get("rights.paste_only_pending"))
	for _, entry := range pending {
		if !slices.Contains(change.Added, entry.Text()) {
			continue
		}
		term := text.Get("agent.pending_permanent")
		if until := change.After.Expiries[entry.Name].Until; !until.IsZero() {
			term = text.Format("agent.pending_until", until.Local().Format(time.DateTime))
		}
		fmt.Fprintln(out, text.Format("agent.pending_right", entry.Text(), rightLabel(text, entry.Name), term, entry.RefusedAt.Local().Format(time.DateTime)))
	}
}

// rightLabel rend ce qu'un droit permet, tel que l'écran le dit
// (web/src/lib/machines.ts, capabilityLabelKey).
func rightLabel(text lang.Catalog, name string) string {
	return text.Get("machine.capability_" + strings.ReplaceAll(name, ".", "_"))
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

// changeRights joue grant, grant --set ou revoke. Les droits et le jeu se
// lisent avant d'ouvrir la politique : un droit mal écrit ne prend pas le
// verrou.
func changeRights(verb string, opts agent.PolicyOptions, names []string, setName string, term agentpolicy.Term, confirm func(agent.PolicyChange) error) (agent.PolicyChange, error) {
	if verb == policyRevoke {
		return agent.RevokeRights(opts, names, confirm)
	}
	if setName != "" {
		set, err := agentpolicy.ParseSet(setName)
		if err != nil {
			return agent.PolicyChange{}, err
		}
		return agent.GrantSet(opts, set, confirm)
	}
	granted, err := agentpolicy.ParsePolicyRights(strings.Join(names, agentpolicy.RightSeparator))
	if err != nil {
		return agent.PolicyChange{}, err
	}
	return agent.GrantRights(opts, granted, term, confirm)
}

// printPolicyChange dit, avant la question, chaque droit, chaque ancre et
// chaque clé du serveur posés et retirés, puis ce que la commande fait aussi
// sur le système (R-A3-15, R-A3-8).
func printPolicyChange(out io.Writer, text lang.Catalog, change agent.PolicyChange) {
	if change.First {
		fmt.Fprintln(out, text.Get("agent.policy_first"))
	}
	if !change.Changed() {
		fmt.Fprintln(out, text.Get("agent.policy_same"))
	} else {
		fmt.Fprintln(out, text.Get("agent.policy_change"))
	}
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
	if len(change.Prerequisites) > 0 {
		fmt.Fprintln(out, text.Get("agent.prerequisites"))
		for _, step := range change.Prerequisites {
			fmt.Fprintln(out, "  "+prerequisiteText(text, step))
		}
	}
	if change.RootOnServer {
		fmt.Fprintln(out, text.Get("agent.policy_root_on_server"))
	}
}

// prerequisiteText dit un pas de la pose des prérequis.
func prerequisiteText(text lang.Catalog, step agent.Prerequisite) string {
	switch step.Kind {
	case agent.PrerequisiteDockerJoin:
		return text.Format("agent.prerequisite_docker_join", step.Detail)
	case agent.PrerequisiteDockerLeave:
		return text.Format("agent.prerequisite_docker_leave", step.Detail)
	case agent.PrerequisiteDockerMissing:
		return text.Get("agent.prerequisite_docker_missing")
	case agent.PrerequisiteFolder:
		return text.Format("agent.prerequisite_folder", step.Detail)
	case agent.PrerequisiteDropIn:
		return text.Format("agent.prerequisite_drop_in", step.Detail)
	case agent.PrerequisiteDropInRemoved:
		return text.Format("agent.prerequisite_drop_in_removed", step.Detail)
	case agent.PrerequisiteOtherDropIn:
		return text.Format("agent.prerequisite_other_drop_in", step.Detail)
	case agent.PrerequisiteRootGate:
		return text.Format("agent.prerequisite_root_gate", step.Detail)
	case agent.PrerequisiteRestart:
		return text.Format("agent.prerequisite_restart", step.Detail)
	}
	return string(step.Kind) + " " + step.Detail
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

// printRightNotices dit, pour chaque droit posé, la phrase de son risque,
// une fois par phrase (« vaut root » sous Gérer pour tous les droits du groupe
// docker) et, posé sous le compte par défaut, la ligne qui le pose sous un
// autre (R-A3-12, N-M6) : avant la question.
func printRightNotices(out io.Writer, text lang.Catalog, change agent.PolicyChange) {
	var said []string
	for _, right := range change.After.Rights {
		if !slices.Contains(change.Added, agentpolicy.FormatCapabilities([]agentpolicy.Capability{right})) {
			continue
		}
		notice := agentpolicy.NoticeOf(right)
		if notice.RiskKey != "" && !slices.Contains(said, notice.RiskKey) {
			said = append(said, notice.RiskKey)
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

// printPolicyDone dit ce qui est écrit et posé ; rien de posé, il redit ce
// qui manque encore (Docker), jamais un prérequis comme posé (E03-10).
func printPolicyDone(out io.Writer, text lang.Catalog, change agent.PolicyChange) {
	switch {
	case change.Changed():
		fmt.Fprintln(out, text.Get("agent.policy_done"))
	case len(change.Laid) > 0:
		fmt.Fprintln(out, text.Get("agent.policy_same"))
	default:
		fmt.Fprintln(out, text.Get("agent.policy_unchanged"))
		for _, step := range change.Prerequisites {
			if step.Kind == agent.PrerequisiteDockerMissing {
				fmt.Fprintln(out, "  "+prerequisiteText(text, step))
			}
		}
		return
	}
	for _, step := range change.Laid {
		fmt.Fprintln(out, "  ✓ "+prerequisiteText(text, step))
	}
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
		printPolicyRefusal(out, text, applied.Refusal, report.Refused)
	}
	for _, capability := range applied.Rights {
		fmt.Fprintln(out, agentpolicy.FormatCapabilities([]agentpolicy.Capability{capability}))
	}
}

// printPolicyRefusal écrit pourquoi la politique est refusée, dans les mots
// de l'onglet Droits, puis la commande qui corrige quand elle existe. Un
// document illisible garde aussi l'erreur du décodeur : la seule à dire
// quelle ligne fautive.
func printPolicyRefusal(out io.Writer, text lang.Catalog, refused agentpolicy.Refusal, err error) {
	fmt.Fprintln(out, text.Format("agent.policy_source_refused", text.Format("rights.refusal_"+refused.Reason, refused.Detail)))
	if line := refused.FixLine(); line != "" {
		fmt.Fprintln(out, "  "+line)
	}
	if refused.Reason == agentpolicy.RefusedUnreadable && err != nil {
		fmt.Fprintln(out, "  "+err.Error())
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
		errors.Is(err, agentpolicy.ErrCapabilityAccount), errors.Is(err, agentpolicy.ErrCapabilityPeers), errors.Is(err, agentpolicy.ErrSetUnknown),
		errors.Is(err, agentpolicy.ErrNoMonotonicClock):
		// Un droit mal écrit, ou une échéance sans horloge monotone, se dit
		// avec la phrase de son refus.
		key, _ := kitrefusal.KeyOf(err)
		return &refusal{message: text.Get(key)}
	}
	return err
}
