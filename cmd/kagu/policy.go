package main

import (
	"flag"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
)

// kagu agent policy migrate : sur une machine installée avant la
// politique, recopie dans la politique les droits, les ancres et la clé du
// serveur qu'identity.json porte, puis les y efface. Root seul ; ce qui est
// recopié est dit, puis demandé [o/N] (R-A3-15).
const policyMigrate = "migrate"

func runAgentPolicyMigrate(args []string, command policyCommand) error {
	flags := flag.NewFlagSet("agent policy migrate", flag.ContinueOnError)
	stateDir := flags.String("state", defaultAgentStateDir, "répertoire d'état de l'agent")
	yes := flags.Bool("yes", false, "confirme sans poser la question (obligatoire sans terminal)")
	catalogs, err := lang.Load()
	if err != nil {
		return err
	}
	text := catalogs.For(lang.Default)
	if len(args) == 0 || args[0] != policyMigrate {
		return &refusal{message: text.Format("agent.policy_migrate_usage", agentpolicy.MigrateLine())}
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return &refusal{message: text.Format("agent.policy_migrate_usage", agentpolicy.MigrateLine())}
	}
	root, err := openStateDir(*stateDir)
	if err != nil {
		return explainStateDirError(err, *stateDir, agent.CurrentAccount(), text)
	}
	defer root.Close()
	if identity, loadErr := agent.LoadIdentity(root); loadErr == nil && identity.Language != "" {
		text = catalogs.For(identity.Language)
	}
	if err := agent.RequireTrustRoot(command.euid); err != nil {
		return explainPolicyError(err, text)
	}
	place, err := command.place(root)
	if err != nil {
		return err
	}
	opts := agent.PolicyOptions{StateDir: root, StatePath: *stateDir, Place: place, EUID: command.euid, Audit: auditToSystemJournal}
	confirm := func(change agent.PolicyChange) error {
		printPolicyChange(command.out, text, change)
		return confirmChange(command.out, command.openTerminal, *yes, text)
	}
	change, err := agent.MigratePolicy(opts, confirm)
	if err != nil {
		return explainPolicyError(err, text)
	}
	printPolicyDone(command.out, text, change)
	return nil
}
