package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
)

// kagu agent proxmox-token : pose le jeton Proxmox local de l'agent, en root
// sur l'hôte (décision de Lucas du 26/11/2026, #902). La commande dit ce
// qu'elle crée et demande [o/N] comme grant (R-DROIT-8) ; le secret ne passe
// ni à l'écran ni au journal.
func runAgentProxmoxToken(args []string, command policyCommand) error {
	flags := flag.NewFlagSet("agent "+machine.ProxmoxTokenCommand, flag.ContinueOnError)
	stateDir := flags.String("state", defaultAgentStateDir, "répertoire d'état de l'agent")
	yes := flags.Bool("yes", false, "sans terminal seulement (script, cloud-init) : confirme sans poser la question ; avec un terminal, la question est posée")
	if err := flags.Parse(args); err != nil {
		return err
	}
	catalogs, err := lang.Load()
	if err != nil {
		return err
	}
	text := catalogs.For(lang.Default)
	if flags.NArg() != 0 {
		return &refusal{message: text.Format("agent.proxmox_token_usage", brand.Command)}
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
		return &refusal{message: text.Get("agent.proxmox_token_root_only")}
	}
	place, err := command.place(root)
	if err != nil {
		return err
	}
	opts := agent.PolicyOptions{StateDir: root, StatePath: *stateDir, Place: place, EUID: command.euid, Audit: auditToSystemJournal, System: command.system}
	change, err := agent.LayProxmoxToken(opts, func(plan []agent.Prerequisite) error {
		return confirmOnTerminal(command.out, command.openTerminal, *yes, text, func() {
			fmt.Fprintln(command.out, text.Get("agent.proxmox_token_plan"))
			for _, step := range plan {
				fmt.Fprintln(command.out, "  "+prerequisiteText(text, step))
			}
		})
	})
	for _, step := range change.Laid {
		fmt.Fprintln(command.out, "  ✓ "+prerequisiteText(text, step))
	}
	if change.AuditError != nil {
		fmt.Fprintln(os.Stderr, text.Format("agent.trust_audit_failed", change.AuditError.Error()))
	}
	if err != nil && len(change.Laid) > 0 {
		return &refusal{message: text.Format("agent.proxmox_token_failed", err.Error())}
	}
	if err != nil {
		return explainPolicyError(err, text)
	}
	fmt.Fprintln(command.out, text.Get("agent.proxmox_token_done"))
	return nil
}
