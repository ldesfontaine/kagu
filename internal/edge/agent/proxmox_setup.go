package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// « agent proxmox-token » pose le jeton Proxmox local de l'agent sur l'hôte
// (décision de Lucas du 26/11/2026, #902) : le rôle réduit, le compte, son
// rôle sur /vms, le jeton, puis le fichier du jeton dans l'état de l'agent,
// en 0600 au compte de l'agent, avec l'empreinte du certificat de l'API
// locale. Le plan se dit avant la question [o/N], comme grant. Le secret
// sort de « pveum user token add » et n'entre que dans ce fichier : ni ligne
// de commande, ni écran, ni journal, ni message d'erreur. « agent revoke »
// du dernier droit qui s'en sert retire tout (planProxmoxToken).

var (
	// ErrNotProxmoxHost : l'agent ne reconnaît pas un hôte Proxmox VE ici.
	ErrNotProxmoxHost = refusal.Invalid("agent.proxmox_token_not_proxmox", "this machine is not a Proxmox VE host")
	// ErrProxmoxRightMissing : sans proxmox.power ni proxmox.snapshot, le
	// prochain grant ou revoke retirerait le jeton.
	ErrProxmoxRightMissing = refusal.Invalid("agent.proxmox_token_no_right", "grant proxmox.power or proxmox.snapshot first")
)

const (
	// pveum est l'outil de Proxmox qui gère rôles, comptes, droits et jetons ;
	// pveumFormat et pveumJSON le font répondre en JSON.
	pveum       = "pveum"
	pveumFormat = "--output-format"
	pveumJSON   = "json"
)

// ProxmoxTokenChange est ce que « agent proxmox-token » prévoit, et ce qui en
// est posé ; AuditError, l'échec de la trace au journal du système.
type ProxmoxTokenChange struct {
	Plan       []Prerequisite
	Laid       []Prerequisite
	AuditError error
}

// LayProxmoxToken pose le jeton : root seul, sur un hôte Proxmox VE dont la
// politique porte proxmox.power ou proxmox.snapshot. Le plan se lit avant
// confirm, empreinte du certificat comprise ; rien n'est créé sans son
// accord. Un pas qui échoue arrête la pose : Laid dit ce qui l'est.
func LayProxmoxToken(opts PolicyOptions, confirm func([]Prerequisite) error) (ProxmoxTokenChange, error) {
	report, err := ReadPolicyAsRoot(opts)
	if err != nil {
		return ProxmoxTokenChange{}, err
	}
	system := opts.system()
	if !system.Proxmox() {
		return ProxmoxTokenChange{}, ErrNotProxmoxHost
	}
	if !agentpolicy.NeedsProxmoxToken(report.Applied.Rights) {
		return ProxmoxTokenChange{}, ErrProxmoxRightMissing
	}
	account, err := agentAccountOf(opts.StateDir)
	if err != nil {
		return ProxmoxTokenChange{}, err
	}
	plan, err := planProxmoxTokenSetup(system, opts.StateDir, opts.StatePath, account)
	if err != nil {
		return ProxmoxTokenChange{}, err
	}
	if err := confirm(plan); err != nil {
		return ProxmoxTokenChange{}, err
	}
	change := ProxmoxTokenChange{Plan: plan}
	change.Laid, err = layPrerequisites(system, plan)
	if opts.Audit != nil && len(change.Laid) > 0 {
		change.AuditError = opts.Audit(fmt.Sprintf("proxmox-token role %s user %s acl %s token %s file %s (uid %d)",
			machine.ProxmoxRole, machine.ProxmoxUser, machine.ProxmoxACLPath, machine.ProxmoxTokenID, machine.ProxmoxTokenFile(opts.StatePath), opts.EUID))
	}
	return change, err
}

// planProxmoxTokenSetup dit, dans l'ordre : le rôle (créé, ou remis à ses
// seuls privilèges), le compte s'il manque, ses rôles ailleurs que sur /vms
// retirés, son rôle sur /vms, le jeton (remplacé s'il existe : son secret
// n'est plus lisible nulle part), le fichier, puis la relance de l'agent,
// qui juge ses droits au démarrage et redit proxmox.* exerçable.
func planProxmoxTokenSetup(system System, stateDir *os.Root, statePath string, account hostAccount) ([]Prerequisite, error) {
	objects, err := readProxmoxObjects(system)
	if err != nil {
		return nil, err
	}
	fingerprint, err := system.ProxmoxCertificate()
	if err != nil {
		return nil, fmt.Errorf("read the certificate of the local Proxmox API: %w", err)
	}
	privileges := machine.ProxmoxRolePrivileges()
	roleVerb := "add"
	if objects.role {
		roleVerb = "modify"
	}
	plan := []Prerequisite{{Kind: PrerequisiteProxmoxRole, Detail: machine.ProxmoxRole + " (" + strings.Join(privileges, ", ") + ")", lay: func(system System) error {
		return system.Run(pveum, "role", roleVerb, machine.ProxmoxRole, "--privs", strings.Join(privileges, ","))
	}}}
	if !objects.user {
		plan = append(plan, Prerequisite{Kind: PrerequisiteProxmoxUser, Detail: machine.ProxmoxUser, lay: func(system System) error {
			return system.Run(pveum, "user", "add", machine.ProxmoxUser)
		}})
	}
	for _, stray := range objects.strayACLs {
		plan = append(plan, Prerequisite{Kind: PrerequisiteProxmoxACLRemoved, Detail: stray.Path + " " + stray.Role, lay: func(system System) error {
			return system.Run(pveum, "acl", "delete", stray.Path, "--users", machine.ProxmoxUser, "--roles", stray.Role)
		}})
	}
	plan = append(plan, Prerequisite{Kind: PrerequisiteProxmoxACL, Detail: machine.ProxmoxACLPath, lay: func(system System) error {
		return system.Run(pveum, "acl", "modify", machine.ProxmoxACLPath, "--users", machine.ProxmoxUser, "--roles", machine.ProxmoxRole)
	}})
	// Le secret passe du pas du jeton à celui du fichier, en mémoire seule.
	var secret string
	token := Prerequisite{Kind: PrerequisiteProxmoxToken, Detail: machine.ProxmoxTokenID, lay: func(system System) error {
		if objects.token {
			if err := system.Run(pveum, "user", "token", "remove", machine.ProxmoxUser, machine.ProxmoxTokenName); err != nil {
				return err
			}
		}
		var err error
		secret, err = addProxmoxToken(system)
		return err
	}}
	if objects.token {
		token.Kind = PrerequisiteProxmoxTokenReplaced
	}
	file := Prerequisite{Kind: PrerequisiteProxmoxTokenFile, Detail: machine.ProxmoxTokenFile(statePath), lay: func(System) error {
		return writeProxmoxToken(stateDir, account.owner, proxmoxToken{ID: machine.ProxmoxTokenID, Secret: secret, Fingerprint: fingerprint})
	}}
	restart := Prerequisite{Kind: PrerequisiteRestart, Detail: brand.AgentUnit, lay: restartAgent}
	return append(plan, token, file, restart), nil
}

// addProxmoxToken crée le jeton et rend son secret. --privsep 0 : le jeton a
// les droits du compte, qui n'a que le rôle réduit sur /vms. La sortie de
// pveum porte le secret : elle n'entre dans aucune erreur.
func addProxmoxToken(system System) (string, error) {
	output, err := system.Output(pveum, "user", "token", "add", machine.ProxmoxUser, machine.ProxmoxTokenName, "--privsep", "0", pveumFormat, pveumJSON)
	if err != nil {
		return "", err
	}
	var created struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(output, &created) != nil || created.Value == "" {
		return "", errors.New("pveum did not give the token secret in JSON")
	}
	return created.Value, nil
}

// writeProxmoxToken juge le jeton comme l'agent le jugera, puis l'écrit d'un
// coup, en 0600, au compte de l'agent.
func writeProxmoxToken(stateDir *os.Root, owner fsx.Owner, token proxmoxToken) error {
	judged, reason := judgeProxmoxToken(token)
	if reason != "" {
		return fmt.Errorf("the token is not usable by the agent: %s", reason)
	}
	content, err := json.Marshal(judged) // #nosec G117 -- le secret va dans le fichier du jeton, 0600, et nulle part ailleurs.
	if err != nil {
		return err
	}
	return fsx.WriteAtomicOwned(stateDir, brand.AgentProxmoxFile, append(content, '\n'), 0o600, owner)
}

// planProxmoxToken est la part du jeton dans le plan de grant et revoke :
// un droit le demande et le fichier manque, la commande qui le pose est dite ;
// plus aucun droit ne le demande, le jeton, le compte, le rôle et le fichier
// sont retirés, ceux qui restent.
func planProxmoxToken(system System, stateDir *os.Root, statePath string, after []agentpolicy.Capability) ([]Prerequisite, error) {
	_, statErr := stateDir.Lstat(brand.AgentProxmoxFile)
	fileThere := statErr == nil
	if agentpolicy.NeedsProxmoxToken(after) {
		if system.Proxmox() && !fileThere {
			return []Prerequisite{{Kind: PrerequisiteProxmoxTokenMissing, Detail: machine.ProxmoxTokenLine()}}, nil
		}
		return nil, nil
	}
	var objects proxmoxObjects
	if system.Proxmox() {
		var err error
		if objects, err = readProxmoxObjects(system); err != nil {
			return nil, err
		}
	}
	var removed []string
	var commands [][]string
	if objects.token {
		removed = append(removed, machine.ProxmoxTokenID)
		commands = append(commands, []string{pveum, "user", "token", "remove", machine.ProxmoxUser, machine.ProxmoxTokenName})
	}
	if objects.user {
		removed = append(removed, machine.ProxmoxUser)
		commands = append(commands, []string{pveum, "user", "delete", machine.ProxmoxUser})
	}
	if objects.role {
		removed = append(removed, machine.ProxmoxRole)
		commands = append(commands, []string{pveum, "role", "delete", machine.ProxmoxRole})
	}
	if fileThere {
		removed = append(removed, machine.ProxmoxTokenFile(statePath))
	}
	if len(removed) == 0 {
		return nil, nil
	}
	return []Prerequisite{{Kind: PrerequisiteProxmoxTokenRemoved, Detail: strings.Join(removed, " "), lay: func(system System) error {
		if err := runAll(system, commands); err != nil {
			return err
		}
		if err := stateDir.Remove(brand.AgentProxmoxFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}}}, nil
}

// proxmoxObjects dit ce qui existe déjà dans Proxmox du jeton de l'agent ;
// strayACLs, les rôles du compte ailleurs que le sien sur /vms (une pose à la
// main d'avant la commande, sur « / »).
type proxmoxObjects struct {
	role, user, token bool
	strayACLs         []proxmoxACL
}

type proxmoxACL struct {
	Path string `json:"path"`
	Who  string `json:"ugid"`
	Role string `json:"roleid"`
}

// readProxmoxObjects lit les rôles, les comptes, les droits et, si le compte
// existe, ses jetons.
func readProxmoxObjects(system System) (proxmoxObjects, error) {
	var objects proxmoxObjects
	var roles []struct {
		ID string `json:"roleid"`
	}
	if err := readPveum(system, &roles, "role", "list"); err != nil {
		return objects, err
	}
	for _, role := range roles {
		objects.role = objects.role || role.ID == machine.ProxmoxRole
	}
	var users []struct {
		ID string `json:"userid"`
	}
	if err := readPveum(system, &users, "user", "list"); err != nil {
		return objects, err
	}
	for _, user := range users {
		objects.user = objects.user || user.ID == machine.ProxmoxUser
	}
	if !objects.user {
		return objects, nil
	}
	var acls []proxmoxACL
	if err := readPveum(system, &acls, "acl", "list"); err != nil {
		return objects, err
	}
	for _, acl := range acls {
		if acl.Who == machine.ProxmoxUser && (acl.Path != machine.ProxmoxACLPath || acl.Role != machine.ProxmoxRole) {
			objects.strayACLs = append(objects.strayACLs, acl)
		}
	}
	var tokens []struct {
		ID string `json:"tokenid"`
	}
	if err := readPveum(system, &tokens, "user", "token", "list", machine.ProxmoxUser); err != nil {
		return objects, err
	}
	for _, token := range tokens {
		objects.token = objects.token || token.ID == machine.ProxmoxTokenName
	}
	return objects, nil
}

// readPveum lance une lecture de pveum en JSON et la décode dans into.
func readPveum(system System, into any, args ...string) error {
	output, err := system.Output(pveum, append(args, pveumFormat, pveumJSON)...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(output, into); err != nil {
		return fmt.Errorf("pveum %s: unexpected answer: %w", strings.Join(args, " "), err)
	}
	return nil
}
