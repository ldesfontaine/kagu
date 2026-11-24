package agent

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
)

// « agent grant » et « agent revoke » : la seule voie qui change la politique
// (R-A3-3). Réservée à root, elle relit la politique sous son verrou, dit ce
// qui change, attend l'accord, puis écrit le fichier d'un coup (temporaire
// puis renommage), à root et au groupe de l'agent, en 0640 (R-A3-1). Deux
// gestes en même temps se suivent : le second relit ce que le premier a
// écrit. L'agent en marche relit la politique : pas de redémarrage.

// ErrAgentTooOld : le binaire de l'agent ne lit pas encore la politique ; ce
// que root y écrirait resterait sans effet, un retrait compris.
var ErrAgentTooOld = errors.New("the agent does not read the policy yet: update it first")

// PolicyOptions est ce que les commandes de la politique touchent : l'état de
// l'agent (son identité), la politique, qui les lance et où va leur trace.
type PolicyOptions struct {
	StateDir  *os.Root
	StatePath string
	Place     PolicyPlace
	// EUID est celui du processus ; un test y met le sien.
	EUID int
	// Audit reçoit la phrase du changement pour le journal du système
	// (journald) ; nil : pas de trace. Son échec ne défait pas le changement :
	// il est rendu dans PolicyChange.
	Audit func(message string) error
}

// PolicyChange est ce qu'un geste change dans la politique : les droits posés
// et retirés, sous leur forme texte, et la politique d'après.
type PolicyChange struct {
	// First : la machine n'avait pas de politique ; la première part des
	// droits d'identity.json, et chacun est dit posé.
	First      bool
	Added      []string
	Removed    []string
	After      agentpolicy.Document
	AuditError error
}

// Changed dit si le geste change quelque chose ; sinon rien ne s'écrit.
func (c PolicyChange) Changed() bool {
	return len(c.Added) > 0 || len(c.Removed) > 0
}

// GrantRights pose des droits (« docker.deploy », « files.write=/srv/a »).
func GrantRights(opts PolicyOptions, granted []agentpolicy.Capability, confirm func(PolicyChange) error) (PolicyChange, error) {
	return changePolicy(opts, "grant", func(document agentpolicy.Document) (agentpolicy.Document, error) {
		return document.Grant(granted)
	}, confirm)
}

// RevokeRights retire des droits, par leur nom.
func RevokeRights(opts PolicyOptions, names []string, confirm func(PolicyChange) error) (PolicyChange, error) {
	return changePolicy(opts, "revoke", func(document agentpolicy.Document) (agentpolicy.Document, error) {
		return document.Revoke(names)
	}, confirm)
}

// changePolicy relit la politique sous son verrou, y applique change, dit ce
// qui change à confirm, et n'écrit que si confirm l'accepte. Une politique qui
// ne se lit pas, ou mal gardée, n'est pas réécrite : on ne pose rien sur ce
// qu'on ne sait pas lire.
func changePolicy(opts PolicyOptions, verb string, change func(agentpolicy.Document) (agentpolicy.Document, error), confirm func(PolicyChange) error) (PolicyChange, error) {
	if err := RequireTrustRoot(opts.EUID); err != nil {
		return PolicyChange{}, err
	}
	identity, err := loadIdentityAsRoot(opts.StateDir, opts.StatePath)
	if err != nil {
		return PolicyChange{}, err
	}
	if identity.PolicyFormat < agentpolicy.FormatVersion {
		return PolicyChange{}, ErrAgentTooOld
	}
	dir, err := openPolicyDir(opts.Place)
	if err != nil {
		return PolicyChange{}, err
	}
	defer dir.Close()
	unlock, err := lockFile(dir, policyLockFile, nil)
	if err != nil {
		return PolicyChange{}, err
	}
	defer unlock()
	before, base, first, err := currentDocument(dir, opts.Place, identity)
	if err != nil {
		return PolicyChange{}, err
	}
	after, err := change(base)
	if err != nil {
		return PolicyChange{}, err
	}
	added, removed := agentpolicy.Changes(before.Rights, after.Rights)
	result := PolicyChange{First: first, Added: added, Removed: removed, After: after}
	if !result.Changed() {
		return result, nil
	}
	if err := confirm(result); err != nil {
		return PolicyChange{}, err
	}
	content, err := agentpolicy.Encode(after)
	if err != nil {
		return PolicyChange{}, err
	}
	if err := fsx.WriteAtomicOwned(dir, policyFile, content, policyMode, opts.Place.Owner); err != nil {
		return PolicyChange{}, fmt.Errorf("write policy: %w", err)
	}
	if opts.Audit != nil {
		result.AuditError = opts.Audit(fmt.Sprintf("policy %s +[%s] -[%s] digest %s (uid %d)",
			verb, strings.Join(added, " "), strings.Join(removed, " "), agentpolicy.Digest(content), opts.EUID))
	}
	return result, nil
}

// openPolicyDir ouvre le dossier de la politique, le crée à root en 0755 s'il
// manque, et le juge comme l'agent le jugera.
func openPolicyDir(place PolicyPlace) (*os.Root, error) {
	if err := os.Mkdir(place.Dir, policyDirMode); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create policy dir: %w", err)
	}
	dir, err := os.OpenRoot(place.Dir)
	if err != nil {
		return nil, fmt.Errorf("open policy dir: %w", err)
	}
	if _, err := checkOpenedDir(dir, place.Dir, uint32(place.Owner.UID)); err != nil { // #nosec G115 -- un uid.
		_ = dir.Close()
		return nil, err
	}
	return dir, nil
}

// currentDocument rend la politique d'avant le geste (before) et celle à
// laquelle il s'applique (base). Sans fichier, before est vide et base porte
// la machine et les droits d'identity.json : la première politique les
// recopie, et la commande les montre tous.
func currentDocument(dir *os.Root, place PolicyPlace, identity Identity) (before, base agentpolicy.Document, first bool, err error) {
	content, err := readPolicyFile(dir, place)
	if errors.Is(err, errNoPolicy) {
		before = agentpolicy.Document{MachineID: identity.MachineID}
		base = agentpolicy.Document{MachineID: identity.MachineID, Rights: identity.Capabilities()}
		return before, base, true, nil
	}
	if err != nil {
		return before, base, false, err
	}
	document, err := agentpolicy.Decode(content)
	if err != nil {
		return before, base, false, err
	}
	return document, document, false, nil
}

// PolicyReport est ce que « agent rights » montre : ce que l'agent applique,
// et pourquoi la politique est refusée quand elle l'est.
type PolicyReport struct {
	Applied AppliedPolicy
	Refused error
}

// ReadPolicyAsRoot lit la politique comme l'agent la lit, pour root.
func ReadPolicyAsRoot(opts PolicyOptions) (PolicyReport, error) {
	if err := RequireTrustRoot(opts.EUID); err != nil {
		return PolicyReport{}, err
	}
	identity, err := loadIdentityAsRoot(opts.StateDir, opts.StatePath)
	if err != nil {
		return PolicyReport{}, err
	}
	applied, refused := readPolicy(opts.Place, identity)
	return PolicyReport{Applied: applied, Refused: refused}, nil
}
