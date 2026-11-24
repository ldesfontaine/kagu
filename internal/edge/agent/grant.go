package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
)

// « agent grant », « agent revoke » et « agent trust » : la seule voie qui
// change la politique (R-A3-3). Réservée à root, elle relit la politique sous
// son verrou, dit ce qui change, attend l'accord, puis écrit le fichier d'un
// coup (temporaire puis renommage), à root et au groupe de l'agent, en 0640
// (R-A3-1). Deux gestes en même temps se suivent : le second relit ce que le
// premier a écrit. L'agent en marche relit la politique : pas de redémarrage.
// Sur une machine d'avant la politique, « agent policy migrate » passe
// d'abord (migrate.go) : lui seul crée le dossier (R-A3-16).

var (
	// ErrAgentTooOld : le binaire de l'agent ne lit pas encore la politique ;
	// ce que root y écrirait resterait sans effet, un retrait compris.
	ErrAgentTooOld = errors.New("the agent does not read the policy yet: update it first")
	// ErrNotMigrated : la machine est d'avant la politique ; « agent policy
	// migrate » y recopie d'abord ce qu'identity.json porte.
	ErrNotMigrated = errors.New("no policy directory yet: run agent policy migrate first")
)

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
	// Clock lit l'horloge de la machine (une échéance se pose dessus) ; nil :
	// SystemClock.
	Clock func() agentpolicy.Clock
}

func (o PolicyOptions) clock() agentpolicy.Clock {
	if o.Clock == nil {
		return SystemClock()
	}
	return o.Clock()
}

// PolicyChange est ce qu'un geste change dans la politique : la politique
// d'avant et d'après, et les droits posés et retirés sous leur forme texte.
type PolicyChange struct {
	// First : la machine n'avait pas de politique ; Before est ce dont la
	// première part, et chaque droit qu'elle porte est dit posé.
	First      bool
	Before     agentpolicy.Document
	After      agentpolicy.Document
	Added      []string
	Removed    []string
	AuditError error
}

// Changed dit si le geste change quelque chose ; sinon rien ne s'écrit.
func (c PolicyChange) Changed() bool {
	return !c.Before.Same(c.After)
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
// qu'on ne sait pas lire. Sans dossier de politique, rien ne s'écrit :
// ErrNotMigrated.
func changePolicy(opts PolicyOptions, verb string, change func(agentpolicy.Document) (agentpolicy.Document, error), confirm func(PolicyChange) error) (PolicyChange, error) {
	identity, err := policyWriterIdentity(opts)
	if err != nil {
		return PolicyChange{}, err
	}
	if _, err := os.Lstat(opts.Place.Dir); errors.Is(err, fs.ErrNotExist) {
		return PolicyChange{}, ErrNotMigrated
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
	before, first, err := currentDocument(dir, opts.Place, identity)
	if err != nil {
		return PolicyChange{}, err
	}
	after, err := change(before)
	if err != nil {
		return PolicyChange{}, err
	}
	return writePolicy(opts, dir, verb, PolicyChange{First: first, Before: before, After: after}, confirm)
}

// policyWriterIdentity juge qui écrit la politique : root, sur l'état d'un
// agent enrôlé et bien gardé, dont le binaire lit la politique.
func policyWriterIdentity(opts PolicyOptions) (Identity, error) {
	if err := RequireTrustRoot(opts.EUID); err != nil {
		return Identity{}, err
	}
	identity, err := loadIdentityAsRoot(opts.StateDir, opts.StatePath)
	if err != nil {
		return Identity{}, err
	}
	if identity.PolicyFormat < agentpolicy.FormatVersion {
		return Identity{}, ErrAgentTooOld
	}
	return identity, nil
}

// writePolicy dit le changement à confirm puis l'écrit dans dir, verrou pris ;
// un geste qui ne change rien n'écrit rien et ne demande rien.
func writePolicy(opts PolicyOptions, dir *os.Root, verb string, change PolicyChange, confirm func(PolicyChange) error) (PolicyChange, error) {
	change.Added, change.Removed = agentpolicy.Changes(change.Before.Rights, change.After.Rights)
	if !change.Changed() {
		return change, nil
	}
	if err := confirm(change); err != nil {
		return PolicyChange{}, err
	}
	content, err := agentpolicy.Encode(change.After)
	if err != nil {
		return PolicyChange{}, err
	}
	if err := fsx.WriteAtomicOwned(dir, policyFile, content, policyMode, opts.Place.Owner); err != nil {
		return PolicyChange{}, fmt.Errorf("write policy: %w", err)
	}
	if opts.Audit != nil {
		change.AuditError = opts.Audit(fmt.Sprintf("policy %s +[%s] -[%s] digest %s (uid %d)",
			verb, strings.Join(change.Added, " "), strings.Join(change.Removed, " "), agentpolicy.Digest(content), opts.EUID))
	}
	return change, nil
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

// currentDocument rend la politique d'avant le geste. Sans fichier, dans un
// dossier qui existe : la machine d'identity.json et observe, rien de ce
// qu'identity.json porte d'autre (R-A3-16), et first le dit.
func currentDocument(dir *os.Root, place PolicyPlace, identity Identity) (document agentpolicy.Document, first bool, err error) {
	content, err := readPolicyFile(dir, place)
	if errors.Is(err, errPolicyMissing) {
		return agentpolicy.Document{MachineID: identity.MachineID, Rights: observeOnly()}, true, nil
	}
	if err != nil {
		return document, false, err
	}
	document, err = agentpolicy.Decode(content)
	return document, false, err
}

// PolicyReport est ce que « agent rights » et « agent trust list » montrent :
// ce que l'agent applique, et pourquoi la politique est refusée quand elle
// l'est.
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
	applied, refused := readPolicy(opts.Place, identity, opts.clock())
	return PolicyReport{Applied: applied, Refused: refused}, nil
}
