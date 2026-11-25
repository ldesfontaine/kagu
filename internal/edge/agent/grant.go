package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
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
	// System est ce que grant et revoke touchent aussi (R-A3-8) ; nil :
	// HostSystem, la machine.
	System System
}

func (o PolicyOptions) system() System {
	if o.System == nil {
		return HostSystem{}
	}
	return o.System
}

func (o PolicyOptions) clock() agentpolicy.Clock {
	if o.Clock == nil {
		return SystemClock()
	}
	return o.Clock()
}

// PolicyChange est ce qu'un geste change dans la politique : la politique
// d'avant et d'après, et les droits posés et retirés sous leur forme texte ;
// ce qu'il demande au système, et ce qui en est posé (R-A3-8).
type PolicyChange struct {
	// First : la machine n'avait pas de politique ; Before est ce dont la
	// première part, et chaque droit qu'elle porte est dit posé.
	First      bool
	Before     agentpolicy.Document
	After      agentpolicy.Document
	Added      []string
	Removed    []string
	AuditError error
	// Prerequisites : le plan, dit avant la question ; Laid : ce qui en est
	// posé, dans l'ordre.
	Prerequisites []Prerequisite
	Laid          []Prerequisite
	// RootOnServer : la machine du serveur passe en « Gérer en root » ; qui
	// entre dans l'interface y devient root (R-DROIT-5).
	RootOnServer bool
}

// Changed dit si le geste change la politique ; sinon elle ne s'écrit pas.
func (c PolicyChange) Changed() bool {
	return !c.Before.Same(c.After)
}

// LaysPrerequisites dit si le plan pose quelque chose sur le système, la
// politique inchangée ou non (E03-10).
func (c PolicyChange) LaysPrerequisites() bool {
	return slices.ContainsFunc(c.Prerequisites, func(step Prerequisite) bool { return step.lay != nil })
}

// GrantRights pose des droits (« docker.deploy », « files.write=/srv/a »)
// pour le terme donné, l'échéance posée sur l'horloge de la machine (R-A3-5).
func GrantRights(opts PolicyOptions, granted []agentpolicy.Capability, term agentpolicy.Term, confirm func(PolicyChange) error) (PolicyChange, error) {
	return changePolicy(opts, "grant", planSystem, func(document agentpolicy.Document) (agentpolicy.Document, error) {
		return document.Grant(granted, term, opts.clock())
	}, confirm)
}

// GrantSet remplace les droits des jeux par ceux de set (R-A3-7), sans
// échéance, pour la racine des services de l'agent et selon que la machine
// est un hôte Proxmox.
func GrantSet(opts PolicyOptions, set agentpolicy.Set, confirm func(PolicyChange) error) (PolicyChange, error) {
	return changePolicy(opts, "grant", planSystem, func(document agentpolicy.Document) (agentpolicy.Document, error) {
		identity, err := loadIdentityAsRoot(opts.StateDir, opts.StatePath)
		if err != nil {
			return agentpolicy.Document{}, err
		}
		return document.GrantSet(set, agentpolicy.SetHost{ServicesRoot: identity.Root(), Proxmox: opts.system().Proxmox()})
	}, confirm)
}

// RevokeRights retire des droits, par leur nom.
func RevokeRights(opts PolicyOptions, names []string, confirm func(PolicyChange) error) (PolicyChange, error) {
	return changePolicy(opts, "revoke", planSystem, func(document agentpolicy.Document) (agentpolicy.Document, error) {
		return document.Revoke(names)
	}, confirm)
}

// systemPlan dit si un geste refait le plan des prérequis du système : grant
// et revoke le refont à chaque appel, même quand les droits ne changent pas
// (E03-10 : Docker installé après « Gérer ») ; trust ne touche qu'aux ancres.
type systemPlan bool

const (
	planSystem  systemPlan = true
	leaveSystem systemPlan = false
)

// changePolicy relit la politique sous son verrou, y applique change, dit ce
// qui change à confirm, et n'écrit que si confirm l'accepte. Une politique qui
// ne se lit pas, ou mal gardée, n'est pas réécrite : on ne pose rien sur ce
// qu'on ne sait pas lire. Sans dossier de politique, rien ne s'écrit :
// ErrNotMigrated.
func changePolicy(opts PolicyOptions, verb string, plan systemPlan, change func(agentpolicy.Document) (agentpolicy.Document, error), confirm func(PolicyChange) error) (PolicyChange, error) {
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
	planned := PolicyChange{First: first, Before: before, After: after}
	if plan == planSystem {
		if err := planChange(opts, identity, &planned); err != nil {
			return PolicyChange{}, err
		}
	}
	return writePolicy(opts, dir, verb, planned, confirm)
}

// planChange lit ce que les droits d'après demandent au système, qu'ils
// changent ou non, et si la machine du serveur passe en « Gérer en root »
// (R-DROIT-5).
func planChange(opts PolicyOptions, identity Identity, change *PolicyChange) error {
	account, err := agentAccountOf(opts.StateDir)
	if err != nil {
		return err
	}
	system := opts.system()
	change.Prerequisites, err = planPrerequisites(system, account, identity.Root(), change.Before.Rights, change.After.Rights)
	if err != nil {
		return fmt.Errorf("read what the rights ask of the system: %w", err)
	}
	becomesRoot := agentpolicy.CoversSet(change.After.Rights, agentpolicy.SetRoot) && !agentpolicy.CoversSet(change.Before.Rights, agentpolicy.SetRoot)
	change.RootOnServer = becomesRoot && system.ServerMachine()
	return nil
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
// un geste qui ne change ni la politique ni le système n'écrit rien et ne
// demande rien. Une politique inchangée ne se réécrit pas : seul le plan se
// pose, après le même accord (R-A3-15).
func writePolicy(opts PolicyOptions, dir *os.Root, verb string, change PolicyChange, confirm func(PolicyChange) error) (PolicyChange, error) {
	change.Added, change.Removed = agentpolicy.Changes(change.Before.Rights, change.After.Rights)
	if !change.Changed() && !change.LaysPrerequisites() {
		return change, nil
	}
	if err := confirm(change); err != nil {
		return PolicyChange{}, err
	}
	if change.Changed() {
		if err := savePolicy(opts, dir, verb, &change); err != nil {
			return PolicyChange{}, err
		}
	}
	// La politique d'abord : un retrait vaut dès qu'elle est relue, même si
	// le système ne suit pas ; ce qui est posé se dit, l'échec aussi.
	var err error
	change.Laid, err = layPrerequisites(opts.system(), change.Prerequisites)
	if err != nil {
		return change, &PrerequisiteError{Change: change, Err: err}
	}
	return change, nil
}

// savePolicy écrit la politique d'après d'un coup, puis trace le
// changement au journal ; l'échec de la trace se rend dans change.
func savePolicy(opts PolicyOptions, dir *os.Root, verb string, change *PolicyChange) error {
	content, err := agentpolicy.Encode(change.After)
	if err != nil {
		return err
	}
	if err := fsx.WriteAtomicOwned(dir, policyFile, content, policyMode, opts.Place.Owner); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}
	if opts.Audit != nil {
		change.AuditError = opts.Audit(fmt.Sprintf("policy %s +[%s] -[%s] digest %s (uid %d)",
			verb, strings.Join(change.Added, " "), strings.Join(change.Removed, " "), agentpolicy.Digest(content), opts.EUID))
	}
	return nil
}

// PrerequisiteError : la pose du système s'est arrêtée à un pas, la
// politique écrite si elle changeait ; Change dit ce qui est posé.
type PrerequisiteError struct {
	Change PolicyChange
	Err    error
}

func (e *PrerequisiteError) Error() string {
	return "system not fully prepared: " + e.Err.Error()
}
func (e *PrerequisiteError) Unwrap() error { return e.Err }

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
