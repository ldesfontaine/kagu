package agent

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
)

// « agent trust » : la seule voie qui change les ancres de confiance locales
// d'un agent enrôlé et la clé du serveur qu'il accepte. Réservée à root, elle
// écrit la politique comme « agent grant » (grant.go) : sous son verrou, après
// accord, avec une trace. L'agent en marche relit la politique avant chaque
// ordre : pas de redémarrage.

// Les verbes de la commande.
const (
	TrustList   = "list"
	TrustAdd    = "add"
	TrustSet    = "set"
	TrustRemove = "remove"
)

var (
	// ErrTrustNotRoot : la commande change ce que l'agent, root, accepte
	// d'exécuter ; un compte sans privilège ne la lance pas.
	ErrTrustNotRoot = errors.New("agent trust is reserved to root")
	// ErrTrustUnknownKind : le type n'est pas dans le registre.
	ErrTrustUnknownKind = errors.New("unknown anchor kind")
	// ErrTrustUnknownVerb : ni list, ni add, ni remove, ni set ; ou set sur
	// une ancre, remove sur la clé du serveur.
	ErrTrustUnknownVerb = errors.New("unknown trust verb")
	// ErrKeepOldRequired : « add server-key » sans --keep-old. Garder deux
	// clés sans échéance laisserait une clé volée signer après la rotation
	// (N-M2) : « set » remplace.
	ErrKeepOldRequired = errors.New("add server-key needs --keep-old: use set to replace the key")
	// ErrKeepOldServerKeyOnly : --keep-old ne vaut que pour add server-key.
	ErrKeepOldServerKeyOnly = errors.New("--keep-old only applies to add server-key")
)

// TrustRequest est un geste de la commande : le verbe, le type (une ancre ou
// agentpolicy.TrustServerKey), la valeur et, pour add server-key, combien de
// temps l'ancienne clé reste acceptée.
type TrustRequest struct {
	Verb    string
	Kind    string
	Value   string
	KeepOld time.Duration
}

// RequireTrustRoot refuse tout compte qui n'est pas root : la commande le
// vérifie avant de poser sa question, Trust avant d'écrire.
func RequireTrustRoot(euid int) error {
	if euid != 0 {
		return ErrTrustNotRoot
	}
	return nil
}

// Trust joue un geste sur la politique : add ou remove d'une ancre, set ou
// add --keep-old de la clé du serveur. La liste se lit par ReadPolicyAsRoot.
func Trust(opts PolicyOptions, request TrustRequest, confirm func(PolicyChange) error) (PolicyChange, error) {
	if err := RequireTrustRoot(opts.EUID); err != nil {
		return PolicyChange{}, err
	}
	change, err := trustChange(request, opts.clock)
	if err != nil {
		return PolicyChange{}, err
	}
	verb := "trust " + request.Verb + " " + request.Kind + " " + request.Value
	return changePolicy(opts, verb, leaveSystem, change, confirm)
}

// trustChange rend ce que le geste fait à la politique, ou le refus d'un
// geste mal formé, avant toute lecture.
func trustChange(request TrustRequest, clock func() agentpolicy.Clock) (func(agentpolicy.Document) (agentpolicy.Document, error), error) {
	if request.Kind == agentpolicy.TrustServerKey {
		return serverKeyChange(request, clock)
	}
	if request.KeepOld != 0 {
		return nil, ErrKeepOldServerKeyOnly
	}
	if request.Verb != TrustAdd && request.Verb != TrustRemove {
		return nil, ErrTrustUnknownVerb
	}
	kind, known := anchor.Lookup(request.Kind)
	if !known {
		return nil, ErrTrustUnknownKind
	}
	return func(document agentpolicy.Document) (agentpolicy.Document, error) {
		changed, err := changeAnchors(document.Anchors, request.Verb, kind, request.Value)
		document.Anchors = changed
		return document, err
	}, nil
}

// serverKeyChange : set remplace la clé acceptée ; add la remplace aussi et
// garde l'ancienne jusqu'à l'échéance de --keep-old, sans lequel il est
// refusé (R-A3-14, N-M2).
func serverKeyChange(request TrustRequest, clock func() agentpolicy.Clock) (func(agentpolicy.Document) (agentpolicy.Document, error), error) {
	if request.Verb != TrustSet && request.Verb != TrustAdd {
		return nil, ErrTrustUnknownVerb
	}
	if request.Verb == TrustAdd && request.KeepOld == 0 {
		return nil, ErrKeepOldRequired
	}
	if request.Verb == TrustSet && request.KeepOld != 0 {
		return nil, ErrKeepOldServerKeyOnly
	}
	key, err := agentpolicy.ParseServerKey(request.Value)
	if err != nil {
		return nil, err
	}
	return func(document agentpolicy.Document) (agentpolicy.Document, error) {
		if request.Verb == TrustSet {
			return document.SetServerKey(key), nil
		}
		return document.KeepServerKey(key, request.KeepOld, clock())
	}, nil
}

func changeAnchors(stored map[string][]string, verb string, kind anchor.Kind, value string) (map[string][]string, error) {
	if verb == TrustAdd {
		return anchor.Add(stored, kind, value)
	}
	return anchor.Remove(stored, kind, value)
}

// checkStateAsRoot juge l'état de l'agent pour root, avec les gardes que
// l'agent applique (CheckStateDir), et rend le compte qui le possède.
func checkStateAsRoot(stateDir *os.Root, statePath string) (fsx.Owner, error) {
	owner, err := stateOwner(stateDir)
	if err != nil {
		return fsx.Owner{}, err
	}
	if err := CheckStateDirOwnedBy(stateDir, statePath, uint32(owner.UID)); err != nil { // #nosec G115 -- un uid de stat.
		return fsx.Owner{}, err
	}
	return owner, nil
}

// loadIdentityAsRoot lit l'identité de l'agent pour root, état jugé d'abord.
func loadIdentityAsRoot(stateDir *os.Root, statePath string) (Identity, error) {
	if _, err := checkStateAsRoot(stateDir, statePath); err != nil {
		return Identity{}, err
	}
	return LoadIdentity(stateDir)
}

// stateOwner rend le compte à qui appartient l'état : c'est à lui que le
// fichier réécrit par root reste donné.
func stateOwner(stateDir *os.Root) (fsx.Owner, error) {
	info, err := stateDir.Stat(".")
	if err != nil {
		return fsx.Owner{}, fmt.Errorf("stat state dir: %w", err)
	}
	raw, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fsx.Owner{}, errors.New("no owner reported for the state dir")
	}
	return fsx.Owner{UID: int(raw.Uid), GID: int(raw.Gid)}, nil
}
