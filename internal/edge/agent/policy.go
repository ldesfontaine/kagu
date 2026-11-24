package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
)

// La politique de l'agent (fiche A3) : un fichier à root, hors de l'état de
// l'agent, que l'agent lit et n'écrit jamais (R-A3-1). Seuls « agent grant »
// et « agent revoke », en root, l'écrivent (grant.go). L'agent la relit avant
// chaque ordre, toutes les 15 s et à SIGHUP (R-A3-4). Sans politique, il lit
// encore les droits d'identity.json (source identity).

const (
	policyFile     = brand.AgentPolicyFile
	policyMode     = 0o640
	policyDirMode  = 0o755
	policyLockFile = policyFile + ".lock"
	// policyRereadInterval : la relecture sans ordre ni signal (R-A3-4).
	policyRereadInterval = 15 * time.Second
)

// errNoPolicy : ni dossier ni fichier de politique ; les droits viennent
// d'identity.json.
var errNoPolicy = errors.New("no agent policy")

// PolicyPlace est où vit la politique et à qui elle appartient : son dossier,
// et root avec le groupe du compte de l'agent pour le fichier. Le compte
// propriétaire (Owner.UID) est aussi le seul, avec root, à qui le dossier,
// ceux au-dessus et le fichier peuvent appartenir. Les tests y mettent un
// dossier et un compte à eux.
type PolicyPlace struct {
	Dir   string
	Owner fsx.Owner
}

// agentPolicyPlace est ce que l'agent lit : le dossier de root, à root.
// L'agent n'a pas à connaître le groupe, il n'écrit rien.
var agentPolicyPlace = PolicyPlace{Dir: brand.AgentPolicyDir}

// SystemPolicyPlace rend où root écrit la politique : son dossier, le fichier
// à root et au groupe du compte de l'agent, celui qui possède son état.
func SystemPolicyPlace(stateDir *os.Root) (PolicyPlace, error) {
	owner, err := stateOwner(stateDir)
	if err != nil {
		return PolicyPlace{}, err
	}
	return PolicyPlace{Dir: brand.AgentPolicyDir, Owner: fsx.Owner{UID: 0, GID: owner.GID}}, nil
}

// AppliedPolicy est ce que l'agent applique, tel qu'une lecture de la
// politique l'a laissé, et ce qu'il en rapporte au serveur.
type AppliedPolicy struct {
	// MachineID est celle du fichier ; vide hors de la source policy, où
	// celle de l'identité vaut.
	MachineID string
	Rights    []agentpolicy.Capability
	// Source : agentpolicy.SourcePolicy, SourceIdentity ou SourceRefused.
	Source string
	// Digest : l'empreinte du fichier lu (source policy seulement).
	Digest string
	// anchors : les ancres d'identity.json relues avec elle (forme texte),
	// rapportées à côté.
	anchors string
}

// report est ce qu'une lecture change pour le serveur : la source,
// l'empreinte, les droits appliqués et les ancres.
func (p AppliedPolicy) report() string {
	return p.Source + " " + p.Digest + " " + agentpolicy.FormatCapabilities(p.Rights) + " " + p.anchors
}

// readPolicy rend ce que l'agent applique. Sans dossier ni fichier, les
// droits d'identity.json (source identity). Une politique qui ne se lit pas,
// n'appartient pas à root ou s'écrit par un autre compte : observe seul
// (source refused), et l'erreur dit pourquoi (R-A3-6). Rien ne s'élargit sur
// une erreur : ni les droits d'avant ni ceux de l'identité. Un état mal gardé
// (narrowed) n'a que observe, quelle que soit la source.
func readPolicy(place PolicyPlace, identity Identity) (AppliedPolicy, error) {
	document, digest, err := loadPolicy(place)
	var applied AppliedPolicy
	switch {
	case errors.Is(err, errNoPolicy):
		return AppliedPolicy{Rights: identity.Capabilities(), Source: agentpolicy.SourceIdentity}, nil
	case err != nil:
		applied = AppliedPolicy{Rights: observeOnly(), Source: agentpolicy.SourceRefused}
	default:
		applied = AppliedPolicy{MachineID: document.MachineID, Rights: document.Rights, Source: agentpolicy.SourcePolicy, Digest: digest}
	}
	if identity.narrowed {
		applied.Rights = observeOnly()
	}
	return applied, err
}

// loadPolicy ouvre le dossier de la politique, le juge, puis lit et décode le
// fichier : errNoPolicy quand l'un ou l'autre manque.
func loadPolicy(place PolicyPlace) (agentpolicy.Document, string, error) {
	dir, err := os.OpenRoot(place.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return agentpolicy.Document{}, "", errNoPolicy
	}
	if err != nil {
		return agentpolicy.Document{}, "", fmt.Errorf("open policy dir: %w", err)
	}
	defer dir.Close()
	content, err := readPolicyFile(dir, place)
	if err != nil {
		return agentpolicy.Document{}, "", err
	}
	document, err := agentpolicy.Decode(content)
	if err != nil {
		return agentpolicy.Document{}, "", err
	}
	return document, agentpolicy.Digest(content), nil
}

// readPolicyFile lit le fichier après avoir jugé, comme l'état de l'agent,
// chaque dossier que le chemin traverse et le fichier lui-même : à root (ou
// à place.Owner), inscriptibles par personne d'autre. errNoPolicy s'il manque.
func readPolicyFile(dir *os.Root, place PolicyPlace) ([]byte, error) {
	owner := uint32(place.Owner.UID) // #nosec G115 -- un uid.
	resolved, err := checkOpenedDir(dir, place.Dir, owner)
	if err != nil {
		return nil, err
	}
	if _, err := dir.Lstat(policyFile); errors.Is(err, fs.ErrNotExist) {
		return nil, errNoPolicy
	}
	if err := checkStateFile(dir, filepath.Join(resolved, policyFile), policyFile, owner); err != nil {
		return nil, err
	}
	content, err := dir.ReadFile(policyFile)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return content, nil
}

// notePolicyFormat écrit dans l'identité la version de la politique que ce
// binaire sait lire, si elle n'y est pas encore : « agent grant » la lit avant
// d'écrire. Un échec ne coupe pas l'agent ; grant refusera, ce qui est sûr.
func notePolicyFormat(stateDir *os.Root, identity Identity, logger *slog.Logger) Identity {
	if identity.PolicyFormat >= agentpolicy.FormatVersion {
		return identity
	}
	identity.PolicyFormat = agentpolicy.FormatVersion
	noted, err := saveKeepingAnchors(stateDir, identity)
	if err != nil {
		logger.Warn("note policy format", "error", err)
		return identity
	}
	return noted
}
