package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/hostinfo"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// La politique de l'agent (fiche A3) : un fichier à root, hors de l'état de
// l'agent, que l'agent lit et n'écrit jamais (R-A3-1). Seuls « agent grant »,
// « agent revoke », « agent trust » et « agent policy migrate », en root,
// l'écrivent (grant.go, trust.go, migrate.go). L'agent la relit avant chaque
// ordre, toutes les 15 s et à SIGHUP (R-A3-4). Sur une machine installée avant
// elle, reconnue à l'absence de son dossier, il lit encore droits, ancres et
// clé du serveur dans identity.json (source identity) ; jamais ailleurs
// (R-A3-16).

const (
	policyFile     = brand.AgentPolicyFile
	policyMode     = agentpolicy.FileMode
	policyDirMode  = agentpolicy.DirMode
	policyLockFile = policyFile + ".lock"
	// policyRereadInterval : la relecture sans ordre ni signal (R-A3-4).
	policyRereadInterval = 15 * time.Second
)

var (
	// errNoPolicy : pas de dossier de politique, la machine est d'avant elle ;
	// droits, ancres et clé du serveur viennent d'identity.json.
	errNoPolicy = errors.New("no agent policy")
	// errPolicyMissing : le dossier est là, le fichier non ; observe seul,
	// identity.json ne se lit pas (R-A3-16).
	errPolicyMissing = errors.New("the agent policy is missing from its directory")
)

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
	// Les droits que la politique donne à cette lecture : un droit échu n'y
	// est plus. Until porte l'échéance de ceux qui en ont une (R-A3-5).
	Rights []agentpolicy.Capability
	Until  map[string]time.Time
	// Les clés du serveur acceptées à cette lecture, la clé acceptée d'abord ;
	// une clé gardée échue n'y est plus.
	ServerKeys [][]byte
	Anchors    map[string][]string
	// Source : agentpolicy.SourcePolicy, SourceIdentity ou SourceRefused.
	Source string
	// Digest : l'empreinte du fichier lu (source policy seulement).
	Digest string
	// Refusal : pourquoi la politique est refusée (source refused seulement).
	Refusal agentpolicy.Refusal
}

// report est ce qu'une lecture change pour le serveur : la source,
// l'empreinte, les droits appliqués et leurs échéances, les ancres et les
// clés acceptées. Un droit ou une clé gardée qui échoit le change : le flux
// se rouvre et ne les redit plus (R-A3-5).
func (p AppliedPolicy) report() string {
	return p.Source + " " + p.Digest + " " + p.Refusal.Format() + " " + agentpolicy.FormatCapabilities(p.Rights) + " " + agentpolicy.FormatRightsUntil(p.Until) + " " +
		anchor.FromFile(p.Anchors).Format() + " " + p.serverKeyFingerprints()
}

func (p AppliedPolicy) serverKeyFingerprints() string {
	fingerprints := make([]string, 0, len(p.ServerKeys))
	for _, key := range p.ServerKeys {
		fingerprints = append(fingerprints, agentwire.KeyFingerprint(key))
	}
	return strings.Join(fingerprints, ",")
}

// AcceptedServerKey rend la clé du serveur acceptée, celle que l'agent redit
// au serveur ; nil sans clé.
func (p AppliedPolicy) AcceptedServerKey() []byte {
	if len(p.ServerKeys) == 0 {
		return nil
	}
	return p.ServerKeys[0]
}

// readPolicy rend ce que l'agent applique à l'heure now : un droit ou une
// clé gardée échus n'y sont plus, serveur joint ou non. Sans dossier, ce
// qu'identity.json porte (source identity). Un dossier sans fichier (R-A3-16),
// une politique qui ne se lit pas, n'appartient pas à root ou s'écrit par un
// autre compte : observe seul, ni clé ni ancre (source refused), et l'erreur
// dit pourquoi (R-A3-6). Rien ne s'élargit sur une erreur : ni les droits
// d'avant ni ceux de l'identité. Un état mal gardé (narrowed) n'a que
// observe, quelle que soit la source.
func readPolicy(place PolicyPlace, identity Identity, now agentpolicy.Clock) (AppliedPolicy, error) {
	document, digest, err := loadPolicy(place)
	var applied AppliedPolicy
	switch {
	case errors.Is(err, errNoPolicy):
		legacy := agentpolicy.Migrate(identity.legacy())
		return AppliedPolicy{Rights: legacy.Rights, ServerKeys: legacy.LiveServerKeys(now), Anchors: legacy.Anchors, Source: agentpolicy.SourceIdentity}, nil
	case err != nil:
		applied = AppliedPolicy{Rights: observeOnly(), Source: agentpolicy.SourceRefused, Refusal: refusalOf(err, place)}
	default:
		rights, until := document.LiveRights(now)
		applied = AppliedPolicy{
			MachineID: document.MachineID, Rights: rights, Until: until, ServerKeys: document.LiveServerKeys(now), Anchors: document.Anchors,
			Source: agentpolicy.SourcePolicy, Digest: digest,
		}
	}
	if identity.narrowed {
		applied.Rights, applied.Until = observeOnly(), nil
	}
	return applied, err
}

// refusalOf range l'erreur d'une lecture refusée dans l'ensemble fermé des
// raisons que l'agent rapporte : un chemin mal gardé (propriétaire, puis
// droits), une clé inconnue, un fichier absent ; illisible sinon. Le détail
// nomme toujours ce qui est en cause : le chemin, ou la clé.
func refusalOf(err error, place PolicyPlace) agentpolicy.Refusal {
	var unsafe *UnsafeStateError
	var unknown *agentpolicy.UnknownKeyError
	switch {
	case errors.As(err, &unsafe) && !ownedBy(unsafe.UID, uint32(place.Owner.UID)): // #nosec G115 -- un uid.
		return agentpolicy.NewRefusal(agentpolicy.RefusedOwner, unsafe.Path)
	case errors.As(err, &unsafe) && (unsafe.Mode.IsRegular() || unsafe.Mode.IsDir()):
		return agentpolicy.NewRefusal(agentpolicy.RefusedMode, unsafe.Path)
	case errors.As(err, &unknown):
		return agentpolicy.NewRefusal(agentpolicy.RefusedUnknownKey, unknown.Key)
	case errors.Is(err, errPolicyMissing):
		return agentpolicy.NewRefusal(agentpolicy.RefusedMissing, place.Dir)
	}
	return agentpolicy.NewRefusal(agentpolicy.RefusedUnreadable, filepath.Join(place.Dir, policyFile))
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
// à place.Owner), inscriptibles par personne d'autre. errPolicyMissing s'il
// manque.
func readPolicyFile(dir *os.Root, place PolicyPlace) ([]byte, error) {
	owner := uint32(place.Owner.UID) // #nosec G115 -- un uid.
	resolved, err := checkOpenedDir(dir, place.Dir, owner)
	if err != nil {
		return nil, err
	}
	if _, err := dir.Lstat(policyFile); errors.Is(err, fs.ErrNotExist) {
		return nil, errPolicyMissing
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
	noted, err := saveKeepingRootFields(stateDir, identity)
	if err != nil {
		logger.Warn("note policy format", "error", err)
		return identity
	}
	return noted
}

// SystemClock lit l'horloge de la machine : l'heure, le démarrage et le temps
// écoulé depuis (hostinfo.MonotonicClock).
func SystemClock() agentpolicy.Clock {
	boot, uptime := hostinfo.MonotonicClock()
	return agentpolicy.Clock{Now: time.Now(), Boot: boot, Uptime: uptime}
}
