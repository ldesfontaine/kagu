package agentpolicy

import (
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// Capability est un droit et, pour un droit borné, les chemins qu'il couvre.
// Pour backup.produce, ce sont des noms de producteurs et non des chemins
// (producer.go).
type Capability struct {
	Name  string
	Paths []string
}

const (
	// La forme texte : les droits séparés par « , », un droit borné suivi de
	// « = » et de ses chemins séparés par « : ». Aucun de ces signes ni
	// espace dans un chemin : la ligne d'installation la porte sans
	// guillemets, l'en-tête de l'agent aussi.
	RightSeparator     = ","
	ScopeSeparator     = "="
	pathSeparator      = ":"
	maxCapabilityPaths = 8
	maxCapabilityText  = 2048
)

var capabilityPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,254}$`)

var (
	ErrCapabilityUnknown = refusal.Invalid("machine.capability_unknown", "unknown agent capability")
	ErrCapabilityPath    = refusal.Invalid("machine.capability_path", "capability path must be absolute, clean, and made of letters, digits, dot, dash, underscore")
	ErrCapabilityScope   = refusal.Invalid("machine.capability_scope", "backup.receive and restic.target take one path, files.write one to eight, backup.produce one to four producers, the others none")
	ErrCapabilityAccount = refusal.Invalid("machine.capability_account", "terminal.host takes one Unix account name: a lowercase letter or underscore, then lowercase letters, digits, underscores or dashes, 32 at most")
	ErrCapabilityPeers   = refusal.Invalid("machine.capability_peers", "network.private takes one number of peers, from 1 to 254")
)

// maxPrivatePeers borne la valeur de network.private : le nombre de pairs du
// réseau privé que la machine accepte (E5).
const maxPrivatePeers = 254

// NormalizeCapabilities vérifie une liste de droits lue hors de la politique
// (le jeton, identity.json, -rights), ajoute observe, retire les doublons et
// la range dans l'ordre de Names : deux listes égales s'écrivent pareil. Un
// droit de la politique seule y est inconnu (R-A3-10).
func NormalizeCapabilities(capabilities []Capability) ([]Capability, error) {
	return normalize(capabilities, readEverywhere)
}

// NormalizePolicyRights fait de même pour les droits de la politique, et pour
// ceux qu'un agent rapporte d'elle : les droits de la politique seule y sont
// lus, ceux que rien n'ouvre encore restent inconnus.
func NormalizePolicyRights(capabilities []Capability) ([]Capability, error) {
	return normalize(capabilities, readInPolicy)
}

// normalize lit les droits qui se lisent jusqu'à widest (readEverywhere, ou
// aussi readInPolicy).
func normalize(capabilities []Capability, widest readable) ([]Capability, error) {
	byName := map[string]Capability{CapabilityObserve: {Name: CapabilityObserve}}
	for _, capability := range capabilities {
		known, ok := knownRightOf(capability.Name)
		if !ok || known.readable > widest {
			return nil, ErrCapabilityUnknown
		}
		value, err := normalizeValue(known, capability.Paths)
		if err != nil {
			return nil, err
		}
		byName[capability.Name] = Capability{Name: capability.Name, Paths: value}
	}
	normalized := make([]Capability, 0, len(byName))
	for _, name := range Names() {
		if capability, ok := byName[name]; ok {
			normalized = append(normalized, capability)
		}
	}
	return normalized, nil
}

// normalizeValue juge la valeur d'un droit selon sa grammaire (knownRights) :
// un chemin, un à huit, des producteurs, un compte, ou rien. Un droit posé
// sans valeur prend la sienne (terminal.host vaut root). Elle ressort triée,
// sans doublon.
func normalizeValue(known knownRight, given []string) ([]string, error) {
	if len(given) == 0 && known.bare != "" {
		given = []string{known.bare}
	}
	switch known.value {
	case valueProducers:
		return normalizeProducers(given)
	case valueAccount:
		return normalizeAccount(given)
	case valuePeers:
		return normalizePeers(given)
	case valueNone:
		if len(given) != 0 {
			return nil, ErrCapabilityScope
		}
		return nil, nil
	}
	paths := slices.Clone(given)
	slices.Sort(paths)
	paths = slices.Compact(paths)
	for _, candidate := range paths {
		if !ValidCapabilityPath(candidate) {
			return nil, ErrCapabilityPath
		}
	}
	if (known.value == valueOnePath && len(paths) != 1) || len(paths) == 0 || len(paths) > maxCapabilityPaths {
		return nil, ErrCapabilityScope
	}
	return paths, nil
}

// Un nom de compte POSIX portable, en minuscules : ce que useradd accepte par
// défaut (une minuscule ou « _ », puis minuscules, chiffres, « _ » ou « - »).
var accountNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// IsAccountName dit si un nom de compte a la forme portable : la valeur de
// terminal.host, et le compte que l'agent dit au serveur dans son en-tête.
func IsAccountName(name string) bool {
	return accountNamePattern.MatchString(name)
}

// normalizeAccount juge la valeur d'un droit qui nomme un compte : un seul.
func normalizeAccount(given []string) ([]string, error) {
	if len(given) != 1 || !IsAccountName(given[0]) {
		return nil, ErrCapabilityAccount
	}
	return slices.Clone(given), nil
}

// normalizePeers juge la valeur de network.private : un seul nombre, écrit
// sans zéro devant ni signe, de 1 à maxPrivatePeers.
func normalizePeers(given []string) ([]string, error) {
	if len(given) != 1 {
		return nil, ErrCapabilityPeers
	}
	peers, err := strconv.Atoi(given[0])
	if err != nil || peers < 1 || peers > maxPrivatePeers || strconv.Itoa(peers) != given[0] {
		return nil, ErrCapabilityPeers
	}
	return slices.Clone(given), nil
}

// ValidCapabilityPath : un chemin absolu, déjà propre, jamais la racine :
// « / » voudrait dire toute la machine.
func ValidCapabilityPath(candidate string) bool {
	return capabilityPathPattern.MatchString(candidate) && path.Clean(candidate) == candidate
}

// CoversPath dit si un droit borné couvre ce chemin : le chemin du droit, ou
// un dossier dessous. Le préfixe se compare avec son séparateur,
// « /srv/backups2 » n'est pas sous « /srv/backups ». Le chemin demandé doit
// être propre : « /srv/backups/../etc » ne l'est pas.
func CoversPath(capabilities []Capability, name, candidate string) bool {
	_, covered := CoveringPath(capabilities, name, candidate)
	return covered
}

// CoveringPath rend le chemin du droit qui couvre candidate (le plus long
// s'il y en a plusieurs) : l'agent ouvre sa racine là, pour qu'un lien posé
// dessous ne fasse pas sortir l'écriture du droit.
func CoveringPath(capabilities []Capability, name, candidate string) (string, bool) {
	// La portée de backup.produce est une liste de producteurs : aucun chemin
	// ne s'y compare (CoversProducer).
	if name == CapabilityBackupProduce || !ValidCapabilityPath(candidate) {
		return "", false
	}
	covering := ""
	for _, capability := range capabilities {
		if capability.Name != name {
			continue
		}
		for _, granted := range capability.Paths {
			if (candidate == granted || strings.HasPrefix(candidate, granted+"/")) && len(granted) > len(covering) {
				covering = granted
			}
		}
	}
	return covering, covering != ""
}

// FormatCapabilities écrit une liste déjà normalisée sous sa forme texte.
func FormatCapabilities(capabilities []Capability) string {
	items := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		items = append(items, formatCapability(capability))
	}
	return strings.Join(items, RightSeparator)
}

func formatCapability(capability Capability) string {
	if len(capability.Paths) == 0 {
		return capability.Name
	}
	return capability.Name + ScopeSeparator + strings.Join(capability.Paths, pathSeparator)
}

// ParseCapabilities lit la forme texte d'une liste prise hors de la
// politique et la normalise (NormalizeCapabilities). Un texte vide vaut
// observe seul.
func ParseCapabilities(text string) ([]Capability, error) {
	capabilities, err := splitCapabilities(text)
	if err != nil {
		return nil, err
	}
	return NormalizeCapabilities(capabilities)
}

// ParsePolicyRights lit la forme texte de droits de la politique (ce que
// « grant » reçoit, ce qu'un agent rapporte) et la normalise
// (NormalizePolicyRights).
func ParsePolicyRights(text string) ([]Capability, error) {
	capabilities, err := splitCapabilities(text)
	if err != nil {
		return nil, err
	}
	return NormalizePolicyRights(capabilities)
}

func splitCapabilities(text string) ([]Capability, error) {
	if len(text) > maxCapabilityText {
		return nil, ErrCapabilityScope
	}
	var capabilities []Capability
	for item := range strings.SplitSeq(text, RightSeparator) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, scope, hasScope := strings.Cut(item, ScopeSeparator)
		capability := Capability{Name: name}
		if hasScope {
			capability.Paths = strings.Split(scope, pathSeparator)
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities, nil
}

// HasCapability dit si la liste porte ce droit. Les chemins d'un droit borné
// se jugent avec l'ordre qui les nomme, pas ici.
func HasCapability(capabilities []Capability, name string) bool {
	return slices.ContainsFunc(capabilities, func(capability Capability) bool { return capability.Name == name })
}

// SameCapabilities dit si deux listes normalisées disent la même chose.
func SameCapabilities(first, second []Capability) bool {
	return FormatCapabilities(first) == FormatCapabilities(second)
}
