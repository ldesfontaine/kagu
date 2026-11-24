package agentpolicy

import (
	"errors"
	"time"
)

// Policy est ce que root permet à l'agent d'une machine (fiche A3, §5) : la
// machine, les clés du serveur acceptées, les droits et les ancres. Le juge
// d'un ordre la reçoit, il ne lit aucun fichier. L'agent la construit depuis
// le fichier de la politique (Document), ou depuis identity.json sur une
// machine d'avant la politique (R-A3-16).
type Policy struct {
	MachineID string
	// Les clés publiques Ed25519 du serveur acceptées en ce moment : une, ou
	// deux le temps d'un --keep-old ; une clé échue n'y est plus. Vide : aucun
	// ordre ne passe.
	ServerKeys [][]byte
	Rights     []Capability
	// Par type d'ancre (internal/fact/anchor), les valeurs posées par root,
	// telles que le fichier les porte.
	Anchors map[string][]string
}

// FormatVersion est la version du fichier de la politique que ce code lit et
// écrit (la clé « version »). Un agent la note aussi dans son identité :
// « agent grant » refuse d'écrire pour un agent qui ne la lirait pas.
const FormatVersion = 1

// D'où l'agent tient les droits qu'il applique, tel qu'il le rapporte au
// serveur. SourceRefused : la politique existe mais ne se lit pas, n'est pas
// à root ou s'écrit par un autre compte, ou manque sur une machine installée
// avec elle ; seul observe s'applique (R-A3-6, R-A3-16).
const (
	SourcePolicy   = "policy"
	SourceIdentity = "identity"
	SourceRefused  = "refused"
)

// Sources rend les sources qu'un agent peut rapporter.
func Sources() []string {
	return []string{SourcePolicy, SourceIdentity, SourceRefused}
}

// Document est la politique telle que son fichier la porte (fiche A3, §5) :
// la machine, les clés du serveur, les droits normalisés et les ancres. Les
// échéances des droits viendront avec T03-05.
type Document struct {
	MachineID string
	// La première est la clé acceptée ; la seconde, gardée par --keep-old,
	// porte son échéance (R-A3-14).
	ServerKeys []ServerKey
	Rights     []Capability
	Anchors    map[string][]string
}

// ServerKey est une clé publique Ed25519 du serveur que la politique accepte.
// Until est nul pour la clé acceptée ; la clé gardée par --keep-old échoit à
// Until et porte l'horloge de sa pose (Granted), comme un droit à durée
// (R-A3-5).
type ServerKey struct {
	Key     []byte
	Until   time.Time
	Granted Clock
}

// Clock est une lecture de l'horloge de la machine : l'heure affichée, et
// l'horloge monotone (le démarrage, /proc/sys/kernel/random/boot_id, et le
// temps écoulé depuis, /proc/uptime). NTP n'est pas authentifié : l'heure
// seule ne suffit pas à faire tomber une échéance (N-F5).
type Clock struct {
	Now    time.Time
	Boot   string
	Uptime time.Duration
}

// Lapsed dit si une échéance posée à granted est passée à now (R-A3-5) : à
// l'heure ; ou, depuis le même démarrage, quand le temps monotone écoulé
// depuis la pose dépasse sa durée, quelle que soit l'heure affichée ; après
// un redémarrage, une pose dans le futur (horloge reculée) est échue aussi.
// Une échéance nulle ne tombe jamais.
func Lapsed(until time.Time, granted, now Clock) bool {
	if until.IsZero() {
		return false
	}
	if !now.Now.Before(until) {
		return true
	}
	if granted.Boot != "" && granted.Boot == now.Boot {
		return now.Uptime-granted.Uptime >= until.Sub(granted.Now)
	}
	return granted.Now.After(now.Now)
}

// La durée d'un droit à durée, ou d'une clé gardée par --keep-old : de cinq
// minutes à sept jours (R-A3-5, R-A3-14).
const (
	MinDuration = 5 * time.Minute
	MaxDuration = 7 * 24 * time.Hour
)

// ErrDurationOutOfBounds : la durée sort de MinDuration à MaxDuration.
var ErrDurationOutOfBounds = errors.New("duration out of bounds: 5m to 168h")

// CheckDuration refuse une durée hors des bornes.
func CheckDuration(duration time.Duration) error {
	if duration < MinDuration || duration > MaxDuration {
		return ErrDurationOutOfBounds
	}
	return nil
}
