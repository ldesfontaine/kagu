package agentpolicy

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/untrusted"
	"github.com/pelletier/go-toml/v2"
)

// Les modes que root pose sur la politique et son dossier (R-A3-1) : le
// fichier lisible du groupe de l'agent, le dossier de tous ; inscriptibles
// par root seul.
const (
	FileMode = 0o640
	DirMode  = 0o755
)

// FilePath est le chemin du fichier de la politique sur une machine.
func FilePath() string {
	return brand.AgentPolicyDir + "/" + brand.AgentPolicyFile
}

// Pourquoi l'agent refuse sa politique (R-A3-6), tel qu'il le rapporte : un
// ensemble fermé. RefusedMode : le fichier ou un dossier du chemin
// s'écrit par un autre compte ; RefusedOwner : il n'est pas à root ;
// RefusedUnknownKey : le fichier porte une clé que l'agent ne connaît pas ;
// RefusedMissing : le dossier est là, le fichier non (R-A3-16) ;
// RefusedUnreadable : tout le reste.
const (
	RefusedMode       = "mode"
	RefusedOwner      = "owner"
	RefusedUnknownKey = "unknown_key"
	RefusedMissing    = "missing"
	RefusedUnreadable = "unreadable"
)

// RefusedReasons rend les raisons qu'un agent peut rapporter.
func RefusedReasons() []string {
	return []string{RefusedMode, RefusedOwner, RefusedUnknownKey, RefusedMissing, RefusedUnreadable}
}

// maxRefusalDetailBytes borne le détail : un nom de clé ou un chemin.
const maxRefusalDetailBytes = 128

// Refusal est la raison d'un refus de la politique et son détail : la clé
// inconnue, ou le chemin en cause. Le détail vient d'un fichier que root a
// écrit, peut-être mal : il se nettoie avant d'être rapporté et à sa lecture.
// Nulle hors de la source refused.
type Refusal struct {
	Reason string
	Detail string
}

// NewRefusal rend une raison au détail borné et nettoyé (untrusted).
func NewRefusal(reason, detail string) Refusal {
	clean, _ := untrusted.Strip(untrusted.Bound(detail, maxRefusalDetailBytes))
	return Refusal{Reason: reason, Detail: clean}
}

// Format écrit la raison telle que l'agent la rapporte : « raison » ou
// « raison:détail » ; vide pour une raison nulle.
func (r Refusal) Format() string {
	if r.Detail == "" {
		return r.Reason
	}
	return r.Reason + ":" + r.Detail
}

// ParseRefusal lit une raison rapportée par un agent. Une raison hors de
// l'ensemble rend une raison nulle : l'écran garde alors sa phrase générale.
func ParseRefusal(text string) Refusal {
	reason, detail, _ := strings.Cut(text, ":")
	if !slices.Contains(RefusedReasons(), reason) {
		return Refusal{}
	}
	return NewRefusal(reason, detail)
}

// FixLine écrit la commande qui corrige le refus, quand il en existe une :
// les droits ou le propriétaire du fichier de la politique ou de son
// dossier. Vide pour un autre chemin, qu'on ne remet pas d'ici, et pour une
// clé inconnue ou un document illisible, qui se corrigent dans le fichier.
func (r Refusal) FixLine() string {
	var mode int64
	switch r.Detail {
	case FilePath():
		mode = FileMode
	case brand.AgentPolicyDir:
		mode = DirMode
	default:
		return ""
	}
	switch r.Reason {
	case RefusedMode:
		return "sudo chmod " + strconv.FormatInt(mode, 8) + " " + r.Detail
	case RefusedOwner:
		return "sudo chown root " + r.Detail
	}
	return ""
}

// UnknownKeyError : le fichier de la politique porte une clé que ce code ne
// lit pas ; Decode la rend dans ErrUnreadable.
type UnknownKeyError struct {
	Key string
}

func (e *UnknownKeyError) Error() string {
	return "unknown key " + e.Key
}

// unknownKeyOf rend la première clé inconnue d'une erreur du décodeur
// strict, ou nil.
func unknownKeyOf(err error) error {
	var strict *toml.StrictMissingError
	if !errors.As(err, &strict) || len(strict.Errors) == 0 {
		return nil
	}
	return &UnknownKeyError{Key: strings.Join(strict.Errors[0].Key(), ".")}
}
