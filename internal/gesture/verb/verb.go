package verb

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Verb est un geste inscrit au registre, avec son niveau (A4). Route est le
// motif enregistré de la route d'opérateur qu'il ouvre, « POST /api/... » ;
// Label et Summary sont des clés de catalogue (fr et en). Params sont les
// segments {…} du chemin, dans l'ordre ; Target dit ce que le segment {id}
// désigne, pour juger la portée d'un jeton ; Body les champs JSON que la route
// attend. Ils sont déclarés et non déduits : le client d'un jeton les lit tels
// quels, sans parser de texte.
//
// Level dit ce qu'un jeton en fait (R-A4-2) : au niveau 1 il agit, et Reverse
// nomme le verbe qui le défait ; au niveau 2 il dépose une demande que
// l'opérateur confirme dans l'interface (internal/gesture/verbrequest), et le
// geste n'a pas d'inverse ; aux niveaux 3 et 4, il est refusé : Token est
// faux, et Reason dit pourquoi (une clé de catalogue). Order est le genre
// d'ordre que le geste envoie, Right le droit d'agent qu'il exige (celui du
// genre), vides si le geste n'envoie rien. Audit est l'action sous laquelle
// le geste s'écrit. Ces trois-là se croisent avec agentwire et audit dans
// TestRegistry_ThreeListsAgree (internal/edge/server).
type Verb struct {
	ID      string
	Route   string
	Params  []string
	Target  Target
	Body    []string
	Label   string
	Summary string
	Reverse string
	Level   int
	Token   bool
	Reason  string
	Order   agentwire.Kind
	Right   string
	Audit   audit.Action
}

// AsksConfirmation dit si un jeton qui appelle le geste dépose une demande
// au lieu d'agir : c'est le niveau 2.
func (v Verb) AsksConfirmation() bool {
	return v.Level == 2
}

// Target dit ce que le segment {id} d'un verbe désigne : la machine dont
// l'agent reçoit l'ordre, ou une sonde ou une tâche, qu'on rattache à sa
// machine, ou un dépôt restic : {id} est la source et l'ordre part aussi à la
// cible du dépôt, jugée comme la source. Un verbe de Proxmox vise en plus
// l'invité du segment {vmid}.
type Target string

const (
	TargetMachine Target = "machine"
	TargetProbe   Target = "probe"
	TargetJob     Target = "job"
	// TargetResticLink : la machine du chemin est la source du dépôt ; sa
	// cible reçoit aussi un ordre.
	TargetResticLink Target = "restic_link"
)

// TargetsGuest dit si le verbe vise un invité Proxmox, en plus de sa machine.
func (v Verb) TargetsGuest() bool {
	return slices.Contains(v.Params, "vmid")
}

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

var pathParamPattern = regexp.MustCompile(`\{([a-z]+)\}`)

// PathParams rend les segments {…} du chemin d'une route, dans l'ordre.
func PathParams(route string) []string {
	params := []string{}
	for _, match := range pathParamPattern.FindAllStringSubmatch(route, -1) {
		params = append(params, match[1])
	}
	return params
}

var (
	ErrIDInvalid      = errors.New("verb: id invalid")
	ErrRouteInvalid   = errors.New("verb: route must be a POST on /api/, or a POST, PUT or DELETE above level 1")
	ErrCatalogMissing = errors.New("verb: label and summary keys are required")
	ErrLevelInvalid   = errors.New("verb: level must be 1, 2, 3 or 4")
	ErrTokenLevel     = errors.New("verb: a gesture of level 3 or 4 is never open to a token")
	ErrReasonMissing  = errors.New("verb: a gesture of level 3 or 4 says why it is closed to tokens")
	ErrNoReverse      = errors.New("verb: a verb of level 1 names its reverse")
	ErrConfirmReverse = errors.New("verb: a gesture above level 1 has no reverse")
	ErrParamsMismatch = errors.New("verb: params do not match the route path")
	ErrTargetInvalid  = errors.New("verb: target must be machine, probe, job or restic_link, and the route must carry {id}")
	ErrDuplicate      = errors.New("verb: already registered")
	ErrConfirmTarget  = errors.New("verb: a verb to confirm must target a machine")
	ErrUnknownReverse = errors.New("verb: reverse is not registered")
)

// Registry est la liste des verbes. L'ordre d'enregistrement est celui de
// l'interface.
type Registry struct {
	verbs []Verb
}

// Register ajoute un geste. Il ne vérifie pas que l'inverse existe déjà :
// deux verbes se répondent, l'un des deux vient forcément en premier. C'est
// Check qui le tranche, une fois tout enregistré.
func (r *Registry) Register(v Verb) error {
	if !idPattern.MatchString(v.ID) {
		return fmt.Errorf("%w: %q", ErrIDInvalid, v.ID)
	}
	if err := checkLevel(v); err != nil {
		return fmt.Errorf("%w: %s", err, v.ID)
	}
	if !routeAllowed(v) {
		return fmt.Errorf("%w: %q", ErrRouteInvalid, v.Route)
	}
	if v.Label == "" || v.Summary == "" {
		return fmt.Errorf("%w: %s", ErrCatalogMissing, v.ID)
	}
	// Le serveur ne sait nommer, dans la demande, que la machine visée ; un
	// autre objet s'ajoute avec le premier verbe qui le vise.
	if v.AsksConfirmation() && v.Target != TargetMachine {
		return fmt.Errorf("%w: %s", ErrConfirmTarget, v.ID)
	}
	if !slices.Equal(v.Params, PathParams(v.Route)) {
		return fmt.Errorf("%w: %s", ErrParamsMismatch, v.ID)
	}
	if !slices.Contains([]Target{TargetMachine, TargetProbe, TargetJob, TargetResticLink}, v.Target) || !slices.Contains(v.Params, "id") {
		return fmt.Errorf("%w: %s", ErrTargetInvalid, v.ID)
	}
	if _, found := r.Lookup(v.ID); found {
		return fmt.Errorf("%w: %s", ErrDuplicate, v.ID)
	}
	if _, found := r.ByRoute(v.Route); found {
		return fmt.Errorf("%w: route %s", ErrDuplicate, v.Route)
	}
	r.verbs = append(r.verbs, v)
	return nil
}

// checkLevel juge le niveau et ce qu'il exige (R-A4-2, R-A4-4) : le niveau 1
// nomme son inverse, les autres n'en ont pas ; les niveaux 3 et 4 sont fermés
// aux jetons et disent pourquoi. Le niveau 0 est une lecture, pas un geste du
// registre : comme un niveau absent, il est refusé.
func checkLevel(v Verb) error {
	switch {
	case v.Level < 1 || v.Level > 4:
		return ErrLevelInvalid
	case v.Level >= 3 && v.Token:
		return ErrTokenLevel
	case v.Level >= 3 && v.Reason == "":
		return ErrReasonMissing
	case v.Level == 1 && v.Reverse == "":
		return ErrNoReverse
	case v.Level > 1 && v.Reverse != "":
		return ErrConfirmReverse
	}
	return nil
}

// MustRegister est Register pour le câblage au démarrage : une erreur est
// un défaut du code, pas une entrée à refuser.
func (r *Registry) MustRegister(v Verb) {
	if err := r.Register(v); err != nil {
		panic(err)
	}
}

// routeAllowed dit si la route est de la forme que le geste permet : un POST
// sur /api/, ou, au-dessus du niveau 1, aussi un PUT ou un DELETE.
func routeAllowed(v Verb) bool {
	methods := []string{"POST"}
	if v.Level > 1 {
		methods = append(methods, "PUT", "DELETE")
	}
	return slices.ContainsFunc(methods, func(method string) bool {
		return strings.HasPrefix(v.Route, method+" /api/")
	})
}

// Check vérifie que l'inverse de chaque verbe de niveau 1 est un verbe
// enregistré (R-A4-4) ; il peut être de niveau 2. Au-dessus, il n'y en a pas.
func (r *Registry) Check() error {
	for _, v := range r.verbs {
		if v.Level != 1 {
			continue
		}
		if _, found := r.Lookup(v.Reverse); !found {
			return fmt.Errorf("%w: %s -> %s", ErrUnknownReverse, v.ID, v.Reverse)
		}
	}
	return nil
}

func (r *Registry) Lookup(id string) (Verb, bool) {
	index := slices.IndexFunc(r.verbs, func(v Verb) bool { return v.ID == id })
	if index < 0 {
		return Verb{}, false
	}
	return r.verbs[index], true
}

// ByRoute rend le verbe qui ouvre cette route d'opérateur.
func (r *Registry) ByRoute(route string) (Verb, bool) {
	index := slices.IndexFunc(r.verbs, func(v Verb) bool { return v.Route == route })
	if index < 0 {
		return Verb{}, false
	}
	return r.verbs[index], true
}

// OpenToTokens rend les verbes qu'un jeton peut porter, dans l'ordre
// d'enregistrement : ceux des niveaux 1 et 2 ouverts aux jetons.
func (r *Registry) OpenToTokens() []Verb {
	var open []Verb
	for _, v := range r.verbs {
		if v.Token {
			open = append(open, v)
		}
	}
	return open
}

// All rend une copie, dans l'ordre d'enregistrement.
func (r *Registry) All() []Verb {
	return slices.Clone(r.verbs)
}
