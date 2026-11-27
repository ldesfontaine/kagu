// Package step porte les étapes cochées d'un geste suivi (brique B-1,
// R-GESTE-4) : un run d'agent, une machine qui arrive. Une étape a une clé
// déclarée ici, une fois, dont le libellé vit dans les catalogues de
// internal/kit/lang : le terminal l'imprime par Print, l'écran la dessine par
// StepTrail, avec le même libellé.
package step

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/untrusted"
)

type State string

const (
	StateRunning State = "running"
	StateDone    State = "done"
	StateFailed  State = "failed"
	StateSkipped State = "skipped"
	// StateWarned : fait, avec une réserve que la ligne dit (la coche jaune
	// de B1 : un daemon.json sans plafond, un jeu ramené à Observer). Seuls
	// setup et join l'impriment, sur le terminal de root : aucun agent ne le
	// rapporte, gesture_steps ne le garde pas.
	StateWarned State = "warned"
)

// IsKnown : seuls ces quatre états s'écrivent dans gesture_steps.
func (s State) IsKnown() bool {
	switch s {
	case StateRunning, StateDone, StateFailed, StateSkipped:
		return true
	}
	return false
}

// Key est une clé de catalogue, « step.enroll.docker » : le libellé de
// l'étape.
type Key string

// Step est une étape rapportée ; Detail dit ce qui a été trouvé ou fait
// (« 27.3.1 »), en texte venu d'ailleurs.
type Step struct {
	Key    Key       `json:"key"`
	State  State     `json:"state"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// Les bornes d'une clé et d'un détail : ce que gesture_steps garde.
const (
	maxKeyBytes     = 64
	MaxDetailRunes  = 200
	keyPrefix       = "step."
	keyCharacters   = "abcdefghijklmnopqrstuvwxyz0123456789_."
	detailSeparator = "  "
)

// IsKey juge la forme d'une clé : « step. » puis des minuscules, chiffres,
// points et soulignés. Une clé bien formée mais inconnue du catalogue
// s'affiche entre crochets : l'agent peut être plus récent que le serveur.
func IsKey(text string) bool {
	if len(text) > maxKeyBytes || !strings.HasPrefix(text, keyPrefix) || len(text) == len(keyPrefix) {
		return false
	}
	return strings.Trim(text, keyCharacters) == ""
}

var defined []Key

// Define déclare une clé d'étape, une fois. Une clé mal formée ou déclarée
// deux fois arrête le programme au démarrage : c'est une faute du code.
func Define(key string) Key {
	if !IsKey(key) {
		panic(fmt.Sprintf("step key %q is malformed", key))
	}
	if slices.Contains(defined, Key(key)) {
		panic(fmt.Sprintf("step key %q is defined twice", key))
	}
	defined = append(defined, Key(key))
	return Key(key)
}

// Clean juge une étape venue d'ailleurs : clé bien formée, état connu,
// heure posée. Le détail perd ses caractères de contrôle (untrusted.Strip)
// et ne dépasse pas MaxDetailRunes ; faux si l'étape est refusée.
func Clean(reported Step) (Step, bool) {
	if !IsKey(string(reported.Key)) || !reported.State.IsKnown() || reported.At.IsZero() {
		return Step{}, false
	}
	detail, _ := untrusted.Strip(reported.Detail)
	if utf8.RuneCountInString(detail) > MaxDetailRunes {
		return Step{}, false
	}
	reported.Detail = detail
	return reported, true
}

// CleanAll juge un parcours venu d'ailleurs : au plus limit étapes, chacune
// passée par Clean ; faux si le parcours est trop long ou si une étape est
// refusée.
func CleanAll(reported []Step, limit int) ([]Step, bool) {
	if len(reported) > limit {
		return nil, false
	}
	steps := make([]Step, 0, len(reported))
	for _, one := range reported {
		cleaned, ok := Clean(one)
		if !ok {
			return nil, false
		}
		steps = append(steps, cleaned)
	}
	return steps, true
}

// Print écrit la ligne d'une étape au terminal, « ✓ Docker installé
// 27.3.1 » : le libellé est celui que l'écran montre pour la même clé.
func Print(w io.Writer, catalog lang.Catalog, s Step) {
	line := fmt.Sprintf("  %s %-28s%s%s", stateMark(s.State), catalog.Get(string(s.Key)), detailSeparator, s.Detail)
	fmt.Fprintln(w, strings.TrimRight(line, " "))
}

func stateMark(state State) string {
	switch state {
	case StateDone:
		return "✓"
	case StateFailed:
		return "✗"
	case StateSkipped:
		return "–"
	case StateWarned:
		return "!"
	}
	return "…"
}
