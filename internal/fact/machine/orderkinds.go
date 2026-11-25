package machine

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// OrderKinds est ce qu'un agent annonce à l'ouverture de son flux (R-B2-8) :
// les genres d'ordres qu'il sait exécuter et ce qu'il sait lire de
// l'enveloppe, chacun avec son numéro (« docker.deploy@2 »). C'est le seul
// moyen de dire ce qu'un agent sait faire : ni sa version ni son protocole ne
// le disent. Nil tant qu'il n'a rien annoncé (un agent du protocole 2).
type OrderKinds map[string]int

// Les bornes d'une annonce : un agent de ce produit en annonce une trentaine.
const (
	maxAnnouncedKinds = 128
	kindSeparator     = ","
	revisionSeparator = "@"
)

// kindNamePattern : un genre du registre (« proxmox.vm.snapshot_delete ») ou
// ce que lit l'enveloppe (« floor »), court.
var kindNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

// ErrOrderKindsUnreadable : l'annonce n'a pas la forme « genre@n,… ».
var ErrOrderKindsUnreadable = errors.New("announced order kinds unreadable")

// ParseOrderKinds lit l'annonce, en entier ou pas du tout : un genre hors
// forme, répété, un numéro qui n'en est pas un, ou trop de genres la font
// refuser.
func ParseOrderKinds(text string) (OrderKinds, error) {
	items := strings.Split(text, kindSeparator)
	if len(items) > maxAnnouncedKinds {
		return nil, fmt.Errorf("%w: %d kinds", ErrOrderKindsUnreadable, len(items))
	}
	kinds := make(OrderKinds, len(items))
	for _, item := range items {
		name, revision, found := strings.Cut(item, revisionSeparator)
		if !found || !kindNamePattern.MatchString(name) || !isShortNumber(revision) {
			return nil, fmt.Errorf("%w: %q", ErrOrderKindsUnreadable, item)
		}
		if _, repeated := kinds[name]; repeated {
			return nil, fmt.Errorf("%w: %s repeated", ErrOrderKindsUnreadable, name)
		}
		kinds[name], _ = strconv.Atoi(revision)
	}
	return kinds, nil
}

// Format écrit l'annonce, par nom de genre : ce que ParseOrderKinds relit.
func (k OrderKinds) Format() string {
	items := make([]string, 0, len(k))
	for _, name := range slices.Sorted(maps.Keys(k)) {
		items = append(items, name+revisionSeparator+strconv.Itoa(k[name]))
	}
	return strings.Join(items, kindSeparator)
}

// Announces dit si l'agent a annoncé ce genre, à ce numéro ou au-delà : un
// genre qui s'élargit monte son numéro, l'agent qui annonce l'ancien ne sait
// pas le nouveau.
func (k OrderKinds) Announces(name string, revision int) bool {
	announced, found := k[name]
	return found && announced >= revision
}
