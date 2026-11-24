package agentpolicy

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Expiry est l'échéance d'un droit à durée, ou de la clé gardée par
// --keep-old : l'heure absolue, et l'horloge de sa pose, qui la fait tomber
// aussi par le temps monotone (Lapsed, R-A3-5). Nulle : sans échéance.
type Expiry struct {
	Until   time.Time
	Granted Clock
}

// expiryAfter pose une échéance à duration de l'horloge granted, à la
// seconde : le fichier ne garde pas mieux.
func expiryAfter(granted Clock, duration time.Duration) Expiry {
	granted.Now = granted.Now.UTC().Truncate(time.Second)
	granted.Uptime = granted.Uptime.Truncate(time.Second)
	return Expiry{Until: granted.Now.Add(duration), Granted: granted}
}

func (e Expiry) equal(other Expiry) bool {
	return e.Until.Equal(other.Until) && e.Granted.Now.Equal(other.Granted.Now) &&
		e.Granted.Boot == other.Granted.Boot && e.Granted.Uptime == other.Granted.Uptime
}

// fileExpiry est l'échéance telle qu'un bloc [[right]] ou [[server_key]] la
// porte : les mêmes champs dans les deux, l'uptime en secondes.
type fileExpiry struct {
	Until         time.Time `toml:"until,omitempty"`
	GrantedAt     time.Time `toml:"granted_at,omitempty"`
	GrantedBoot   string    `toml:"granted_boot,omitempty"`
	GrantedUptime int64     `toml:"granted_uptime,omitempty"`
}

func fileExpiryOf(expiry Expiry) fileExpiry {
	return fileExpiry{
		Until: expiry.Until, GrantedAt: expiry.Granted.Now, GrantedBoot: expiry.Granted.Boot,
		GrantedUptime: int64(expiry.Granted.Uptime / time.Second),
	}
}

// expiry lit l'échéance d'un bloc : aucun champ, ou l'heure avec l'horloge de
// sa pose (le démarrage compris) ; une moitié ne se lit pas.
func (f fileExpiry) expiry() (Expiry, error) {
	if f == (fileExpiry{}) {
		return Expiry{}, nil
	}
	if f.Until.IsZero() || f.GrantedAt.IsZero() || f.GrantedBoot == "" || f.GrantedUptime < 0 {
		return Expiry{}, errors.New("an expiry needs until and the clock of its grant")
	}
	return Expiry{Until: f.Until, Granted: Clock{
		Now: f.GrantedAt, Boot: f.GrantedBoot, Uptime: time.Duration(f.GrantedUptime) * time.Second,
	}}, nil
}

// Term est la durée que « grant --for » donne aux droits qu'il pose : celle
// de chaque droit quand rien n'est dit (zéro), sans échéance (Permanent), ou
// une durée de MinDuration à MaxDuration.
type Term struct {
	Permanent bool
	Duration  time.Duration
}

// TermPermanent est le mot de « --for permanent ».
const TermPermanent = "permanent"

// ParseTerm lit la valeur de --for : vide, « permanent », ou une durée
// (« 5m », « 2h ») dans les bornes.
func ParseTerm(text string) (Term, error) {
	switch text {
	case "":
		return Term{}, nil
	case TermPermanent:
		return Term{Permanent: true}, nil
	}
	duration, err := time.ParseDuration(text)
	if err != nil {
		return Term{}, ErrDurationOutOfBounds
	}
	if err := CheckDuration(duration); err != nil {
		return Term{}, err
	}
	return Term{Duration: duration}, nil
}

// DurationOf rend la durée d'un droit posé avec ce terme : la sienne
// (knownRights) quand rien n'est dit ; zéro : sans échéance.
func (t Term) DurationOf(name string) time.Duration {
	switch {
	case t.Permanent:
		return 0
	case t.Duration != 0:
		return t.Duration
	}
	known, _ := knownRightOf(name)
	return known.term
}

// FormatTerm écrit une durée comme --for la lit : « 2h », « 5m ».
func FormatTerm(duration time.Duration) string {
	switch {
	case duration%time.Hour == 0:
		return strconv.FormatInt(int64(duration/time.Hour), 10) + "h"
	case duration%time.Minute == 0:
		return strconv.FormatInt(int64(duration/time.Minute), 10) + "m"
	}
	return duration.String()
}

// LiveRights rend les droits que la politique donne à l'heure now, et
// l'échéance de ceux qui en ont une : un droit échu n'y est plus (Lapsed,
// R-A3-5). La seule lecture des droits à durée, pour l'agent comme pour root.
func (d Document) LiveRights(now Clock) ([]Capability, map[string]time.Time) {
	rights := make([]Capability, 0, len(d.Rights))
	until := map[string]time.Time{}
	for _, right := range d.Rights {
		expiry := d.Expiries[right.Name]
		if Lapsed(expiry.Until, expiry.Granted, now) {
			continue
		}
		rights = append(rights, right)
		if !expiry.Until.IsZero() {
			until[right.Name] = expiry.Until
		}
	}
	return rights, until
}

// HeldThrough dit si des droits rapportés portent name jusqu'à at : un droit
// dont l'échéance tombe avant at ne suffit pas à un ordre valable jusque-là.
func HeldThrough(rights []Capability, until map[string]time.Time, name string, at time.Time) bool {
	if !HasCapability(rights, name) {
		return false
	}
	expiry, bounded := until[name]
	return !bounded || !expiry.Before(at)
}

// La forme texte des échéances, telle que l'agent les rapporte :
// « terminal.host=1764003720,observe.env=1764001200 », l'heure en secondes
// Unix, les droits dans l'ordre où ils s'affichent.
const maxRightsUntilText = 2048

// ErrRightsUntilUnreadable : les échéances rapportées ne se lisent pas.
var ErrRightsUntilUnreadable = errors.New("rights until are unreadable")

// FormatRightsUntil écrit les échéances des droits ; vide sans échéance.
func FormatRightsUntil(until map[string]time.Time) string {
	items := make([]string, 0, len(until))
	for _, name := range Names() {
		if expiry, ok := until[name]; ok {
			items = append(items, name+ScopeSeparator+strconv.FormatInt(expiry.Unix(), 10))
		}
	}
	return strings.Join(items, RightSeparator)
}

// ParseRightsUntil lit la forme de FormatRightsUntil : un nom connu, une
// seule fois, une heure positive.
func ParseRightsUntil(text string) (map[string]time.Time, error) {
	until := map[string]time.Time{}
	if text == "" {
		return until, nil
	}
	if len(text) > maxRightsUntilText {
		return nil, ErrRightsUntilUnreadable
	}
	for item := range strings.SplitSeq(text, RightSeparator) {
		name, seconds, found := strings.Cut(item, ScopeSeparator)
		unix, err := strconv.ParseInt(seconds, 10, 64)
		if _, known := knownRightOf(name); !found || !known || err != nil || unix <= 0 {
			return nil, fmt.Errorf("%w: %q", ErrRightsUntilUnreadable, item)
		}
		if _, twice := until[name]; twice {
			return nil, fmt.Errorf("%w: %s twice", ErrRightsUntilUnreadable, name)
		}
		until[name] = time.Unix(unix, 0).UTC()
	}
	return until, nil
}

// sameExpiries dit si deux tables d'échéances portent la même chose.
func sameExpiries(first, second map[string]Expiry) bool {
	return maps.EqualFunc(first, second, Expiry.equal)
}

// expiriesWithout rend une copie des échéances, sans celles de names.
func expiriesWithout(expiries map[string]Expiry, names []string) map[string]Expiry {
	kept := map[string]Expiry{}
	maps.Copy(kept, expiries)
	maps.DeleteFunc(kept, func(name string, _ Expiry) bool { return slices.Contains(names, name) })
	return kept
}
