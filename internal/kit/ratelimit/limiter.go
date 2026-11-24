package ratelimit

import (
	"container/list"
	"sync"
	"time"
)

// sweepEvery : le balayage des seaux oubliés se fait au passage d'une
// requête, au plus une fois par période, sans goroutine.
const sweepEvery = 5 * time.Minute

// MaxSources borne les clés d'un limiteur par adresse : une adresse se
// invente, et chaque clé reste en mémoire jusqu'au balayage. Plein, le
// limiteur oublie la source vue il y a le plus longtemps.
const MaxSources = 4096

// globalKey est l'unique clé du seau global d'un limiteur par adresse.
const globalKey = "all"

// Un seau par clé : il se remplit au rythme donné jusqu'à sa contenance, et
// chaque requête en retire une unité.
type bucket struct {
	key      string
	tokens   float64
	lastSeen time.Time
}

// Limiter compte par clé brute : une machine, l'empreinte d'un jeton. Pour
// une adresse cliente, c'est BySource.
type Limiter struct {
	// Unités rendues par seconde, et contenance du seau.
	rate  float64
	burst int
	// Un seau silencieux depuis idle est oublié : plein, il n'a rien à
	// mémoriser. idle doit dépasser le temps de remplir le seau.
	idle time.Duration
	// Au plus maxKeys seaux ; 0, pas de plafond : pour des clés que
	// l'appelant sait bornées (machines authentifiées).
	maxKeys int
	// Plein, oublier le seau vu le plus anciennement plutôt que refuser la
	// clé nouvelle.
	forgetOldest bool
	now          func() time.Time

	mu sync.Mutex
	// recent range les seaux du plus récemment vu (devant) au plus ancien.
	recent    *list.List
	buckets   map[string]*list.Element
	lastSweep time.Time
}

// New borne à `rate` requêtes par seconde en régime continu, avec une
// rafale de `burst` requêtes d'un coup ; un seau sans requête depuis `idle`
// est oublié.
func New(rate float64, burst int, idle time.Duration) *Limiter {
	return &Limiter{
		rate: rate, burst: burst, idle: idle, now: time.Now,
		recent: list.New(), buckets: make(map[string]*list.Element),
	}
}

// NewCapped : les mêmes bornes que New, et au plus maxKeys clés à la fois.
// Plein, le limiteur balaie les seaux oubliés, puis refuse toute clé nouvelle
// (les clés déjà là continuent). Le coût : tant qu'un anonyme tient la table
// pleine, une clé légitime nouvelle est refusée. Pour une clé dont la perte
// ne se rattrape pas, comme le seau d'un jeton reconnu.
func NewCapped(rate float64, burst int, idle time.Duration, maxKeys int) *Limiter {
	limiter := New(rate, burst, idle)
	limiter.maxKeys = maxKeys
	return limiter
}

// newForgetting : au plus maxKeys clés ; plein, le limiteur balaie, puis
// oublie la clé vue il y a le plus longtemps et compte la nouvelle. Jamais
// de refus pour cause de table pleine. Le coût : une rafale de clés
// inventées fait oublier les vraies, qui retrouvent un seau plein ; c'est la
// limite globale de BySource qui borne ce crédit regagné.
func newForgetting(rate float64, burst int, idle time.Duration, maxKeys int) *Limiter {
	limiter := NewCapped(rate, burst, idle, maxKeys)
	limiter.forgetOldest = true
	return limiter
}

func (l *Limiter) SetClock(now func() time.Time) {
	l.now = now
}

// Allow dit si la requête de cette clé passe, et la compte si oui. Les
// seaux oubliés sont balayés au passage ; au plafond, une clé nouvelle est
// refusée, ou fait oublier la plus ancienne (newForgetting).
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepIfDue(now)
	element, ok := l.buckets[key]
	if ok {
		l.recent.MoveToFront(element)
	} else {
		if l.maxKeys > 0 && len(l.buckets) >= l.maxKeys {
			l.sweep(now)
			if len(l.buckets) >= l.maxKeys && !l.forgetOldest {
				return false
			}
			if len(l.buckets) >= l.maxKeys {
				l.forget(l.recent.Back())
			}
		}
		element = l.recent.PushFront(&bucket{key: key, tokens: float64(l.burst), lastSeen: now})
		l.buckets[key] = element
	}
	current := element.Value.(*bucket)
	current.tokens = min(float64(l.burst), current.tokens+now.Sub(current.lastSeen).Seconds()*l.rate)
	current.lastSeen = now
	if current.tokens < 1 {
		return false
	}
	current.tokens--
	return true
}

// sweepIfDue se tient sous le verrou de Allow.
func (l *Limiter) sweepIfDue(now time.Time) {
	if now.Sub(l.lastSweep) < sweepEvery {
		return
	}
	l.sweep(now)
}

// sweep oublie les seaux silencieux depuis idle, sous le verrou de Allow. Il
// part du plus ancien et s'arrête au premier seau encore récent : le coût suit
// ce qu'il oublie, pas la taille de la table.
func (l *Limiter) sweep(now time.Time) {
	l.lastSweep = now
	cutoff := now.Add(-l.idle)
	for oldest := l.recent.Back(); oldest != nil && oldest.Value.(*bucket).lastSeen.Before(cutoff); oldest = l.recent.Back() {
		l.forget(oldest)
	}
}

// forget retire un seau, sous le verrou de Allow.
func (l *Limiter) forget(element *list.Element) {
	delete(l.buckets, element.Value.(*bucket).key)
	l.recent.Remove(element)
}

// Size sert aux tests et au journal.
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// GlobalLimit borne un compteur par adresse toutes sources confondues.
type GlobalLimit struct {
	// Requêtes par minute en régime continu, et rafale d'autant : un
	// compteur qui n'a rien reçu depuis une minute est plein.
	PerMinute int
	// Une source exemptée n'est jamais comptée ici (elle reste comptée par sa
	// propre clé) : la boucle locale de la connexion, l'accès de secours.
	Exempt func(address string) bool
}

// BySource compte par adresse cliente, normalisée par SourceKey : l'appelant
// passe l'adresse telle qu'il la lit, il ne peut pas oublier le /64.
type BySource struct {
	limiter *Limiter
	// Nil : pas de limite globale.
	global *Limiter
	exempt func(address string) bool
}

// NewBySource : les mêmes bornes que New, par source. Au plus MaxSources
// adresses : plein, la source vue il y a le plus longtemps est oubliée et la
// nouvelle comptée, jamais refusée pour cette seule raison.
func NewBySource(rate float64, burst int, idle time.Duration) *BySource {
	return &BySource{limiter: newForgetting(rate, burst, idle, MaxSources)}
}

// NewBySourceWithGlobal : NewBySource, et une limite pour toutes les sources
// ensemble. Elle borne ce que l'oubli rend possible : une rafale d'adresses
// inventées retrouve un seau plein à chaque adresse, pas un crédit sans fin.
func NewBySourceWithGlobal(rate float64, burst int, idle time.Duration, global GlobalLimit) *BySource {
	bySource := NewBySource(rate, burst, idle)
	perSecond := float64(global.PerMinute) / 60
	bySource.global = New(perSecond, global.PerMinute, idle)
	bySource.exempt = global.Exempt
	return bySource
}

func (b *BySource) SetClock(now func() time.Time) {
	b.limiter.SetClock(now)
	if b.global != nil {
		b.global.SetClock(now)
	}
}

// Size sert aux tests, comme Limiter.Size.
func (b *BySource) Size() int {
	return b.limiter.Size()
}

// Allow dit si la requête de cette adresse passe, et la compte si oui. La
// source compte d'abord : une source qui abuse n'entame pas la limite
// globale des autres.
func (b *BySource) Allow(address string) bool {
	if !b.limiter.Allow(SourceKey(address)) {
		return false
	}
	if b.global == nil || (b.exempt != nil && b.exempt(address)) {
		return true
	}
	return b.global.Allow(globalKey)
}
