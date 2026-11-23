package ratelimit

import (
	"sync"
	"time"
)

// sweepEvery : le balayage des seaux oubliés se fait au passage d'une
// requête, au plus une fois par période, sans goroutine.
const sweepEvery = 5 * time.Minute

// MaxSources borne les clés d'un limiteur par adresse : une adresse se
// invente, et chaque clé reste en mémoire jusqu'au balayage.
const MaxSources = 4096

// Un seau par clé : il se remplit au rythme donné jusqu'à sa contenance, et
// chaque requête en retire une unité.
type bucket struct {
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
	now     func() time.Time

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

// New borne à `rate` requêtes par seconde en régime continu, avec une
// rafale de `burst` requêtes d'un coup ; un seau sans requête depuis `idle`
// est oublié.
func New(rate float64, burst int, idle time.Duration) *Limiter {
	return &Limiter{rate: rate, burst: burst, idle: idle, now: time.Now, buckets: make(map[string]*bucket)}
}

// NewCapped : les mêmes bornes que New, et au plus maxKeys clés à la fois.
// Plein, le limiteur balaie les seaux oubliés, puis refuse toute clé nouvelle
// (les clés déjà là continuent). Le coût : tant qu'un anonyme tient la table
// pleine, une clé légitime nouvelle est refusée. Pour toute clé qu'un anonyme
// peut inventer.
func NewCapped(rate float64, burst int, idle time.Duration, maxKeys int) *Limiter {
	limiter := New(rate, burst, idle)
	limiter.maxKeys = maxKeys
	return limiter
}

func (l *Limiter) SetClock(now func() time.Time) {
	l.now = now
}

// Allow dit si la requête de cette clé passe, et la compte si oui. Les
// seaux oubliés sont balayés au passage ; au plafond, une clé nouvelle est
// refusée.
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepIfDue(now)
	current, ok := l.buckets[key]
	if !ok {
		if l.maxKeys > 0 && len(l.buckets) >= l.maxKeys {
			l.sweep(now)
			if len(l.buckets) >= l.maxKeys {
				return false
			}
		}
		current = &bucket{tokens: float64(l.burst), lastSeen: now}
		l.buckets[key] = current
	}
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

// sweep oublie les seaux silencieux depuis idle, sous le verrou de Allow.
func (l *Limiter) sweep(now time.Time) {
	l.lastSweep = now
	cutoff := now.Add(-l.idle)
	for key, current := range l.buckets {
		if current.lastSeen.Before(cutoff) {
			delete(l.buckets, key)
		}
	}
}

// Size sert aux tests et au journal.
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// BySource compte par adresse cliente, normalisée par sourceKey : l'appelant
// passe l'adresse telle qu'il la lit, il ne peut pas oublier le /64.
type BySource struct {
	limiter *Limiter
}

// NewBySource : les mêmes bornes que New, par source. Plafonné à MaxSources adresses.
func NewBySource(rate float64, burst int, idle time.Duration) *BySource {
	return &BySource{limiter: NewCapped(rate, burst, idle, MaxSources)}
}

func (b *BySource) SetClock(now func() time.Time) {
	b.limiter.SetClock(now)
}

// Size sert aux tests, comme Limiter.Size.
func (b *BySource) Size() int {
	return b.limiter.Size()
}

// Allow dit si la requête de cette adresse passe, et la compte si oui.
func (b *BySource) Allow(address string) bool {
	return b.limiter.Allow(sourceKey(address))
}
