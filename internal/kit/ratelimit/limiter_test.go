package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

const testIdle = 10 * time.Minute

func newTestLimiter(rate float64, burst int) (*Limiter, *time.Time) {
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	limiter := New(rate, burst, testIdle)
	limiter.SetClock(func() time.Time { return now })
	return limiter, &now
}

func TestAllow_BurstThenRefillAtRate(t *testing.T) {
	limiter, now := newTestLimiter(1, 3)
	for i := range 3 {
		if !limiter.Allow("ip") {
			t.Fatalf("request %d of the burst refused", i+1)
		}
	}
	if limiter.Allow("ip") {
		t.Fatal("fourth request passed with an empty bucket")
	}
	*now = now.Add(500 * time.Millisecond)
	if limiter.Allow("ip") {
		t.Fatal("half a unit is not a unit")
	}
	*now = now.Add(500 * time.Millisecond)
	if !limiter.Allow("ip") {
		t.Fatal("one second later, one request must pass")
	}
	*now = now.Add(time.Hour)
	for i := range 3 {
		if !limiter.Allow("ip") {
			t.Fatalf("after a long rest the burst is back, request %d refused", i+1)
		}
	}
	if limiter.Allow("ip") {
		t.Fatal("the bucket never holds more than the burst")
	}
}

func TestAllow_KeysAreIndependent(t *testing.T) {
	limiter, _ := newTestLimiter(1, 1)
	if !limiter.Allow("a") || limiter.Allow("a") || !limiter.Allow("b") {
		t.Fatal("keys share a bucket")
	}
}

// Le balayage passe avec une requête, au plus une fois par période, et
// n'oublie que les seaux silencieux depuis plus que l'oisiveté.
func TestAllow_SweepsIdleKeysOnlyOncePerPeriod(t *testing.T) {
	limiter, now := newTestLimiter(1, 1)
	limiter.Allow("old")
	*now = now.Add(testIdle + time.Minute)
	limiter.Allow("fresh")
	if limiter.Size() != 1 {
		t.Fatalf("after the sweep: size %d, want 1", limiter.Size())
	}
	limiter.Allow("other")
	*now = now.Add(testIdle + time.Minute)
	limiter.Allow("again")
	*now = now.Add(sweepEvery - time.Second)
	limiter.Allow("late")
	// « fresh » et « other » sont partis au balayage d'« again » ; celui de
	// « late » n'est pas encore dû.
	if limiter.Size() != 2 {
		t.Fatalf("before the next period: size %d, want 2", limiter.Size())
	}
}

// Deux adresses d'un même /64 partagent un seau ; un autre /64 a le sien.
func TestBySource_SharesOneBucketPerIPv6SixtyFour(t *testing.T) {
	limiter := NewBySource(1, 2, testIdle)
	if !limiter.Allow("2001:db8:9:9::1") || !limiter.Allow("2001:db8:9:9::2") {
		t.Fatal("the burst must pass")
	}
	if limiter.Allow("2001:db8:9:9::3") {
		t.Fatal("a third address of the same /64 got its own bucket")
	}
	if !limiter.Allow("2001:db8:9:a::1") || !limiter.Allow("203.0.113.9") {
		t.Fatal("another source must have its own bucket")
	}
}

// Au plafond, une clé nouvelle est refusée, une clé déjà là passe, et un
// seau oublié, balayé, libère sa place.
func TestR_A2_15_ALimiterStopsAtItsCap(t *testing.T) {
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	limiter := NewCapped(1, 5, testIdle, 2)
	limiter.SetClock(func() time.Time { return now })
	if !limiter.Allow("a") || !limiter.Allow("b") {
		t.Fatal("keys under the cap must pass")
	}
	if limiter.Allow("c") {
		t.Fatal("a new key passed at the cap")
	}
	if limiter.Size() != 2 {
		t.Fatalf("size %d, want 2: a refused key must leave no bucket", limiter.Size())
	}
	if !limiter.Allow("a") {
		t.Fatal("a key already there must keep passing at the cap")
	}
	// « a » et « b » deviennent oubliables ; le balayage forcé par la clé
	// nouvelle, sans attendre la période, leur reprend la place.
	now = now.Add(testIdle + time.Second)
	if !limiter.Allow("c") {
		t.Fatal("a forgotten bucket must free its place")
	}
	if limiter.Size() != 1 {
		t.Fatalf("size %d, want 1 after the sweep", limiter.Size())
	}
}

func TestR_A2_15_BySourceIsCappedAtMaxSources(t *testing.T) {
	limiter := NewBySource(1, 1, testIdle)
	for i := range MaxSources + 100 {
		limiter.Allow(fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255))
	}
	if size := limiter.Size(); size != MaxSources {
		t.Fatalf("size %d, want %d", size, MaxSources)
	}
}

// Table pleine : la source neuve est comptée, la plus anciennement vue est
// oubliée, la taille ne dépasse jamais le plafond.
func TestE02_19_ASourceTableForgetsTheOldestInsteadOfRefusing(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	limiter := NewBySource(1, 1, testIdle)
	limiter.SetClock(func() time.Time { return now })
	for i := range MaxSources {
		now = now.Add(time.Millisecond)
		limiter.Allow(fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255))
	}
	now = now.Add(time.Millisecond)
	if !limiter.Allow("203.0.113.77") {
		t.Fatal("a new source was refused because the table is full")
	}
	if size := limiter.Size(); size != MaxSources {
		t.Fatalf("size %d, want %d", size, MaxSources)
	}
	// La plus ancienne (10.0.0.0) est partie : elle retrouve un seau plein.
	if !limiter.Allow("10.0.0.0") {
		t.Fatal("the forgotten oldest source must be counted as new")
	}
	// La plus récente avant la nouvelle garde son seau vide.
	if limiter.Allow("10.0.15.255") {
		t.Fatal("a recent source lost its bucket")
	}
}

// Une source qui revient est la plus récente : elle n'est pas la prochaine
// oubliée.
func TestE02_19_ASeenSourceIsNotTheNextForgotten(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	limiter := newForgetting(1, 1, testIdle, 2)
	limiter.SetClock(func() time.Time { return now })
	limiter.Allow("a")
	now = now.Add(time.Second)
	limiter.Allow("b")
	now = now.Add(time.Second)
	limiter.Allow("a")
	now = now.Add(time.Second)
	limiter.Allow("c")
	if _, kept := limiter.buckets["a"]; !kept {
		t.Fatal("a was forgotten while b was older")
	}
	if _, kept := limiter.buckets["b"]; kept {
		t.Fatal("b, the oldest seen, was kept")
	}
}

func newGlobalTestLimiter(perMinute int, exempt func(string) bool) (*BySource, *time.Time) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	limiter := NewBySourceWithGlobal(1, 5, testIdle, GlobalLimit{PerMinute: perMinute, Exempt: exempt})
	limiter.SetClock(func() time.Time { return now })
	return limiter, &now
}

// Les sources neuves ont chacune un seau plein : la limite globale borne le
// total, et rend le crédit au rythme de la minute.
func TestE02_19_TheGlobalLimitBoundsAllSourcesTogether(t *testing.T) {
	limiter, now := newGlobalTestLimiter(60, nil)
	for i := range 60 {
		if !limiter.Allow(fmt.Sprintf("10.0.0.%d", i)) {
			t.Fatalf("request %d under the global limit refused", i+1)
		}
	}
	if limiter.Allow("10.0.1.1") {
		t.Fatal("the global limit did not stop a fresh source")
	}
	*now = now.Add(2 * time.Second)
	if !limiter.Allow("10.0.1.2") {
		t.Fatal("the global limit must refill over time")
	}
}

// Un refus de la source ne coûte rien à la limite globale.
func TestE02_19_ARefusedSourceSpendsNothingGlobally(t *testing.T) {
	limiter, _ := newGlobalTestLimiter(10, nil)
	for range 5 {
		limiter.Allow("10.0.0.1")
	}
	for range 100 {
		if limiter.Allow("10.0.0.1") {
			t.Fatal("an empty source bucket let a request pass")
		}
	}
	for i := range 5 {
		if !limiter.Allow(fmt.Sprintf("10.0.1.%d", i)) {
			t.Fatal("the abusive source drained the global limit")
		}
	}
}

// L'exemptée n'est jamais comptée globalement, mais garde son seau.
func TestE02_19_AnExemptSourceIsNeverCountedGlobally(t *testing.T) {
	limiter, _ := newGlobalTestLimiter(5, func(address string) bool { return address == "127.0.0.1" })
	for i := range 5 {
		limiter.Allow(fmt.Sprintf("10.0.0.%d", i))
	}
	if limiter.Allow("10.0.1.1") {
		t.Fatal("the global limit is not saturated")
	}
	if !limiter.Allow("127.0.0.1") {
		t.Fatal("the exempt source was stopped by the global limit")
	}
	for range 4 {
		limiter.Allow("127.0.0.1")
	}
	if limiter.Allow("127.0.0.1") {
		t.Fatal("the exempt source lost its own bucket")
	}
}

// Le balayage part du plus ancien et ne touche pas les seaux récents.
func TestSweep_KeepsRecentBucketsBehindAnOldOne(t *testing.T) {
	limiter, now := newTestLimiter(1, 1)
	limiter.Allow("old")
	*now = now.Add(testIdle - time.Second)
	limiter.Allow("recent")
	*now = now.Add(2 * time.Second)
	limiter.sweep(*now)
	if _, kept := limiter.buckets["recent"]; limiter.Size() != 1 || !kept {
		t.Fatal("the sweep must forget only the idle bucket")
	}
}
