package alert_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/domain/alert"
)

// fakeClockSync est l'état de l'horloge que le test choisit.
type fakeClockSync struct {
	synced bool
	err    error
}

func (s *fakeClockSync) read() (bool, error) { return s.synced, s.err }

// E02-21 : l'horloge de la machine Kagu non synchronisée plus de
// ClockUnsyncedDelay ouvre l'alerte, qui dit depuis quand ; elle se ferme
// d'elle-même au retour de la synchronisation.
func TestE02_21_UnsyncedClockOpensThenClosesTheAlert(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	clock := &fakeClockSync{synced: true}
	watch := alert.NewClockWatch(f.Engine, clock.read)

	watch.Check(ctx)
	clock.synced = false
	f.advance(time.Minute)
	started := f.clock
	watch.Check(ctx)
	f.advance(alert.ClockUnsyncedDelay - time.Second)
	watch.Check(ctx)
	if got := f.open(t, alert.StatusOpen); len(got) != 0 {
		t.Fatalf("open before the delay: %+v", got)
	}

	f.advance(time.Second)
	watch.Check(ctx)
	opened := f.only(t, alert.StatusOpen)
	if opened.Kind != alert.KindClockUnsynced || opened.Object.Kind != alert.ObjectServer || opened.Severity != alert.SeverityAttention || !opened.Details.Since.Equal(started) {
		t.Fatalf("opened %+v", opened)
	}
	if category, _ := alert.CategoryOf(opened.Kind); category != alert.CategoryMachines {
		t.Fatalf("category %s", category)
	}

	// Une lecture impossible ne ferme rien.
	clock.err = errors.New("adjtimex: operation not permitted")
	watch.Check(ctx)
	f.only(t, alert.StatusOpen)

	clock.synced, clock.err = true, nil
	f.advance(time.Minute)
	watch.Check(ctx)
	if got := f.open(t, alert.StatusOpen); len(got) != 0 {
		t.Fatalf("still open once synchronized: %+v", got)
	}
	if resolved := f.only(t, alert.StatusResolved); resolved.ID != opened.ID {
		t.Fatalf("resolved %+v", resolved)
	}
}

// Une perte brève, plus courte que le délai, n'alerte pas : le délai repart
// de zéro à la perte suivante.
func TestE02_21_ShortLossesDoNotAddUp(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	clock := &fakeClockSync{}
	watch := alert.NewClockWatch(f.Engine, clock.read)

	watch.Check(ctx)
	f.advance(alert.ClockUnsyncedDelay - time.Minute)
	watch.Check(ctx)
	clock.synced = true
	watch.Check(ctx)
	clock.synced = false
	f.advance(time.Minute)
	watch.Check(ctx)
	f.advance(alert.ClockUnsyncedDelay - time.Minute)
	watch.Check(ctx)
	if got := f.open(t, alert.StatusOpen); len(got) != 0 {
		t.Fatalf("short losses added up: %+v", got)
	}
}
