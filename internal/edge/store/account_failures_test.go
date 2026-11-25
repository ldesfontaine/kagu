package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
)

func addPasswordFailure(failures auth.AccountFailures) auth.AccountFailures {
	failures.Password.Count++
	failures.Password.WindowStart = time.Unix(5_000, 0)
	return failures
}

// Les compteurs se lisent, se changent et s'écrivent dans une seule
// transaction : des changements lancés ensemble s'additionnent tous. Sans
// compte, rien ne s'écrit.
func TestChangeAccountFailures_ConcurrentChangesAllCount(t *testing.T) {
	ctx := context.Background()
	empty := openTestDB(t)
	if _, after, err := empty.ChangeAccountFailures(ctx, addPasswordFailure); err != nil || after.Password.Count != 1 {
		t.Fatalf("without an account: %+v %v, want the change computed and nothing stored", after, err)
	}
	if got, err := empty.GetAccountFailures(ctx); err != nil || got.Password.Count != 0 {
		t.Fatalf("without an account: stored %+v %v", got, err)
	}

	db := nativeTOTPDB(t)
	const attempts = 12
	var group sync.WaitGroup
	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, _, err := db.ChangeAccountFailures(ctx, addPasswordFailure); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	got, err := db.GetAccountFailures(ctx)
	if err != nil || got.Password.Count != attempts || !got.Password.WindowStart.Equal(time.Unix(5_000, 0)) {
		t.Fatalf("%d changes at once left %+v %v", attempts, got.Password, err)
	}
}

// Un code suspendu ne sert aucun pas, même juste ; la suspension finie, il le
// sert et remet les codes faux à zéro.
func TestConsumeTOTPStep_RefusedWhileLockedAndResetsTheCount(t *testing.T) {
	db := nativeTOTPDB(t)
	ctx := context.Background()
	until := time.Unix(2_000, 0)
	if _, _, err := db.ChangeAccountFailures(ctx, func(failures auth.AccountFailures) auth.AccountFailures {
		failures.TOTP = auth.TOTPFailures{Count: 0, LockedUntil: until}
		return failures
	}); err != nil {
		t.Fatal(err)
	}
	if served, err := db.ConsumeTOTPStep(ctx, 101, until.Add(-time.Second)); err != nil || served {
		t.Fatalf("while locked: served %v (%v)", served, err)
	}
	if got, _ := db.GetTOTP(ctx); got.LastStep != 100 {
		t.Fatalf("a refused step moved the last step to %d", got.LastStep)
	}
	if served, err := db.ConsumeTOTPStep(ctx, 101, until); err != nil || !served {
		t.Fatalf("once the lock is over: served %v (%v)", served, err)
	}
	if got, _ := db.GetAccountFailures(ctx); got.TOTP.Count != 0 || !got.TOTP.LockedUntil.IsZero() {
		t.Fatalf("a served step left %+v", got.TOTP)
	}
}

// Les échecs suivent le compte comme le code : un mot de passe refait les
// garde, un autre compte, le SSO, le retrait du code et une clé perdue les
// remettent à zéro.
func TestAccountFailures_FollowTheAccount(t *testing.T) {
	ctx := context.Background()
	counted := func(failures auth.AccountFailures) auth.AccountFailures {
		failures = addPasswordFailure(failures)
		failures.TOTP = auth.TOTPFailures{Count: 3, LockedUntil: time.Unix(9_000, 0)}
		failures.Password.LastAttempt = time.Unix(5_010, 0)
		return failures
	}
	db := nativeTOTPDB(t)
	if _, _, err := db.ChangeAccountFailures(ctx, counted); err != nil {
		t.Fatal(err)
	}
	native, _ := db.GetAuthState(ctx)
	refreshed := native
	refreshed.PasswordHash = "$2a$other"
	if saved, err := db.SaveAuthStateIf(ctx, native, refreshed, time.Unix(2, 0)); err != nil || !saved {
		t.Fatal(err)
	}
	if got, _ := db.GetAccountFailures(ctx); got.Password.Count != 1 || got.TOTP.Count != 3 || !got.Password.LastAttempt.Equal(time.Unix(5_010, 0)) {
		t.Fatalf("a password reset cleared the failures: %+v", got)
	}
	another := refreshed
	another.Username = "marie"
	if saved, err := db.SaveAuthStateIf(ctx, refreshed, another, time.Unix(3, 0)); err != nil || !saved {
		t.Fatal(err)
	}
	if got, _ := db.GetAccountFailures(ctx); !got.Same(auth.AccountFailures{}) {
		t.Fatalf("another account inherited %+v", got)
	}

	removed := nativeTOTPDB(t)
	if _, _, err := removed.ChangeAccountFailures(ctx, counted); err != nil {
		t.Fatal(err)
	}
	if cleared, err := removed.ClearTOTP(ctx); err != nil || !cleared {
		t.Fatal(cleared, err)
	}
	if got, _ := removed.GetAccountFailures(ctx); got.TOTP.Count != 0 || !got.TOTP.LockedUntil.IsZero() || got.Password.Count != 1 {
		t.Fatalf("removing the code left %+v, want the code counters at zero and the password ones kept", got)
	}
}
