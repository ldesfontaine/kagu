package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// recordingAlerter note ce que le composant lui dit du code suspendu.
type recordingAlerter struct {
	mu       sync.Mutex
	locks    []TOTPLock
	unlocked []string
}

func (a *recordingAlerter) TOTPLocked(_ context.Context, lock TOTPLock) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.locks = append(a.locks, lock)
}

func (a *recordingAlerter) TOTPUnlocked(_ context.Context, username string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.unlocked = append(a.unlocked, username)
}

func (a *recordingAlerter) lockCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.locks)
}

func loginFrom(service *Service, state State, source, password, code string) error {
	_, err := service.Login(context.Background(), state, "lucas", password, code, SessionClient{Address: source, Cookie: CookieHost})
	return err
}

// R-A2-16 (W-M4) : six codes faux de six sources suspendent le code ; le
// septième, juste, est refusé ; l'alerte s'ouvre une fois, avec la dernière
// source ; root lève la suspension.
func TestR_A2_16_SixWrongCodesFromSixSourcesLockTheCode(t *testing.T) {
	service, _, state, secret, now := withTOTP(t)
	alerter := &recordingAlerter{}
	service.SetAlerter(alerter)
	wrong := wrongCodeAt(t, secret, *now)
	sources := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5", "203.0.113.6"}
	for index, source := range sources {
		err := loginFrom(service, state, source, testPassword, wrong)
		if index < 4 && !errors.Is(err, ErrTOTPWrong) {
			t.Fatalf("wrong code %d: got %v, want ErrTOTPWrong", index+1, err)
		}
		if index >= 4 && !errors.Is(err, ErrTOTPLocked) {
			t.Fatalf("wrong code %d: got %v, want ErrTOTPLocked", index+1, err)
		}
	}
	right := codeAt(t, secret, *now)
	err := loginFrom(service, state, "203.0.113.7", testPassword, right)
	var locked *TOTPLockedError
	if !errors.As(err, &locked) || !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("the right code while suspended: got %v, want ErrTOTPLocked", err)
	}
	if want := now.Add(DefaultTOTPLock); !locked.Until.Equal(want) {
		t.Fatalf("suspended until %v, want %v", locked.Until, want)
	}
	if len(alerter.locks) != 1 || alerter.locks[0].Source != "203.0.113.5" || alerter.locks[0].Username != "lucas" || !alerter.locks[0].Until.Equal(locked.Until) {
		t.Fatalf("alerts: %+v, want one, naming the source of the fifth wrong code", alerter.locks)
	}

	if err := service.Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := loginFrom(service, state, "203.0.113.7", testPassword, right); err != nil {
		t.Fatalf("the right code after unlock: %v", err)
	}
	if len(alerter.unlocked) == 0 || alerter.unlocked[0] != "lucas" {
		t.Fatalf("unlocked: %v, want the account named", alerter.unlocked)
	}
}

// Une suspension finit d'elle-même ; un code juste remet les codes faux à
// zéro ; un autre mot de passe faux ne touche pas au code.
func TestR_A2_16_ALockEndsAndARightCodeResetsTheCount(t *testing.T) {
	service, store, state, secret, now := withTOTP(t)
	wrong := wrongCodeAt(t, secret, *now)
	for range 4 {
		_ = loginFrom(service, state, "203.0.113.1", testPassword, wrong)
	}
	if err := loginFrom(service, state, "203.0.113.1", testPassword, codeAt(t, secret, *now)); err != nil {
		t.Fatalf("the right code under the limit: %v", err)
	}
	if store.failures.TOTP.Count != 0 {
		t.Fatalf("a right code left %d wrong codes counted", store.failures.TOTP.Count)
	}
	*now = now.Add(TOTPPeriod)
	for range 4 {
		if err := loginFrom(service, state, "203.0.113.2", testPassword, wrong); errors.Is(err, ErrTOTPLocked) {
			t.Fatal("the count was not reset by the right code")
		}
	}
	*now = now.Add(TOTPPeriod)
	if err := loginFrom(service, state, "203.0.113.2", testPassword, wrongCodeAt(t, secret, *now)); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("fifth wrong code: got %v", err)
	}
	*now = now.Add(DefaultTOTPLock)
	if err := loginFrom(service, state, "203.0.113.2", testPassword, codeAt(t, secret, *now)); err != nil {
		t.Fatalf("the right code after the suspension: %v", err)
	}
}

// Un mot de passe faux ne compte pas contre le code, et un code faux sans
// mot de passe juste n'est jamais jugé.
func TestR_A2_16_OnlyACodeJudgedAfterTheRightPasswordCounts(t *testing.T) {
	service, store, state, secret, now := withTOTP(t)
	wrong := wrongCodeAt(t, secret, *now)
	for range 8 {
		_ = loginFrom(service, state, "203.0.113.1", "a wrong passphrase", wrong)
	}
	if store.failures.TOTP.Count != 0 || store.failures.TOTP.Locked(*now) {
		t.Fatalf("wrong passwords moved the code counters: %+v", store.failures.TOTP)
	}
}

// R-A2-16 : au-delà de vingt mots de passe faux dans l'heure, le compte
// n'accepte plus qu'un essai toutes les trente secondes, quelle que soit la
// source, et un essai ralenti n'est pas même comparé.
func TestR_A2_16_TwentyWrongPasswordsSlowTheAccount(t *testing.T) {
	service, store := newTestService(t)
	now := totpNow
	service.SetClock(func() time.Time { return now })
	state := newNativeState(t, service)
	for index := range DefaultPasswordFailuresPerHour + 1 {
		source := fmt.Sprintf("198.51.100.%d", index)
		if err := loginFrom(service, state, source, "a wrong passphrase", ""); !errors.Is(err, ErrLoginFailed) {
			t.Fatalf("wrong password %d: got %v, want ErrLoginFailed", index+1, err)
		}
	}
	if err := loginFrom(service, state, "198.51.100.99", "a wrong passphrase", ""); !errors.Is(err, ErrAccountSlowed) {
		t.Fatalf("the 22nd wrong password: got %v, want ErrAccountSlowed", err)
	}
	if err := loginFrom(service, state, "198.51.100.98", testPassword, ""); !errors.Is(err, ErrAccountSlowed) {
		t.Fatalf("the right password while slowed: got %v, want ErrAccountSlowed (never compared)", err)
	}
	now = now.Add(DefaultPasswordPace - time.Second)
	if err := loginFrom(service, state, "198.51.100.97", testPassword, ""); !errors.Is(err, ErrAccountSlowed) {
		t.Fatalf("29 s later: got %v, want ErrAccountSlowed", err)
	}
	now = now.Add(time.Second)
	if err := loginFrom(service, state, "198.51.100.96", "a wrong passphrase", ""); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("30 s later, one try: got %v, want ErrLoginFailed", err)
	}
	if err := loginFrom(service, state, "198.51.100.95", testPassword, ""); !errors.Is(err, ErrAccountSlowed) {
		t.Fatalf("right after that try: got %v, want ErrAccountSlowed", err)
	}
	now = now.Add(DefaultPasswordPace)
	if err := loginFrom(service, state, "198.51.100.94", testPassword, ""); err != nil {
		t.Fatalf("the right password at the next slot: %v", err)
	}
	if store.failures.Password.Count != 0 {
		t.Fatalf("a right password left %d wrong ones counted", store.failures.Password.Count)
	}
	if err := loginFrom(service, state, "198.51.100.93", "a wrong passphrase", ""); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("after the reset: got %v, want a plain ErrLoginFailed", err)
	}
}

// Vingt mots de passe faux répartis sur plus d'une heure ne ralentissent
// pas : l'heure comptée est une fenêtre, pas un total.
func TestR_A2_16_WrongPasswordsOfAnotherHourDoNotAdd(t *testing.T) {
	service, _ := newTestService(t)
	now := totpNow
	service.SetClock(func() time.Time { return now })
	state := newNativeState(t, service)
	for range DefaultPasswordFailuresPerHour {
		_ = loginFrom(service, state, "198.51.100.1", "a wrong passphrase", "")
	}
	now = now.Add(time.Hour)
	for range 3 {
		if err := loginFrom(service, state, "198.51.100.2", "a wrong passphrase", ""); !errors.Is(err, ErrLoginFailed) {
			t.Fatalf("an hour later: got %v, want ErrLoginFailed", err)
		}
	}
}

// root lève aussi le ralentissement du compte.
func TestUnlock_LiftsTheSlowdown(t *testing.T) {
	service, _ := newTestService(t)
	state := newNativeState(t, service)
	for range DefaultPasswordFailuresPerHour + 2 {
		_ = loginFrom(service, state, "198.51.100.1", "a wrong passphrase", "")
	}
	if err := loginFrom(service, state, "198.51.100.1", testPassword, ""); !errors.Is(err, ErrAccountSlowed) {
		t.Fatalf("got %v, want ErrAccountSlowed", err)
	}
	if err := service.Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := loginFrom(service, state, "198.51.100.1", testPassword, ""); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
}

func TestUnlock_RefusedWithoutAPasswordAccount(t *testing.T) {
	service, _ := newTestService(t)
	if err := service.Unlock(context.Background()); !errors.Is(err, ErrDisabled) {
		t.Fatalf("no account: got %v, want ErrDisabled", err)
	}
}

// R-A2-16 : deux tentatives fausses lancées ensemble comptent deux, et cinq
// codes faux lancés ensemble suspendent le code une seule fois.
func TestR_A2_16_TwoAttemptsAtOnceCountTwice(t *testing.T) {
	service, store, state, secret, now := withTOTP(t)
	alerter := &recordingAlerter{}
	service.SetAlerter(alerter)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			_ = loginFrom(service, state, "198.51.100.1", "a wrong passphrase", "")
		}()
	}
	group.Wait()
	if got := store.failures.Password.Count; got != 2 {
		t.Fatalf("two wrong passwords at once counted %d", got)
	}
	wrong := wrongCodeAt(t, secret, *now)
	for range 5 {
		group.Add(1)
		go func() {
			defer group.Done()
			_ = loginFrom(service, state, "198.51.100.2", testPassword, wrong)
		}()
	}
	group.Wait()
	if !store.failures.TOTP.Locked(*now) {
		t.Fatalf("five wrong codes at once left the code open: %+v", store.failures.TOTP)
	}
	if got := alerter.lockCount(); got != 1 {
		t.Fatalf("%d alerts for one suspension", got)
	}
}
