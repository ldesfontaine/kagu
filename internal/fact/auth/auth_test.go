package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/wait/waittest"
	"golang.org/x/crypto/bcrypt"
)

// memoryStore tient l'état comme la base, sans elle.
type memoryStore struct {
	state    State
	code     SetupCode
	sessions memorySessions
	totp     TOTP
}

func (m *memoryStore) GetAuthState(context.Context) (State, error) {
	if m.state.Mode == "" {
		return State{Mode: ModeNone}, nil
	}
	return m.state, nil
}

func (m *memoryStore) SaveAuthStateIf(ctx context.Context, expected, next State, _ time.Time) (bool, error) {
	current, _ := m.GetAuthState(ctx)
	if !expected.Same(current) {
		return false, nil
	}
	if next.Mode != ModeNative || next.Username != current.Username {
		m.totp = TOTP{}
	}
	m.state = next
	m.code = SetupCode{}
	if next.Mode == ModeNone {
		m.sessions = nil
	}
	return true, nil
}

func (m *memoryStore) GetSetupCode(context.Context) (SetupCode, error) {
	return m.code, nil
}

func (m *memoryStore) SaveSetupCodeIfNone(_ context.Context, code SetupCode, _ time.Time) (bool, error) {
	if m.state.Mode != "" && m.state.Mode != ModeNone {
		return false, nil
	}
	m.code = code
	return true, nil
}

func (m *memoryStore) RecordSetupCodeFailure(context.Context) error {
	m.code.Failures++
	return nil
}

// none est l'état d'une installation neuve, celui sous lequel s'active l'accès.
var none = State{Mode: ModeNone}

func newTestService(t *testing.T) (*Service, *memoryStore) {
	t.Helper()
	store := &memoryStore{}
	service := New(store, slog.New(slog.DiscardHandler))
	service.SetHashCost(bcrypt.MinCost)
	return service, store
}

// issueCode rend le code de première configuration ; hors du mode none il
// n'y en a pas, et le vide est refusé comme un code absent.
func issueCode(t *testing.T, service *Service) string {
	t.Helper()
	issued, err := service.IssueSetupCode(context.Background())
	if errors.Is(err, ErrAlreadyEnabled) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return issued.Code
}

// verifies rend le verdict d'une vérification qui ne doit pas échouer
// autrement que par un mauvais identifiant.
func verifies(t *testing.T, service *Service, state State, username, password string) bool {
	t.Helper()
	verified, err := service.Verify(context.Background(), state, username, password)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return verified
}

func TestEnableNative_StoresASlowHashNeverThePassword(t *testing.T) {
	service, store := newTestService(t)
	if _, err := service.EnableNative(context.Background(), none, issueCode(t, service), "lucas", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if store.state.Mode != ModeNative || !strings.HasPrefix(store.state.PasswordHash, "$2") {
		t.Fatalf("stored %+v", store.state)
	}
	if strings.Contains(store.state.PasswordHash, "correct horse") {
		t.Fatal("the password must not be stored")
	}
}

func TestValidate_RefusesShortPasswordsAndSeparatorInUsername(t *testing.T) {
	if !errors.Is(ValidatePassword("onze carac."), ErrPasswordTooShort) {
		t.Error("11 characters must be refused")
	}
	if ValidatePassword("douze carac.") != nil {
		t.Error("12 characters must pass")
	}
	if !errors.Is(ValidatePassword(strings.Repeat("a", 73)), ErrPasswordTooLong) {
		t.Error("bcrypt ignores beyond 72 bytes: refuse")
	}
	for _, name := range []string{"", "a:b", " lucas", "lu\ncas", strings.Repeat("a", 65)} {
		if !errors.Is(ValidateUsername(name), ErrUsernameInvalid) {
			t.Errorf("%q must be refused", name)
		}
	}
}

// Verify juge contre l'empreinte en vigueur : l'ancien mot de passe ne passe
// plus après un changement, ni après celui de root.
func TestVerify_JudgesTheHashInForce(t *testing.T) {
	service, store := newTestService(t)
	ctx := context.Background()
	state, err := service.EnableNative(ctx, none, issueCode(t, service), "lucas", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !verifies(t, service, state, "lucas", "correct horse battery") {
		t.Fatal("right credentials refused")
	}
	if verifies(t, service, state, "lucas", "something else") {
		t.Fatal("a wrong password passed")
	}
	if verifies(t, service, state, "other", "correct horse battery") {
		t.Fatal("a wrong username passed")
	}
	changed, err := service.ChangePassword(ctx, state, "", "correct horse battery", "another long passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if verifies(t, service, changed, "lucas", "correct horse battery") {
		t.Fatal("the old password survived the change")
	}
	if _, err := service.ResetPassword(ctx, "a passphrase from root"); err != nil {
		t.Fatal(err)
	}
	if verifies(t, service, store.state, "lucas", "another long passphrase") || !verifies(t, service, store.state, "lucas", "a passphrase from root") {
		t.Fatal("the reset password is not the one in force")
	}
}

func TestEnableForward_StoresTheHeaderAndNoCredentials(t *testing.T) {
	service, store := newTestService(t)
	ctx := context.Background()
	state, err := service.EnableForward(ctx, none, issueCode(t, service), DefaultForwardHeader)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != ModeForward || state.Header != "Remote-User" || state.EnabledAt.IsZero() {
		t.Fatalf("returned %+v", state)
	}
	if store.state.Mode != ModeForward || store.state.Header != "Remote-User" || store.state.Username != "" || store.state.PasswordHash != "" {
		t.Fatalf("stored %+v", store.state)
	}
	if _, err := service.EnableForward(ctx, state, issueCode(t, service), "X-Forwarded-User"); !errors.Is(err, ErrAlreadyEnabled) {
		t.Fatalf("enable twice: %v", err)
	}
	if _, err := service.EnableNative(ctx, state, issueCode(t, service), "lucas", "correct horse battery"); !errors.Is(err, ErrAlreadyEnabled) {
		t.Fatalf("native over forward: %v", err)
	}
	if _, err := service.ChangePassword(ctx, state, "", "correct horse battery", "another long passphrase"); !errors.Is(err, ErrNoPassword) {
		t.Fatalf("change password in forward mode: %v", err)
	}
	if verifies(t, service, store.state, "", "") {
		t.Fatal("no credentials verify in forward mode")
	}
	if _, err := service.ResetPassword(ctx, "a passphrase from root"); !errors.Is(err, ErrNoPassword) {
		t.Fatalf("reset password in forward mode: %v", err)
	}
}

func TestEnableForward_RefusesAnInvalidHeaderName(t *testing.T) {
	service, store := newTestService(t)
	for _, header := range []string{"", "Remote User", "Remote-User:", "Remote_User", "Rémote-User", strings.Repeat("a", 65)} {
		if _, err := service.EnableForward(context.Background(), none, issueCode(t, service), header); !errors.Is(err, ErrHeaderInvalid) {
			t.Errorf("%q: %v, want ErrHeaderInvalid", header, err)
		}
	}
	if store.state.Mode != "" {
		t.Fatalf("a refused header changed the state: %+v", store.state)
	}
	for _, header := range []string{"Remote-User", "X-Forwarded-User", "X-Auth-Request-Email", strings.Repeat("a", 64)} {
		if err := ValidateHeader(header); err != nil {
			t.Errorf("%q must pass: %v", header, err)
		}
	}
}

func TestModes_ListsEveryModeTheStoreAccepts(t *testing.T) {
	want := []Mode{ModeNone, ModeNative, ModeForward}
	if got := Modes(); !slices.Equal(got, want) {
		t.Fatalf("modes %v, want %v", got, want)
	}
}

// holdVerification occupe la place de la vérification lente, comme le ferait
// un bcrypt en cours, et la rend à la fin du test.
func holdVerification(t *testing.T, service *Service) (release func()) {
	t.Helper()
	service.verifying <- struct{}{}
	released := false
	release = func() {
		if !released {
			released = true
			<-service.verifying
		}
	}
	t.Cleanup(release)
	return release
}

func waitForQueued(t *testing.T, service *Service, want int32) {
	t.Helper()
	waittest.Until(t, fmt.Sprintf("queued to reach %d", want), func() bool { return service.queued.Load() == want })
}

type verdict struct {
	verified bool
	err      error
}

func verifyInBackground(ctx context.Context, service *Service, state State, username, password string) <-chan verdict {
	result := make(chan verdict, 1)
	go func() {
		verified, err := service.Verify(ctx, state, username, password)
		result <- verdict{verified, err}
	}()
	return result
}

func newNativeState(t *testing.T, service *Service) State {
	t.Helper()
	state, err := service.EnableNative(context.Background(), none, issueCode(t, service), "lucas", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// Une requête qui prend fin pendant l'attente rend sa place dans la file et
// ne coûte aucun bcrypt : des identifiants justes ne passent pas non plus.
func TestVerify_CanceledWhileWaiting_ReturnsWithoutComparing(t *testing.T) {
	service, _ := newTestService(t)
	state := newNativeState(t, service)
	holdVerification(t, service)
	ctx, cancel := context.WithCancel(context.Background())
	result := verifyInBackground(ctx, service, state, "lucas", "correct horse battery")
	waitForQueued(t, service, 1)
	cancel()
	got := <-result
	if got.verified || !errors.Is(got.err, context.Canceled) {
		t.Fatalf("verdict %+v", got)
	}
	waitForQueued(t, service, 0)
}

func TestVerify_CanceledBeforeStarting_GivesTheSlotBack(t *testing.T) {
	service, _ := newTestService(t)
	state := newNativeState(t, service)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	verified, err := service.Verify(ctx, state, "lucas", "correct horse battery")
	if verified || !errors.Is(err, context.Canceled) {
		t.Fatalf("verified %v, err %v", verified, err)
	}
	if len(service.verifying) != 0 {
		t.Fatal("the slot was not given back")
	}
}

func TestVerify_FullQueue_RefusesAtOnce(t *testing.T) {
	service, _ := newTestService(t)
	state := newNativeState(t, service)
	holdVerification(t, service)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiting := make([]<-chan verdict, 0, maxQueuedVerifications)
	for range maxQueuedVerifications {
		waiting = append(waiting, verifyInBackground(ctx, service, state, "lucas", "wrong password here"))
	}
	waitForQueued(t, service, maxQueuedVerifications)

	refused := verifyInBackground(context.Background(), service, state, "lucas", "correct horse battery")
	select {
	case got := <-refused:
		if got.verified || !errors.Is(got.err, ErrVerificationQueueFull) {
			t.Fatalf("verdict %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a full queue must refuse at once, not wait")
	}
	if got := service.queued.Load(); got != maxQueuedVerifications {
		t.Fatalf("a refusal changed the queue: %d", got)
	}

	cancel()
	for _, result := range waiting {
		if got := <-result; !errors.Is(got.err, context.Canceled) {
			t.Fatalf("waiting verdict %+v", got)
		}
	}
	waitForQueued(t, service, 0)
}

// Plusieurs onglets qui se connectent ensemble remplissent la file sans être
// refusés : chacun attend son bcrypt.
func TestVerify_OperatorTabsSigningInTogether_AllPass(t *testing.T) {
	service, _ := newTestService(t)
	state := newNativeState(t, service)
	release := holdVerification(t, service)
	tabs := make([]<-chan verdict, 0, maxQueuedVerifications)
	for range maxQueuedVerifications {
		tabs = append(tabs, verifyInBackground(context.Background(), service, state, "lucas", "correct horse battery"))
	}
	waitForQueued(t, service, maxQueuedVerifications)
	release()
	for i, tab := range tabs {
		if got := <-tab; !got.verified || got.err != nil {
			t.Fatalf("tab %d: verdict %+v", i+1, got)
		}
	}
}

// L'opérateur qui arrive derrière quelques mauvaises tentatives attend son
// tour et passe, tant que la file n'est pas pleine.
func TestVerify_RightOperatorBehindAShortQueue_Passes(t *testing.T) {
	service, _ := newTestService(t)
	state := newNativeState(t, service)
	release := holdVerification(t, service)
	for range maxQueuedVerifications - 1 {
		verifyInBackground(context.Background(), service, state, "lucas", "wrong password here")
	}
	operator := verifyInBackground(context.Background(), service, state, "lucas", "correct horse battery")
	waitForQueued(t, service, maxQueuedVerifications)
	release()
	select {
	case got := <-operator:
		if !got.verified || got.err != nil {
			t.Fatalf("verdict %+v", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the operator never got through")
	}
}

// Une requête autorisée sous un état ne s'applique pas à un autre : le mot
// de passe changé entre-temps, par l'interface ou par root, elle est refusée
// et rien n'est écrit.
func TestChangePassword_RefusesAnAuthorizingStateThatChanged(t *testing.T) {
	service, store := newTestService(t)
	ctx := context.Background()
	authorizing, err := service.EnableNative(ctx, none, issueCode(t, service), "lucas", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	changed, err := service.ChangePassword(ctx, authorizing, "", "correct horse battery", "another long passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ChangePassword(ctx, authorizing, "", "correct horse battery", "a third long passphrase"); !errors.Is(err, ErrStateChanged) {
		t.Fatalf("change under the old state: %v, want ErrStateChanged", err)
	}
	if !store.state.Same(changed) {
		t.Fatalf("a refused request wrote: %+v, want %+v", store.state, changed)
	}
	if _, err := service.ResetPassword(ctx, "a passphrase from root"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ChangePassword(ctx, changed, "", "another long passphrase", "a third long passphrase"); !errors.Is(err, ErrStateChanged) {
		t.Fatalf("change after root reset the password: %v, want ErrStateChanged", err)
	}
}

func TestEnable_RefusesAnAuthorizingStateThatIsNotTheStoredOne(t *testing.T) {
	service, store := newTestService(t)
	ctx := context.Background()
	stale := State{Mode: ModeNative, Username: "lucas", PasswordHash: "ancienne", EnabledAt: time.Unix(1, 0)}
	if _, err := service.EnableNative(ctx, stale, issueCode(t, service), "lucas", "correct horse battery"); !errors.Is(err, ErrStateChanged) {
		t.Fatalf("native: %v, want ErrStateChanged", err)
	}
	if _, err := service.EnableForward(ctx, stale, issueCode(t, service), DefaultForwardHeader); !errors.Is(err, ErrStateChanged) {
		t.Fatalf("forward: %v, want ErrStateChanged", err)
	}
	if store.state.Mode != "" {
		t.Fatalf("a refused activation wrote: %+v", store.state)
	}
}

func TestStateSame_ComparesEveryField(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	base := State{Mode: ModeNative, Username: "lucas", PasswordHash: "empreinte", Header: "", EnabledAt: at}
	if !base.Same(base) || !base.Same(State{Mode: ModeNative, Username: "lucas", PasswordHash: "empreinte", EnabledAt: at.In(time.UTC)}) {
		t.Fatal("the same state must be the same, whatever the time zone")
	}
	for name, other := range map[string]State{
		"mode":      {Mode: ModeForward, Username: "lucas", PasswordHash: "empreinte", EnabledAt: at},
		"username":  {Mode: ModeNative, Username: "autre", PasswordHash: "empreinte", EnabledAt: at},
		"hash":      {Mode: ModeNative, Username: "lucas", PasswordHash: "autre", EnabledAt: at},
		"header":    {Mode: ModeNative, Username: "lucas", PasswordHash: "empreinte", Header: "Remote-User", EnabledAt: at},
		"enabledAt": {Mode: ModeNative, Username: "lucas", PasswordHash: "empreinte", EnabledAt: at.Add(time.Second)},
	} {
		if base.Same(other) {
			t.Errorf("a different %s must not be the same state", name)
		}
	}
}

func TestChangePassword_RefusesAWrongCurrentPasswordBeforeHashing(t *testing.T) {
	service, store := newTestService(t)
	ctx := context.Background()
	state, err := service.EnableNative(ctx, none, issueCode(t, service), "lucas", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	// Un nouveau mot de passe trop court n'est dit qu'au hachage : la
	// réponse prouve que le mot de passe actuel a été jugé avant.
	for _, current := range []string{"", "wrong password here", "Correct horse battery"} {
		if _, err := service.ChangePassword(ctx, state, "", current, "short"); !errors.Is(err, ErrCurrentPasswordWrong) {
			t.Fatalf("current %q: %v, want ErrCurrentPasswordWrong", current, err)
		}
		if !store.state.Same(state) {
			t.Fatalf("current %q: a refused change wrote %+v", current, store.state)
		}
	}
	if _, err := service.ChangePassword(ctx, state, "", "correct horse battery", "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("right current, short new: %v, want ErrPasswordTooShort", err)
	}
}
