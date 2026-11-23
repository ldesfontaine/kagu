package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func (m *memoryStore) GetTOTP(context.Context) (TOTP, error) {
	return m.totp, nil
}

func (m *memoryStore) EnableTOTPIfNone(_ context.Context, secret string, servedStep int64) (bool, error) {
	if m.state.Mode != ModeNative || m.totp.Active() {
		return false, nil
	}
	m.totp = TOTP{Secret: secret, LastStep: servedStep}
	return true, nil
}

func (m *memoryStore) ClearTOTP(context.Context) (bool, error) {
	was := m.totp.Active()
	m.totp = TOTP{}
	return was, nil
}

func (m *memoryStore) ConsumeTOTPStep(_ context.Context, step int64) (bool, error) {
	if !m.totp.Active() || step <= m.totp.LastStep {
		return false, nil
	}
	m.totp.LastStep = step
	return true, nil
}

// RFC 6238, annexe B : le secret ASCII « 12345678901234567890 », SHA-1, huit
// chiffres, pas de 30 s.
func TestTOTPCode_RFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, vector := range vectors {
		step := TOTPStep(time.Unix(vector.unix, 0))
		if got := hotp(secret, uint64(step), 8); got != vector.want {
			t.Errorf("T=%d: got %s, want %s", vector.unix, got, vector.want)
		}
	}
}

// RFC 4226, annexe D : HOTP à six chiffres, compteurs 0 à 9. TOTP en est la
// forme à six chiffres que la connexion juge.
func TestTOTPCode_RFC4226Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, expected := range want {
		if got := hotp(secret, uint64(counter), TOTPDigits); got != expected {
			t.Errorf("counter %d: got %s, want %s", counter, got, expected)
		}
	}
}

// totpNow est l'horloge des tests : au début d'un pas, pour que « un pas plus
// tard » ne déborde pas.
var totpNow = time.Unix(1_800_000_000-1_800_000_000%30, 0)

// codeAt rend le code du secret au pas de at.
func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	raw, err := DecodeTOTPSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	return TOTPCode(raw, TOTPStep(at))
}

// wrongCodeAt rend un code bien formé qu'aucun pas voisin de at n'accepte.
func wrongCodeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	for _, candidate := range []string{"000000", "111111", "222222", "333333"} {
		taken := false
		for _, step := range []time.Duration{-TOTPPeriod, 0, TOTPPeriod} {
			taken = taken || codeAt(t, secret, at.Add(step)) == candidate
		}
		if !taken {
			return candidate
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

// withTOTP rend un service en native avec un code actif, son état, son secret
// et l'horloge réglable.
func withTOTP(t *testing.T) (*Service, *memoryStore, State, string, *time.Time) {
	t.Helper()
	service, store := newTestService(t)
	now := totpNow
	service.SetClock(func() time.Time { return now })
	state := newNativeState(t, service)
	proposal, err := service.ProposeTOTP(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnableTOTP(context.Background(), state, proposal.Secret, codeAt(t, proposal.Secret, now)); err != nil {
		t.Fatal(err)
	}
	// Le pas suivant : le code de l'activation est servi.
	now = now.Add(TOTPPeriod)
	return service, store, state, proposal.Secret, &now
}

func login(service *Service, state State, code string) error {
	_, err := service.Login(context.Background(), state, "lucas", testPassword, code, SessionClient{})
	return err
}

// R-A2-6 : un code juste ne sert qu'une fois. Servi, il est refusé dans sa
// fenêtre, comme tout code d'un pas déjà passé.
func TestR_A2_6_ACodeServesOnce(t *testing.T) {
	service, _, state, secret, now := withTOTP(t)
	code := codeAt(t, secret, *now)
	if err := login(service, state, code); err != nil {
		t.Fatalf("first use: %v", err)
	}
	*now = now.Add(10 * time.Second)
	if err := login(service, state, code); !errors.Is(err, ErrTOTPWrong) {
		t.Fatalf("the same code again in its window: got %v, want ErrTOTPWrong", err)
	}
	if err := login(service, state, codeAt(t, secret, now.Add(-TOTPPeriod))); !errors.Is(err, ErrTOTPWrong) {
		t.Fatalf("the code of the step before, still in the margin: got %v, want ErrTOTPWrong", err)
	}
	*now = now.Add(TOTPPeriod)
	if err := login(service, state, codeAt(t, secret, *now)); err != nil {
		t.Fatalf("the next step's code: %v", err)
	}
}

// Le code de l'activation est servi : il ne rouvre pas une connexion.
func TestEnableTOTP_TheFirstCodeIsServed(t *testing.T) {
	service, store := newTestService(t)
	service.SetClock(func() time.Time { return totpNow })
	state := newNativeState(t, service)
	proposal, err := service.ProposeTOTP(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	code := codeAt(t, proposal.Secret, totpNow)
	if err := service.EnableTOTP(context.Background(), state, proposal.Secret, code); err != nil {
		t.Fatal(err)
	}
	if store.totp.Secret != proposal.Secret || store.totp.LastStep != TOTPStep(totpNow) {
		t.Fatalf("stored %+v", store.totp)
	}
	if err := login(service, state, code); !errors.Is(err, ErrTOTPWrong) {
		t.Fatalf("the enrolment code opened a session: %v", err)
	}
}

// Un pas de marge de part et d'autre, pas deux.
func TestRequireTOTP_OneStepOfMargin(t *testing.T) {
	cases := map[time.Duration]bool{-TOTPPeriod: true, TOTPPeriod: true, 2 * TOTPPeriod: false, -2 * TOTPPeriod: false}
	for offset, accepted := range cases {
		service, _, state, secret, now := withTOTP(t)
		*now = now.Add(5 * TOTPPeriod)
		err := login(service, state, codeAt(t, secret, now.Add(offset)))
		if accepted && err != nil {
			t.Errorf("offset %s: refused: %v", offset, err)
		}
		if !accepted && !errors.Is(err, ErrTOTPWrong) {
			t.Errorf("offset %s: got %v, want ErrTOTPWrong", offset, err)
		}
	}
}

// Le code ne se juge qu'après un mot de passe juste ; sans code, la
// connexion le demande ; un code mal formé ou faux est refusé, sans dire
// lequel.
func TestLogin_WithTOTP_AsksTheCodeAfterThePassword(t *testing.T) {
	service, _, state, secret, now := withTOTP(t)
	if _, err := service.Login(context.Background(), state, "lucas", "a wrong passphrase", codeAt(t, secret, *now), SessionClient{}); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("wrong password with a right code: got %v, want ErrLoginFailed", err)
	}
	if err := login(service, state, ""); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("no code: got %v, want ErrTOTPRequired", err)
	}
	right := codeAt(t, secret, *now)
	for _, given := range []string{wrongCodeAt(t, secret, *now), " " + right[1:], right + "0", "12345a", "١٢٣٤٥٦"} {
		if err := login(service, state, given); !errors.Is(err, ErrTOTPWrong) {
			t.Errorf("%q: got %v, want ErrTOTPWrong", given, err)
		}
	}
}

// R-CNX-2 dans le composant : sans code activé, la connexion n'en demande pas.
func TestLogin_WithoutTOTP_AsksNoCode(t *testing.T) {
	service, _ := newTestService(t)
	state := newNativeState(t, service)
	if err := login(service, state, ""); err != nil {
		t.Fatal(err)
	}
}

// Le secret proposé se lit par toute application : base 32, 160 bits, et
// l'URI otpauth le porte avec l'émetteur et le compte.
func TestProposeTOTP_DrawsA160BitSecretAndItsURI(t *testing.T) {
	service, store := newTestService(t)
	state := newNativeState(t, service)
	first, err := service.ProposeTOTP(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := service.ProposeTOTP(context.Background(), state)
	if first.Secret == second.Secret {
		t.Fatal("two proposals share a secret")
	}
	if raw, err := DecodeTOTPSecret(first.Secret); err != nil || len(raw) != 20 {
		t.Fatalf("secret %q: %v", first.Secret, err)
	}
	parsed, err := url.Parse(first.URI)
	if err != nil || parsed.Scheme != "otpauth" || parsed.Host != "totp" || parsed.Query().Get("secret") != first.Secret || !strings.HasSuffix(parsed.Path, ":lucas") {
		t.Fatalf("uri %q", first.URI)
	}
	if store.totp.Active() {
		t.Fatal("a proposal is not stored")
	}
}

// Négatifs de l'activation : un secret qui n'est pas de 160 bits, un code
// faux, un code déjà actif, le mode SSO.
func TestEnableTOTP_Refusals(t *testing.T) {
	service, store := newTestService(t)
	service.SetClock(func() time.Time { return totpNow })
	state := newNativeState(t, service)
	proposal, _ := service.ProposeTOTP(context.Background(), state)
	weak := totpEncoding.EncodeToString([]byte("short"))
	if err := service.EnableTOTP(context.Background(), state, weak, "123456"); !errors.Is(err, ErrTOTPSecretInvalid) {
		t.Errorf("weak secret: got %v", err)
	}
	if err := service.EnableTOTP(context.Background(), state, "not base 32!", "123456"); !errors.Is(err, ErrTOTPSecretInvalid) {
		t.Errorf("garbage secret: got %v", err)
	}
	if err := service.EnableTOTP(context.Background(), state, proposal.Secret, wrongCodeAt(t, proposal.Secret, totpNow)); !errors.Is(err, ErrTOTPWrong) {
		t.Errorf("wrong code: got %v", err)
	}
	if store.totp.Active() {
		t.Fatal("a refused activation stored a secret")
	}
	if err := service.EnableTOTP(context.Background(), state, proposal.Secret, codeAt(t, proposal.Secret, totpNow)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ProposeTOTP(context.Background(), state); !errors.Is(err, ErrTOTPActive) {
		t.Errorf("proposal while active: got %v", err)
	}
	forward, _ := newTestService(t)
	forwardState, err := forward.EnableForward(context.Background(), none, issueCode(t, forward), DefaultForwardHeader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forward.ProposeTOTP(context.Background(), forwardState); !errors.Is(err, ErrNoPassword) {
		t.Errorf("forward: got %v, want ErrNoPassword", err)
	}
}

// Retirer le code demande le mot de passe ; root le retire sans rien.
func TestDisableTOTP_NeedsThePasswordAndResetDoesNot(t *testing.T) {
	service, store, state, _, _ := withTOTP(t)
	if err := service.DisableTOTP(context.Background(), state, "a wrong passphrase"); !errors.Is(err, ErrCurrentPasswordWrong) {
		t.Fatalf("wrong password: got %v", err)
	}
	if !store.totp.Active() {
		t.Fatal("a wrong password removed the code")
	}
	if err := service.DisableTOTP(context.Background(), state, testPassword); err != nil {
		t.Fatal(err)
	}
	if err := service.DisableTOTP(context.Background(), state, testPassword); !errors.Is(err, ErrTOTPInactive) {
		t.Fatalf("twice: got %v", err)
	}
	if err := login(service, state, ""); err != nil {
		t.Fatalf("after removal, the password alone: %v", err)
	}

	service, store, _, _, _ = withTOTP(t)
	if err := service.ResetTOTP(context.Background()); err != nil || store.totp.Active() {
		t.Fatalf("reset: %v, %+v", err, store.totp)
	}
	if err := service.ResetTOTP(context.Background()); !errors.Is(err, ErrTOTPInactive) {
		t.Fatalf("reset twice: got %v", err)
	}
}

// Le code ne survit pas à un autre compte : root qui passe au SSO et revient
// ne retrouve pas le code d'avant. Un mot de passe refait le garde.
func TestTOTP_SurvivesAPasswordResetNotAModeChange(t *testing.T) {
	service, store, _, _, _ := withTOTP(t)
	if _, err := service.ResetPassword(context.Background(), "another passphrase"); err != nil {
		t.Fatal(err)
	}
	if !store.totp.Active() {
		t.Fatal("a password reset removed the code")
	}
	if _, _, err := service.SetMode(context.Background(), ModeChange{Mode: ModeForward, Header: DefaultForwardHeader}); err != nil {
		t.Fatal(err)
	}
	if store.totp.Active() {
		t.Fatal("the code survived the switch to SSO")
	}
}
