package auth

import (
	"context"
	"errors"
	"testing"
)

// openSecondSession ouvre une autre session sous state : deux navigateurs.
func openSecondSession(t *testing.T, service *Service, state State) {
	t.Helper()
	if _, err := service.Login(context.Background(), state, "lucas", testPassword, "", SessionClient{UserAgent: "Chromium"}); err != nil {
		t.Fatal(err)
	}
}

// Root refait le mot de passe : l'ancien ne passe plus, aucune session ne
// survit (R-A2-2), le compte garde son nom.
func TestResetPassword_ReplacesThePasswordAndClosesEverySession(t *testing.T) {
	service, store, state, _, opened := signedIn(t)
	openSecondSession(t, service, state)
	closed, err := service.ResetPassword(context.Background(), "a passphrase from root")
	if err != nil {
		t.Fatal(err)
	}
	if closed != 2 || len(store.sessions) != 0 {
		t.Fatalf("closed %d, left %d", closed, len(store.sessions))
	}
	if resumes(t, service, store.state, opened.Token) {
		t.Fatal("a session survived the reset")
	}
	if store.state.Username != "lucas" || verifies(t, service, store.state, "lucas", testPassword) || !verifies(t, service, store.state, "lucas", "a passphrase from root") {
		t.Fatalf("state after the reset: %+v", store.state)
	}
}

// Un mot de passe refusé n'écrit rien et ne ferme rien ; sans compte, il n'y
// a rien à refaire, et rien ne rouvre la première configuration.
func TestResetPassword_RefusesAndWritesNothing(t *testing.T) {
	service, store, state, _, _ := signedIn(t)
	for password, want := range map[string]error{"short": ErrPasswordTooShort, string(make([]byte, 80)) + "long enough": ErrPasswordTooLong} {
		if _, err := service.ResetPassword(context.Background(), password); !errors.Is(err, want) {
			t.Fatalf("%q: %v, want %v", password, err, want)
		}
	}
	if !store.state.Same(state) || len(store.sessions) != 1 {
		t.Fatalf("a refused reset wrote: %+v, %d sessions", store.state, len(store.sessions))
	}

	fresh, freshStore := newTestService(t)
	if _, err := fresh.ResetPassword(context.Background(), "a passphrase from root"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("reset without an account: %v, want ErrDisabled", err)
	}
	if freshStore.state.Mode != "" {
		t.Fatalf("a reset without an account wrote %+v", freshStore.state)
	}
}

// native → forward → native : chaque passage ferme les sessions ; le retour
// crée le compte demandé.
func TestSetMode_MovesBetweenNativeAndForward(t *testing.T) {
	service, store, state, _, _ := signedIn(t)
	openSecondSession(t, service, state)
	ctx := context.Background()

	forward, closed, err := service.SetMode(ctx, ModeChange{Mode: ModeForward, Header: "X-Forwarded-User"})
	if err != nil {
		t.Fatal(err)
	}
	if closed != 2 || len(store.sessions) != 0 || forward.Mode != ModeForward || forward.Header != "X-Forwarded-User" || store.state.PasswordHash != "" {
		t.Fatalf("forward: %+v, closed %d, stored %+v", forward, closed, store.state)
	}
	if _, _, err := service.SetMode(ctx, ModeChange{Mode: ModeForward, Header: "Remote-User"}); err != nil {
		t.Fatalf("changing the header: %v", err)
	}

	native, _, err := service.SetMode(ctx, ModeChange{Mode: ModeNative, Username: "root-made", Password: "a passphrase from root"})
	if err != nil {
		t.Fatal(err)
	}
	if native.Mode != ModeNative || native.Header != "" || !verifies(t, service, store.state, "root-made", "a passphrase from root") {
		t.Fatalf("native: %+v", store.state)
	}
}

// Ce que SetMode refuse, sans rien écrire : aucun compte encore, none
// demandé (rien ne rouvre la première configuration, R-A2-10), le mode déjà
// en vigueur, un en-tête ou un compte invalide.
func TestSetMode_RefusesAndWritesNothing(t *testing.T) {
	service, store, state, _, _ := signedIn(t)
	ctx := context.Background()
	refused := []struct {
		change ModeChange
		want   error
	}{
		{ModeChange{Mode: ModeNone}, ErrModeInvalid},
		{ModeChange{Mode: "basic"}, ErrModeInvalid},
		{ModeChange{Mode: ModeNative, Username: "lucas", Password: "a passphrase from root"}, ErrSameMode},
		{ModeChange{Mode: ModeForward, Header: "Remote User"}, ErrHeaderInvalid},
	}
	for _, c := range refused {
		if _, _, err := service.SetMode(ctx, c.change); !errors.Is(err, c.want) {
			t.Errorf("%+v: %v, want %v", c.change, err, c.want)
		}
	}
	if !store.state.Same(state) || len(store.sessions) != 1 {
		t.Fatalf("a refused change wrote: %+v, %d sessions", store.state, len(store.sessions))
	}
	if _, _, err := service.SetMode(ctx, ModeChange{Mode: ModeForward, Header: DefaultForwardHeader}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		change ModeChange
		want   error
	}{
		{ModeChange{Mode: ModeForward, Header: DefaultForwardHeader}, ErrSameMode},
		{ModeChange{Mode: ModeNative, Username: "a:b", Password: "a passphrase from root"}, ErrUsernameInvalid},
		{ModeChange{Mode: ModeNative, Username: "lucas", Password: "short"}, ErrPasswordTooShort},
	} {
		if _, _, err := service.SetMode(ctx, c.change); !errors.Is(err, c.want) {
			t.Errorf("%+v: %v, want %v", c.change, err, c.want)
		}
	}

	fresh, freshStore := newTestService(t)
	if _, _, err := fresh.SetMode(ctx, ModeChange{Mode: ModeForward, Header: DefaultForwardHeader}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("set mode without an account: %v, want ErrDisabled", err)
	}
	if freshStore.state.Mode != "" {
		t.Fatalf("the first setup was skipped: %+v", freshStore.state)
	}
}

func TestCloseAllSessions_ClosesEveryOne(t *testing.T) {
	service, store, state, _, _ := signedIn(t)
	openSecondSession(t, service, state)
	closed, err := service.CloseAllSessions(context.Background())
	if err != nil || closed != 2 || len(store.sessions) != 0 {
		t.Fatalf("closed %d, left %d, %v", closed, len(store.sessions), err)
	}
	if !store.state.Same(state) {
		t.Fatal("closing the sessions changed the account")
	}
}
