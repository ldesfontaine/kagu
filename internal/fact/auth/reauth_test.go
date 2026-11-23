package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// La redemande juste renouvelle le jeton de la session et pose reauth_at :
// l'ancien jeton ne vaut plus, l'identifiant reste.
func TestReauth_RenewsTheTokenAndStampsTheSession(t *testing.T) {
	service, _, state, now, opened := signedIn(t)
	token, err := service.Reauth(context.Background(), state, opened.ID, testPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	if token == opened.Token || resumes(t, service, state, opened.Token) {
		t.Fatal("the token presented before still opens the session")
	}
	session, alive, err := service.ResumeSession(context.Background(), state, token)
	if err != nil || !alive || session.ID != opened.ID {
		t.Fatalf("renewed session: %+v %v %v", session, alive, err)
	}
	if !session.ReauthAt.Equal(*now) {
		t.Fatalf("reauth_at %s, want %s", session.ReauthAt, *now)
	}
}

// Cinq minutes, pour cette session seulement ; en forward, rien.
func TestRequireFreshReauth_FiveMinutesForThisSession(t *testing.T) {
	service, _, state, now, opened := signedIn(t)
	if err := service.RequireFreshReauth(state, opened.Session); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("never re-authenticated: got %v", err)
	}
	token, err := service.Reauth(context.Background(), state, opened.ID, testPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	session, _, _ := service.ResumeSession(context.Background(), state, token)
	*now = now.Add(ReauthLifetime - time.Second)
	if err := service.RequireFreshReauth(state, session); err != nil {
		t.Fatalf("within five minutes: %v", err)
	}
	*now = now.Add(time.Second)
	if err := service.RequireFreshReauth(state, session); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("after five minutes: got %v", err)
	}
	if err := service.RequireFreshReauth(State{Mode: ModeForward}, Session{}); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if err := service.RequireFreshReauth(State{Mode: ModeNone}, session); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("none: got %v", err)
	}
}

// Négatifs : mot de passe faux, code manquant ou faux quand il est actif ;
// rien n'est posé sur la session.
func TestReauth_Refusals(t *testing.T) {
	service, _, state, now, opened := signedIn(t)
	if _, err := service.Reauth(context.Background(), state, opened.ID, "a wrong passphrase", ""); !errors.Is(err, ErrCurrentPasswordWrong) {
		t.Fatalf("wrong password: got %v", err)
	}
	proposal, _ := service.ProposeTOTP(context.Background(), state)
	if err := service.EnableTOTP(context.Background(), state, proposal.Secret, codeAt(t, proposal.Secret, *now)); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(TOTPPeriod)
	if _, err := service.Reauth(context.Background(), state, opened.ID, testPassword, ""); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("no code: got %v", err)
	}
	if _, err := service.Reauth(context.Background(), state, opened.ID, testPassword, wrongCodeAt(t, proposal.Secret, *now)); !errors.Is(err, ErrTOTPWrong) {
		t.Fatalf("wrong code: got %v", err)
	}
	session, _, _ := service.ResumeSession(context.Background(), state, opened.Token)
	if !session.ReauthAt.IsZero() {
		t.Fatal("a refused re-authentication stamped the session")
	}
	if _, err := service.Reauth(context.Background(), state, opened.ID, testPassword, codeAt(t, proposal.Secret, *now)); err != nil {
		t.Fatalf("password and code: %v", err)
	}
}

// En forward, il n'y a pas de mot de passe à redonner : le SSO authentifie.
func TestReauth_RefusedInForward(t *testing.T) {
	service, _, state, opened := forwardService(t)
	if _, err := service.Reauth(context.Background(), state, opened.ID, testPassword, ""); !errors.Is(err, ErrNoPassword) {
		t.Fatalf("got %v, want ErrNoPassword", err)
	}
}
