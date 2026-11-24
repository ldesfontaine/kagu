package auth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/ident"
)

// memorySessions tient les sessions comme la base, par empreinte de jeton.
type memorySessions []storedSession

type storedSession struct {
	Session
	tokenHash string
}

func (m *memoryStore) CreateSession(_ context.Context, session Session, tokenHash string) error {
	m.sessions = append(m.sessions, storedSession{Session: session, tokenHash: tokenHash})
	return nil
}

func (m *memoryStore) SessionByTokenHash(_ context.Context, tokenHash string) (Session, bool, error) {
	for _, stored := range m.sessions {
		if stored.tokenHash == tokenHash {
			return stored.Session, true, nil
		}
	}
	return Session{}, false, nil
}

func (m *memoryStore) SessionByID(_ context.Context, id string) (Session, bool, error) {
	for _, stored := range m.sessions {
		if stored.ID == id {
			return stored.Session, true, nil
		}
	}
	return Session{}, false, nil
}

func (m *memoryStore) TouchSession(_ context.Context, id string, seenAt time.Time) error {
	for index := range m.sessions {
		if m.sessions[index].ID == id {
			m.sessions[index].SeenAt = seenAt
		}
	}
	return nil
}

func (m *memoryStore) DeleteSession(_ context.Context, id string) (bool, error) {
	before := len(m.sessions)
	m.sessions = slices.DeleteFunc(m.sessions, func(stored storedSession) bool { return stored.ID == id })
	return len(m.sessions) < before, nil
}

func (m *memoryStore) DeleteOtherSessions(_ context.Context, keepID string) (int, error) {
	before := len(m.sessions)
	m.sessions = slices.DeleteFunc(m.sessions, func(stored storedSession) bool { return stored.ID != keepID })
	return before - len(m.sessions), nil
}

func (m *memoryStore) DeleteDeadSessions(_ context.Context, idleSince, now time.Time) error {
	m.sessions = slices.DeleteFunc(m.sessions, func(stored storedSession) bool {
		return !stored.SeenAt.After(idleSince) || !stored.ExpiresAt.After(now)
	})
	return nil
}

func (m *memoryStore) ListSessions(context.Context) ([]Session, error) {
	sessions := make([]Session, 0, len(m.sessions))
	for _, stored := range m.sessions {
		sessions = append(sessions, stored.Session)
	}
	return sessions, nil
}

func (m *memoryStore) RenewSessionToken(_ context.Context, id, tokenHash string, reauthAt time.Time) (bool, error) {
	for index := range m.sessions {
		if m.sessions[index].ID == id {
			m.sessions[index].tokenHash = tokenHash
			m.sessions[index].ReauthAt = reauthAt
			return true, nil
		}
	}
	return false, nil
}

const testPassword = "correct horse battery"

// overHTTPS présente le jeton sous __Host-, le cookie des sessions du banc.
func overHTTPS(token string) PresentedToken {
	return PresentedToken{Value: token, Cookie: CookieHost}
}

// signedIn rend un service en native, son état, une horloge réglable et une
// session ouverte par la connexion.
func signedIn(t *testing.T) (*Service, *memoryStore, State, *time.Time, OpenedSession) {
	t.Helper()
	service, store := newTestService(t)
	now := time.Unix(1_800_000_000, 0)
	service.SetClock(func() time.Time { return now })
	state := newNativeState(t, service)
	opened, err := service.Login(context.Background(), state, "lucas", testPassword, "", SessionClient{Address: "2001:db8:1:2:3:4:5:6", UserAgent: "Firefox", Cookie: CookieHost})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, state, &now, opened
}

func resumes(t *testing.T, service *Service, state State, token string) bool {
	t.Helper()
	_, alive, err := service.ResumeSession(context.Background(), state, overHTTPS(token))
	if err != nil {
		t.Fatal(err)
	}
	return alive
}

// La base ne garde que l'empreinte du jeton, par ident.HashToken ; le jeton a
// 256 bits ; la source est le /64.
func TestLogin_KeepsOnlyTheTokenHash(t *testing.T) {
	_, store, _, _, opened := signedIn(t)
	if len(opened.Token) != 64 || len(store.sessions) != 1 {
		t.Fatalf("token %q, sessions %d", opened.Token, len(store.sessions))
	}
	stored := store.sessions[0]
	if stored.tokenHash != ident.HashToken(opened.Token) || strings.Contains(stored.tokenHash, opened.Token) {
		t.Fatalf("stored hash %q", stored.tokenHash)
	}
	if stored.Source != "2001:db8:1:2::/64" || stored.Identity != "lucas" || !stored.ExpiresAt.Equal(stored.CreatedAt.Add(SessionLifetime)) {
		t.Fatalf("stored %+v", stored.Session)
	}
}

// Un mauvais mot de passe, un mauvais nom ou un autre mode n'ouvrent rien.
func TestLogin_RefusesWrongCredentialsAndOtherModes(t *testing.T) {
	service, store, state, _, _ := signedIn(t)
	ctx := context.Background()
	for _, credentials := range [][2]string{{"lucas", "a wrong passphrase"}, {"other", testPassword}, {"", ""}} {
		if _, err := service.Login(ctx, state, credentials[0], credentials[1], "", SessionClient{Cookie: CookieHost}); !errors.Is(err, ErrLoginFailed) {
			t.Fatalf("%q: %v, want ErrLoginFailed", credentials, err)
		}
	}
	if len(store.sessions) != 1 {
		t.Fatalf("%d sessions after the refusals", len(store.sessions))
	}
	if _, err := service.Login(ctx, none, "lucas", testPassword, "", SessionClient{Cookie: CookieHost}); !errors.Is(err, ErrStateChanged) {
		t.Fatalf("stale state: %v", err)
	}
	other, _ := newTestService(t)
	if _, err := other.Login(ctx, none, "lucas", testPassword, "", SessionClient{Cookie: CookieHost}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("mode none: %v", err)
	}
}

// Deux connexions donnent deux sessions et deux jetons : rien n'est repris.
func TestLogin_DrawsAFreshSessionEachTime(t *testing.T) {
	service, store, state, _, first := signedIn(t)
	second, err := service.Login(context.Background(), state, "lucas", testPassword, "", SessionClient{Cookie: CookieHost})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID || second.Token == first.Token || len(store.sessions) != 2 {
		t.Fatalf("first %s, second %s, %d sessions", first.ID, second.ID, len(store.sessions))
	}
}

// seen_at ne s'écrit qu'une fois par minute.
func TestResumeSession_TouchesAtMostOncePerMinute(t *testing.T) {
	service, store, state, now, opened := signedIn(t)
	created := *now
	*now = created.Add(59 * time.Second)
	if !resumes(t, service, state, opened.Token) || !store.sessions[0].SeenAt.Equal(created) {
		t.Fatalf("seen_at %v written within the minute", store.sessions[0].SeenAt)
	}
	*now = created.Add(time.Minute)
	if !resumes(t, service, state, opened.Token) || !store.sessions[0].SeenAt.Equal(*now) {
		t.Fatalf("seen_at %v not written after a minute", store.sessions[0].SeenAt)
	}
}

// Une session d'un autre compte (recréé par la commande de secours) ne vaut
// rien et s'efface ; un jeton inconnu ou vide n'ouvre rien.
func TestResumeSession_RefusesAnotherAccountAndUnknownTokens(t *testing.T) {
	service, store, state, _, opened := signedIn(t)
	renamed := state
	renamed.Username = "autre"
	if resumes(t, service, renamed, opened.Token) || len(store.sessions) != 0 {
		t.Fatalf("a session of another account resumed, %d left", len(store.sessions))
	}
	if resumes(t, service, state, "") || resumes(t, service, state, strings.Repeat("0", 64)) {
		t.Fatal("an unknown token resumed")
	}
}

// Changer le mot de passe ferme les autres sessions, pas celle qui le change.
func TestChangePassword_ClosesTheOtherSessions(t *testing.T) {
	service, _, state, _, kept := signedIn(t)
	other, err := service.Login(context.Background(), state, "lucas", testPassword, "", SessionClient{Cookie: CookieHost})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := service.ChangePassword(context.Background(), state, kept.ID, testPassword, "another long passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !resumes(t, service, changed, kept.Token) || resumes(t, service, changed, other.Token) {
		t.Fatal("the change kept the wrong sessions")
	}
}

// Le navigateur se garde nettoyé et borné.
func TestLogin_BoundsTheUserAgent(t *testing.T) {
	service, store, state, _, _ := signedIn(t)
	if _, err := service.Login(context.Background(), state, "lucas", testPassword, "", SessionClient{UserAgent: "a\u202eb" + strings.Repeat("x", 500), Cookie: CookieHost}); err != nil {
		t.Fatal(err)
	}
	stored := store.sessions[1].UserAgent
	if len(stored) > MaxUserAgentLength || strings.ContainsRune(stored, '\u202e') {
		t.Fatalf("user agent %q", stored)
	}
}

// Fermer une session inconnue le dit ; la liste ne rend que les vivantes.
func TestSessions_ListsTheAliveOnesAndClosesByID(t *testing.T) {
	service, _, _, now, opened := signedIn(t)
	ctx := context.Background()
	if err := service.CloseSession(ctx, "unknown"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	*now = now.Add(SessionIdleTimeout)
	if alive, err := service.Sessions(ctx); err != nil || len(alive) != 0 {
		t.Fatalf("an idle session is listed: %+v %v", alive, err)
	}
	if err := service.CloseSession(ctx, opened.ID); err != nil {
		t.Fatal(err)
	}
}

// isEnded dit si le canal d'une fin de session est fermé.
func isEnded(ended <-chan struct{}) bool {
	select {
	case <-ended:
		return true
	default:
		return false
	}
}

func watch(t *testing.T, service *Service, id string) <-chan struct{} {
	t.Helper()
	ended, stop, err := service.WatchSession(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return ended
}

// R-A2-12 : chaque mort d'une session ferme le canal que ses flux attendent ;
// celui d'une autre session reste ouvert.
func TestWatchSession_EndsWithEachDeathOfItsSession(t *testing.T) {
	ctx := context.Background()
	deaths := map[string]func(*Service, State, OpenedSession, OpenedSession) error{
		"closed": func(service *Service, _ State, watched, _ OpenedSession) error {
			return service.CloseSession(ctx, watched.ID)
		},
		"the others closed": func(service *Service, _ State, _, kept OpenedSession) error {
			_, err := service.CloseOtherSessions(ctx, kept.ID)
			return err
		},
		"the password changed": func(service *Service, state State, _, kept OpenedSession) error {
			_, err := service.ChangePassword(ctx, state, kept.ID, testPassword, "another long passphrase")
			return err
		},
	}
	for name, die := range deaths {
		t.Run(name, func(t *testing.T) {
			service, _, state, _, watched := signedIn(t)
			kept, err := service.Login(ctx, state, "lucas", testPassword, "", SessionClient{Cookie: CookieHost})
			if err != nil {
				t.Fatal(err)
			}
			ended, keptEnded := watch(t, service, watched.ID), watch(t, service, kept.ID)
			if isEnded(ended) {
				t.Fatal("the stream ended with its session alive")
			}
			if err := die(service, state, watched, kept); err != nil {
				t.Fatal(err)
			}
			if !isEnded(ended) || isEnded(keptEnded) {
				t.Fatalf("ended %v, kept ended %v", isEnded(ended), isEnded(keptEnded))
			}
		})
	}
	// Le canal local de root ferme toutes les sessions, et leurs flux.
	everyOne := map[string]func(*Service) error{
		"reset-password": func(service *Service) error {
			_, err := service.ResetPassword(ctx, "a passphrase from root")
			return err
		},
		"auth-mode": func(service *Service) error {
			_, _, err := service.SetMode(ctx, ModeChange{Mode: ModeForward, Header: DefaultForwardHeader})
			return err
		},
		"sessions close-all": func(service *Service) error {
			_, err := service.CloseAllSessions(ctx)
			return err
		},
	}
	for name, die := range everyOne {
		t.Run(name, func(t *testing.T) {
			service, _, _, _, watched := signedIn(t)
			ended := watch(t, service, watched.ID)
			if err := die(service); err != nil {
				t.Fatal(err)
			}
			if !isEnded(ended) {
				t.Fatal("a stream outlived its session closed on the local channel")
			}
		})
	}
}

// Une session déjà morte, ou inconnue, rend un canal fermé ; morte, elle est
// effacée. Un flux parti libère sa place : la fin d'une session qu'aucun flux
// n'attend ne ferme rien.
func TestWatchSession_ADeadSessionEndsAtOnce(t *testing.T) {
	service, store, _, now, opened := signedIn(t)
	if !isEnded(watch(t, service, "unknown")) {
		t.Fatal("an unknown session is watched")
	}
	ended, stop, err := service.WatchSession(context.Background(), opened.ID)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if len(service.watches.byID) != 0 {
		t.Fatalf("watches left %d", len(service.watches.byID))
	}
	*now = now.Add(SessionIdleTimeout)
	if !isEnded(watch(t, service, opened.ID)) || len(store.sessions) != 0 {
		t.Fatalf("a dead session is watched, %d sessions", len(store.sessions))
	}
	if isEnded(ended) {
		t.Fatal("a stream that left was ended")
	}
}

// forwardService rend un service en forward et une session ouverte pour lucas.
func forwardService(t *testing.T) (*Service, *memoryStore, State, OpenedSession) {
	t.Helper()
	service, store := newTestService(t)
	state, err := service.EnableForward(context.Background(), none, issueCode(t, service), DefaultForwardHeader)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := service.OpenForwardSession(context.Background(), state, "lucas", SessionClient{Address: "192.0.2.7", Cookie: CookieHost})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, state, opened
}

// R-A2-17 : en forward, la session se reprend pour l'identité de l'en-tête ;
// une autre identité la tue et le dit.
func TestResumeForwardSession_AnotherIdentityKillsTheSession(t *testing.T) {
	service, store, state, opened := forwardService(t)
	ctx := context.Background()
	if _, alive, err := service.ResumeForwardSession(ctx, state, overHTTPS(opened.Token), "lucas"); err != nil || !alive {
		t.Fatalf("same identity: %v %v", alive, err)
	}
	if _, alive, err := service.ResumeSession(ctx, state, overHTTPS(opened.Token)); err != nil || alive {
		t.Fatalf("a forward session resumed as a native one: %v %v", alive, err)
	}
	ended := watch(t, service, opened.ID)
	if _, alive, err := service.ResumeForwardSession(ctx, state, overHTTPS(opened.Token), "mallory"); !errors.Is(err, ErrSessionIdentityChanged) || alive {
		t.Fatalf("another identity: %v %v", alive, err)
	}
	if len(store.sessions) != 0 || !isEnded(ended) {
		t.Fatalf("%d sessions, ended %v", len(store.sessions), isEnded(ended))
	}
	if _, alive, err := service.ResumeForwardSession(ctx, state, overHTTPS(opened.Token), "lucas"); err != nil || alive {
		t.Fatalf("the killed session came back: %v %v", alive, err)
	}
}

// Une session forward ne s'ouvre que sous l'état qui a admis la requête, en
// forward ; un cookie arrivé sans la preuve du mandataire tue sa session.
func TestForwardSessions_OpenUnderForwardOnlyAndDieWithoutTheProof(t *testing.T) {
	service, store, state, opened := forwardService(t)
	ctx := context.Background()
	if _, err := service.OpenForwardSession(ctx, none, "lucas", SessionClient{Cookie: CookieHost}); !errors.Is(err, ErrStateChanged) {
		t.Fatalf("stale state: %v", err)
	}
	native, _, nativeState, _, _ := signedIn(t)
	if _, err := native.OpenForwardSession(ctx, nativeState, "lucas", SessionClient{Cookie: CookieHost}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("native: %v", err)
	}
	if err := service.ClosePresentedSession(ctx, strings.Repeat("0", 64)); err != nil || len(store.sessions) != 1 {
		t.Fatalf("an unknown token: %v, %d sessions", err, len(store.sessions))
	}
	ended := watch(t, service, opened.ID)
	if err := service.ClosePresentedSession(ctx, opened.Token); err != nil || len(store.sessions) != 0 || !isEnded(ended) {
		t.Fatalf("%v, %d sessions, ended %v", err, len(store.sessions), isEnded(ended))
	}
	if _, alive, _ := service.ResumeForwardSession(ctx, state, overHTTPS(opened.Token), "lucas"); alive {
		t.Fatal("the closed session came back")
	}
}

// R-A2-3 : présenté sous un autre cookie que celui de sa naissance, le jeton
// n'ouvre rien et sa session meurt ; en forward aussi, sans erreur : la garde
// a admis la requête, une session neuve s'ouvre sous le bon cookie.
func TestR_A2_3_AnotherCookieKillsTheSession(t *testing.T) {
	service, store, state, _, signedInSession := signedIn(t)
	if _, alive, err := service.ResumeSession(context.Background(), state, PresentedToken{Value: signedInSession.Token, Cookie: CookieLocal}); err != nil || alive {
		t.Fatalf("a __Host- session resumed under the local cookie: %v %v", alive, err)
	}
	if len(store.sessions) != 0 || resumes(t, service, state, signedInSession.Token) {
		t.Fatal("the session survived its token under another cookie")
	}

	forward, forwardStore, forwardState, opened := forwardService(t)
	if _, alive, err := forward.ResumeForwardSession(context.Background(), forwardState, PresentedToken{Value: opened.Token, Cookie: CookieLocal}, "lucas"); err != nil || alive {
		t.Fatalf("forward: a __Host- session resumed under the local cookie: %v %v", alive, err)
	}
	if len(forwardStore.sessions) != 0 {
		t.Fatal("forward: the session survived its token under another cookie")
	}
}
