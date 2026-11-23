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

const testPassword = "correct horse battery"

// signedIn rend un service en native, son état, une horloge réglable et une
// session ouverte par la connexion.
func signedIn(t *testing.T) (*Service, *memoryStore, State, *time.Time, OpenedSession) {
	t.Helper()
	service, store := newTestService(t)
	now := time.Unix(1_800_000_000, 0)
	service.SetClock(func() time.Time { return now })
	state := newNativeState(t, service)
	opened, err := service.Login(context.Background(), state, "lucas", testPassword, SessionClient{Address: "2001:db8:1:2:3:4:5:6", UserAgent: "Firefox"})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, state, &now, opened
}

func resumes(t *testing.T, service *Service, state State, token string) bool {
	t.Helper()
	_, alive, err := service.ResumeSession(context.Background(), state, token)
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
		if _, err := service.Login(ctx, state, credentials[0], credentials[1], SessionClient{}); !errors.Is(err, ErrLoginFailed) {
			t.Fatalf("%q: %v, want ErrLoginFailed", credentials, err)
		}
	}
	if len(store.sessions) != 1 {
		t.Fatalf("%d sessions after the refusals", len(store.sessions))
	}
	if _, err := service.Login(ctx, none, "lucas", testPassword, SessionClient{}); !errors.Is(err, ErrStateChanged) {
		t.Fatalf("stale state: %v", err)
	}
	other, _ := newTestService(t)
	if _, err := other.Login(ctx, none, "lucas", testPassword, SessionClient{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("mode none: %v", err)
	}
}

// Deux connexions donnent deux sessions et deux jetons : rien n'est repris.
func TestLogin_DrawsAFreshSessionEachTime(t *testing.T) {
	service, store, state, _, first := signedIn(t)
	second, err := service.Login(context.Background(), state, "lucas", testPassword, SessionClient{})
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
	other, err := service.Login(context.Background(), state, "lucas", testPassword, SessionClient{})
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
	if _, err := service.Login(context.Background(), state, "lucas", testPassword, SessionClient{UserAgent: "a\u202eb" + strings.Repeat("x", 500)}); err != nil {
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
