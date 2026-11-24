package store

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
)

// Une session se retrouve par l'empreinte de son jeton, se touche, se liste
// des plus récentes aux plus anciennes et s'efface une à une ou toutes sauf
// une.
func TestOperatorSessions_RoundTrip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	at := time.Unix(1_800_000_000, 0)
	older := auth.Session{ID: "s1", Identity: "lucas", CreatedAt: at, SeenAt: at, ExpiresAt: at.Add(12 * time.Hour), Source: "192.0.2.0", UserAgent: "Firefox"}
	newer := older
	newer.ID, newer.CreatedAt = "s2", at.Add(time.Minute)
	for _, session := range []auth.Session{older, newer} {
		if err := db.CreateSession(ctx, session, "hash-"+session.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.CreateSession(ctx, auth.Session{ID: "s3", CreatedAt: at, SeenAt: at, ExpiresAt: at}, "hash-s1"); err == nil {
		t.Fatal("two sessions share a token hash")
	}

	got, found, err := db.SessionByTokenHash(ctx, "hash-s1")
	if err != nil || !found || got != older {
		t.Fatalf("by hash %+v %v %v", got, found, err)
	}
	if _, found, err := db.SessionByTokenHash(ctx, "unknown"); err != nil || found {
		t.Fatalf("unknown hash found %v %v", found, err)
	}
	if got, found, err := db.SessionByID(ctx, "s1"); err != nil || !found || got != older {
		t.Fatalf("by id %+v %v %v", got, found, err)
	}
	if _, found, err := db.SessionByID(ctx, "unknown"); err != nil || found {
		t.Fatalf("unknown id found %v %v", found, err)
	}
	if err := db.TouchSession(ctx, "s1", at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := db.SessionByTokenHash(ctx, "hash-s1"); !got.SeenAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("seen_at %v", got.SeenAt)
	}
	listed, err := db.ListSessions(ctx)
	if err != nil || len(listed) != 2 || listed[0].ID != "s2" {
		t.Fatalf("list %+v %v", listed, err)
	}
	if closed, err := db.DeleteOtherSessions(ctx, "s2"); err != nil || closed != 1 {
		t.Fatalf("delete others %d %v", closed, err)
	}
	if deleted, err := db.DeleteSession(ctx, "s2"); err != nil || !deleted {
		t.Fatalf("delete %v %v", deleted, err)
	}
	if deleted, err := db.DeleteSession(ctx, "s2"); err != nil || deleted {
		t.Fatalf("delete twice %v %v", deleted, err)
	}
}

// Les sessions mortes s'effacent : sans requête depuis la borne, ou passées
// leur fin.
func TestOperatorSessions_DeleteDeadSessions(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	sessions := map[string]auth.Session{
		"alive":   {ID: "alive", SeenAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)},
		"idle":    {ID: "idle", SeenAt: now.Add(-3 * time.Hour), ExpiresAt: now.Add(time.Hour)},
		"expired": {ID: "expired", SeenAt: now, ExpiresAt: now.Add(-time.Second)},
	}
	for id, session := range sessions {
		session.CreatedAt = now.Add(-4 * time.Hour)
		if err := db.CreateSession(ctx, session, "hash-"+id); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.DeleteDeadSessions(ctx, now.Add(-2*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	listed, err := db.ListSessions(ctx)
	if err != nil || len(listed) != 1 || listed[0].ID != "alive" {
		t.Fatalf("left %+v %v", listed, err)
	}
}

// Un retour au mode none efface toutes les sessions avec l'état.
func TestOperatorSessions_ModeNoneDeletesThem(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	at := time.Unix(1_800_000_000, 0)
	native := auth.State{Mode: auth.ModeNative, Username: "lucas", PasswordHash: "h", EnabledAt: at}
	if _, err := db.SaveAuthStateIf(ctx, auth.State{Mode: auth.ModeNone}, native, at); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession(ctx, auth.Session{ID: "s1", Identity: "lucas", CreatedAt: at, SeenAt: at, ExpiresAt: at.Add(time.Hour)}, "h1"); err != nil {
		t.Fatal(err)
	}
	if swapped, err := db.SaveAuthStateIf(ctx, native, auth.State{Mode: auth.ModeNone}, at); err != nil || !swapped {
		t.Fatalf("disable %v %v", swapped, err)
	}
	if left := count(t, db, `SELECT COUNT(*) FROM operator_sessions`); left != 0 {
		t.Fatalf("%d sessions survive the return to none", left)
	}
}

// R-A2-3 : la base garde la sorte du cookie, et rien d'autre ; une session née
// avant 048, sans sorte, ne se reprend sous aucun cookie et s'efface : elle se
// reconnecte, rien ne devine sous lequel elle était.
func TestR_A2_3_ASessionWithoutItsCookieKindIsNeverResumed(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	at := time.Unix(1_800_000_000, 0)
	native := auth.State{Mode: auth.ModeNative, Username: "lucas", PasswordHash: "h", EnabledAt: at}
	if _, err := db.SaveAuthStateIf(ctx, auth.State{Mode: auth.ModeNone}, native, at); err != nil {
		t.Fatal(err)
	}
	state, err := db.GetAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kept := auth.Session{ID: "kept", Identity: "lucas", CreatedAt: at, SeenAt: at, ExpiresAt: at.Add(time.Hour), Cookie: auth.CookieLocal}
	if err := db.CreateSession(ctx, kept, "hash-kept"); err != nil {
		t.Fatal(err)
	}
	if read, _, err := db.SessionByID(ctx, "kept"); err != nil || read.Cookie != auth.CookieLocal {
		t.Fatalf("cookie kind read back %q %v", read.Cookie, err)
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE operator_sessions SET cookie_kind = 'other' WHERE id = 'kept'`); err == nil {
		t.Fatal("an unknown cookie kind was stored")
	}

	service := auth.New(db, slog.New(slog.DiscardHandler))
	service.SetClock(func() time.Time { return at })
	token := strings.Repeat("0", 64)
	for _, cookie := range []auth.CookieKind{auth.CookieHost, auth.CookieLocal} {
		_, err := db.sql.ExecContext(ctx, `
			INSERT INTO operator_sessions (id, token_hash, identity, created_at, seen_at, expires_at)
			VALUES ('before', ?, 'lucas', ?, ?, ?)`, ident.HashToken(token), at.Unix(), at.Unix(), at.Add(time.Hour).Unix())
		if err != nil {
			t.Fatal(err)
		}
		if _, alive, err := service.ResumeSession(ctx, state, auth.PresentedToken{Value: token, Cookie: cookie}); err != nil || alive {
			t.Fatalf("a session from before 048 resumed under %s: %v %v", cookie, alive, err)
		}
		if _, found, _ := db.SessionByID(ctx, "before"); found {
			t.Fatalf("the session from before 048 survived under %s", cookie)
		}
	}
}
