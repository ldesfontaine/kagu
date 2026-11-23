package store

import (
	"context"
	"log/slog"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
)

// R-A2-1 : une base d'avant, en basic, démarre en native : même nom, même
// empreinte, et l'ancien mot de passe ouvre une session. Les autres colonnes
// de la ligne passent telles quelles.
func TestMigration044_ABasicBaseStartsNativeAndTheOldPasswordOpensASession(t *testing.T) {
	ctx := context.Background()
	const oldPassword = "correct horse battery"
	hash, err := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	db := replayLegacyMigrations(t)
	exec(t, db, `INSERT INTO auth_settings (id, mode, username, password_hash, enabled_at, updated_at) VALUES (1, 'basic', 'lucas', ?, 1700000000, 1700000001)`, string(hash))

	applyLaterMigrations(t, db)

	state, err := db.GetAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != auth.ModeNative || state.Username != "lucas" || state.PasswordHash != string(hash) || state.EnabledAt.Unix() != 1700000000 {
		t.Fatalf("after the migration %+v", state)
	}
	if updated := count(t, db, `SELECT updated_at FROM auth_settings WHERE id = 1`); updated != 1700000001 {
		t.Fatalf("updated_at %d", updated)
	}
	if _, err := db.sql.Exec(`UPDATE auth_settings SET mode = 'basic' WHERE id = 1`); err == nil {
		t.Fatal("basic is still accepted after the migration")
	}

	service := auth.New(db, slog.New(slog.DiscardHandler))
	if _, err := service.Login(ctx, state, "lucas", "a wrong passphrase", auth.SessionClient{}); err == nil {
		t.Fatal("a wrong password opened a session")
	}
	opened, err := service.Login(ctx, state, "lucas", oldPassword, auth.SessionClient{Address: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, alive, err := service.ResumeSession(ctx, state, opened.Token); err != nil || !alive {
		t.Fatalf("the session opened by the old password does not resume: %v %v", alive, err)
	}
}

// Une base en none ou en forward garde son mode et son code de première
// configuration.
func TestMigration044_NoneAndForwardKeepTheirRow(t *testing.T) {
	for _, mode := range []string{"none", "forward"} {
		t.Run(mode, func(t *testing.T) {
			db := replayLegacyMigrations(t)
			exec(t, db, `INSERT INTO auth_settings (id, mode, forward_header, updated_at) VALUES (1, ?, 'Remote-User', 1)`, mode)
			applyLaterMigrations(t, db)
			if got := text(t, db, `SELECT mode || '/' || forward_header FROM auth_settings WHERE id = 1`); got != mode+"/Remote-User" {
				t.Fatalf("row %q", got)
			}
		})
	}
}
