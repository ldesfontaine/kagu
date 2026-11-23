package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/domain/heartbeat"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/seal"
)

// Un faux secret de code : le test cherche son clair dans la colonne.
const plainTOTPSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // gitleaks:allow -- faux secret de test

// nativeTOTPDB rend une base scellée, en native, avec le code actif au pas 100.
func nativeTOTPDB(t *testing.T) *DB {
	t.Helper()
	db := openSecretsDB(t)
	db.SetSealer(seal.Generate())
	ctx := context.Background()
	native := auth.State{Mode: auth.ModeNative, Username: "lucas", PasswordHash: "$2a$hash"}
	if saved, err := db.SaveAuthStateIf(ctx, auth.State{Mode: auth.ModeNone}, native, time.Unix(1, 0)); err != nil || !saved {
		t.Fatalf("save native: %v %v", saved, err)
	}
	if enabled, err := db.EnableTOTPIfNone(ctx, plainTOTPSecret, 100); err != nil || !enabled {
		t.Fatalf("enable: %v %v", enabled, err)
	}
	return db
}

// Le secret du code est scellé par secret.key, jamais en clair dans la base ;
// GetTOTP l'ouvre.
func TestTOTP_SecretIsSealed(t *testing.T) {
	db := nativeTOTPDB(t)
	raw := rawColumn(t, db, `SELECT totp_secret FROM auth_settings`)
	if !seal.IsSealed(raw) || strings.Contains(raw, plainTOTPSecret) {
		t.Fatalf("stored %q", raw)
	}
	got, err := db.GetTOTP(context.Background())
	if err != nil || got.Secret != plainTOTPSecret || got.LastStep != 100 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if err := db.VerifySealedSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if enabled, err := db.EnableTOTPIfNone(context.Background(), "ANOTHERSECRET", 1); err != nil || enabled {
		t.Fatalf("a second activation wrote: %v %v", enabled, err)
	}
}

// Un pas ne se sert qu'une fois, et jamais un pas plus ancien.
func TestConsumeTOTPStep_OnlyForward(t *testing.T) {
	db := nativeTOTPDB(t)
	ctx := context.Background()
	for _, attempt := range []struct {
		step   int64
		served bool
	}{{100, false}, {99, false}, {101, true}, {101, false}, {103, true}} {
		served, err := db.ConsumeTOTPStep(ctx, attempt.step)
		if err != nil || served != attempt.served {
			t.Errorf("step %d: served %v (%v), want %v", attempt.step, served, err, attempt.served)
		}
	}
}

// Un mot de passe refait garde le code ; un passage au SSO le retire ; une
// clé perdue aussi (ForgetSecrets).
func TestTOTP_FollowsTheAccount(t *testing.T) {
	db := nativeTOTPDB(t)
	ctx := context.Background()
	native, _ := db.GetAuthState(ctx)
	reset := native
	reset.PasswordHash = "$2a$other"
	if saved, err := db.SaveAuthStateIf(ctx, native, reset, time.Unix(2, 0)); err != nil || !saved {
		t.Fatal(err)
	}
	if got, _ := db.GetTOTP(ctx); !got.Active() {
		t.Fatal("a password reset removed the code")
	}
	forward := auth.State{Mode: auth.ModeForward, Header: auth.DefaultForwardHeader}
	if saved, err := db.SaveAuthStateIf(ctx, reset, forward, time.Unix(3, 0)); err != nil || !saved {
		t.Fatal(err)
	}
	if got, _ := db.GetTOTP(ctx); got.Active() || got.LastStep != 0 {
		t.Fatalf("the code survived the switch to SSO: %+v", got)
	}

	lost := nativeTOTPDB(t)
	lost.SetSealer(seal.Generate())
	if _, err := lost.ForgetSecrets(ctx, heartbeat.NewToken); err != nil {
		t.Fatal(err)
	}
	if got, err := lost.GetTOTP(ctx); err != nil || got.Active() {
		t.Fatalf("after a lost key: %+v, %v", got, err)
	}
	if cleared, err := db.ClearTOTP(ctx); err != nil || cleared {
		t.Fatalf("clear without a code: %v %v", cleared, err)
	}
}
