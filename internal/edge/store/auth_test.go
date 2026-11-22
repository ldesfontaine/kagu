package store

import (
	"context"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
)

func TestAuthState_HeaderRoundTripsAndModeNoneClearsIt(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	enabledAt := time.Unix(1_800_000_000, 0)
	forward := auth.State{Mode: auth.ModeForward, Header: "Remote-User", EnabledAt: enabledAt}
	if swapped, err := db.SaveAuthStateIf(ctx, auth.State{Mode: auth.ModeNone}, forward, enabledAt); err != nil || !swapped {
		t.Fatal(swapped, err)
	}
	got, err := db.GetAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != auth.ModeForward || got.Header != "Remote-User" || !got.EnabledAt.Equal(enabledAt) || got.Username != "" {
		t.Fatalf("read back %+v", got)
	}
	if swapped, err := db.SaveAuthStateIf(ctx, got, auth.State{Mode: auth.ModeNone}, enabledAt); err != nil || !swapped {
		t.Fatal(swapped, err)
	}
	got, err = db.GetAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != auth.ModeNone || got.Header != "" || !got.EnabledAt.IsZero() {
		t.Fatalf("after disable %+v", got)
	}
}

// La comparaison-échange : l'écriture ne passe que si la ligne vaut encore
// l'état attendu, et de deux écritures parties du même état, une seule gagne.
func TestSaveAuthStateIf_WritesOnlyFromTheExpectedState(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	at := time.Unix(1_800_000_000, 0)
	none := auth.State{Mode: auth.ModeNone}
	basic := auth.State{Mode: auth.ModeBasic, Username: "lucas", PasswordHash: "empreinte", EnabledAt: at}
	other := auth.State{Mode: auth.ModeBasic, Username: "autre", PasswordHash: "autre", EnabledAt: at}

	// Sans ligne, l'état stocké est « none ».
	swapped, err := db.SaveAuthStateIf(ctx, none, basic, at)
	if err != nil || !swapped {
		t.Fatalf("first write: %v %v", swapped, err)
	}
	swapped, err = db.SaveAuthStateIf(ctx, none, other, at)
	if err != nil || swapped {
		t.Fatalf("second write from the same state: %v %v", swapped, err)
	}
	got, err := db.GetAuthState(ctx)
	if err != nil || !got.Same(basic) {
		t.Fatalf("stored %+v %v, want %+v", got, err, basic)
	}
	swapped, err = db.SaveAuthStateIf(ctx, basic, none, at)
	if err != nil || !swapped {
		t.Fatalf("write from the stored state: %v %v", swapped, err)
	}
	if got, _ := db.GetAuthState(ctx); got.Mode != auth.ModeNone || got.PasswordHash != "" {
		t.Fatalf("after the swap %+v", got)
	}
}

// Le code de première configuration : écrit sur une installation neuve, compté
// en essais faux, effacé par tout changement d'état, jamais écrit hors du mode
// none.
func TestSetupCode_IsKeptCountedAndWipedByAnyStateChange(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	at := time.Unix(1_800_000_000, 0)
	code := auth.SetupCode{Hash: "empreinte", Expires: at.Add(30 * time.Minute)}

	if empty, err := db.GetSetupCode(ctx); err != nil || empty.Hash != "" {
		t.Fatalf("fresh install: %+v %v", empty, err)
	}
	if saved, err := db.SaveSetupCodeIfNone(ctx, code, at); err != nil || !saved {
		t.Fatal(saved, err)
	}
	if err := db.RecordSetupCodeFailure(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetSetupCode(ctx)
	if err != nil || got.Hash != "empreinte" || got.Failures != 1 || !got.Expires.Equal(code.Expires) {
		t.Fatalf("read back %+v %v", got, err)
	}
	if state, err := db.GetAuthState(ctx); err != nil || state.Mode != auth.ModeNone {
		t.Fatalf("the code row is in mode none: %+v %v", state, err)
	}

	basic := auth.State{Mode: auth.ModeBasic, Username: "lucas", PasswordHash: "h", EnabledAt: at}
	if swapped, err := db.SaveAuthStateIf(ctx, auth.State{Mode: auth.ModeNone}, basic, at); err != nil || !swapped {
		t.Fatal(swapped, err)
	}
	if wiped, err := db.GetSetupCode(ctx); err != nil || wiped.Hash != "" || wiped.Failures != 0 || !wiped.Expires.IsZero() {
		t.Fatalf("a state change keeps the code: %+v %v", wiped, err)
	}
	if saved, err := db.SaveSetupCodeIfNone(ctx, code, at); err != nil || saved {
		t.Fatalf("a code is never written outside mode none: %v %v", saved, err)
	}
}
