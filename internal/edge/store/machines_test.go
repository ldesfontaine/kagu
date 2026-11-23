package store

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
)

// Une base d'avant R-A1-11 peut garder une machine enrôlée sous une autre
// forme (majuscules, tirets ailleurs). Un nouvel identifiant égal à elle sans
// casse ni tirets partagerait son utilisateur restic : refusé ErrBadID, rien
// n'est écrit, le jeton reste à consommer.
func TestEnroll_RefusesAnIDEqualToAnExistingOneWithoutCaseOrDashes(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	legacy := candidate(t)
	canonical := legacy.ID
	legacy.ID = strings.ToUpper(strings.ReplaceAll(canonical, "-", ""))
	if _, err := db.Enroll(ctx, ident.HashToken(issueToken(t, db, "ancienne", "", now)), legacy, newAgent(t, now), now); err != nil {
		t.Fatal(err)
	}

	for i, lookalike := range []string{canonical, strings.ToLower(legacy.ID), legacy.ID} {
		token := issueToken(t, db, "nouvelle-"+strconv.Itoa(i), "", now)
		wanted := candidate(t)
		wanted.ID = lookalike
		if _, err := db.Enroll(ctx, ident.HashToken(token), wanted, newAgent(t, now), now); !errors.Is(err, machine.ErrBadID) {
			t.Fatalf("%q beside %q: got %v, want ErrBadID", lookalike, legacy.ID, err)
		}
		pending, err := db.ListPendingTokens(ctx, now)
		if err != nil || len(pending) != 1 {
			t.Fatalf("the refused enrolment consumed its token: %+v %v", pending, err)
		}
		if err := db.DeleteToken(ctx, pending[0].ID); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := db.Enroll(ctx, ident.HashToken(issueToken(t, db, "autre", "", now)), candidate(t), newAgent(t, now), now); err != nil {
		t.Fatalf("a distinct id was refused: %v", err)
	}
}
