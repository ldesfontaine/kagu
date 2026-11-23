package ident

import (
	"regexp"
	"testing"
)

var shape = regexp.MustCompile(`^[0-9a-f]{16}$`)

// La forme est celle que l'interface et l'annuaire attendent depuis le début.
func TestNew_IsSixteenLowercaseHexAndDrawnAgainEachTime(t *testing.T) {
	first, err := New()
	if err != nil {
		t.Fatal(err)
	}
	second, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if !shape.MatchString(first) || !shape.MatchString(second) {
		t.Fatalf("shape: %q, %q", first, second)
	}
	if first == second {
		t.Fatal("two draws gave the same identifier")
	}
}

// Une taille choisie donne deux hexadécimaux en minuscules par octet.
func TestNewSized_IsTwoLowercaseHexPerByte(t *testing.T) {
	for _, bytes := range []int{8, 12, 16} {
		got, err := NewSized(bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(got) || len(got) != 2*bytes {
			t.Fatalf("%d bytes: %q", bytes, got)
		}
	}
	if len(mustNew(t)) != len(mustSized(t, randomBytes)) {
		t.Fatal("New is no longer NewSized(randomBytes)")
	}
}

func mustNew(t *testing.T) string {
	t.Helper()
	id, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustSized(t *testing.T, bytes int) string {
	t.Helper()
	id, err := NewSized(bytes)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// R-A2-2 : l'empreinte d'un jeton est celle que la base garde déjà. Les
// valeurs sont écrites en dur : changer l'encodage rendrait faux tous les
// jetons d'API, d'enrôlement, de ping et le code de première configuration.
func TestR_A2_2_ATokenHashStaysTheHexOfItsSHA256(t *testing.T) {
	witnesses := map[string]struct{ token, want string }{
		"enrollment": {"oc_abcdefghijklmnopqrstuvwxyz234567", "5e94b693f30467559bc9c7c88335758ed0dcc30de4dea36ebb2888d3a2bb1193"},  // gitleaks:allow -- faux secret de test
		"ping":       {"hb_abcdefghijklmnopqrstuvwxyz", "7d66f5e35ed70e7a7116a6e0e8b1313a3afa02844437ab090161cb7261c0072f"},        // gitleaks:allow -- faux secret de test
		"api":        {"ock_abcdefghijklmnopqrstuvwxyz234567", "6f7465869576816b7fdfb83d60daa21521d9d92a62599ea1f0eb83dbc5ceb1df"}, // gitleaks:allow -- faux secret de test
		"setup code": {"12345678", "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f"},
	}
	for name, witness := range witnesses {
		if got := HashToken(witness.token); got != witness.want {
			t.Errorf("%s: HashToken(%q) = %q, want %q", name, witness.token, got, witness.want)
		}
	}
}

// Une autre valeur ne rend jamais la même empreinte : deux jetons, deux
// empreintes, et la casse change l'empreinte.
func TestHashToken_DiffersPerTokenAndPerCase(t *testing.T) {
	if HashToken("oc_a") == HashToken("oc_b") || HashToken("oc_a") == HashToken("OC_A") {
		t.Fatal("two different tokens share a hash")
	}
}
