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

// Le jeton d'une session : 256 bits, soixante-quatre hexadécimaux, neuf à
// chaque tirage.
func TestNewSecret_Is256BitsOfLowercaseHex(t *testing.T) {
	first, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(first) || first == second {
		t.Fatalf("secrets %q %q", first, second)
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
		"enrollment": {"kg_abcdefghijklmnopqrstuvwxyz234567", "44fbb7cf379952d4dcd76be24fd81cc71a58546e3c08d47b3b4f481b93cba781"},  // gitleaks:allow -- faux secret de test
		"ping":       {"hb_abcdefghijklmnopqrstuvwxyz", "7d66f5e35ed70e7a7116a6e0e8b1313a3afa02844437ab090161cb7261c0072f"},        // gitleaks:allow -- faux secret de test
		"api":        {"kgk_abcdefghijklmnopqrstuvwxyz234567", "0437141625b9c223a36f5e94bbecff9e85db9cd7bf55a5943866bd251fee94d5"}, // gitleaks:allow -- faux secret de test
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
	if HashToken("kg_a") == HashToken("kg_b") || HashToken("kg_a") == HashToken("KG_A") {
		t.Fatal("two different tokens share a hash")
	}
}
