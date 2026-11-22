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
