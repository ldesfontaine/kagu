package restic

import (
	"regexp"
	"testing"
)

// L'identifiant d'une requête relayée reste de trente-deux hexadécimaux.
func TestNewRelayID_KeepsItsShape(t *testing.T) {
	id, err := newRelayID()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
		t.Fatalf("relay id %q", id)
	}
}
