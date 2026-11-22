package container

import (
	"regexp"
	"testing"
)

// L'identifiant d'une demande de journal reste de trente-deux hexadécimaux.
func TestNewRequestID_KeepsItsShape(t *testing.T) {
	if id := newRequestID(); !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
		t.Fatalf("request id %q", id)
	}
}
