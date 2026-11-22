package server

import (
	"regexp"
	"testing"
)

// L'identifiant de requête reste de seize hexadécimaux en minuscules.
func TestNewRequestID_KeepsItsShape(t *testing.T) {
	if id := newRequestID(); !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(id) {
		t.Fatalf("request id %q", id)
	}
}
