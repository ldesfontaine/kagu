package clocksync

import "testing"

// La lecture ne demande aucun droit : elle répond, synchronisée ou non.
func TestSynced_ReadsWithoutPrivilege(t *testing.T) {
	if _, err := Synced(); err != nil {
		t.Fatal(err)
	}
}
