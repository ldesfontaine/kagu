package agentpolicy

import (
	"slices"
	"testing"
)

func TestProducers_AreTheClosedListTheRightAccepts(t *testing.T) {
	if got := Producers(); !slices.Equal(got, []string{"proxmox-vzdump"}) {
		t.Fatalf("producers %v", got)
	}
	for _, producer := range Producers() {
		if !producerPattern.MatchString(producer) {
			t.Errorf("%q does not match its own grammar", producer)
		}
	}
}
