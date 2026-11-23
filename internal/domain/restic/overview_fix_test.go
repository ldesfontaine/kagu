package restic

import (
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Une protection refusée faute d'un droit porte le droit et la machine que
// les juges de l'envoi disent encore ; rien quand le droit est revenu, ni pour
// une autre raison.
func TestRefusedRightFix_RejudgesTheSourceRights(t *testing.T) {
	sourceWith := func(rights ...string) machine.Status {
		capabilities := []agentpolicy.Capability{}
		for _, right := range rights {
			capabilities = append(capabilities, agentpolicy.Capability{Name: right})
		}
		status := machine.Status{}
		status.ID = "m-src"
		status.Agent = machine.Agent{ID: "agt_1", ReportedAt: time.Unix(1, 0), Capabilities: capabilities}
		return status
	}
	current := Backup{SourceMachineID: "m-src", Scope: agentwire.ResticScopeVM}
	inputs := overviewInputs{machineMap: map[string]machine.Status{"m-src": sourceWith(agentpolicy.CapabilityObserve)}}

	fix := refusedRightFix("restic.source_right_missing", current, inputs)
	if fix == nil || *fix != (refusal.Fix{Right: agentpolicy.CapabilityResticProduce, Machine: "m-src"}) {
		t.Fatalf("fix %+v", fix)
	}
	if fix := refusedRightFix("timeout", current, inputs); fix != nil {
		t.Fatalf("another reason: %+v", fix)
	}
	inputs.machineMap["m-src"] = sourceWith(agentpolicy.CapabilityResticProduce, agentpolicy.CapabilityBackupProduce)
	if fix := refusedRightFix("restic.source_right_missing", current, inputs); fix != nil {
		t.Fatalf("the right came back: %+v", fix)
	}
}
