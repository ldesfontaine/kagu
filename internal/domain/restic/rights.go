package restic

import (
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
)

// RightView est un droit de restic tel que l'aperçu le montre : le verdict
// d'agentpolicy.Fit et, pour restic.target, le dossier du droit, de quoi
// griser une machine à l'écran et proposer de la ré-enrôler avec lui.
type RightView struct {
	agentpolicy.RightFit
	Path string
}

// targetDirOf rend le dossier du droit restic.target que l'agent a rapporté ;
// vide sans lui.
func targetDirOf(agent machine.Agent) string {
	for _, capability := range agent.Capabilities {
		if capability.Name == agentpolicy.CapabilityResticTarget && len(capability.Paths) == 1 {
			return capability.Paths[0]
		}
	}
	return ""
}
