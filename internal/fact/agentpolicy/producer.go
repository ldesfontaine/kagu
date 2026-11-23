package agentpolicy

import (
	"regexp"
	"slices"

	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// Le droit backup.produce : l'agent sait produire une sauvegarde avec ce
// producteur. Sa portée n'est pas un chemin mais un ou plusieurs noms de
// producteurs, séparés par « : » comme les chemins des autres droits
// (backup.produce=proxmox-vzdump) : le champ Capability.Paths les porte.

// ProducerProxmoxVzdump sauvegarde une VM ou un conteneur Proxmox par vzdump.
const ProducerProxmoxVzdump = "proxmox-vzdump"

// Producers rend la liste fermée des producteurs qu'un agent peut recevoir.
func Producers() []string {
	return []string{ProducerProxmoxVzdump}
}

const maxCapabilityProducers = 4

var producerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)

var ErrCapabilityProducer = refusal.Invalid("machine.capability_producer", "backup.produce takes producer names from the closed list, in lowercase letters, digits and dashes")

// normalizeProducers juge la portée de backup.produce : un à quatre
// producteurs connus, triés, sans doublon.
func normalizeProducers(capability Capability) ([]string, error) {
	producers := slices.Clone(capability.Paths)
	slices.Sort(producers)
	producers = slices.Compact(producers)
	if len(producers) == 0 || len(producers) > maxCapabilityProducers {
		return nil, ErrCapabilityScope
	}
	for _, producer := range producers {
		if !producerPattern.MatchString(producer) || !slices.Contains(Producers(), producer) {
			return nil, ErrCapabilityProducer
		}
	}
	return producers, nil
}

// CoversProducer dit si le droit backup.produce de la liste nomme ce
// producteur.
func CoversProducer(capabilities []Capability, name string) bool {
	return slices.ContainsFunc(capabilities, func(capability Capability) bool {
		return capability.Name == CapabilityBackupProduce && slices.Contains(capability.Paths, name)
	})
}
