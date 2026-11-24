package agentpolicy

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// ErrRevokeObserve : observe ne se retire pas, l'agent ne saurait plus rien
// dire de la machine.
var ErrRevokeObserve = errors.New("observe cannot be revoked")

// Encode écrit la politique sous sa forme de fichier, les droits dans l'ordre
// où ils s'affichent : deux politiques égales s'écrivent pareil.
func Encode(document Document) ([]byte, error) {
	file := policyFile{Version: FormatVersion, MachineID: document.MachineID}
	for _, capability := range document.Rights {
		file.Rights = append(file.Rights, fileRight{Name: capability.Name, Value: strings.Join(capability.Paths, pathSeparator)})
	}
	content, err := toml.Marshal(file)
	if err != nil {
		return nil, fmt.Errorf("encode agent policy: %w", err)
	}
	return content, nil
}

// Grant pose des droits : un droit déjà posé prend la valeur donnée, qui
// remplace la sienne.
func (d Document) Grant(granted []Capability) (Document, error) {
	merged := slices.Clone(d.Rights)
	for _, capability := range granted {
		merged = slices.DeleteFunc(merged, func(held Capability) bool { return held.Name == capability.Name })
		merged = append(merged, capability)
	}
	rights, err := NormalizeCapabilities(merged)
	if err != nil {
		return Document{}, err
	}
	d.Rights = rights
	return d, nil
}

// Revoke retire des droits, avec leur valeur. Un droit absent ne change rien ;
// un nom inconnu, ou observe, est refusé.
func (d Document) Revoke(names []string) (Document, error) {
	rights := slices.Clone(d.Rights)
	for _, name := range names {
		if name == CapabilityObserve {
			return Document{}, ErrRevokeObserve
		}
		if !slices.Contains(CapabilityNames(), name) {
			return Document{}, ErrCapabilityUnknown
		}
		rights = slices.DeleteFunc(rights, func(held Capability) bool { return held.Name == name })
	}
	d.Rights = rights
	return d, nil
}

// Changes dit ce qui sépare deux listes de droits, chacun sous sa forme texte
// (« files.write=/srv/a ») : un droit dont la valeur change est retiré sous
// l'ancienne et posé sous la nouvelle.
func Changes(before, after []Capability) (added, removed []string) {
	beforeText, afterText := formattedEach(before), formattedEach(after)
	for _, text := range afterText {
		if !slices.Contains(beforeText, text) {
			added = append(added, text)
		}
	}
	for _, text := range beforeText {
		if !slices.Contains(afterText, text) {
			removed = append(removed, text)
		}
	}
	return added, removed
}

func formattedEach(capabilities []Capability) []string {
	texts := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		texts = append(texts, formatCapability(capability))
	}
	return texts
}
