package agentpolicy

import (
	"crypto/ed25519"
	"slices"
)

// Legacy est ce que identity.json portait avant la politique, sur une machine
// installée avant elle : la machine, les droits, les ancres et la clé du
// serveur épinglée.
type Legacy struct {
	MachineID string
	Rights    []Capability
	Anchors   map[string][]string
	ServerKey []byte
}

// Migrate rend la politique qui porte à l'identique ce qu'identity.json
// portait : « policy migrate » l'écrit, puis l'efface d'identity.json. Une
// clé du serveur mal formée ne passe pas : sans clé, aucun ordre ne passe.
func Migrate(legacy Legacy) Document {
	document := Document{MachineID: legacy.MachineID, Rights: legacy.Rights, Anchors: legacy.Anchors}
	if len(legacy.ServerKey) == ed25519.PublicKeySize {
		document.ServerKeys = []ServerKey{{Key: slices.Clone(legacy.ServerKey)}}
	}
	return document
}
