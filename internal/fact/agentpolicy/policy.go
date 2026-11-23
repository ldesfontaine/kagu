package agentpolicy

// Policy est ce que root permet à l'agent d'une machine (fiche A3, §5) : la
// machine, la clé du serveur acceptée, les droits et les ancres. Le juge
// d'un ordre la reçoit, il ne lit aucun fichier. Tant que la politique n'a
// pas de fichier à elle (T03-03), l'agent la construit depuis identity.json.
type Policy struct {
	MachineID string
	// La clé publique Ed25519 du serveur ; vide : aucun ordre ne passe.
	ServerKey []byte
	Rights    []Capability
	// Par type d'ancre (internal/fact/anchor), les valeurs posées par root,
	// telles que le fichier les porte.
	Anchors map[string][]string
}
