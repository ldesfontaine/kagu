package agentpolicy

// Policy est ce que root permet à l'agent d'une machine (fiche A3, §5) : la
// machine, la clé du serveur acceptée, les droits et les ancres. Le juge
// d'un ordre la reçoit, il ne lit aucun fichier. L'agent la construit depuis
// le fichier de la politique (Document) ; la clé et les ancres viennent encore
// d'identity.json (T03-04).
type Policy struct {
	MachineID string
	// La clé publique Ed25519 du serveur ; vide : aucun ordre ne passe.
	ServerKey []byte
	Rights    []Capability
	// Par type d'ancre (internal/fact/anchor), les valeurs posées par root,
	// telles que le fichier les porte.
	Anchors map[string][]string
}

// FormatVersion est la version du fichier de la politique que ce code lit et
// écrit (la clé « version »). Un agent la note aussi dans son identité :
// « agent grant » refuse d'écrire pour un agent qui ne la lirait pas.
const FormatVersion = 1

// D'où l'agent tient les droits qu'il applique, tel qu'il le rapporte au
// serveur. SourceRefused : la politique existe mais ne se lit pas, n'est pas
// à root ou s'écrit par un autre compte ; seul observe s'applique (R-A3-6).
const (
	SourcePolicy   = "policy"
	SourceIdentity = "identity"
	SourceRefused  = "refused"
)

// Sources rend les sources qu'un agent peut rapporter.
func Sources() []string {
	return []string{SourcePolicy, SourceIdentity, SourceRefused}
}

// Document est la politique telle que son fichier la porte (fiche A3, §5) :
// la machine et les droits, normalisés. Ni échéance (T03-05) ni ancre ni clé
// du serveur (T03-04).
type Document struct {
	MachineID string
	Rights    []Capability
}
