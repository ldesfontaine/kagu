package agentpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// ErrUnreadable : le fichier de la politique ne se lit pas strictement. Un
// agent qui le rencontre n'applique que observe (R-A3-6).
var ErrUnreadable = errors.New("agent policy is unreadable")

// policyFile est la forme TOML du fichier. Une clé de plus le rend illisible.
type policyFile struct {
	Version   int         `toml:"version"`
	MachineID string      `toml:"machine_id"`
	Rights    []fileRight `toml:"right"`
}

// fileRight est un bloc [[right]] : le nom et, pour un droit borné, sa valeur
// dans la grammaire d'aujourd'hui (« /srv/a:/srv/b », « proxmox-vzdump »).
type fileRight struct {
	Name  string `toml:"name"`
	Value string `toml:"value,omitempty"`
}

// Decode lit le fichier de la politique, strictement : une clé inconnue, une
// autre version, une machine absente, un droit inconnu, mal borné ou écrit
// deux fois le rendent illisible. observe est toujours dans les droits rendus.
func Decode(content []byte) (Document, error) {
	var file policyFile
	decoder := toml.NewDecoder(bytes.NewReader(content)).DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return Document{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	if file.Version != FormatVersion {
		return Document{}, fmt.Errorf("%w: version %d", ErrUnreadable, file.Version)
	}
	if file.MachineID == "" {
		return Document{}, fmt.Errorf("%w: no machine_id", ErrUnreadable)
	}
	rights := make([]Capability, 0, len(file.Rights))
	seen := map[string]bool{}
	for _, right := range file.Rights {
		if seen[right.Name] {
			return Document{}, fmt.Errorf("%w: %s written twice", ErrUnreadable, right.Name)
		}
		seen[right.Name] = true
		rights = append(rights, capabilityOf(right))
	}
	normalized, err := NormalizeCapabilities(rights)
	if err != nil {
		return Document{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	return Document{MachineID: file.MachineID, Rights: normalized}, nil
}

func capabilityOf(right fileRight) Capability {
	capability := Capability{Name: right.Name}
	if right.Value != "" {
		capability.Paths = strings.Split(right.Value, pathSeparator)
	}
	return capability
}

// Digest est l'empreinte du fichier de la politique, telle que l'agent la
// rapporte : le SHA-256 de ses octets en hexadécimal, ce que « sha256sum »
// affiche sur la machine.
func Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// IsDigest dit si un texte a la forme d'une empreinte de Digest.
func IsDigest(text string) bool {
	decoded, err := hex.DecodeString(text)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(text) == text
}
