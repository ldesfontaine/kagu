package agentpolicy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// ErrUnreadable : le fichier de la politique ne se lit pas strictement. Un
// agent qui le rencontre n'applique que observe (R-A3-6).
var ErrUnreadable = errors.New("agent policy is unreadable")

// ErrServerKeyInvalid : une clé du serveur n'est pas une clé publique
// Ed25519 en base64.
var ErrServerKeyInvalid = errors.New("not an Ed25519 public key in base64")

// policyFile est la forme TOML du fichier. Une clé de plus le rend illisible.
type policyFile struct {
	Version    int                 `toml:"version"`
	MachineID  string              `toml:"machine_id"`
	ServerKeys []fileServerKey     `toml:"server_key,omitempty"`
	Rights     []fileRight         `toml:"right"`
	Anchors    map[string][]string `toml:"anchors,omitempty"`
}

// fileServerKey est un bloc [[server_key]] : la clé en base64 et, sur la
// clé gardée par --keep-old, son échéance et l'horloge de sa pose (les champs
// d'un droit à durée, R-A3-5).
type fileServerKey struct {
	Key           string    `toml:"key"`
	Until         time.Time `toml:"until,omitempty"`
	GrantedAt     time.Time `toml:"granted_at,omitempty"`
	GrantedBoot   string    `toml:"granted_boot,omitempty"`
	GrantedUptime int64     `toml:"granted_uptime,omitempty"`
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
	keys, err := serverKeysOf(file.ServerKeys)
	if err != nil {
		return Document{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	return Document{MachineID: file.MachineID, ServerKeys: keys, Rights: normalized, Anchors: file.Anchors}, nil
}

// serverKeysOf lit les blocs [[server_key]] : aucun, une clé acceptée sans
// échéance, ou celle-ci suivie d'une autre clé gardée, avec son échéance et
// l'horloge de sa pose (R-A3-2). Rien d'autre ne se lit.
func serverKeysOf(blocks []fileServerKey) ([]ServerKey, error) {
	if len(blocks) > 2 {
		return nil, errors.New("more than two server keys")
	}
	keys := make([]ServerKey, 0, len(blocks))
	for index, block := range blocks {
		key, err := ParseServerKey(block.Key)
		if err != nil {
			return nil, err
		}
		kept := ServerKey{Key: key, Until: block.Until, Granted: Clock{
			Now: block.GrantedAt, Boot: block.GrantedBoot, Uptime: time.Duration(block.GrantedUptime) * time.Second,
		}}
		if index == 0 && block != (fileServerKey{Key: block.Key}) {
			return nil, errors.New("the accepted server key carries an expiry")
		}
		if index == 1 && (kept.Until.IsZero() || kept.Granted.Now.IsZero() || kept.Granted.Boot == "" || slices.Equal(key, keys[0].Key)) {
			return nil, errors.New("the kept server key needs its own key, an expiry and the clock of its grant")
		}
		keys = append(keys, kept)
	}
	return keys, nil
}

// ParseServerKey lit une clé publique Ed25519 du serveur en base64, telle que
// « opencloud secrets server-key » et la ligne « trust set » la donnent.
func ParseServerKey(text string) ([]byte, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, ErrServerKeyInvalid
	}
	return key, nil
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
