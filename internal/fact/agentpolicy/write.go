package agentpolicy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// ErrRevokeObserve : observe ne se retire pas, l'agent ne saurait plus rien
// dire de la machine.
var ErrRevokeObserve = errors.New("observe cannot be revoked")

var (
	// ErrNoServerKeyToKeep : --keep-old garde la clé acceptée ; il n'y en a pas.
	ErrNoServerKeyToKeep = errors.New("no accepted server key to keep")
	// ErrServerKeyAlreadyAccepted : la clé donnée est déjà la clé acceptée.
	ErrServerKeyAlreadyAccepted = errors.New("this server key is already the accepted one")
)

// Encode écrit la politique sous sa forme de fichier, les droits dans l'ordre
// où ils s'affichent : deux politiques égales s'écrivent pareil.
func Encode(document Document) ([]byte, error) {
	file := policyFile{Version: FormatVersion, MachineID: document.MachineID, Anchors: document.Anchors}
	for _, key := range document.ServerKeys {
		file.ServerKeys = append(file.ServerKeys, fileServerKey{Key: base64.StdEncoding.EncodeToString(key.Key), fileExpiry: fileExpiryOf(key.Expiry)})
	}
	for _, capability := range document.Rights {
		file.Rights = append(file.Rights, fileRight{
			Name: capability.Name, Value: strings.Join(capability.Paths, pathSeparator), fileExpiry: fileExpiryOf(document.Expiries[capability.Name]),
		})
	}
	content, err := toml.Marshal(file)
	if err != nil {
		return nil, fmt.Errorf("encode agent policy: %w", err)
	}
	return content, nil
}

// Grant pose des droits : un droit déjà posé prend la valeur donnée, qui
// remplace la sienne, et l'échéance du terme, posée sur l'horloge clock
// (R-A3-5) ; sans durée, il n'en a plus. observe n'en prend jamais : il ne
// se retire pas.
func (d Document) Grant(granted []Capability, term Term, clock Clock) (Document, error) {
	if term.Duration != 0 {
		if err := CheckDuration(term.Duration); err != nil {
			return Document{}, err
		}
	}
	merged := slices.Clone(d.Rights)
	names := make([]string, 0, len(granted))
	for _, capability := range granted {
		names = append(names, capability.Name)
		merged = slices.DeleteFunc(merged, func(held Capability) bool { return held.Name == capability.Name })
		merged = append(merged, capability)
	}
	rights, err := NormalizePolicyRights(merged)
	if err != nil {
		return Document{}, err
	}
	expiries := expiriesWithout(d.Expiries, names)
	for _, name := range names {
		if duration := term.DurationOf(name); duration != 0 && name != CapabilityObserve {
			expiries[name] = expiryAfter(clock, duration)
		}
	}
	d.Rights, d.Expiries = rights, expiries
	return d, nil
}

// Revoke retire des droits, avec leur valeur. Un droit absent ne change rien ;
// un nom inconnu, ou observe, est refusé.
func (d Document) Revoke(names []string) (Document, error) {
	rights := slices.Clone(d.Rights)
	for _, name := range names {
		if !revocable(name) {
			return Document{}, ErrRevokeObserve
		}
		if known, ok := knownRightOf(name); !ok || known.readable > readInPolicy {
			return Document{}, ErrCapabilityUnknown
		}
		rights = slices.DeleteFunc(rights, func(held Capability) bool { return held.Name == name })
	}
	d.Rights, d.Expiries = rights, expiriesWithout(d.Expiries, names)
	return d, nil
}

// revocable dit si un droit se retire : tous, sauf observe.
func revocable(name string) bool {
	return name != CapabilityObserve
}

// SetServerKey remplace les clés du serveur par celle-ci, seule acceptée :
// l'ancienne ne l'est plus (R-A3-14, N-M2).
func (d Document) SetServerKey(key []byte) Document {
	d.ServerKeys = []ServerKey{{Key: slices.Clone(key)}}
	return d
}

// KeepServerKey accepte une clé neuve et garde la clé acceptée jusqu'ici
// pendant keepOld (de MinDuration à MaxDuration), échéance posée sur
// l'horloge granted ; une clé gardée plus tôt tombe (R-A3-14).
func (d Document) KeepServerKey(key []byte, keepOld time.Duration, granted Clock) (Document, error) {
	if err := CheckDuration(keepOld); err != nil {
		return Document{}, err
	}
	if len(d.ServerKeys) == 0 {
		return Document{}, ErrNoServerKeyToKeep
	}
	accepted := d.ServerKeys[0].Key
	if slices.Equal(accepted, key) {
		return Document{}, ErrServerKeyAlreadyAccepted
	}
	kept := ServerKey{Key: accepted, Expiry: expiryAfter(granted, keepOld)}
	d.ServerKeys = []ServerKey{{Key: slices.Clone(key)}, kept}
	return d, nil
}

// LiveServerKeys rend les clés acceptées à l'heure now : une clé gardée
// échue n'y est plus (Lapsed).
func (d Document) LiveServerKeys(now Clock) [][]byte {
	var live [][]byte
	for _, key := range d.ServerKeys {
		if !Lapsed(key.Until, key.Granted, now) {
			live = append(live, key.Key)
		}
	}
	return live
}

// Same dit si deux politiques portent la même chose : une politique
// inchangée ne se réécrit pas.
func (d Document) Same(other Document) bool {
	return d.MachineID == other.MachineID &&
		FormatCapabilities(d.Rights) == FormatCapabilities(other.Rights) && sameExpiries(d.Expiries, other.Expiries) &&
		maps.EqualFunc(d.Anchors, other.Anchors, slices.Equal) &&
		slices.EqualFunc(d.ServerKeys, other.ServerKeys, func(first, second ServerKey) bool {
			return slices.Equal(first.Key, second.Key) && first.Expiry.equal(second.Expiry)
		})
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
