package machine

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
)

const (
	// Le préfixe rend un jeton reconnaissable dans un journal ou un presse-papier.
	tokenScheme = brand.EnrollmentTokenScheme
	tokenBytes  = 32
	// Le préfixe affiché : le schéma plus six caractères, 30 bits sur 256.
	tokenPrefixLength = len(tokenScheme) + 6
	tokenIDLength     = 16
	// Un jeton consommé reste pour l'historique (« déjà servi » plutôt
	// qu'« inconnu »), puis la purge du démarrage l'efface.
	ConsumedTokenRetention = 90 * 24 * time.Hour
)

// NewToken tire un jeton et renvoie son clair, à montrer une seule fois, et
// la ligne à stocker, qui n'en garde que l'empreinte et le préfixe.
func NewToken(name, machineID string) (string, Token, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", Token{}, err
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	cleartext := tokenScheme + strings.ToLower(encoded)
	hash := ident.HashToken(cleartext)
	token := Token{
		ID:        hash[:tokenIDLength],
		Hash:      hash,
		Prefix:    cleartext[:tokenPrefixLength],
		Name:      name,
		MachineID: machineID,
		Role:      RoleGeneric,
	}
	return cleartext, token, nil
}

// Masked est tout ce qu'une page peut montrer d'un jeton déjà émis.
func (t Token) Masked() string {
	return t.Prefix + "…"
}
