package heartbeat

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

const (
	// Le préfixe rend un jeton de ping reconnaissable dans un cron ou un journal.
	tokenScheme = "hb_" // #nosec G101 -- un préfixe, pas un secret.
	// 128 bits : assez pour un secret d'URL, court dans une ligne de cron.
	tokenBytes = 16
)

// NewToken tire le secret de l'URL de ping. La base le garde chiffré
// (token_sealed), car la page du moniteur doit pouvoir le réafficher ;
// ident.HashToken sert à le chercher (token_lookup).
func NewToken() (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return tokenScheme + strings.ToLower(encoded), nil
}
