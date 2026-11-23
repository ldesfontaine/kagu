package apitoken

import (
	"crypto/rand"
	"encoding/base32"
	"strings"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
)

// Le préfixe des jetons : reconnaissable dans un journal ou un
// presse-papier, jamais confondu avec un jeton d'enrôlement (oc_) ni de
// ping (hb_).
const scheme = brand.APITokenScheme

const (
	secretBytes = 32
	// Le préfixe affiché : le schéma plus six caractères, 30 bits sur 256.
	shownLength = 6
	idLength    = 16
)

// generated est un jeton tiré : le clair, à rendre une seule fois, et ce
// que la base garde.
type generated struct {
	cleartext string
	hash      string
	prefix    string
	id        string
}

func newSecret() (generated, error) {
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return generated{}, err
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	cleartext := scheme + strings.ToLower(encoded)
	hash := ident.HashToken(cleartext)
	return generated{
		cleartext: cleartext,
		hash:      hash,
		prefix:    cleartext[:len(scheme)+shownLength],
		id:        hash[:idLength],
	}, nil
}
