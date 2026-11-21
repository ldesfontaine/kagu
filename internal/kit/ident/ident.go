package ident

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// randomBytes : 64 bits, seize hexadécimaux. Le format est figé : les
// adresses de l'interface et les préfixes de l'annuaire en dépendent.
const randomBytes = 8

// New tire un identifiant de seize hexadécimaux en minuscules.
func New() (string, error) {
	raw := make([]byte, randomBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// HashSecret est la seule forme d'un jeton que la base voit. SHA-256 sans
// dérivation lente : l'entrée est un aléa de 256 bits, pas un mot de passe.
func HashSecret(cleartext string) string {
	sum := sha256.Sum256([]byte(cleartext))
	return hex.EncodeToString(sum[:])
}
