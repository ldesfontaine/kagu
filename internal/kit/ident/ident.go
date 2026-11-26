package ident

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// randomBytes : 64 bits, seize hexadécimaux. Le format est figé : les
// adresses de l'interface et les préfixes de l'annuaire en dépendent.
const randomBytes = 8

// secretBytes : 256 bits, le jeton d'une session (flux d'un agent, session de
// l'opérateur).
const secretBytes = 32

// New tire un identifiant de seize hexadécimaux en minuscules.
func New() (string, error) {
	return NewSized(randomBytes)
}

// NewSized tire un identifiant plus long ou plus court que New, pour les
// formes que d'autres attendent (identifiant de transaction, de corrélation,
// de message) : deux hexadécimaux en minuscules par octet. Un jeton de session
// passe par NewSecret ; les autres secrets gardent leur propre forme.
func NewSized(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// NewSecret tire le jeton d'une session : 256 bits en hexadécimal minuscule.
// C'est un secret : la base n'en garde que HashToken.
func NewSecret() (string, error) {
	return NewSized(secretBytes)
}

// HashToken est la seule forme d'un jeton que la base voit : SHA-256 en
// hexadécimal minuscule, sans dérivation lente (l'entrée est un aléa, pas un
// mot de passe). Le jeton de ping, que la base garde aussi chiffré, s'y cherche
// par cette empreinte. Changer l'encodage invaliderait tous les jetons en base.
func HashToken(cleartext string) string {
	sum := sha256.Sum256([]byte(cleartext))
	return hex.EncodeToString(sum[:])
}

// keyFingerprintPrefix ouvre l'empreinte d'une clé, comme chez OpenSSH.
const keyFingerprintPrefix = "SHA256:"

// KeyFingerprint est l'empreinte d'une clé publique telle que l'opérateur la
// compare : « SHA256: » suivi du condensé en base64 sans remplissage. La clé
// du serveur et celle d'un agent s'écrivent ainsi, à l'écran comme au
// terminal.
func KeyFingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return keyFingerprintPrefix + base64.RawStdEncoding.EncodeToString(sum[:])
}

// IsKeyFingerprint dit si le texte a la forme de KeyFingerprint.
func IsKeyFingerprint(text string) bool {
	digest, found := strings.CutPrefix(text, keyFingerprintPrefix)
	if !found || len(digest) != base64.RawStdEncoding.EncodedLen(sha256.Size) {
		return false
	}
	_, err := base64.RawStdEncoding.Strict().DecodeString(digest)
	return err == nil
}
