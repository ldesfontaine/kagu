package release

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// Les clés publiques des versions, au format minisign : la seule liste des
// clés de confiance du projet (docs/projet/12-methode.md).
//
// CurrentPublicKey signe chaque version ; sa clé privée est le secret
// RELEASE_SIGNING_KEY de l'environnement GitHub « release ». Vide, le binaire
// refuse de vérifier quoi que ce soit.
//
// BackupPublicKey est la clé de secours : sa clé privée est dans le coffre de
// Lucas, jamais dans GitHub. Une version signée par elle retire la courante :
// l'agent qui l'installe ne croit plus jamais l'ancienne. Tirée hors ligne
// par Lucas (minisign -G) le 20/11/2026. Vide, une version
// (`go build -tags release`) ne se construit pas (key_release.go).
const (
	CurrentPublicKey = "RWR3td9Uebbdsc6fVgCOun/FNjBDAx5QCbN8hjrKBPtW47xwkbf1F+o3"
	BackupPublicKey  = "RWRNylnietSsacsUhEFv/jr4jIpQUo57JaIHu4VQWBI9jvb1rZ9aOcau"
)

// ErrNoTrustedKey : ce binaire n'embarque aucune clé de version, ou toutes
// sont retirées.
var ErrNoTrustedKey = refusal.Conflict("release.no_trusted_key", "release: no trusted public key embedded in this binary")

// Keys sont les clés de version qu'un binaire croit : la courante, et la
// secours qui la retire. Une Backup vide ne vérifie rien.
type Keys struct {
	Current PublicKey
	Backup  PublicKey
}

// TrustedPublicKeys rend les clés de version embarquées dans ce binaire.
func TrustedPublicKeys() (Keys, error) {
	if CurrentPublicKey == "" {
		return Keys{}, ErrNoTrustedKey
	}
	current, err := ParsePublicKey(CurrentPublicKey)
	if err != nil {
		return Keys{}, fmt.Errorf("current release key: %w", err)
	}
	keys := Keys{Current: current}
	if BackupPublicKey == "" {
		return keys, nil
	}
	if keys.Backup, err = ParsePublicKey(BackupPublicKey); err != nil {
		return Keys{}, fmt.Errorf("backup release key: %w", err)
	}
	return keys, nil
}

// HasBackup : une clé de secours est posée.
func (keys Keys) HasBackup() bool {
	return keys.Backup.isSet()
}

// Without rend les clés moins celles qui sont retirées : une courante retirée
// laisse la secours seule, qui devient la courante. Retirer ne fait jamais
// croire une clé de plus ; s'il ne reste rien, ErrNoTrustedKey.
func (keys Keys) Without(retired []PublicKey) (Keys, error) {
	isRetired := func(key PublicKey) bool {
		return slices.ContainsFunc(retired, key.Equal)
	}
	remaining := keys
	if keys.HasBackup() && isRetired(keys.Backup) {
		remaining.Backup = PublicKey{}
	}
	if isRetired(keys.Current) {
		remaining = Keys{Current: remaining.Backup}
	}
	if !remaining.Current.isSet() {
		return Keys{}, ErrNoTrustedKey
	}
	return remaining, nil
}

// signer rend la clé dont l'identifiant est id, et si c'est la secours.
func (keys Keys) signer(id []byte) (PublicKey, bool, error) {
	switch {
	case bytes.Equal(id, keys.Current.id[:]):
		return keys.Current, false, nil
	case keys.HasBackup() && bytes.Equal(id, keys.Backup.id[:]):
		return keys.Backup, true, nil
	}
	return PublicKey{}, false, ErrWrongKey
}
