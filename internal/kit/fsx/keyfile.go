package fsx

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// KeyFileRefusals : les refus propres à un fichier de clé, que chaque paquet
// déclare avec ses sentinelles. Reading préfixe une autre erreur de lecture.
type KeyFileRefusals struct {
	Missing error
	TooOpen error
	Invalid error
	Reading string
}

// ReadKeyFile lit un fichier de clé par ReadPrivate et traduit ses refus
// dans ceux de l'appelant : absent, lisible par d'autres comptes, trop long.
func ReadKeyFile(root *os.Root, name string, limit int64, refusals KeyFileRefusals) ([]byte, error) {
	content, err := ReadPrivate(root, name, limit)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, refusals.Missing
	case errors.Is(err, ErrTooOpen):
		return nil, fmt.Errorf("%w: %v", refusals.TooOpen, err)
	case errors.Is(err, ErrTooLarge):
		return nil, fmt.Errorf("%w: too long", refusals.Invalid)
	case err != nil:
		return nil, fmt.Errorf("%s: %w", refusals.Reading, err)
	}
	return content, nil
}
