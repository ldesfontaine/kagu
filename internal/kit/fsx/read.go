package fsx

import (
	"errors"
	"fmt"
	"io"
)

// ErrTooLarge : la source dépasse la borne de la lecture.
var ErrTooLarge = errors.New("more bytes than the limit")

// ReadLimited lit r jusqu'à limit octets. Un octet de plus rend ErrTooLarge,
// jamais un contenu tronqué : l'appelant traduit ce refus dans le sien.
func ReadLimited(r io.Reader, limit int64) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, limit)
	}
	return content, nil
}
