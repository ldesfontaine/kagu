package shape

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/ldesfontaine/kagu/internal/kit/untrusted"
)

var (
	ErrLabelEmpty      = errors.New("label is empty")
	ErrLabelTooLong    = errors.New("label is too long")
	ErrLabelHasControl = errors.New("label carries a control character")
)

// Label juge un libellé libre (nom de sonde, de tâche, de jeton, de
// pare-feu) : espaces coupés, longueur comptée en caractères, aucun
// caractère de contrôle. L'appelant écrit le nom coupé, pas l'original.
func Label(text string, maxLength int) error {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return ErrLabelEmpty
	}
	if utf8.RuneCountInString(trimmed) > maxLength {
		return ErrLabelTooLong
	}
	if untrusted.HasControl(trimmed) {
		return ErrLabelHasControl
	}
	return nil
}
