// Package untrusted juge le texte venu d'ailleurs (un pair, une API, le
// matériel) avant qu'il atteigne l'interface ou un journal. Une seule
// définition de ce qu'un tel texte ne peut pas porter : UTF-8 cassé,
// caractère de contrôle, caractère de sens d'écriture (bidi).
package untrusted

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// replacement remplace ce que Strip retire : le texte garde sa longueur en
// caractères, la perte se voit.
const replacement = '\ufffd'

// HasControl dit si le texte porte de l'UTF-8 invalide, un caractère de
// contrôle ou un caractère bidi. Le texte est alors refusé, pas réparé.
func HasControl(text string) bool {
	for offset := 0; offset < len(text); {
		character, width := utf8.DecodeRuneInString(text[offset:])
		if isRefused(character, width) {
			return true
		}
		offset += width
	}
	return false
}

// Strip rend le texte sans ce que HasControl refuse : chaque caractère
// refusé devient U+FFFD. Le booléen dit si quelque chose a été remplacé.
func Strip(text string) (string, bool) {
	if !HasControl(text) {
		return text, false
	}
	var clean strings.Builder
	for offset := 0; offset < len(text); {
		character, width := utf8.DecodeRuneInString(text[offset:])
		if isRefused(character, width) {
			character = replacement
		}
		clean.WriteRune(character)
		offset += width
	}
	return clean.String(), true
}

// Bound coupe le texte à limit octets, sur une frontière de caractère : un
// caractère n'est jamais coupé en deux.
func Bound(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := max(limit, 0)
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}

// isRefused juge un caractère lu par utf8.DecodeRuneInString : width vaut 1
// pour un octet invalide, que le décodeur rend comme RuneError.
func isRefused(character rune, width int) bool {
	if character == utf8.RuneError && width == 1 {
		return true
	}
	return unicode.IsControl(character) || isBidi(character)
}

// isBidi : les marques et les isolats qui changent le sens d'écriture, par
// lesquels un texte s'affiche autrement qu'il n'est écrit (Trojan Source).
func isBidi(character rune) bool {
	switch {
	case character == '\u061c', character == '\u200e', character == '\u200f':
		return true // marques de lecture (ALM, LRM, RLM)
	case character >= '\u202a' && character <= '\u202e':
		return true // plongements et dépassements (LRE à RLO), PDF
	case character >= '\u2066' && character <= '\u2069':
		return true // isolats (LRI, RLI, FSI), PDI
	}
	return false
}
