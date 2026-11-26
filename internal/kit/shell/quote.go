// Package shell écrit une valeur dans une ligne de commande que l'opérateur
// colle ou que root lance.
package shell

import "strings"

// Quote entoure de guillemets simples ce qui en a besoin : un chemin avec une
// espace, un nom qui n'est pas qu'un mot, une adresse prise dans la
// configuration.
func Quote(value string) string {
	if value != "" && strings.IndexFunc(value, needsQuoting) < 0 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func needsQuoting(character rune) bool {
	switch {
	case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z', character >= '0' && character <= '9':
		return false
	case character == '/', character == '.', character == '-', character == '_', character == ':', character == '@', character == '+':
		return false
	}
	return true
}
