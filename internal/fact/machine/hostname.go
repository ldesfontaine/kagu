package machine

import (
	"regexp"
	"strings"
)

// MaxHostnameLength : la borne d'un nom DNS entier (RFC 1123).
const MaxHostnameLength = 253

var hostLabelPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// IsHostname dit si le texte est un nom d'hôte RFC 1123 : des labels de 63
// caractères au plus (lettres, chiffres, tirets, ni début ni fin en tiret)
// séparés par des points, 253 octets au plus.
func IsHostname(host string) bool {
	if host == "" || len(host) > MaxHostnameLength {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if !hostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}
