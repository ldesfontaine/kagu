package agentpolicy

import (
	"strings"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/untrusted"
)

// Ce que le shell lirait autrement qu'un mot dans une ligne que root colle
// (R-A3-15) : un enchaînement (« ; », « | », « & »), une substitution (« $( »,
// l'accent grave) ou une redirection (« < », « > »). Les retours à la ligne et
// les autres caractères de contrôle, untrusted.HasControl les refuse.
var lineChains = []string{";", "|", "&", "$(", "`", "<", ">"}

// GrantLine écrit la ligne qui pose un droit sur la machine, telle que root la
// colle : « sudo opencloud agent grant docker.deploy », avec « =valeur » pour
// un droit borné. Vide si AgentLine la refuse.
func GrantLine(right, value string) string {
	granted := right
	if value != "" {
		granted += ScopeSeparator + value
	}
	return AgentLine("grant", granted)
}

// AgentLine écrit une commande de l'agent à lancer en root sur la machine :
// l'unique écriture des lignes que l'interface donne à coller (grant, trust).
// Le binaire est celui que root pose hors du dossier de l'agent, jamais
// bin/current (R-DROIT-10). Les mots vides tombent ; vide si la ligne
// enchaînerait une autre commande ou porterait un caractère de contrôle.
func AgentLine(words ...string) string {
	line := "sudo " + brand.Command + " agent"
	for _, word := range words {
		if word != "" {
			line += " " + word
		}
	}
	if untrusted.HasControl(line) {
		return ""
	}
	for _, chain := range lineChains {
		if strings.Contains(line, chain) {
			return ""
		}
	}
	return line
}
