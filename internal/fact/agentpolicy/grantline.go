package agentpolicy

import (
	"encoding/base64"
	"strings"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/untrusted"
)

// Ce que le shell lirait autrement qu'un mot dans une ligne que root colle
// (R-A3-15) : un enchaînement (« ; », « | », « & »), une substitution (« $( »,
// l'accent grave) ou une redirection (« < », « > »). Les retours à la ligne et
// les autres caractères de contrôle, untrusted.HasControl les refuse.
var lineChains = []string{";", "|", "&", "$(", "`", "<", ">"}

// PendingLine écrit la ligne que l'interface donne pour un droit manquant,
// la même pour tous : « sudo kagu agent grant --pending ». Rien n'y vient
// du serveur, qui sert l'écran : la commande pose les droits que l'agent a
// lui-même refusés, après un « o » tapé au clavier (R-DROIT-8, R-A3-15).
func PendingLine() string {
	return AgentLine("grant", "--pending")
}

// GrantSetLine écrit la ligne qui pose un jeu (R-A3-7) :
// « sudo kagu agent grant --set manage ».
func GrantSetLine(set Set) string {
	return AgentLine("grant", "--set", string(set))
}

// RevokeLine écrit la ligne qui retire ces droits : observe ne se retire pas
// et n'y entre pas. Vide quand il ne reste rien à retirer.
func RevokeLine(names []string) string {
	words := []string{"revoke"}
	for _, name := range names {
		if revocable(name) {
			words = append(words, name)
		}
	}
	if len(words) == 1 {
		return ""
	}
	return AgentLine(words...)
}

// TrustServerKey est le nom que « agent trust » donne à la clé du serveur, à
// côté des types d'ancre.
const TrustServerKey = "server-key"

// ServerKeyLine écrit la ligne qui remplace la clé du serveur acceptée par
// celle-ci (R-A3-14) : toujours « trust set », jamais un ajout (N-M2).
func ServerKeyLine(key []byte) string {
	return AgentLine("trust", "set", TrustServerKey, base64.StdEncoding.EncodeToString(key))
}

// MigrateLine écrit la ligne qui recopie dans la politique ce
// qu'identity.json porte encore (R-A3-16).
func MigrateLine() string {
	return AgentLine("policy", "migrate")
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
