package machine

import (
	"strings"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/shell"
)

// JoinLine est la ligne d'ajout d'une machine (R-B1-12) : le script de
// l'adresse des versions, jamais un script servi par le serveur, qui vérifie
// le binaire puis lance join avec le serveur, l'empreinte de sa clé et le
// jeu, en clair (R-DROIT-6). Jamais le jeton (R-B1-10) : il se colle en
// seconde ligne. Hors de l'adresse par défaut, le script reçoit celle de la
// configuration par sa variable.
func JoinLine(releasesURL, number, serverURL, serverKey string, set agentpolicy.Set) (string, error) {
	if !JoinReady(serverURL) {
		return "", ErrJoinNeedsDomain
	}
	base := strings.TrimRight(releasesURL, "/")
	runner := "sudo sh -s --"
	if base != brand.ReleaseBaseURL {
		runner = "sudo " + brand.EnvPrefix + "RELEASES=" + shell.Quote(base) + " sh -s --"
	}
	return "curl -fsSL " + shell.Quote(base+"/"+number+"/"+brand.ReleaseInstallScript) + " | " + runner +
		" join --server " + shell.Quote(serverURL) + " --server-key " + serverKey + " --rights " + string(set), nil
}

// JoinReady dit si le serveur a une adresse où une machine peut s'ajouter :
// publique, en https. Sans elle, l'écran grise « Ajouter une machine » et
// donne setup --domain (R-B1-13).
func JoinReady(serverURL string) bool {
	return strings.HasPrefix(serverURL, "https://")
}

// DomainLine est la commande qui donne un domaine au serveur.
func DomainLine() string {
	return "sudo " + brand.Command + " setup --domain"
}

// ReenrollLines arrêtent l'agent en place puis retirent son identité, avant
// la ligne d'ajout : deux commandes, l'une après l'autre, sans enchaînement
// (ARB-4). join ne remplace jamais une identité, il en tire une neuve quand
// elle manque.
func ReenrollLines() []string {
	return []string{
		"sudo systemctl stop " + brand.AgentUnit,
		"sudo rm -f " + brand.AgentStateDir + "/" + brand.AgentIdentityFile,
	}
}
