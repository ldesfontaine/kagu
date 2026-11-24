package machine

import (
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// Ce que la préparation d'une machine pose pour backup.produce, et que
// l'agent vérifie avant de s'en servir. Les textes vivent ici, une seule fois :
// la page du jeton les écrit, un test les relit, la documentation les cite.
// vzdump tourne sous systemd-run, donc hors du bac à sable de l'unité de
// l'agent (ProtectSystem=strict, PrivateTmp) : il voit /run/qemu-server, les
// journaux de vzdump et les stockages. La règle sudo ne nomme que ce script,
// mais vzdump accepte --script (un crochet lancé en root) : ce droit vaut root
// pour un agent compromis, comme le groupe docker.
const (
	VzdumpBinary     = "/usr/bin/vzdump"
	SystemdRunBinary = "/usr/bin/systemd-run"
	// sudoers.d, au nom du compte : un fichier par règle, qu'on retire seul.
	SudoersFile = "/etc/sudoers.d/" + brand.AgentAccount
	// La règle s'écrit d'abord ici, visudo la juge, puis mv la pose : sudo
	// ignore un fichier de sudoers.d dont le nom porte un point, donc une règle
	// à moitié écrite ou refusée par visudo ne vaut jamais rien.
	SudoersTempFile = "/etc/sudoers.d/." + brand.AgentAccount + ".tmp"
	// Le drop-in de l'unité : NoNewPrivileges=true interdit tout sudo, c'est le
	// seul desserrement que ce droit demande. « agent grant » ne le pose ni ne
	// le retire : ce qui demande root passera par la porte (A5, étape 14).
	ProduceDropInFile = UnitDropInDir + "/produce.conf"
	// Les archives en cours de production, dans l'état de l'agent.
	ProduceDir = brand.AgentStateDir + "/" + brand.AgentProduceDir
)

// VzdumpWrapperLines est le script de root, une ligne par élément. Aucune
// apostrophe : la préparation le passe à printf entre apostrophes.
func VzdumpWrapperLines() []string {
	return []string{
		"#!/bin/sh",
		"# " + brand.ProductName + " : vzdump hors du bac à sable de l agent, sur ordre de l agent.",
		"exec " + SystemdRunBinary + " --pipe --wait --collect --quiet " + VzdumpBinary + ` "$@"`,
	}
}

// SudoersRuleLines est la règle : le compte de l'agent lance le script, rien
// d'autre, sans mot de passe.
func SudoersRuleLines() []string {
	return []string{brand.AgentAccount + " ALL=(root) NOPASSWD: " + brand.VzdumpWrapperPath}
}

// ProduceDropInLines est le contenu du drop-in de l'unité.
func ProduceDropInLines() []string {
	return []string{"[Service]", "NoNewPrivileges=false"}
}
