package machine

import (
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// La porte vzdump de backup.produce=proxmox-vzdump (décision de Lucas du
// 26/11/2026, A5) : une socket de root, ouverte au groupe de l'agent, et une
// unité de root par connexion qui lit une seule demande de forme fermée et
// lance vzdump. L'agent garde son unité durcie : ni sudo, ni produce.conf.
// « agent grant » la pose si le droit est accordé et que vzdump existe,
// « revoke » la retire ; T14-02 la remplace par la porte générale. Les textes
// vivent ici, une seule fois.

// VzdumpBinary est vzdump, que la porte lance et dont grant vérifie la
// présence avant de la poser.
const VzdumpBinary = "/usr/bin/vzdump"

// UnitDir est le dossier des unités que grant et setup posent.
const UnitDir = "/etc/systemd/system"

// Les deux unités de la porte, la socket et son modèle par connexion.
const (
	VzdumpGateSocketUnit  = brand.ID + "-vzdump.socket"
	VzdumpGateServiceUnit = brand.ID + "-vzdump@.service"
)

// Les commandes du binaire : la porte, que le lanceur stable sert en root
// pour une connexion, et le client que restic lance sous le compte de
// l'agent (« agent vzdump-stream <invité> », --stdin-from-command).
const (
	VzdumpGateCommand   = "vzdump-gate"
	VzdumpStreamCommand = "vzdump-stream"
)

// La demande que la porte accepte : « <invité> <compression> », sur une
// ligne. Rien d'autre ne se dit : aucune option de vzdump ne passe.
const (
	VzdumpCompressZstd = "zstd"
	VzdumpCompressNone = "0"
)

// VzdumpGateCompressions est la liste fermée des compressions que la porte
// accepte : zstd pour une archive envoyée au serveur, rien pour restic, qui
// compresse lui-même.
func VzdumpGateCompressions() []string {
	return []string{VzdumpCompressZstd, VzdumpCompressNone}
}

// VzdumpArguments rend ce que la porte passe à vzdump, après son nom : les
// options sont fixées ici, l'invité et la compression jugés avant.
func VzdumpArguments(guest, compress string) []string {
	return []string{guest, "--mode", "snapshot", "--compress", compress, "--stdout", "--quiet", "1"}
}

// vzdumpGateConnections : deux sauvegardes au plus en même temps.
const vzdumpGateConnections = "2"

// VzdumpGateSocketLines est la socket de la porte : à root et au groupe
// du compte de l'agent (group), fermée aux autres.
func VzdumpGateSocketLines(group string) []string {
	return []string{
		"[Unit]",
		"Description=" + brand.ProductName + " (porte vzdump)",
		"Documentation=" + brand.InstallDocURL,
		"",
		"[Socket]",
		"ListenStream=" + brand.VzdumpGateSocket,
		"SocketUser=root",
		"SocketGroup=" + group,
		"SocketMode=0660",
		"Accept=yes",
		"MaxConnections=" + vzdumpGateConnections,
		"",
		"[Install]",
		"WantedBy=sockets.target",
	}
}

// VzdumpGateServiceLines est l'unité d'une connexion : root, sans bac à
// sable (vzdump voit les stockages, /run/qemu-server, ses journaux). Elle
// lance le lanceur stable, la copie du binaire que root a posée et que
// l'agent ne remplace jamais : jamais bin/ de l'état de l'agent.
func VzdumpGateServiceLines() []string {
	return []string{
		"[Unit]",
		"Description=" + brand.ProductName + " (porte vzdump, une demande)",
		"Documentation=" + brand.InstallDocURL,
		"",
		"[Service]",
		"ExecStart=" + brand.AgentGuardPath + " " + VzdumpGateCommand,
		"StandardInput=socket",
		"StandardOutput=socket",
		"StandardError=journal",
		"RuntimeMaxSec=2h",
	}
}

// Les restes de la préparation d'avant la porte (règle sudo, script de root,
// drop-in qui levait NoNewPrivileges) : grant les retire là où il les trouve.
const (
	LegacySudoersFile   = "/etc/sudoers.d/" + brand.AgentAccount
	LegacyVzdumpScript  = "/usr/local/sbin/" + brand.ID + "-vzdump"
	LegacyProduceDropIn = UnitDropInDir + "/produce.conf"
)

// LegacyProducePreparation rend ces restes, dans l'ordre où grant les retire :
// la règle d'abord, qui ouvrait root.
func LegacyProducePreparation() []string {
	return []string{LegacySudoersFile, LegacyVzdumpScript, LegacyProduceDropIn}
}
