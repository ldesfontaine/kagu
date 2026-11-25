// Package agentpolicy porte ce que root permet à l'agent d'une machine
// (fiche A3) : les seuls noms de droits du dépôt, leur forme texte, leurs
// jeux et leurs groupes, la politique et le verdict « l'agent peut-il ce
// droit ? » (Fit). Il ne lit aucun fichier.
package agentpolicy

import (
	"slices"
	"time"
)

// Les droits d'un agent : cochés à l'émission du jeton, écrits par la ligne
// d'installation dans le fichier de l'agent, rapportés par lui à chaque
// ouverture de flux, et appliqués par l'agent : un ordre dont le droit n'est
// pas dans son fichier est refusé (agentwire.Spec.Right dit lequel). observe est
// toujours là. Les changer, c'est ré-enrôler avec d'autres droits.
// probe.lan et observe.env sont les seuls droits qu'aucun ordre n'exige : ce
// sont des bornes de l'observation, que l'agent applique à ses propres
// lectures. observe.env, refusé par défaut, ouvre la lecture de l'environnement
// des conteneurs (étude services-modèle §2.4) ; sans lui, l'agent ne le lit pas.
const (
	CapabilityObserve       = "observe"
	CapabilityProbeLAN      = "probe.lan"
	CapabilityObserveEnv    = "observe.env"
	CapabilityAgentUpdate   = "agent.update"
	CapabilityDockerDeploy  = "docker.deploy"
	CapabilityDockerUpdate  = "docker.update"
	CapabilityBackupReceive = "backup.receive"
	CapabilityBackupProduce = "backup.produce"
	CapabilityFilesWrite    = "files.write"
	// Les gestes sur les invités Proxmox, par le jeton local de l'agent de
	// l'hôte (décision 18) : démarrer et arrêter proprement ; créer et
	// supprimer ses propres instantanés.
	CapabilityProxmoxPower    = "proxmox.power"
	CapabilityProxmoxSnapshot = "proxmox.snapshot"
	// La cible restic : l'agent lance rest-server en écriture seule sur le
	// dossier des dépôts, le chemin du droit, et y applique la rétention
	// (restic.retain), jamais sous le plancher qu'il tient. La source : l'agent lance restic
	// vers une cible liée, sans chemin (le dossier d'un service est sous sa
	// racine, un invité passe par backup.produce).
	CapabilityResticTarget  = "restic.target"
	CapabilityResticProduce = "restic.produce"
	// Sauvegarder les volumes et les bases Docker d'un service : l'agent lit
	// un volume par le conteneur qui le monte (docker cp) et lance l'outil de
	// dump d'une base dans son conteneur (docker exec). Équivaut à la socket
	// Docker qu'il a déjà ; refusé par défaut, coché par machine. Il ne lit
	// jamais l'environnement du conteneur : le mot de passe de la base reste
	// dans le conteneur.
	CapabilityResticDocker = "restic.docker"
	// Vérifier les dépôts reçus : restic check, puis la relecture d'un
	// échantillon de fichiers de chaque dernier instantané. L'agent déchiffre
	// du contenu en mémoire, rien n'est écrit sur son disque ; il détient déjà
	// le mot de passe du dépôt pour la rétention, mais ce droit le dit en
	// clair. Demande restic.target. Refusé par défaut, coché par machine.
	CapabilityResticVerify = "restic.verify"
	// Parcourir les dépôts reçus : la cible lit les NOMS, tailles et dates des
	// fichiers d'un instantané et les rend à l'écran qui les demande (l'explorateur
	// de la page Sauvegardes). Rien du contenu, rien n'est écrit ni restauré ;
	// le serveur ne garde pas les noms. Demande restic.target. Refusé par
	// défaut, coché par machine : les noms de fichiers sont déjà une donnée.
	CapabilityResticBrowse = "restic.browse"
	// Restaurer sur la machine source un fichier ou un dossier d'un instantané,
	// À CÔTÉ de l'original (<chemin>.restaure-<horodatage>), jamais par-dessus et
	// sans rien supprimer. Le droit n'a pas de chemin : où l'agent peut écrire est
	// borné par files.write, que la destination doit couvrir (et par l'unité
	// systemd). Refusé par défaut, coché par machine.
	CapabilityResticRestore = "restic.restore"
	// Les droits qui ne se lisent que dans la politique (R-A3-10) : ni
	// identity.json ni -rights ne les acceptent. Un terminal dans un conteneur
	// (E4) ; un terminal sur la machine sous le compte nommé (A5), l'égal de
	// root au premier terminal ouvert (R-A3-12) ; un Compose à soi (D7) ; le
	// nombre de pairs du réseau privé que la machine accepte (E5).
	CapabilityTerminalContainer = "terminal.container"
	CapabilityTerminalHost      = "terminal.host"
	CapabilityServiceFree       = "service.free"
	CapabilityNetworkPrivate    = "network.private"
)

// Group est ce qu'un droit permet, tel que l'onglet Droits le groupe
// (R-A3-13) : cinq groupes, jamais une liste à plat de noms techniques.
type Group string

const (
	GroupSee     Group = "see"
	GroupDeploy  Group = "deploy"
	GroupBackup  Group = "backup"
	GroupEnter   Group = "enter"
	GroupNetwork Group = "network"
)

// knownRight est un droit que la politique connaît : son groupe, où il se
// lit (R-A3-10), la grammaire de sa valeur, la valeur d'un droit posé sans
// elle, la durée que « grant » lui donne quand rien n'est dit (zéro : sans
// échéance), la phrase de son risque, une clé des catalogues que « grant »
// imprime avant la question (R-A3-12), et ce qu'il demande au système
// (R-A3-8) : le groupe docker, ou la porte root (A5). opens : le droit que
// la ligne grant d'un groupe pas permis pose, un par groupe.
type knownRight struct {
	name        string
	group       Group
	opens       bool
	readable    readable
	value       valueGrammar
	bare        string
	term        time.Duration
	risk        string
	dockerGroup bool
	rootGate    bool
}

// readable dit où un droit se lit.
type readable int

const (
	// Partout : le jeton, identity.json, -rights, la politique.
	readEverywhere readable = iota
	// Dans la politique seule (R-A3-10).
	readInPolicy
)

// valueGrammar est la forme de la valeur d'un droit.
type valueGrammar int

const (
	valueNone valueGrammar = iota
	// Un chemin (backup.receive, restic.target).
	valueOnePath
	// Un à huit chemins (files.write).
	valuePaths
	// Un à quatre producteurs de la liste fermée (backup.produce).
	valueProducers
	// Un nom de compte Unix (terminal.host).
	valueAccount
	// Un nombre de pairs, de 1 à maxPrivatePeers (network.private).
	valuePeers
)

// hostTerminalTerm : un terminal sur la machine s'ouvre pour deux heures
// quand « grant » ne dit rien (R-E4-11, N-M6).
const hostTerminalTerm = 2 * time.Hour

// manageRisk : le groupe docker vaut root (R-A3-12, R-DROIT-7) ; « grant »
// le dit une fois, quel que soit le droit qui l'y met.
const manageRisk = "rights.manage_risk"

// knownRights est la seule liste des droits, dans l'ordre où ils
// s'affichent ; un droit nouveau y entre avec son groupe, où il se lit, la
// forme de sa valeur et ce qu'il demande au système (fiche A3, §5, « Ce que
// grant fait aussi »).
var knownRights = []knownRight{
	{name: CapabilityObserve, group: GroupSee, opens: true},
	{name: CapabilityProbeLAN, group: GroupSee},
	{name: CapabilityObserveEnv, group: GroupSee},
	{name: CapabilityAgentUpdate, group: GroupDeploy},
	{name: CapabilityDockerDeploy, group: GroupDeploy, opens: true, risk: manageRisk, dockerGroup: true},
	{name: CapabilityDockerUpdate, group: GroupDeploy, risk: manageRisk, dockerGroup: true},
	{name: CapabilityBackupReceive, group: GroupBackup, value: valueOnePath},
	{name: CapabilityBackupProduce, group: GroupBackup, value: valueProducers, rootGate: true},
	{name: CapabilityFilesWrite, group: GroupDeploy, value: valuePaths},
	{name: CapabilityProxmoxPower, group: GroupDeploy},
	{name: CapabilityProxmoxSnapshot, group: GroupDeploy},
	{name: CapabilityResticTarget, group: GroupBackup, value: valueOnePath},
	{name: CapabilityResticProduce, group: GroupBackup, opens: true},
	{name: CapabilityResticDocker, group: GroupBackup, risk: manageRisk, dockerGroup: true},
	{name: CapabilityResticVerify, group: GroupBackup},
	{name: CapabilityResticBrowse, group: GroupBackup},
	{name: CapabilityResticRestore, group: GroupBackup},
	{name: CapabilityTerminalContainer, group: GroupEnter, opens: true, readable: readInPolicy, risk: manageRisk, dockerGroup: true},
	{name: CapabilityTerminalHost, group: GroupEnter, readable: readInPolicy, value: valueAccount, bare: "root", term: hostTerminalTerm,
		risk: "rights.host_terminal_risk", rootGate: true},
	{name: CapabilityServiceFree, group: GroupDeploy, readable: readInPolicy, risk: manageRisk, dockerGroup: true},
	{name: CapabilityNetworkPrivate, group: GroupNetwork, opens: true, readable: readInPolicy, value: valuePeers, bare: "1", rootGate: true},
}

// knownRightOf rend le droit de ce nom ; faux pour un nom inconnu.
func knownRightOf(name string) (knownRight, bool) {
	index := slices.IndexFunc(knownRights, func(known knownRight) bool { return known.name == name })
	if index < 0 {
		return knownRight{}, false
	}
	return knownRights[index], true
}

// Notice est ce que « grant » dit d'un droit avant la question (R-A3-12,
// N-M6) : la phrase de son risque (une clé des catalogues, vide s'il n'en a
// pas) et, pour un droit qui nomme un compte et le pose sous celui par
// défaut, qu'un autre compte se choisit.
type Notice struct {
	RiskKey      string
	OtherAccount bool
}

// NoticeOf rend ce que « grant » dit d'un droit normalisé.
func NoticeOf(capability Capability) Notice {
	known, _ := knownRightOf(capability.Name)
	return Notice{RiskKey: known.risk, OtherAccount: known.value == valueAccount && slices.Equal(capability.Paths, []string{known.bare})}
}

// NeedsDockerGroup dit si un de ces droits met le compte de l'agent dans le
// groupe docker (R-A3-12) : docker.*, restic.docker, terminal.container,
// service.free.
func NeedsDockerGroup(rights []Capability) bool {
	return slices.ContainsFunc(rights, func(right Capability) bool {
		known, _ := knownRightOf(right.Name)
		return known.dockerGroup
	})
}

// RootGateRights rend ceux de ces droits qui passent par la porte root (A5) :
// terminal.host, network.private, backup.produce.
func RootGateRights(rights []Capability) []string {
	var names []string
	for _, right := range rights {
		if known, _ := knownRightOf(right.Name); known.rootGate {
			names = append(names, right.Name)
		}
	}
	return names
}

// Names rend tous les droits que la politique connaît, dans l'ordre où ils
// s'affichent.
func Names() []string {
	names := make([]string, 0, len(knownRights))
	for _, known := range knownRights {
		names = append(names, known.name)
	}
	return names
}

// CapabilityNames rend les droits qui se cochent à l'enrôlement et se lisent
// dans identity.json, dans l'ordre où ils s'affichent : chaque droit a son
// libellé dans les catalogues. Les droits de la politique seule n'y sont pas.
func CapabilityNames() []string {
	var names []string
	for _, known := range knownRights {
		if known.readable == readEverywhere {
			names = append(names, known.name)
		}
	}
	return names
}
