// Package agentpolicy porte ce que root permet à l'agent d'une machine
// (fiche A3) : les seuls noms de droits du dépôt, leur forme texte, leurs
// jeux et leurs groupes, la politique et le verdict « l'agent peut-il ce
// droit ? » (Fit). Il ne lit aucun fichier.
package agentpolicy

import "slices"

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

// knownRight est un droit que la politique connaît : son groupe, et s'il ne
// se lit que dans la politique (R-A3-10).
type knownRight struct {
	name       string
	group      Group
	policyOnly bool
}

// knownRights est la seule liste des droits, dans l'ordre où ils
// s'affichent ; un droit nouveau y entre avec son groupe.
var knownRights = []knownRight{
	{name: CapabilityObserve, group: GroupSee},
	{name: CapabilityProbeLAN, group: GroupSee},
	{name: CapabilityObserveEnv, group: GroupSee},
	{name: CapabilityAgentUpdate, group: GroupDeploy},
	{name: CapabilityDockerDeploy, group: GroupDeploy},
	{name: CapabilityDockerUpdate, group: GroupDeploy},
	{name: CapabilityBackupReceive, group: GroupBackup},
	{name: CapabilityBackupProduce, group: GroupBackup},
	{name: CapabilityFilesWrite, group: GroupDeploy},
	{name: CapabilityProxmoxPower, group: GroupDeploy},
	{name: CapabilityProxmoxSnapshot, group: GroupDeploy},
	{name: CapabilityResticTarget, group: GroupBackup},
	{name: CapabilityResticProduce, group: GroupBackup},
	{name: CapabilityResticDocker, group: GroupBackup},
	{name: CapabilityResticVerify, group: GroupBackup},
	{name: CapabilityResticBrowse, group: GroupBackup},
	{name: CapabilityResticRestore, group: GroupBackup},
	{name: CapabilityTerminalContainer, group: GroupEnter, policyOnly: true},
	{name: CapabilityTerminalHost, group: GroupEnter, policyOnly: true},
	{name: CapabilityServiceFree, group: GroupDeploy, policyOnly: true},
	{name: CapabilityNetworkPrivate, group: GroupNetwork, policyOnly: true},
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
		if !known.policyOnly {
			names = append(names, known.name)
		}
	}
	return names
}

// Set est un jeu de droits (R-A3-7) : trois, et seulement trois. Un jeu est
// un raccourci, un droit se pose aussi seul.
type Set string

const (
	SetObserve Set = "observe"
	SetManage  Set = "manage"
	SetRoot    Set = "root"
)

// SetRight est un droit qu'un jeu pose, avec sa valeur. ServicesRoot : la
// valeur est la racine des services de la machine, connue à la pose.
type SetRight struct {
	Name         string
	Value        string
	ServicesRoot bool
}

// setRights est ce qu'un jeu pose partout, et ce qu'il pose en plus sur un
// hôte Proxmox.
type setRights struct {
	everywhere []SetRight
	onProxmox  []SetRight
}

// Gérer reprend Observer, Gérer en root reprend Gérer. Les droits hors jeu
// (observe.env, backup.receive, restic.target, restic.verify, restic.browse)
// se posent un par un.
var (
	observeRights = []SetRight{{Name: CapabilityObserve}, {Name: CapabilityProbeLAN}}
	manageRights  = slices.Concat(observeRights, []SetRight{
		{Name: CapabilityAgentUpdate}, {Name: CapabilityDockerDeploy}, {Name: CapabilityDockerUpdate},
		{Name: CapabilityResticProduce}, {Name: CapabilityResticDocker}, {Name: CapabilityResticRestore},
		{Name: CapabilityFilesWrite, ServicesRoot: true}, {Name: CapabilityTerminalContainer},
	})
	manageProxmoxRights = []SetRight{{Name: CapabilityProxmoxPower}, {Name: CapabilityProxmoxSnapshot}}
	rootRights          = slices.Concat(manageRights, []SetRight{
		{Name: CapabilityTerminalHost, Value: "root"}, {Name: CapabilityServiceFree}, {Name: CapabilityNetworkPrivate, Value: "1"},
	})
	rootProxmoxRights = slices.Concat(manageProxmoxRights, []SetRight{{Name: CapabilityBackupProduce, Value: ProducerProxmoxVzdump}})
)

// sets : les jeux, figés par TestR_A3_7_ThreeSetsAndOnlyThree. grant --set
// les lira (T03-04).
var sets = map[Set]setRights{
	SetObserve: {everywhere: observeRights},
	SetManage:  {everywhere: manageRights, onProxmox: manageProxmoxRights},
	SetRoot:    {everywhere: rootRights, onProxmox: rootProxmoxRights},
}
