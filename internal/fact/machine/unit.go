package machine

import (
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// UnitFile est l'unité de l'agent, telle que la migration la modifie.
const UnitFile = UnitDir + "/" + brand.AgentUnit

// UnitDropInDir est le dossier des drop-ins de l'unité de l'agent ; systemd
// les additionne tous, dans l'ordre de leur nom.
const UnitDropInDir = UnitFile + ".d"

// RightsDropInFile est le drop-in qui autorise les dossiers où les droits de
// l'agent écrivent : l'unité n'écrit que dans son état (ProtectSystem=strict).
// « agent grant » l'écrit en entier et le retire quand plus rien ne s'écrit
// ailleurs ; un ReadWritePaths posé à la main dans un autre drop-in s'y
// ajoute, grant ne le voit pas.
const RightsDropInFile = UnitDropInDir + "/droits.conf"

// DockerGroup est le groupe dont la socket de Docker ouvre l'accès : il vaut
// root (R-DROIT-7).
const DockerGroup = "docker"

// DockerBinary est le programme docker que l'agent lance, et celui dont setup
// juge la présence avant de proposer d'installer Docker.
const DockerBinary = "/usr/bin/docker"

// RightFolder est un dossier où un droit écrit hors de l'état de l'agent :
// créé au nom du compte de l'agent, avec ce mode, et ouvert par l'unité
// (ReadWritePaths). Rights : les droits qui l'utilisent.
type RightFolder struct {
	Path   string
	Mode   fs.FileMode
	Rights []string
}

// RightFolders liste les dossiers des droits, chacun une fois, dans l'ordre
// des droits : la racine des services pour docker.deploy et docker.update, le
// dossier de backup.receive et celui de restic.target (0700 : ce sont des
// sauvegardes), ceux de files.write. Un dossier demandé par deux droits garde
// le mode du premier. La seule définition : la page du jeton l'écrit en
// lignes à coller, « agent grant » le pose (fiche A3, §5).
func RightFolders(capabilities []agentpolicy.Capability, servicesRoot string) []RightFolder {
	var folders []RightFolder
	add := func(path string, mode fs.FileMode, right string) {
		// Les droits viennent normalisés ; un chemin qui ne l'est pas ne
		// se crée pas en root.
		if !agentpolicy.ValidCapabilityPath(path) {
			return
		}
		for index := range folders {
			if folders[index].Path == path {
				if !slices.Contains(folders[index].Rights, right) {
					folders[index].Rights = append(folders[index].Rights, right)
				}
				return
			}
		}
		folders = append(folders, RightFolder{Path: path, Mode: mode, Rights: []string{right}})
	}
	for _, capability := range capabilities {
		switch capability.Name {
		case agentpolicy.CapabilityDockerDeploy, agentpolicy.CapabilityDockerUpdate:
			add(servicesRoot, 0o755, capability.Name)
		case agentpolicy.CapabilityBackupReceive, agentpolicy.CapabilityResticTarget:
			for _, path := range capability.Paths {
				add(path, 0o700, capability.Name)
			}
		case agentpolicy.CapabilityFilesWrite:
			for _, path := range capability.Paths {
				add(path, 0o755, capability.Name)
			}
		}
	}
	return folders
}

// UnderAccountFolder dit si path est sous l'état de l'agent ou sous un autre
// de ces dossiers (pas l'un d'eux) : un nom que le compte contrôle, où root
// n'agit jamais (install -d et chown suivent un lien).
func UnderAccountFolder(path string, folders []RightFolder) bool {
	under := func(folder string) bool { return strings.HasPrefix(path, folder+"/") }
	return under(brand.AgentStateDir) || slices.ContainsFunc(folders, func(folder RightFolder) bool { return under(folder.Path) })
}

// RightsDropInLines est le contenu de RightsDropInFile pour ces dossiers ;
// nil sans dossier : le drop-in n'a pas lieu d'être. Chaque chemin porte
// « - » : systemd refuse de démarrer une unité dont un ReadWritePaths manque,
// un dossier effacé ne doit pas arrêter l'agent (il le dira path_denied).
func RightsDropInLines(folders []RightFolder) []string {
	if len(folders) == 0 {
		return nil
	}
	paths := make([]string, 0, len(folders))
	for _, folder := range folders {
		paths = append(paths, "-"+folder.Path)
	}
	return []string{"[Service]", "ReadWritePaths=" + strings.Join(paths, " ")}
}

// UnitContent est le fichier d'une unité ou d'un drop-in : ses lignes, une
// fin de ligne après la dernière.
func UnitContent(lines []string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

// AgentUnitLines est l'unité de l'agent que la page d'installation donne à
// poser, sans les commentaires de docs/installation/kagu-agent.service :
// ce fichier reste le texte de référence, et un test échoue si les deux
// diffèrent.
func AgentUnitLines() []string {
	state := brand.AgentStateDir
	return []string{
		"[Unit]",
		"Description=" + brand.ProductName + " (agent)",
		"Documentation=" + brand.InstallDocURL,
		"After=network-online.target docker.service",
		"Wants=network-online.target",
		"",
		"[Service]",
		"Type=simple",
		"User=" + brand.AgentAccount,
		"Group=" + brand.AgentAccount,
		"ExecStart=" + brand.AgentGuardPath + " guard -state " + state + " agent -state " + state,
		"StateDirectory=" + path.Base(state),
		"StateDirectoryMode=0700",
		"Restart=on-failure",
		"RestartSec=10",
		"RestartPreventExitStatus=2",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ProtectHome=read-only",
		"PrivateTmp=true",
		"UMask=0077",
		"ProtectKernelTunables=true",
		"ProtectKernelModules=true",
		"ProtectKernelLogs=true",
		"ProtectControlGroups=true",
		"ProtectClock=true",
		"RestrictNamespaces=true",
		"RestrictRealtime=true",
		"RestrictSUIDSGID=true",
		"LockPersonality=true",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
		emptyBoundingSet,
		"AmbientCapabilities=",
		"SystemCallFilter=@system-service",
		"SystemCallErrorNumber=EPERM",
		"ProtectProc=invisible",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
	}
}
