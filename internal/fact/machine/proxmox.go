package machine

import (
	"path/filepath"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// Les droits proxmox.power et proxmox.snapshot s'appuient sur un jeton
// Proxmox local, dans l'état de l'agent ; le serveur n'en voit jamais le
// secret. « agent proxmox-token » le pose, « agent revoke » le retire avec
// le dernier des deux droits : ce qu'ils créent et retirent dans Proxmox
// s'écrit ici, une seule fois.

// ProxmoxLocalAPI est l'API que l'agent appelle : celle de son propre hôte,
// sur la boucle locale.
const ProxmoxLocalAPI = "https://127.0.0.1:8006"

const (
	// ProxmoxTokenCommand est le mot de « agent proxmox-token ».
	ProxmoxTokenCommand = "proxmox-token" // #nosec G101 -- le mot d'une commande, pas un secret.
	// ProxmoxRole est le rôle réduit du jeton, ProxmoxUser le compte qui ne
	// sert qu'à lui, ProxmoxTokenName le nom du jeton sous ce compte.
	ProxmoxRole      = brand.ProductName + "Agent"
	ProxmoxUser      = brand.AgentAccount + "@pve"
	ProxmoxTokenName = "agent"
	// ProxmoxTokenID est l'identifiant complet du jeton, tel que Proxmox le
	// nomme.
	ProxmoxTokenID = ProxmoxUser + "!" + ProxmoxTokenName
	// ProxmoxACLPath : le rôle vaut sur les invités, pas sur toute la grappe.
	ProxmoxACLPath = "/vms"
)

// ProxmoxRolePrivileges sont les privilèges du rôle, et eux seuls : démarrer
// et arrêter (VM.PowerMgmt), les instantanés (VM.Snapshot), et VM.Audit, en
// lecture seule, que l'API exige pour lire l'état d'un invité et ses
// instantanés avant d'agir.
func ProxmoxRolePrivileges() []string {
	return []string{"VM.Audit", "VM.PowerMgmt", "VM.Snapshot"}
}

// ProxmoxTokenFile est le fichier du jeton dans l'état de l'agent.
func ProxmoxTokenFile(stateDir string) string {
	return filepath.Join(stateDir, brand.AgentProxmoxFile)
}

// ProxmoxTokenLine est la commande qui pose le jeton, en root sur l'hôte.
func ProxmoxTokenLine() string {
	return agentpolicy.AgentLine(ProxmoxTokenCommand)
}
