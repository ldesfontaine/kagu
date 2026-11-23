package verb

import (
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Les gestes de l'agent de l'hôte Proxmox. start et shutdown se défont l'un
// l'autre ; snapshot_delete défait snapshot, mais un instantané effacé ne
// revient pas : la suppression est de niveau 2, un jeton dépose une demande
// (R-A4-4). Aucun ne force : l'arrêt est toujours propre, et la suppression ne
// touche que les instantanés créés par ce produit (le serveur et l'agent le
// revérifient, le jeton n'y change rien).
func init() {
	Default.MustRegister(Verb{
		ID: "proxmox.vm.start", Route: "POST /api/machines/{id}/proxmox/guests/{vmid}/actions/start",
		Params: []string{"id", "vmid"}, Body: []string{}, Target: TargetMachine,
		Label: "api_token.verb_proxmox_vm_start", Summary: "api_token.verb_proxmox_vm_start_text", Reverse: "proxmox.vm.shutdown",
		Level: 1, Token: true, Order: agentwire.KindProxmoxStart, Right: agentpolicy.CapabilityProxmoxPower, Audit: audit.MachineProxmoxGuest,
	})
	Default.MustRegister(Verb{
		ID: "proxmox.vm.shutdown", Route: "POST /api/machines/{id}/proxmox/guests/{vmid}/actions/shutdown",
		Params: []string{"id", "vmid"}, Body: []string{}, Target: TargetMachine,
		Label: "api_token.verb_proxmox_vm_shutdown", Summary: "api_token.verb_proxmox_vm_shutdown_text", Reverse: "proxmox.vm.start",
		Level: 1, Token: true, Order: agentwire.KindProxmoxShutdown, Right: agentpolicy.CapabilityProxmoxPower, Audit: audit.MachineProxmoxGuest,
	})
	Default.MustRegister(Verb{
		ID: "proxmox.vm.snapshot", Route: "POST /api/machines/{id}/proxmox/guests/{vmid}/actions/snapshot",
		Params: []string{"id", "vmid"}, Body: []string{}, Target: TargetMachine,
		Label: "api_token.verb_proxmox_vm_snapshot", Summary: "api_token.verb_proxmox_vm_snapshot_text", Reverse: "proxmox.vm.snapshot_delete",
		Level: 1, Token: true, Order: agentwire.KindProxmoxSnapshot, Right: agentpolicy.CapabilityProxmoxSnapshot, Audit: audit.MachineProxmoxGuest,
	})
	Default.MustRegister(Verb{
		ID: "proxmox.vm.snapshot_delete", Route: "POST /api/machines/{id}/proxmox/guests/{vmid}/actions/snapshot-delete",
		Params: []string{"id", "vmid"}, Body: []string{"snapshot"}, Target: TargetMachine,
		Label: "api_token.verb_proxmox_vm_snapshot_delete", Summary: "api_token.verb_proxmox_vm_snapshot_delete_text",
		Level: 2, Token: true, Order: agentwire.KindProxmoxSnapshotDelete, Right: agentpolicy.CapabilityProxmoxSnapshot, Audit: audit.MachineProxmoxGuest,
	})
}
