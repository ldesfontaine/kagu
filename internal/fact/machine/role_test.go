package machine

import (
	"errors"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
)

func TestParseRole_EmptyIsGenericAndUnknownIsRefused(t *testing.T) {
	role, err := ParseRole("")
	if err != nil || role != RoleGeneric {
		t.Fatalf("ParseRole(\"\") = %q, %v", role, err)
	}
	for _, known := range Roles() {
		if got, err := ParseRole(string(known)); err != nil || got != known {
			t.Errorf("ParseRole(%q) = %q, %v", known, got, err)
		}
	}
	if _, err := ParseRole("kubernetes"); !errors.Is(err, ErrRoleUnknown) {
		t.Fatalf("un rôle inconnu doit être refusé, reçu %v", err)
	}
}

func TestRolePreset_IsAValidListForEveryRole(t *testing.T) {
	for _, role := range Roles() {
		preset := RolePreset(role)
		normalized, err := agentpolicy.NormalizeCapabilities(preset)
		if err != nil {
			t.Fatalf("%s : préréglage refusé : %v", role, err)
		}
		if !agentpolicy.SameCapabilities(normalized[1:], preset) {
			t.Errorf("%s : le préréglage doit déjà être rangé, observe exclu", role)
		}
	}
}

func TestRolePreset_AProxmoxMachineIsOfferedTheProxmoxRights(t *testing.T) {
	if !agentpolicy.HasCapability(RolePreset(RoleProxmox), agentpolicy.CapabilityProxmoxPower) || agentpolicy.HasCapability(RolePreset(RoleGeneric), agentpolicy.CapabilityProxmoxPower) {
		t.Fatal("seul le rôle proxmox coche les droits proxmox.*")
	}
}

// restic.verify n'est jamais donné par défaut.
func TestRolePreset_NeverGrantsResticVerify(t *testing.T) {
	for _, role := range Roles() {
		if agentpolicy.HasCapability(RolePreset(role), agentpolicy.CapabilityResticVerify) {
			t.Errorf("role %s grants restic.verify", role)
		}
	}
}
