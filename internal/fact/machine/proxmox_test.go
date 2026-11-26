package machine

import (
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
)

func TestProxmoxRights_TakeNoScopeAndAreRoundTripped(t *testing.T) {
	parsed, err := agentpolicy.ParseCapabilities("proxmox.snapshot,proxmox.power")
	if err != nil {
		t.Fatal(err)
	}
	if text := agentpolicy.FormatCapabilities(parsed); text != "observe,proxmox.power,proxmox.snapshot" {
		t.Fatalf("%q", text)
	}
	if _, err := agentpolicy.ParseCapabilities("proxmox.power=/srv"); err == nil {
		t.Error("a scope was accepted")
	}
}
