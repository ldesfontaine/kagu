package machine

import (
	"os"
	"strings"
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

// R-DROIT-8 (#902) : la ligne qui pose le jeton Proxmox local est une
// commande de l'agent, sans -yes ni enchaînement, et la doc d'installation,
// qui vient du dépôt, la porte dans sa section « Jeton Proxmox local ».
func TestR_DROIT_8_T0409b_DocsCarryTheProxmoxTokenLine(t *testing.T) {
	line := ProxmoxTokenLine()
	if line != "sudo kagu agent proxmox-token" {
		t.Fatalf("line %q", line)
	}
	content, err := os.ReadFile("../../../docs/installation.md")
	if err != nil {
		t.Fatal(err)
	}
	guide := string(content)
	heading := strings.Index(guide, "### Jeton Proxmox local")
	if heading < 0 {
		t.Fatal("docs/installation.md has no « Jeton Proxmox local » section")
	}
	section := guide[heading:]
	if end := strings.Index(section[1:], "\n#"); end > 0 {
		section = section[:end+1]
	}
	if !strings.Contains(section, "\n"+line+"\n") {
		t.Fatalf("the section does not carry %q:\n%s", line, section)
	}
}
