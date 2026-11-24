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
		"/srv `id`",
		"/srv & id",
		"/srv > /etc/passwd",
		"/srv < /etc/shadow",
		"/srv\x1b[2J",
		"/srv\tid",
		"/srv\x00id",
	}
	for _, value := range hostile {
		if line := GrantLine(CapabilityFilesWrite, value); line != "" {
			t.Errorf("GrantLine(files.write, %q) = %q, want no line", value, line)
		}
		if line := AgentLine("trust", "add", "backup.guest", value); line != "" {
			t.Errorf("AgentLine(trust add, %q) = %q, want no line", value, line)
		}
	}
}

// Les valeurs réelles des ancres et d'un droit borné passent : le refus ne
// mord que sur ce qui enchaîne ou cache.
func TestAgentLine_KeepsTheRealValues(t *testing.T) {
	values := []string{
		"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
		"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		"5012",
		"/srv/restore",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	for _, value := range values {
		if line := AgentLine("trust", "add", "backup.guest", value); line != "sudo "+brand.Command+" agent trust add backup.guest "+value {
			t.Errorf("AgentLine refused the real value %q: %q", value, line)
		}
	}
}

func TestAgentLine_DropsEmptyWords(t *testing.T) {
	if got, want := AgentLine("trust", "list", "", ""), "sudo "+brand.Command+" agent trust list"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
