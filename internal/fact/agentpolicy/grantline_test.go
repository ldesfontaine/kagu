package agentpolicy

import (
	"testing"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// R-DROIT-8 (E03-07) : la ligne d'un droit manquant est constante, sans nom
// de droit.
func TestR_A3_15_E03_07_ThePendingLineIsConstant(t *testing.T) {
	if got, want := PendingLine(), "sudo "+brand.Command+" agent grant --pending"; got != want {
		t.Fatalf("PendingLine() = %q, want %q", got, want)
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
		if line := AgentLine("grant", CapabilityFilesWrite+ScopeSeparator+value); line != "" {
			t.Errorf("AgentLine(grant files.write, %q) = %q, want no line", value, line)
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
		"312",
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

// R-DROIT-8 (ARB-1) : aucune ligne servie ne porte -yes, sous aucune forme,
// pas même cachée dans une valeur : elle sauterait la question [o/N]. Un
// mot qui contient « yes » sans être le drapeau passe.
func TestR_DROIT_8_AgentLineRefusesYes(t *testing.T) {
	for _, words := range [][]string{
		{"grant", "--yes", "docker.deploy"},
		{"grant", "-yes", "docker.deploy"},
		{"grant", "--yes=true", "docker.deploy"},
		{"grant", "-yes=1", "docker.deploy"},
		{"policy", "migrate", "--yes=false"},
		{"trust", "add", "backup.guest", "312 --yes"},
		{"grant", "--set", "manage -yes"},
	} {
		if line := AgentLine(words...); line != "" {
			t.Errorf("AgentLine(%q) = %q, want no line", words, line)
		}
	}
	for _, words := range [][]string{{"trust", "add", "backup.guest", "yes"}, {"grant", "--pending"}, {"grant", "--yesterday"}} {
		if line := AgentLine(words...); line == "" {
			t.Errorf("AgentLine(%q) refused a line without -yes", words)
		}
	}
}
