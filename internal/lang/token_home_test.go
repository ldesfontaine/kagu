package lang

import (
	"os"
	"strings"
	"testing"
)

// R-G2-8 : mcp-maison tourne sans network_mode: host, et la page « Nouveau
// jeton » dit où vit le jeton, pour un client local et pour mcp-maison.
func TestR_G2_8(t *testing.T) {
	t.Run("the compose example does not share the host network", func(t *testing.T) {
		compose := readDoc(t, "../../docs/installation/compose.mcp-maison.yml")
		if strings.Contains(withoutComments(compose), "network_mode") {
			t.Error("compose.mcp-maison.yml sets network_mode")
		}
		if !strings.Contains(compose, "host.docker.internal:host-gateway") {
			t.Error("compose.mcp-maison.yml does not reach openCloud through host-gateway")
		}
	})
	t.Run("the install guide shows no host network for mcp-maison", func(t *testing.T) {
		guide := readDoc(t, "../../docs/installation.md")
		start := strings.Index(guide, "## Brancher un agent IA")
		end := strings.Index(guide[start:], "\n## ")
		section := guide[start:]
		if end > 0 {
			section = guide[start : start+end]
		}
		if start < 0 || strings.Contains(section, "network_mode") {
			t.Errorf("section « Brancher un agent IA » found=%v mentions network_mode", start >= 0)
		}
	})
	t.Run("the token page says where the token lives", func(t *testing.T) {
		catalogs, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		for _, code := range Codes() {
			text := catalogs[code].Get("api_token.home")
			for _, want := range []string{"mcp-maison", ".env", "Claude Code"} {
				if !strings.Contains(text, want) {
					t.Errorf("%s: api_token.home lacks %q", code, want)
				}
			}
		}
	})
}

func readDoc(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func withoutComments(yaml string) string {
	var kept []string
	for _, line := range strings.Split(yaml, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}
