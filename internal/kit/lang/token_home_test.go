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
		compose := readDoc(t, "../../../docs/installation/compose.mcp-maison.yml")
		if strings.Contains(withoutComments(compose), "network_mode") {
			t.Error("compose.mcp-maison.yml sets network_mode")
		}
		if !strings.Contains(compose, "host.docker.internal:host-gateway") {
			t.Error("compose.mcp-maison.yml does not reach Kagu through host-gateway")
		}
	})
	t.Run("the install guide shows no host network for mcp-maison", func(t *testing.T) {
		guide := readDoc(t, "../../../docs/installation.md")
		start := strings.Index(guide, "## Brancher un agent IA")
		if start < 0 {
			t.Fatal("docs/installation.md has no « ## Brancher un agent IA » section")
		}
		end := strings.Index(guide[start:], "\n## ")
		section := guide[start:]
		if end > 0 {
			section = guide[start : start+end]
		}
		if strings.Contains(section, "network_mode") {
			t.Error("section « Brancher un agent IA » mentions network_mode")
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

// R-GESTE-9, la part de ce chantier : un jeton sert un seul client, et la
// page le dit. La portée sur tous les environnements sauf le socle et le
// niveau 1 relèvent d'étapes à venir.
func TestR_GESTE_9(t *testing.T) {
	catalogs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	wants := map[Code]string{"fr": "un seul client", "en": "single client"}
	for _, code := range Codes() {
		want, ok := wants[code]
		if !ok {
			t.Fatalf("no expectation for language %s", code)
		}
		if text := catalogs[code].Get("api_token.home"); !strings.Contains(text, want) {
			t.Errorf("%s: api_token.home lacks %q", code, want)
		}
	}
	guide := readDoc(t, "../../../docs/installation.md")
	if !strings.Contains(guide, "Le jeton ne sert qu'à **mcp-maison**") {
		t.Error("installation.md does not say the token serves mcp-maison alone")
	}
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
