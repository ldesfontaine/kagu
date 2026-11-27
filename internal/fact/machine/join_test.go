package machine

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// La ligne d'ajout lance le script de l'adresse des versions ; une adresse
// réglée ailleurs passe au script par sa variable, entre apostrophes. Sans
// https, pas de ligne.
func TestJoinLine_RunsTheScriptOfTheReleasesAddress(t *testing.T) {
	key := "SHA256:Zmh6rfhivXdsj8GLjp+OIAiXFIVu4jOzkCpZHQ1fKSU"
	line, err := JoinLine(brand.ReleaseBaseURL+"/", "v1.0.0", "https://kagu.exemple.fr", key, agentpolicy.SetManage)
	want := "curl -fsSL " + brand.ReleaseBaseURL + "/v1.0.0/" + brand.ReleaseInstallScript + " | sudo sh -s -- join --server https://kagu.exemple.fr --server-key " + key + " --rights manage"
	if err != nil || line != want {
		t.Fatalf("got %q %v\nwant %q", line, err, want)
	}
	mirrored, err := JoinLine("https://miroir.exemple.fr/kagu it's", "v1.0.0", "https://kagu.exemple.fr", key, agentpolicy.SetObserve)
	if err != nil || !strings.Contains(mirrored, "| sudo "+brand.EnvPrefix+`RELEASES='https://miroir.exemple.fr/kagu it'\''s' sh -s -- join`) {
		t.Fatalf("mirror: %q %v", mirrored, err)
	}
	for _, server := range []string{"", "http://kagu.exemple.fr"} {
		if _, err := JoinLine(brand.ReleaseBaseURL, "v1.0.0", server, key, agentpolicy.SetObserve); !errors.Is(err, ErrJoinNeedsDomain) {
			t.Errorf("%q: %v", server, err)
		}
	}
}

// R-B1-12 (ARB-4) : la doc d'installation, qui vient du dépôt et non du
// serveur, porte la forme attendue de la ligne d'ajout, une fois, dans la
// section « Coller une ligne de Kagu en root » : celle que JoinLine écrit
// avec l'adresse des versions par défaut, et le lanceur hors de cette adresse.
func TestR_B1_12_DocsCarryTheJoinLineForm(t *testing.T) {
	content, err := os.ReadFile("../../../docs/installation.md")
	if err != nil {
		t.Fatal(err)
	}
	guide := string(content)
	heading := strings.Index(guide, "#### Coller une ligne de Kagu en root")
	if heading < 0 {
		t.Fatal("docs/installation.md has no « Coller une ligne de Kagu en root » section")
	}
	section := guide[heading:]
	if end := strings.Index(section[1:], "\n#"); end > 0 {
		section = section[:end+1]
	}
	form, err := JoinLine(brand.ReleaseBaseURL, "vX.Y.Z", "https://kagu.example.org", "SHA256:…", agentpolicy.Set("<jeu>"))
	if err != nil {
		t.Fatal(err)
	}
	mirrored, err := JoinLine("<releases_url de config.toml>", "vX.Y.Z", "https://kagu.example.org", "SHA256:…", agentpolicy.SetObserve)
	if err != nil {
		t.Fatal(err)
	}
	_, runner, _ := strings.Cut(mirrored, " | ")
	runner, _, _ = strings.Cut(runner, " join ")
	for _, want := range []string{form, runner} {
		if strings.Count(guide, want) != 1 || !strings.Contains(section, want) {
			t.Errorf("docs/installation.md must carry %q once, in the section", want)
		}
	}
}
