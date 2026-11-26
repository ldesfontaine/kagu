package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// R-NETMAP-DEMO : les jeux de test, les parcours navigateur et les documents
// sont miroités en public ; aucun ne reprend le plan d'une vraie installation
// (adresses 10.10.x.y, domaine, numéros de VM). Les données sont inventées :
// plages de documentation, 192.168.x, numéros neutres.
//
// Aucune exception : une entrée datée et validée par Lucas irait dans
// privateExceptions, avec sa raison.
var privateExceptions = map[string]string{}

var privatePlan = regexp.MustCompile(
	`(?:^|[^\d.])10\.10\.` +
		`|ldesfontaine\.com` +
		`|(?:^|[^\d.])(?:1120|1121|5010|5011|5012|5013|5014|5015|6010|6011|7010|7011|8010)(?:$|[^\d])`)

// privatePlanScanned dit si le fichier est servi au public avec ses données :
// testdata/, parcours navigateur, documents, tests Go et tests du front.
func privatePlanScanned(relative string) bool {
	slashed := filepath.ToSlash(relative)
	if slashed == "internal/edge/server/fixtures_private_test.go" {
		return false
	}
	return strings.Contains("/"+slashed, "/testdata/") ||
		strings.HasPrefix(slashed, "web/e2e/") ||
		strings.HasPrefix(slashed, "docs/") ||
		strings.HasSuffix(slashed, "_test.go") ||
		strings.HasSuffix(slashed, ".test.ts") ||
		strings.HasSuffix(slashed, ".test.tsx")
}

// privatePlanLines rend les lignes qui citent le plan privé.
func privatePlanLines(content string) []string {
	var found []string
	for _, line := range strings.Split(content, "\n") {
		if privatePlan.MatchString(line) {
			found = append(found, strings.TrimSpace(line))
		}
	}
	return found
}

func privatePlanFaults(t *testing.T, root string) []string {
	t.Helper()
	var faults []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "dist", "test-results", "playwright-report":
				return filepath.SkipDir
			}
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		if !privatePlanScanned(relative) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.IndexByte(string(content), 0) >= 0 {
			return nil // image ou binaire : aucune ligne à lire
		}
		if _, excepted := privateExceptions[filepath.ToSlash(relative)]; excepted {
			return nil
		}
		for _, line := range privatePlanLines(string(content)) {
			faults = append(faults, filepath.ToSlash(relative)+" : "+line)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return faults
}

func TestR_NETMAPDEMO_NoRealInstallationInPublicFixtures(t *testing.T) {
	for _, fault := range privatePlanFaults(t, moduleRoot()) {
		t.Errorf("le plan d'une vraie installation : %.160s", fault)
	}
}

func TestR_NETMAPDEMO_GuardCatchesItsFault(t *testing.T) {
	for name, line := range map[string]string{
		"private address":  `"address": "10.10.50.14"`,
		"private domain":   `https://pve.ldesfontaine.com`,
		"vm number":        `VM 5012 sur pve`,
		"vm number at end": `selector: "5010,5012"`,
		"vm number in id":  `pve-vm-6010-20261024`,
	} {
		if len(privatePlanLines(line)) == 0 {
			t.Errorf("%s : %q aurait dû être refusé", name, line)
		}
	}
	for name, line := range map[string]string{
		"documentation address": `"address": "192.0.2.14"`,
		"neutral vm number":     `VM 312 sur pve`,
		"longer number":         `size 150100`,
		"version":               `v110.10.1`,
		"decimal":               `1.5012`,
	} {
		if got := privatePlanLines(line); len(got) != 0 {
			t.Errorf("%s : %q refusé à tort", name, line)
		}
	}
}
