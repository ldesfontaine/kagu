package server

import (
	"bytes"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// R-NETMAP-DEMO : le dépôt est miroité en public ; aucun fichier suivi ne
// reprend le plan d'une vraie installation (adresses, domaine, numéros de VM).
// Les données sont inventées : plages d'exemple, 192.168.x, example.org,
// numéros de VM de 100 à 199.
//
// Aucune exception sur le plan privé. Les adresses publiques que des tests
// exigent sont listées ici, avec leur raison.
var publicAddressExceptions = map[string]string{
	"8.8.8.8":        "résolveur public connu, utilisé par les tests de joignabilité",
	"9.9.9.9":        "résolveur public connu, utilisé par les tests de joignabilité",
	"93.184.216.34":  "adresse publique d'example.com, pour la sortie réseau",
	"64.0.0.0":       "borne d'une plage testée par le filtre du secret du mandataire",
	"126.0.0.0":      "borne d'une plage testée par le filtre du secret du mandataire",
	"128.0.0.0":      "borne d'une plage testée par le filtre du secret du mandataire",
	"172.15.255.255": "juste sous la plage privée 172.16.0.0/12, testée par la sortie réseau",
	"172.32.0.1":     "juste au-dessus de la plage privée 172.16.0.0/12, testée par la sortie réseau",
	"100.63.255.255": "juste sous la plage partagée 100.64.0.0/10, testée par la sortie réseau",
	"100.128.0.1":    "juste au-dessus de la plage partagée 100.64.0.0/10, testée par la sortie réseau",
}

var privatePlan = regexp.MustCompile(
	`(?:^|[^\d.])10\.10\.` +
		`|(?:^|[^\d.])10\.99\.0\.` +
		`|(?:^|[^\d.])172\.30\.0\.` +
		`|ldesfontaine\.com` +
		`|(?:^|[^\d.])(?:1120|1121|5010|5011|5012|5013|5014|5015|6010|6011|7010|7011|8010)(?:$|[^\d])`)

var dottedQuad = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)

var exampleRanges = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("100.64.0.0/10"), // plage partagée, non routée sur Internet
}

func isPublicAddress(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range exampleRanges {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func isWordOrDot(character byte) bool {
	return character == '.' || character == '_' || character >= '0' && character <= '9' ||
		character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
}

// foreignAddresses rend les adresses IPv4 publiques d'une ligne, hors plages
// d'exemple et hors exceptions. « v1.2.3.4 » ou « 1.2.3.4.5 » sont des versions.
func foreignAddresses(line string) []string {
	var found []string
	for _, span := range dottedQuad.FindAllStringIndex(line, -1) {
		start, end := span[0], span[1]
		if start > 0 && isWordOrDot(line[start-1]) {
			continue
		}
		if end < len(line) && (line[end] >= '0' && line[end] <= '9' || line[end] == '.' && end+1 < len(line) && line[end+1] >= '0' && line[end+1] <= '9') {
			continue
		}
		text := line[start:end]
		address, err := netip.ParseAddr(text)
		if err != nil || !isPublicAddress(address) {
			continue
		}
		if _, allowed := publicAddressExceptions[text]; !allowed {
			found = append(found, text)
		}
	}
	return found
}

// privatePlanLines rend les lignes qui citent le plan privé ou une adresse
// publique étrangère aux plages d'exemple.
func privatePlanLines(content string) []string {
	var found []string
	for _, line := range strings.Split(content, "\n") {
		if privatePlan.MatchString(line) || len(foreignAddresses(line)) > 0 {
			found = append(found, strings.TrimSpace(line))
		}
	}
	return found
}

// trackedFiles : tout ce que git suit, c'est-à-dire tout ce que le miroir publie.
func trackedFiles(t *testing.T, root string) []string {
	t.Helper()
	command := exec.Command("git", "ls-files", "-z")
	command.Dir = root
	listing, err := command.Output()
	if err != nil {
		t.Fatalf("git ls-files : %v", err)
	}
	return strings.Split(strings.TrimRight(string(listing), "\x00"), "\x00")
}

func privatePlanFaults(t *testing.T, root string) []string {
	t.Helper()
	var faults []string
	for _, relative := range trackedFiles(t, root) {
		if relative == "internal/edge/server/fixtures_private_test.go" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, relative)) // #nosec G304 G703 -- un fichier suivi du dépôt, sous sa racine.
		if err != nil {
			continue // lien ou fichier retiré de l'arbre : rien à lire
		}
		if bytes.IndexByte(content, 0) >= 0 {
			continue // image ou binaire : aucune ligne à lire
		}
		for _, line := range privatePlanLines(string(content)) {
			faults = append(faults, relative+" : "+line)
		}
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
		"docker network":   `ipv4_address: 172.30.0.2`,
		"private domain":   `https://ldesfontaine.com`,
		"vm number":        `VM 5012 sur pve`,
		"vm number at end": `selector: "5010,5012"`,
		"vm number in id":  `pve-vm-6010-20261024`,
		"public address":   `"address": "11.22.33.44"`,
		"public in a line": `proxmox_url_help = "par exemple https://11.22.33.44:8006"`,
		"toml line":        `reach_guests_help = "« 200 5012 »."`,
		"go comment":       `// La VM 5012 de pve, joignable en 11.22.33.44.`,
	} {
		if len(privatePlanLines(line)) == 0 {
			t.Errorf("%s : %q aurait dû être refusé", name, line)
		}
	}
	for name, line := range map[string]string{
		"documentation address": `"address": "192.0.2.14"`,
		"example domain":        `https://pve.example.org:8006`,
		"neutral vm number":     `VM 312 sur pve`,
		"longer number":         `size 150100`,
		"version":               `v110.10.1 puis v1.2.3.4`,
		"decimal":               `1.5012`,
		"private address":       `"address": "192.168.1.20"`,
		"shared range":          `100.64.0.1`,
		"known resolver":        `dns = "8.8.8.8"`,
		"five numbers":          `1.2.3.4.5`,
	} {
		if got := privatePlanLines(line); len(got) != 0 {
			t.Errorf("%s : %q refusé à tort", name, line)
		}
	}
}
