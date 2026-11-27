package machine

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

func TestGuardInstallLines_PutRootsCopyOutsideTheStateOfTheAccount(t *testing.T) {
	got := GuardInstallLines("/tmp/kagu")
	want := []string{
		"install -d -m 0755 -o root -g root /usr/local/lib/kagu-agent",
		"install -m 0755 -o root -g root /tmp/kagu /usr/local/lib/kagu-agent/kagu-guard",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s", strings.Join(got, "\n"))
	}
	for _, line := range got {
		// Ce que root pose n'est jamais sous l'état que le compte de l'agent écrit.
		if strings.Contains(line, "/var/lib/kagu-agent") || strings.Contains(line, "runuser") {
			t.Errorf("root acts under the state of the account: %q", line)
		}
	}
}

func TestGuardMigrationLines_AreTheExactLinesToPasteWithSudo(t *testing.T) {
	got := strings.Join(GuardMigrationLines("/tmp/kagu", "v0.0.2", false), "\n")
	want := strings.Join([]string{
		"sudo systemctl stop kagu-agent.service",
		"sudo install -d -m 0755 -o root -g root /usr/local/lib/kagu-agent",
		"sudo install -m 0755 -o root -g root /tmp/kagu /usr/local/lib/kagu-agent/kagu-guard",
		"sudo -u kagu-agent install -m 0755 /tmp/kagu /var/lib/kagu-agent/bin/kagu-v0.0.2",
		"sudo -u kagu-agent ln -sfn kagu-v0.0.2 /var/lib/kagu-agent/bin/current",
		"sudo sed -i 's|^ExecStart=/var/lib/kagu-agent/bin/current |ExecStart=/usr/local/lib/kagu-agent/kagu-guard guard -state /var/lib/kagu-agent |' /etc/systemd/system/kagu-agent.service",
		"systemctl cat kagu-agent.service | grep '^ExecStart='",
		"sudo systemctl daemon-reload",
		"sudo systemctl start kagu-agent.service",
	}, "\n")
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
	if !strings.HasSuffix(GuardMigrationText(brand.ReleaseBaseURL, "v0.0.2", false), got) {
		t.Fatal("the text does not end with the lines")
	}
	// Rien ne vient de l'opérateur ni du réseau, et rien ne lance l'agent en root.
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "sudo -u root") || strings.Contains(line, "su -c") || strings.Contains(line, "eval") || strings.Contains(line, "sh -c") {
			t.Errorf("a line hands a shell an input: %q", line)
		}
	}
}

// Sans sudo (un hôte Proxmox n'en a pas) : les mêmes lignes en root, le compte
// de l'agent pris par runuser. Aucune ne nomme sudo.
func TestGuardMigrationLines_RootVariantNeverNamesSudo(t *testing.T) {
	lines := GuardMigrationLines("/tmp/kagu", "v0.0.2", true)
	for _, line := range lines {
		if strings.Contains(line, "sudo") {
			t.Errorf("the root variant names sudo: %q", line)
		}
	}
	want := []string{
		"systemctl stop kagu-agent.service",
		"runuser -u kagu-agent -- install -m 0755 /tmp/kagu /var/lib/kagu-agent/bin/kagu-v0.0.2",
		"runuser -u kagu-agent -- ln -sfn kagu-v0.0.2 /var/lib/kagu-agent/bin/current",
		"systemctl daemon-reload",
		"systemctl start kagu-agent.service",
	}
	text := strings.Join(lines, "\n")
	for _, line := range want {
		if !strings.Contains(text+"\n", line+"\n") {
			t.Errorf("the root variant lacks %q", line)
		}
	}
}

// Le bloc de migration commence par le téléchargement vérifié : il ne suppose
// plus /tmp/kagu déjà copié.
func TestGuardMigrationText_DownloadsAndChecksTheBinaryFirst(t *testing.T) {
	text := GuardMigrationText(brand.ReleaseBaseURL, "v0.0.2", true)
	download := strings.Join(ReleaseDownloadLines(brand.ReleaseBaseURL, "v0.0.2"), "\n")
	if !strings.HasPrefix(text, download+"\n") {
		t.Fatalf("the block must start with the download:\n%s", text)
	}
	if shell, err := exec.LookPath("sh"); err == nil {
		if output, err := exec.Command(shell, "-n", "-c", text).CombinedOutput(); err != nil { // #nosec G204 -- le texte que le test juge : « -n » ne l'exécute pas, il le lit seulement.
			t.Fatalf("the block is not valid shell: %v %s", err, output)
		}
	}
	for _, want := range []string{
		"base=https://github.com/ldesfontaine/kagu/releases/download/v0.0.2 &&",
		`curl -fLO "$base/kagu-linux-$arch" -fLO "$base/SHA256SUMS" &&`,
		"sha256sum -c --ignore-missing SHA256SUMS &&",
		`install -m 0755 "kagu-linux-$arch" /tmp/kagu)`,
	} {
		if !strings.Contains(download, want) {
			t.Errorf("the download lacks %q:\n%s", want, download)
		}
	}
}

// Migrer l'unité installée par la ligne de sed donne exactement l'unité que la
// documentation livre ; la rejouer ne change rien de plus.
func TestGuardMigration_RewritesTheOldUnitLineIntoTheShippedOne(t *testing.T) {
	sed, err := exec.LookPath("sed")
	if err != nil {
		t.Skip("no sed")
	}
	var script string
	for _, line := range GuardMigrationLines("/tmp/kagu", "v0.0.2", false) {
		if strings.HasPrefix(line, "sudo sed -i ") {
			parts := strings.Split(line, "'")
			if len(parts) != 3 {
				t.Fatalf("the sed script is not one quoted word: %q", line)
			}
			script = parts[1]
		}
	}
	if script == "" {
		t.Fatal("no sed line")
	}
	unit := filepath.Join(t.TempDir(), "kagu-agent.service")
	old := "[Service]\nUser=kagu-agent\nExecStart=/var/lib/kagu-agent/bin/current agent -state /var/lib/kagu-agent -ca-file /etc/ssl/ca-interne.pem\nRestart=on-failure\n"
	if err := os.WriteFile(unit, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if output, err := exec.Command(sed, "-i", script, unit).CombinedOutput(); err != nil { // #nosec G204 -- le script que le test juge, sur un fichier de test.
			t.Fatalf("sed: %v %s", err, output)
		}
	}
	migrated, err := os.ReadFile(unit) // #nosec G304 -- un fichier de test.
	if err != nil {
		t.Fatal(err)
	}
	const wantLine = "ExecStart=/usr/local/lib/kagu-agent/kagu-guard guard -state /var/lib/kagu-agent agent -state /var/lib/kagu-agent -ca-file /etc/ssl/ca-interne.pem"
	if !strings.Contains(string(migrated), wantLine+"\n") || strings.Count(string(migrated), "ExecStart=") != 1 {
		t.Fatalf("migrated unit:\n%s", migrated)
	}

	shipped, err := os.ReadFile("../../../docs/installation/kagu-agent.service") // #nosec G304 -- le fichier livré, lu par un test.
	if err != nil {
		t.Fatal(err)
	}
	var shippedLine string
	for line := range strings.SplitSeq(string(shipped), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			shippedLine = line
		}
	}
	if want := strings.TrimSuffix(wantLine, " -ca-file /etc/ssl/ca-interne.pem"); shippedLine != want {
		t.Fatalf("the shipped unit runs %q, the migration produces %q", shippedLine, want)
	}
	// Le reste de l'unité livrée ne change pas ce que les autres textes disent :
	// Restart=on-failure relance un code 3, RestartPreventExitStatus=2 ne retient que le 2.
	for _, line := range []string{"Restart=on-failure", "RestartPreventExitStatus=2", "NoNewPrivileges=true", "User=kagu-agent"} {
		if !strings.Contains(string(shipped), "\n"+line+"\n") {
			t.Errorf("the shipped unit lost %q", line)
		}
	}
}

// L'unité que la page d'installation donne à poser est celle du fichier livré,
// commentaires mis à part : un seul texte de référence, deux présentations.
func TestAgentUnitLines_MatchTheShippedUnit(t *testing.T) {
	shipped, err := os.ReadFile("../../../docs/installation/kagu-agent.service") // #nosec G304 -- le fichier livré, lu par un test.
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for line := range strings.SplitSeq(string(shipped), "\n") {
		if !strings.HasPrefix(line, "#") {
			want = append(want, line)
		}
	}
	got := strings.Join(AgentUnitLines(), "\n")
	if strings.TrimRight(strings.Join(want, "\n"), "\n") != got {
		t.Fatalf("la page d'installation et le fichier livré diffèrent.\npage :\n%s\nfichier :\n%s", got, strings.Join(want, "\n"))
	}
}

// R-B1-16 : l'unité de l'agent n'a aucune capacité, filtre ses appels
// système et cache les processus des autres comptes ; NoNewPrivileges reste
// vrai (décision du 26/11 : vzdump passe par la porte, jamais par sudo). Pas
// de ProcSubset=pid : l'agent lit /proc/stat et boot_id (ARB-2). La forme
// livrée suit par TestAgentUnitLines_MatchTheShippedUnit.
func TestR_B1_16_TheAgentUnitIsHardened(t *testing.T) {
	lines := AgentUnitLines()
	for _, want := range []string{
		emptyBoundingSet, "AmbientCapabilities=", "SystemCallFilter=@system-service",
		"SystemCallErrorNumber=EPERM", "ProtectProc=invisible", "NoNewPrivileges=true",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("the agent unit lacks %q", want)
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "ProcSubset=") || strings.HasPrefix(line, "NoNewPrivileges=false") {
			t.Errorf("the agent unit carries %q", line)
		}
	}
	// La porte ne desserre rien de l'unité de l'agent : elle vit dans les
	// siennes, et ce que grant retire comprend l'ancien produce.conf.
	gate := strings.Join(append(VzdumpGateSocketLines(brand.AgentAccount), VzdumpGateServiceLines()...), "\n")
	if strings.Contains(gate, brand.AgentUnit) || strings.Contains(gate, "NoNewPrivileges") {
		t.Fatalf("the vzdump gate touches the agent unit:\n%s", gate)
	}
	if !slices.Contains(LegacyProducePreparation(), UnitDropInDir+"/produce.conf") {
		t.Fatal("grant does not remove the old produce.conf")
	}
}

// L'adresse des versions vient de la configuration (releases_url) : un
// miroir se lit tel quel, et un texte que le shell interpréterait reste une
// seule valeur entre apostrophes, que root colle sans rien lancer.
func TestReleaseDownloadLines_ReadTheReleasesAddressAsOneWord(t *testing.T) {
	mirror := strings.Join(ReleaseDownloadLines("https://mirror.example.org/kagu/", "v0.0.2"), "\n")
	if !strings.Contains(mirror, "base=https://mirror.example.org/kagu/v0.0.2 &&") {
		t.Fatalf("the mirror is not the base:\n%s", mirror)
	}
	hostile := strings.Join(ReleaseDownloadLines("https://mirror.example.org/$(touch pwned);x`id`'", "v0.0.2"), "\n")
	if !strings.Contains(hostile, `base='https://mirror.example.org/$(touch pwned);x`+"`id`"+`'\''/v0.0.2' &&`) {
		t.Fatalf("the address is not quoted:\n%s", hostile)
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	script := "cd " + dir + " && " + strings.Join(ReleaseDownloadLines("https://mirror.example.org/$(touch pwned)", "v0.0.2")[1:2], "") + " echo \"$base\""
	output, err := exec.Command(shell, "-c", script).CombinedOutput() // #nosec G204 -- la ligne que le test juge, dans un dossier de test.
	if err != nil {
		t.Fatalf("sh: %v %s", err, output)
	}
	if strings.TrimSpace(string(output)) != "https://mirror.example.org/$(touch pwned)/v0.0.2" {
		t.Fatalf("base read by sh: %q", output)
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
		t.Fatal("the address ran a command")
	}
}
