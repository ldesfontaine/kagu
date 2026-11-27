package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// Les sources que setup lit pour Docker et restic, écrites en entier : un
// changement de source ou de version doit se voir ici.
var (
	dockerKeyURL = "https://download.docker.com/linux/debian/gpg"
	resticURL    = "https://github.com/restic/restic/releases/download/v0.19.1/restic_0.19.1_linux_" + runtime.GOARCH + ".bz2"
	// Un faux restic, compressé en bzip2, et la somme de son archive.
	fakeResticArchive, _ = base64.StdEncoding.DecodeString("QlpoOTFBWSZTWdLdNAEAAALZgAAQaAHgIBphnAAgADFMmJkGRhjA0eSPUaM5TWJygfi6Q51RDQ4GPC7kinChIaW6aAI=")
	fakeResticSum        = "6af77e540ce41fe1fa26ed9996d22827998062f5c4d966a80d29bdce449c7419"
	fakeResticBinary     = "#!/bin/sh\necho restic 0.19.1\n"
)

// freshMachine est une machine sans Docker ni restic, ni groupe docker ; ses
// sources servent la vraie clé du dépôt de Docker et le faux restic.
func freshMachine(t *testing.T) *setupBench {
	t.Helper()
	b := newSetupBench(t)
	b.system.files = map[string]bool{}
	b.system.noDocker = true
	key, err := os.ReadFile("../../internal/kit/pgpkey/testdata/docker.asc")
	if err != nil {
		t.Fatal(err)
	}
	b.system.downloads = map[string][]byte{dockerKeyURL: key, resticURL: fakeResticArchive}
	b.resticSums = map[string]string{runtime.GOARCH: fakeResticSum}
	return b
}

// installs rend ce que setup a téléchargé et posé par APT.
func (s *setupSystemFake) installs() []string {
	var done []string
	for _, call := range s.calls {
		if strings.HasPrefix(call, "download ") || strings.HasPrefix(call, "apt-get ") {
			done = append(done, call)
		}
	}
	return done
}

// R-B1-15 : un daemon.json présent garde ses octets, avec ou sans plafond ;
// sans plafond, la coche « Docker installé » est jaune et dit la ligne à
// ajouter. Absent, il est écrit avec le plafond : pilote local, 10 Mio, trois
// fichiers ; Docker à installer, il est écrit avant que le démon démarre.
func TestR_B1_15_AnExistingDaemonJSONIsNeverRewritten(t *testing.T) {
	for name, c := range map[string]struct {
		content string
		mark    string
	}{
		"a mirror, no limit": {`{"registry-mirrors": ["https://mirror.example.org"], "bip": "10.200.0.1/24"}` + "\n", "  !"},
		"a json-file limit":  {`{"log-driver":"json-file","log-opts":{"max-size":"50m"}}`, "  ✓"},
		"not even json":      {"# à la main\n", "  !"},
	} {
		t.Run(name, func(t *testing.T) {
			b := newSetupBench(t)
			writeDaemonConfigByHand(t, b, c.content)
			out, err := b.run(noTerminal, "", "--rights", "manage")
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if after, _ := os.ReadFile(b.paths.dockerConfig); string(after) != c.content {
				t.Fatalf("daemon.json rewritten:\n%s", after)
			}
			line := lineOf(t, out, "Docker installé")
			if !strings.HasPrefix(line, c.mark) {
				t.Fatalf("the line: %q", line)
			}
			if c.mark == "  !" && (!strings.Contains(line, b.paths.dockerConfig) || !strings.Contains(line, `"log-driver":"local"`) || !strings.Contains(line, `"max-size":"10m"`)) {
				t.Fatalf("the line does not say what to add: %q", line)
			}
		})
	}

	b := newSetupBench(t)
	out, err := b.run(noTerminal, "", "--rights", "manage")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	written := requireLogLimit(t, b)
	if line := lineOf(t, out, "Docker installé"); !strings.HasPrefix(line, "  ✓") || !strings.Contains(line, "plafond") {
		t.Fatalf("the line: %q", line)
	}
	// Relancé, setup relit le fichier qu'il a écrit et ne le réécrit pas.
	if _, err := b.run(noTerminal, "", "--rights", "manage"); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(b.paths.dockerConfig); !bytes.Equal(again, written) {
		t.Fatal("daemon.json rewritten by a second setup")
	}

	fresh := freshMachine(t)
	if out, err := fresh.run(noTerminal, "", "--rights", "manage"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	requireLogLimit(t, fresh)
	if !slices.Contains(fresh.system.calls, "daemon.json before apt-get") {
		t.Fatalf("daemon.json came after Docker: %v", fresh.system.calls)
	}
}

func writeDaemonConfigByHand(t *testing.T, b *setupBench, content string) {
	t.Helper()
	if err := os.MkdirAll(strings.TrimSuffix(b.paths.dockerConfig, "/daemon.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.paths.dockerConfig, []byte(content), 0o644); err != nil { // #nosec G306 -- un daemon.json de banc.
		t.Fatal(err)
	}
}

// requireLogLimit : daemon.json porte le pilote local, 10 Mio et 3 fichiers.
func requireLogLimit(t *testing.T, b *setupBench) []byte {
	t.Helper()
	content, err := os.ReadFile(b.paths.dockerConfig)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		LogDriver string            `json:"log-driver"`
		LogOpts   map[string]string `json:"log-opts"`
	}
	if err := json.Unmarshal(content, &config); err != nil || config.LogDriver != "local" ||
		config.LogOpts["max-size"] != "10m" || config.LogOpts["max-file"] != "3" {
		t.Fatalf("daemon.json:\n%s", content)
	}
	return content
}

// R-B1-5 : Docker passe avant le compte de l'agent ; le groupe docker existe
// quand grant y met le compte.
func TestR_B1_5_DockerComesBeforeTheAgentAccount(t *testing.T) {
	b := freshMachine(t)
	out, err := b.run(noTerminal, "", "--rights", "manage")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	gestures := b.system.gestures()
	installed := slices.IndexFunc(gestures, func(gesture string) bool { return strings.HasPrefix(gesture, "apt-get install ") })
	account := slices.Index(gestures, "useradd --system --home-dir <banc>/agent --shell /usr/sbin/nologin "+brand.AgentAccount)
	joined := slices.IndexFunc(gestures, func(gesture string) bool { return strings.HasPrefix(gesture, "usermod -aG docker ") })
	if installed < 0 || account < 0 || joined < 0 || installed > account || account > joined {
		t.Fatalf("Docker %d, account %d, docker group %d:\n%s", installed, account, joined, strings.Join(gestures, "\n"))
	}
	if strings.Index(out, "Docker installé") > strings.Index(out, "Compte "+brand.ServerAccount) {
		t.Fatalf("the lines are out of order:\n%s", out)
	}
}

// R-B1-4 : Docker et restic ne se posent qu'après un oui (la question, ou
// pas de terminal), depuis leurs sources officielles, aux versions et sommes
// de cette version : un non ou --no-docker ne télécharge rien et pose
// « Observer » en jaune, avec la commande de plus tard ; une clé ou une
// archive qui n'a pas l'empreinte inscrite n'installe rien.
func TestR_B1_4_DockerAndResticOnlyAfterAYesFromTheirPinnedSources(t *testing.T) {
	for name, run := range map[string]func(b *setupBench) (string, error){
		"answered no": func(b *setupBench) (string, error) { return b.run(fakeTerminal("n\n"), "", "--rights", "manage") },
		"--no-docker": func(b *setupBench) (string, error) {
			return b.run(fakeTerminal("o\n"), "", "--rights", "manage", "--no-docker")
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := freshMachine(t)
			out, err := run(b)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if installs := b.system.installs(); len(installs) != 0 {
				t.Fatalf("installed without a yes: %v", installs)
			}
			if (name == "--no-docker") == strings.Contains(out, "? Docker") {
				t.Fatalf("the question:\n%s", out)
			}
			for _, label := range []string{"Docker installé", "restic installé"} {
				if line := lineOf(t, out, label); !strings.HasPrefix(line, "  –") {
					t.Fatalf("%s: %q", label, line)
				}
			}
			agentLine := lineOf(t, out, "Agent de cette machine")
			if !strings.HasPrefix(agentLine, "  !") || !strings.Contains(agentLine, "Observer") || !strings.Contains(agentLine, agentpolicy.GrantSetLine(agentpolicy.SetManage)) {
				t.Fatalf("the agent line: %q", agentLine)
			}
			if policy := storedPolicy(t, b.place); agentpolicy.CoversSet(policy.Rights, agentpolicy.SetManage) {
				t.Fatalf("manage laid without Docker: %v", policy.Rights)
			}
		})
	}

	observe := freshMachine(t)
	out, err := observe.run(fakeTerminal("o\n"), "", "--rights", "observe")
	if err != nil || strings.Contains(out, "? ") || len(observe.system.installs()) != 0 {
		t.Fatalf("observe asked or installed (%v):\n%s", err, out)
	}

	b := freshMachine(t)
	out, err = b.run(fakeTerminal("\n"), "", "--rights", "manage")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "? Docker et restic ne sont pas installés") {
		t.Fatalf("the question:\n%s", out)
	}
	want := []string{
		"download " + dockerKeyURL,
		"apt-get install docker-ce=5:29.10.0-1~debian.12~bookworm docker-ce-cli=5:29.10.0-1~debian.12~bookworm containerd.io=2.4.2-3~debian.12~bookworm docker-compose-plugin=5.7.2-1~debian.12~bookworm",
		"download " + resticURL,
	}
	if got := b.system.installs(); !slices.Equal(got, want) {
		t.Fatalf("installed %q\nwant %q", got, want)
	}
	if key, _ := os.ReadFile(b.paths.dockerKeyring); !bytes.Equal(key, b.system.downloads[dockerKeyURL]) {
		t.Fatal("the keyring is not the verified key")
	}
	source, _ := os.ReadFile(b.paths.dockerSource)
	if string(source) != "deb [arch="+runtime.GOARCH+" signed-by="+b.paths.dockerKeyring+"] https://download.docker.com/linux/debian bookworm stable\n" {
		t.Fatalf("source %q", source)
	}
	info, err := os.Stat(b.paths.resticBinary)
	if restic, _ := os.ReadFile(b.paths.resticBinary); err != nil || string(restic) != fakeResticBinary || info.Mode().Perm() != 0o755 {
		t.Fatalf("restic %q (%v)", restic, err)
	}
	if line := lineOf(t, out, "Docker installé"); !strings.HasPrefix(line, "  ✓") || !strings.Contains(line, "29.10.0") {
		t.Fatalf("the Docker line: %q", line)
	}
	if line := lineOf(t, out, "restic installé"); !strings.HasPrefix(line, "  ✓") || !strings.Contains(line, brand.ResticVersion) {
		t.Fatalf("the restic line: %q", line)
	}

	// Seul restic manque : la question le dit.
	onlyRestic := freshMachine(t)
	onlyRestic.system.files[machine.DockerBinary] = true
	out, _ = onlyRestic.run(fakeTerminal("n\n"), "", "--rights", "manage")
	if !strings.Contains(out, "? restic n'est pas installé") || strings.Contains(out, "? Docker") {
		t.Fatalf("the question:\n%s", out)
	}
}

// R-B1-4, négatif : une clé du dépôt de Docker mal formée (deux blocs), ou
// bien formée mais qui n'a pas l'empreinte de brand, ou une archive de restic qui n'a pas la somme inscrite, s'arrête en
// rouge sans rien poser.
func TestR_B1_4_AnUnpinnedKeyOrArchiveInstallsNothing(t *testing.T) {
	b := freshMachine(t)
	other := b.system.downloads[dockerKeyURL]
	b.system.downloads[dockerKeyURL] = append(bytes.Clone(other), other...)
	out, err := b.run(noTerminal, "", "--rights", "manage")
	var refused *refusal
	if !errors.As(err, &refused) {
		t.Fatalf("got %v\n%s", err, out)
	}
	if line := lineOf(t, out, "Docker installé"); !strings.HasPrefix(line, "  ✗") || !strings.Contains(line, brand.DockerKeyFingerprint) {
		t.Fatalf("the line: %q", line)
	}
	if slices.ContainsFunc(b.system.calls, func(call string) bool { return strings.HasPrefix(call, "apt-get") }) {
		t.Fatal("apt-get ran with an unpinned key")
	}
	if _, err := os.Stat(b.paths.dockerKeyring); err == nil {
		t.Fatal("the unpinned key was laid")
	}

	// Une clé bien formée, mais d'une autre empreinte que celle de brand.
	b = freshMachine(t)
	foreign, err := os.ReadFile("../../internal/kit/pgpkey/testdata/other.asc")
	if err != nil {
		t.Fatal(err)
	}
	b.system.downloads[dockerKeyURL] = foreign
	out, err = b.run(noTerminal, "", "--rights", "manage")
	if !errors.As(err, &refused) {
		t.Fatalf("a well-formed foreign key: %v\n%s", err, out)
	}
	if line := lineOf(t, out, "Docker installé"); !strings.HasPrefix(line, "  ✗") || !strings.Contains(line, brand.DockerKeyFingerprint) {
		t.Fatalf("the line: %q", line)
	}
	if slices.ContainsFunc(b.system.calls, func(call string) bool { return strings.HasPrefix(call, "apt-get") }) {
		t.Fatal("apt-get ran with a foreign key")
	}
	if _, err := os.Stat(b.paths.dockerKeyring); err == nil {
		t.Fatal("the foreign key was laid")
	}

	b = freshMachine(t)
	b.system.files[machine.DockerBinary] = true
	b.resticSums = nil
	out, err = b.run(noTerminal, "", "--rights", "manage")
	if !errors.As(err, &refused) {
		t.Fatalf("got %v\n%s", err, out)
	}
	if line := lineOf(t, out, "restic installé"); !strings.HasPrefix(line, "  ✗") {
		t.Fatalf("the line: %q", line)
	}
	if _, err := os.Stat(b.paths.resticBinary); err == nil {
		t.Fatal("an archive without the pinned sum was laid")
	}
}
