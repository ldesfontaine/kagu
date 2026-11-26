package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/release/releasetest"
)

// install.sh est joué par sh contre des versions de releasetest.Write,
// signées par des clés de test que le banc écrit dans le script à la place
// de celles de key.go, comme la publication y écrit MIN_VERSION.

const installScriptPath = "../../install.sh"

// installScriptTools sont les commandes qu'install.sh appelle ; le banc ne
// lui en donne pas d'autre, et choisit ainsi minisign ou openssl.
var installScriptTools = []string{
	"base64", "cat", "curl", "grep", "install", "mktemp", "od", "rm", "sed", "sha256sum", "tail", "tr", "uname", "wc",
}

// installVerifiers : les deux chemins de la vérification de la signature.
var installVerifiers = []string{"minisign", "openssl"}

func readInstallScript(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(installScriptPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func scriptAssignment(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^` + name + `="([^"]*)"$`)
}

// scriptValue rend la valeur que le script donne à name, écrite une fois.
func scriptValue(t *testing.T, script, name string) string {
	t.Helper()
	found := scriptAssignment(name).FindAllStringSubmatch(script, -1)
	if len(found) != 1 {
		t.Fatalf("install.sh sets %s %d times", name, len(found))
	}
	return found[0][1]
}

// withScriptValue réécrit la ligne de name, comme la publication le fait de
// MIN_VERSION.
func withScriptValue(t *testing.T, script, name, value string) string {
	t.Helper()
	scriptValue(t, script, name)
	return scriptAssignment(name).ReplaceAllLiteralString(script, name+`="`+value+`"`)
}

// Le script porte les deux clés de key.go, la courante et la secours : une
// version de remède signée par la secours passe aussi.
func TestInstallScriptCarriesTheEmbeddedKeys(t *testing.T) {
	script := readInstallScript(t)
	if got := scriptValue(t, script, "CURRENT_KEY"); got != release.CurrentPublicKey {
		t.Errorf("CURRENT_KEY = %q, key.go has %q", got, release.CurrentPublicKey)
	}
	if got := scriptValue(t, script, "BACKUP_KEY"); got != release.BackupPublicKey {
		t.Errorf("BACKUP_KEY = %q, key.go has %q", got, release.BackupPublicKey)
	}
	if got := scriptValue(t, script, "MIN_VERSION"); got != "" {
		t.Errorf("MIN_VERSION is written at publication only, got %q", got)
	}
}

// Les noms du script sont ceux de brand : un renommage qui l'oublie casse ici.
func TestInstallScriptNamesAreTheBrands(t *testing.T) {
	script := readInstallScript(t)
	for name, want := range map[string]string{
		"BINARY_PREFIX":    brand.ReleaseBinaryPrefix,
		"SUMS_FILE":        brand.ReleaseSumsFile,
		"SIGNATURE_FILE":   brand.ReleaseSignatureFile,
		"INSTALLED_BINARY": brand.InstalledBinary,
		"KEPT_DIR":         brand.SetupReleaseDir,
	} {
		if got := scriptValue(t, script, name); got != want {
			t.Errorf("%s = %q, brand has %q", name, got, want)
		}
	}
	variable := brand.EnvPrefix + "RELEASES"
	if line := variable + "=${" + variable + ":-" + brand.ReleaseBaseURL + "}\n"; !strings.Contains(script, "\n"+line) {
		t.Errorf("install.sh does not default %s to %s", variable, brand.ReleaseBaseURL)
	}
}

// installBench est une machine où install.sh tourne : ses outils seuls dans
// le PATH, un faux id qui dit root, le binaire et le dossier gardé sous un
// dossier de test, et les versions servies par file://.
type installBench struct {
	t          *testing.T
	shell      string
	script     string
	tools      string
	work       string
	releases   string
	minVersion string
	binary     string
	kept       string
	marker     string
}

func newInstallBench(t *testing.T, verifier string, keys release.Keys, minVersion string) *installBench {
	t.Helper()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	b := &installBench{
		t: t, shell: shell, tools: filepath.Join(dir, "tools"), work: filepath.Join(dir, "tmp"),
		releases: filepath.Join(dir, "releases"), minVersion: minVersion,
		binary: filepath.Join(dir, "usr", "bin", brand.Command), kept: filepath.Join(dir, "var", "setup", "release"),
		marker: filepath.Join(dir, "setup-args"),
	}
	for _, folder := range []string{b.tools, b.work, b.releases, filepath.Dir(b.binary)} {
		if err := os.MkdirAll(folder, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range append(installScriptTools, verifier) {
		found, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("no %s on this machine", tool)
		}
		if err := os.Symlink(found, filepath.Join(b.tools, tool)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(b.tools, "id"), []byte("#!/bin/sh\necho 0\n"), 0o755); err != nil { // #nosec G306 -- un faux id de banc.
		t.Fatal(err)
	}
	script := readInstallScript(t)
	backup := ""
	if keys.HasBackup() {
		backup = keys.Backup.String()
	}
	for name, value := range map[string]string{
		"MIN_VERSION": minVersion, "CURRENT_KEY": keys.Current.String(), "BACKUP_KEY": backup,
		"INSTALLED_BINARY": b.binary, "KEPT_DIR": b.kept,
	} {
		script = withScriptValue(t, script, name, value)
	}
	b.script = filepath.Join(dir, "install.sh")
	if err := os.WriteFile(b.script, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	return b
}

// binaries rend des binaires de version qui, lancés, notent leurs arguments :
// ce que setup recevrait.
func (b *installBench) binaries(version string) map[string][]byte {
	binaries := make(map[string][]byte)
	for _, arch := range []string{"amd64", "arm64"} {
		binaries[release.BinaryName(arch)] = []byte("#!/bin/sh\n# " + arch + " " + version + "\nprintf '%s\\n' \"$@\" > " + b.marker + "\n")
	}
	return binaries
}

// serve met dir à l'adresse de la version que le script attend : un miroir
// peut y servir n'importe quelle version signée.
func (b *installBench) serve(dir string) {
	if err := os.Symlink(dir, filepath.Join(b.releases, "v"+b.minVersion)); err != nil {
		b.t.Fatal(err)
	}
}

// run lance « sh install.sh --rights observe » ; rend sa sortie d'erreur et
// s'il a fini sans erreur.
func (b *installBench) run() (string, bool) {
	b.t.Helper()
	command := exec.Command(b.shell, b.script, "--rights", "observe") // #nosec G204 -- le script du dépôt, joué par le test.
	command.Env = []string{"PATH=" + b.tools, "TMPDIR=" + b.work, brand.EnvPrefix + "RELEASES=file://" + b.releases}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	err := command.Run()
	var exited *exec.ExitError
	if err != nil && !errors.As(err, &exited) {
		b.t.Fatal(err)
	}
	if left, _ := os.ReadDir(b.work); len(left) != 0 {
		b.t.Errorf("install.sh left its temporary folder: %v", left)
	}
	return stderr.String(), err == nil
}

// refused vérifie un refus qui dit reason, avant toute écriture : ni binaire,
// ni dossier gardé, ni setup lancé.
func (b *installBench) refused(stderr string, ok bool, reason string) {
	b.t.Helper()
	if ok || !strings.Contains(stderr, reason) {
		b.t.Fatalf("install.sh did not refuse with %q: ok=%v\n%s", reason, ok, stderr)
	}
	for _, written := range []string{b.binary, filepath.Dir(filepath.Dir(b.kept)), b.marker} {
		if _, err := os.Lstat(written); !errors.Is(err, os.ErrNotExist) {
			b.t.Errorf("written before the refusal: %s", written)
		}
	}
}

// installed vérifie que le binaire de cette machine est posé, que les
// fichiers de la version sont gardés pour setup, et que setup a reçu
// l'adresse des versions et les arguments du script.
func (b *installBench) installed(stderr string, ok bool, served string) {
	b.t.Helper()
	if !ok {
		b.t.Fatalf("install.sh refused:\n%s", stderr)
	}
	want, err := os.ReadFile(filepath.Join(served, release.BinaryName(runtime.GOARCH)))
	if err != nil {
		b.t.Fatal(err)
	}
	if got, err := os.ReadFile(b.binary); err != nil || !bytes.Equal(got, want) {
		b.t.Fatalf("installed binary %q %v", got, err)
	}
	entries, err := os.ReadDir(served)
	if err != nil {
		b.t.Fatal(err)
	}
	for _, entry := range entries {
		original, _ := os.ReadFile(filepath.Join(served, entry.Name()))
		if kept, err := os.ReadFile(filepath.Join(b.kept, entry.Name())); err != nil || !bytes.Equal(kept, original) {
			b.t.Errorf("%s is not kept for setup: %v", entry.Name(), err)
		}
	}
	args, err := os.ReadFile(b.marker)
	if err != nil {
		b.t.Fatalf("setup was not launched: %v", err)
	}
	wantArgs := "setup\n--releases-url\nfile://" + b.releases + "\n--rights\nobserve\n"
	if string(args) != wantArgs {
		b.t.Fatalf("setup received %q, want %q", args, wantArgs)
	}
}

// goAccepts est le jugement de référence, celui du binaire : la signature
// par release.VerifySums (signature globale comprise), puis la version
// minimale.
func goAccepts(t *testing.T, dir string, keys release.Keys, minVersion string) bool {
	t.Helper()
	sums, _ := os.ReadFile(filepath.Join(dir, brand.ReleaseSumsFile))
	signature, _ := os.ReadFile(filepath.Join(dir, brand.ReleaseSignatureFile))
	signed, err := release.VerifySums(sums, signature, keys)
	if err != nil {
		return false
	}
	floor, err := release.ParseVersion("v" + minVersion)
	if err != nil {
		t.Fatal(err)
	}
	return signed.Version.Compare(floor) >= 0
}

// sameVerdictAsGo : le script refait en shell ce que release.Verify fait ; il
// juge comme lui.
func sameVerdictAsGo(t *testing.T, dir string, keys release.Keys, minVersion string, scriptAccepted bool) {
	t.Helper()
	if goAccepts(t, dir, keys, minVersion) != scriptAccepted {
		t.Fatalf("install.sh accepted=%v, release.VerifySums says the opposite", scriptAccepted)
	}
}

func testReleaseKeys(t *testing.T) (release.Keys, release.PrivateKey) {
	t.Helper()
	public, private, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return release.Keys{Current: public}, private
}

// rewriteFile change old en new dans un fichier de la version servie.
func rewriteFile(t *testing.T, name, old, new string) {
	t.Helper()
	content, err := os.ReadFile(name) // #nosec G304 -- un fichier du test.
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, []byte(old)) {
		t.Fatalf("%s has no %q", name, old)
	}
	if err := os.WriteFile(name, bytes.Replace(content, []byte(old), []byte(new), 1), 0o600); err != nil {
		t.Fatal(err)
	}
}

// R-B1-14, W-F5 : une v0.9.0 signée servie à la place de la v1.0.0 est
// refusée avant toute écriture ; une signature des sommes valable dont le
// commentaire de confiance a été changé aussi ; la bonne version est posée.
// Par minisign comme par openssl.
func TestR_B1_14_InstallScriptRefusesAnOlderSignedVersionOrAChangedTrustedComment(t *testing.T) {
	for _, verifier := range installVerifiers {
		t.Run(verifier, func(t *testing.T) {
			keys, private := testReleaseKeys(t)

			t.Run("older signed version", func(t *testing.T) {
				b := newInstallBench(t, verifier, keys, "1.0.0")
				served := releasetest.Write(t, private, "v0.9.0", b.binaries("v0.9.0"))
				b.serve(served)
				stderr, ok := b.run()
				b.refused(stderr, ok, "version plus ancienne que celle attendue : v0.9.0 servie, v1.0.0 au moins")
				sameVerdictAsGo(t, served, keys, "1.0.0", ok)
			})

			t.Run("changed trusted comment", func(t *testing.T) {
				b := newInstallBench(t, verifier, keys, "1.0.0")
				served := releasetest.Write(t, private, "v0.9.0", b.binaries("v0.9.0"))
				// Les sommes et leur signature sont intactes : seule la
				// version du commentaire a changé.
				rewriteFile(t, filepath.Join(served, brand.ReleaseSignatureFile), "version:v0.9.0", "version:v1.0.0")
				b.serve(served)
				stderr, ok := b.run()
				b.refused(stderr, ok, "commentaire de confiance")
				sameVerdictAsGo(t, served, keys, "1.0.0", ok)
			})

			t.Run("right version", func(t *testing.T) {
				b := newInstallBench(t, verifier, keys, "1.0.0")
				served := releasetest.Write(t, private, "v1.0.0", b.binaries("v1.0.0"))
				b.serve(served)
				stderr, ok := b.run()
				b.installed(stderr, ok, served)
				sameVerdictAsGo(t, served, keys, "1.0.0", ok)
			})
		})
	}
}

// Les autres refus, avant toute écriture, et ce qui passe : une version plus
// récente que MIN_VERSION, une version de remède signée par la secours.
func TestInstallScript_JudgesLikeTheBinary(t *testing.T) {
	keys, private := testReleaseKeys(t)
	backupPublic, backupPrivate, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keys.Backup = backupPublic
	_, stranger, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		signer     release.PrivateKey
		version    string
		minVersion string
		change     func(t *testing.T, served string)
		reason     string
	}{
		{name: "newer version", signer: private, version: "v1.0.1", minVersion: "1.0.0"},
		{name: "remedy signed by the backup key", signer: backupPrivate, version: "v1.0.0", minVersion: "1.0.0"},
		{name: "another key", signer: stranger, version: "v1.0.0", minVersion: "1.0.0", reason: "faite par une autre clé"},
		{name: "unpublished script", signer: private, version: "v1.0.0", minVersion: "", reason: "MIN_VERSION vide"},
		{name: "changed sums", signer: private, version: "v1.0.0", minVersion: "1.0.0", reason: "signature refusée",
			change: func(t *testing.T, served string) {
				rewriteFile(t, filepath.Join(served, brand.ReleaseSumsFile), "  ", "  ./")
			}},
		{name: "changed binary", signer: private, version: "v1.0.0", minVersion: "1.0.0", reason: "somme fausse",
			change: func(t *testing.T, served string) {
				rewriteFile(t, filepath.Join(served, release.BinaryName(runtime.GOARCH)), "printf", "echo pwned;printf")
			}},
		{name: "legacy algorithm", signer: private, version: "v1.0.0", minVersion: "1.0.0", reason: "non pré-haché",
			change: func(t *testing.T, served string) {
				legacySignature(t, filepath.Join(served, brand.ReleaseSignatureFile))
			}},
		{name: "other file in the trusted comment", signer: private, version: "v1.0.0", minVersion: "1.0.0", reason: "commentaire de confiance",
			change: func(t *testing.T, served string) {
				rewriteFile(t, filepath.Join(served, brand.ReleaseSignatureFile), "file:SHA256SUMS", "file:other")
			}},
	}
	for _, verifier := range installVerifiers {
		for _, c := range cases {
			t.Run(verifier+"/"+c.name, func(t *testing.T) {
				b := newInstallBench(t, verifier, keys, c.minVersion)
				served := releasetest.Write(t, c.signer, c.version, b.binaries(c.version))
				if c.change != nil {
					c.change(t, served)
				}
				if c.minVersion == "" {
					b.minVersion = "0.0.0"
				}
				b.serve(served)
				stderr, ok := b.run()
				if c.reason == "" {
					b.installed(stderr, ok, served)
				} else {
					b.refused(stderr, ok, c.reason)
				}
				if c.minVersion != "" && c.name != "changed binary" {
					sameVerdictAsGo(t, served, keys, c.minVersion, ok)
				}
			})
		}
	}
}

// legacySignature donne à la signature l'algorithme « Ed », non pré-haché.
func legacySignature(t *testing.T, name string) {
	t.Helper()
	content, err := os.ReadFile(name) // #nosec G304 -- un fichier du test.
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(content), "\n")
	header, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	header[1] = 'd'
	lines[1] = base64.StdEncoding.EncodeToString(header)
	if err := os.WriteFile(name, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}
