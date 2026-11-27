package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/release/releasetest"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/kit/version"
)

// upgradeTarget est la version que le banc publie, au-dessus de celle de ce
// binaire de test.
const upgradeTarget = "v0.0.2"

// upgradeBench est la machine Kagu installée par setup : ses chemins sous un
// dossier court, un faux serve sur la vraie socket de contrôle, un faux
// système (systemctl, systemd-run, la passation au nouveau binaire) et une
// adresse des versions servie en local.
type upgradeBench struct {
	t        *testing.T
	dir      string
	paths    upgradePaths
	stateDir string
	keys     release.Keys
	private  release.PrivateKey
	binaries map[string][]byte
	system   *upgradeSystemFake
	serve    *fakeUpgradeServe
	releases *httptest.Server
	// Ce que l'adresse des versions sert : un dossier de version, et une
	// redirection hors d'elle si non vide.
	published  string
	redirectTo string
	terminal   *cutTerminal
	// Le binaire que l'unité du serveur lance.
	installed string
	afterStep func(step.Key) error
	noKeys    bool
	place     agent.PolicyPlace
	// Le terminal de root, où se pose la question de la politique.
	openTerminal terminalOpener
	// Un autre hôte, en https, vers lequel l'adresse des versions renvoie
	// quand redirectTo le nomme.
	mirror *httptest.Server
}

func newUpgradeBench(t *testing.T) *upgradeBench {
	t.Helper()
	dir := shortDir(t)
	public, private, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := &upgradeBench{
		t: t, dir: dir, stateDir: filepath.Join(dir, "state"), keys: release.Keys{Current: public}, private: private,
		binaries: releasetest.Binaries(upgradeTarget, runtime.GOARCH, "riscv64"), terminal: &cutTerminal{},
	}
	b.paths = upgradePaths{
		stateFile: filepath.Join(dir, "upgrade", "state.json"), lockFile: filepath.Join(dir, "upgrade.lock"),
		stagingDir: filepath.Join(dir, "upgrade"), setupStateFile: filepath.Join(dir, "etc", "setup.json"),
		configFile: filepath.Join(dir, "etc", "config.toml"), binary: filepath.Join(dir, "bin", brand.Command),
		previous: filepath.Join(dir, "lib", brand.Command+".previous"), unitDir: filepath.Join(dir, "units"),
		guardPath: filepath.Join(dir, "guard", brand.AgentGuardBinary), agentStateDir: filepath.Join(dir, "agent"),
	}
	for _, folder := range []string{"etc", "bin", "units", "guard", "agent/bin"} {
		mkdir(t, filepath.Join(dir, folder), 0o755)
	}
	b.installed = b.paths.binary
	b.place = agent.PolicyPlace{Dir: filepath.Join(dir, "policy"), Owner: fsx.Owner{UID: os.Getuid(), GID: os.Getgid()}}
	mkdir(t, b.stateDir, 0o700)
	writeBenchFile(t, b.paths.configFile, "listen = \"127.0.0.1:18081\"\nstate_dir = \""+b.stateDir+"\"\n")
	writeBenchFile(t, b.paths.setupStateFile, "{\"rights\":\"manage\",\"steps\":[]}\n")
	writeBenchFile(t, b.paths.binary, "the binary in place")
	writeBenchFile(t, b.paths.guardPath, "the binary in place")
	writeBenchFile(t, filepath.Join(b.stateDir, brand.DatabaseFile), "the database")
	writeBenchFile(t, filepath.Join(b.paths.unitDir, brand.ServerUnit), strings.Join(machine.ServerUnitLines(), "\n")+"\n")
	writeBenchFile(t, filepath.Join(b.paths.unitDir, brand.AgentUnit), strings.Join(machine.AgentUnitLines(), "\n")+"\n")
	writeBenchFile(t, filepath.Join(b.paths.agentStateDir, brand.AgentBinDir, brand.AgentCurrentLink), "the agent's current binary")
	b.serve = &fakeUpgradeServe{version: version.Number(), stateDir: b.stateDir}
	serveOnControlSocket(t, b.stateDir, b.serve.handler())
	b.system = &upgradeSystemFake{bench: b, free: 8 << 30}
	b.releases = httptest.NewServer(http.HandlerFunc(b.serveReleases))
	t.Cleanup(b.releases.Close)
	b.mirror = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(b.published, filepath.Base(r.URL.Path)))
	}))
	t.Cleanup(b.mirror.Close)
	b.openTerminal = noTerminal
	return b
}

func mkdir(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeBenchFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil { // #nosec G306 -- un faux binaire de banc.
		t.Fatal(err)
	}
}

// publish écrit la version signée par private et la sert à l'adresse des
// versions ; rend son dossier.
func (b *upgradeBench) publish(private release.PrivateKey) string {
	b.published = releasetest.Write(b.t, private, upgradeTarget, b.binaries)
	return b.published
}

// serveReleases est l'adresse des versions : « latest » renvoie vers le tag,
// les fichiers se lisent sous download/<version>/.
func (b *upgradeBench) serveReleases(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/releases/latest" {
		http.Redirect(w, r, "/releases/tag/"+upgradeTarget, http.StatusFound)
		return
	}
	name, found := strings.CutPrefix(r.URL.Path, "/releases/download/"+upgradeTarget+"/")
	if !found || b.published == "" {
		http.NotFound(w, r)
		return
	}
	if b.redirectTo != "" {
		http.Redirect(w, r, b.redirectTo+"/"+name, http.StatusFound)
		return
	}
	http.ServeFile(w, r, filepath.Join(b.published, filepath.Base(name)))
}

// newRun est la commande telle que root la lance, sur ce banc, avec ce
// binaire comme version en place.
func (b *upgradeBench) newRun(running string) *upgradeRun {
	keys := func() (release.Keys, error) { return b.keys, nil }
	if b.noKeys {
		keys = func() (release.Keys, error) { return release.Keys{}, release.ErrNoTrustedKey }
	}
	place := b.place
	return &upgradeRun{
		out: b.terminal, openTerminal: b.openTerminal, transport: b.mirror.Client().Transport, euid: 0, system: b.system, paths: b.paths, keys: keys, running: running,
		releaseBase: b.releases.URL + "/releases/download", latestURL: b.releases.URL + "/releases/latest",
		place: func(*os.Root) (agent.PolicyPlace, error) { return place, nil }, audit: func(string) error { return nil },
		wait: 2 * time.Second, poll: 10 * time.Millisecond, afterStep: b.afterStep,
	}
}

// upgrade lance « kagu upgrade » dans le terminal, comme root.
func (b *upgradeBench) upgrade(args ...string) error {
	b.t.Helper()
	return b.newRun(version.Number()).command(context.Background(), args)
}

func (b *upgradeBench) status() string {
	b.t.Helper()
	var out bytes.Buffer
	run := b.newRun(version.Number())
	run.out = &out
	if err := run.command(context.Background(), []string{"--status"}); err != nil {
		b.t.Fatal(err)
	}
	return out.String()
}

func (b *upgradeBench) read(path string) string {
	b.t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		b.t.Fatal(err)
	}
	return string(content)
}

// nothingMoved : ni binaire, ni lanceur, ni copie de la base, ni import, ni
// redémarrage.
func (b *upgradeBench) nothingMoved() {
	t := b.t
	t.Helper()
	if got := b.read(b.paths.binary); got != "the binary in place" {
		t.Errorf("binary replaced: %q", got)
	}
	if got := b.read(b.paths.guardPath); got != "the binary in place" {
		t.Errorf("guard replaced: %q", got)
	}
	if _, err := os.Stat(b.paths.previous); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("previous binary written: %v", err)
	}
	if b.serve.copies != 0 || len(b.serve.imports) != 0 {
		t.Errorf("serve asked to copy %d times, to import %v", b.serve.copies, b.serve.imports)
	}
	if len(b.system.calls) != 0 {
		t.Errorf("system touched: %v", b.system.calls)
	}
	if _, err := os.Stat(filepath.Join(b.paths.stagingDir, upgradeTarget)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("version staged: %v", err)
	}
}

// cutTerminal est le terminal de la session SSH : coupé, chaque écriture
// échoue, comme sur un pty dont la session est tombée.
type cutTerminal struct {
	lock    sync.Mutex
	content bytes.Buffer
	cut     bool
}

func (c *cutTerminal) Write(line []byte) (int, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.cut {
		return 0, syscall.EIO
	}
	return c.content.Write(line)
}

func (c *cutTerminal) String() string {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.content.String()
}

func (c *cutTerminal) close() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.cut = true
}

// fakeUpgradeServe est serve sur sa socket de contrôle : il dit sa version,
// copie sa base (sans rien écrire ici, sauf writesCopy) et importe ; il
// retient chaque appel. Muet, health ne répond pas.
type fakeUpgradeServe struct {
	lock       sync.Mutex
	version    string
	stateDir   string
	copies     int
	imports    []string
	silent     bool
	writesCopy bool
}

func (s *fakeUpgradeServe) runs(version string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.version, s.silent = version, false
}

func (s *fakeUpgradeServe) stops() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.silent = true
}

func (s *fakeUpgradeServe) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+controlHealthPath, func(w http.ResponseWriter, _ *http.Request) {
		s.lock.Lock()
		defer s.lock.Unlock()
		if s.silent {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"version": s.version})
	})
	mux.HandleFunc("POST "+controlPreUpgradePath, func(w http.ResponseWriter, _ *http.Request) {
		s.lock.Lock()
		defer s.lock.Unlock()
		s.copies++
		copyPath := filepath.Join(s.stateDir, brand.UpgradeDir, brand.UpgradeCopyPrefix+s.version+".db")
		if s.writesCopy && !s.copyDatabase(w, copyPath) {
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"path": copyPath})
	})
	mux.HandleFunc("POST "+controlReleaseImportPath, func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Folder string `json:"folder"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		s.lock.Lock()
		defer s.lock.Unlock()
		s.imports = append(s.imports, request.Folder)
		_ = json.NewEncoder(w).Encode(map[string]string{"version": upgradeTarget})
	})
	return mux
}

// copyDatabase écrit la copie comme serve : la base telle quelle, en 0600
// dans un dossier 0700.
func (s *fakeUpgradeServe) copyDatabase(w http.ResponseWriter, copyPath string) bool {
	content, err := os.ReadFile(filepath.Join(s.stateDir, brand.DatabaseFile))
	if err == nil {
		err = os.MkdirAll(filepath.Dir(copyPath), 0o700)
	}
	if err == nil {
		err = os.WriteFile(copyPath, content, 0o600)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	return true
}

// childRun est un enfant lancé sous un autre compte : son compte, ses
// options, et state_dir avant et après lui.
type childRun struct {
	account       fsx.Owner
	args          []string
	before, after []string
}

// upgradeSystemFake : systemctl restart et start font tourner la version du
// binaire posé, stop rend serve muet ; systemd-run et la passation relancent
// la commande dans ce processus, comme le ferait l'unité.
type upgradeSystemFake struct {
	bench    *upgradeBench
	free     uint64
	calls    []string
	unitArgs []string
	// La nouvelle version a une migration qui échoue : elle écrit dans la
	// base et ses -wal, -shm, puis reste muette.
	failingMigration bool
	// Ce que la base contenait quand serve a été relancé par start.
	databaseAtStart string
	// systemctl start échoue : le retour rate.
	startFails bool
	// Les comptes demandés et les enfants lancés sous un autre compte.
	accounts []string
	children []childRun
	// state_dir à chaque systemctl.
	treeAtCall []string
	// Le oui de root lu dans state.json au moment de la relance.
	consentAtRelaunch bool
	handOver          []string
}

func (s *upgradeSystemFake) Run(name string, args ...string) error {
	s.calls = append(s.calls, name+" "+strings.Join(args, " "))
	if name != "systemctl" {
		return nil
	}
	s.treeAtCall = append(s.treeAtCall, strings.Join(treeOf(s.bench.t, s.bench.stateDir), "\n"))
	switch args[0] {
	case "stop":
		s.bench.serve.stops()
	case "start":
		if s.startFails {
			return errors.New("systemctl start: unit failed")
		}
		database, _ := os.ReadFile(filepath.Join(s.bench.stateDir, brand.DatabaseFile))
		s.databaseAtStart = string(database)
		return s.startInstalled()
	case "restart":
		return s.startInstalled()
	}
	return nil
}

// startInstalled fait tourner le binaire posé : la nouvelle version, ou
// l'ancienne remise par le retour.
func (s *upgradeSystemFake) startInstalled() error {
	installed, err := os.ReadFile(s.bench.installed)
	if err != nil {
		return err
	}
	switch {
	case !bytes.Equal(installed, s.bench.binaries[release.BinaryName(runtime.GOARCH)]):
		if string(installed) == "the binary in place" {
			s.bench.serve.runs(version.Number())
		}
	case s.failingMigration:
		s.bench.serve.stops()
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if err := os.WriteFile(filepath.Join(s.bench.stateDir, brand.DatabaseFile+suffix), []byte("faulty"+suffix), 0o600); err != nil {
				return err
			}
		}
	default:
		s.bench.serve.runs(upgradeTarget)
	}
	return nil
}

func (s *upgradeSystemFake) FreeBytes(string) (uint64, error) { return s.free, nil }

// serviceAccount est le compte du service sur le banc : un uid qui n'est
// pas root, même quand le test tourne en root. Les fichiers restent écrits
// par le processus du test.
func serviceAccount() fsx.Owner {
	return fsx.Owner{UID: 6501, GID: 6501}
}

func (s *upgradeSystemFake) Account(name string) (fsx.Owner, bool, error) {
	s.accounts = append(s.accounts, name)
	return serviceAccount(), name == brand.ServerAccount, nil
}

// RunAsAccount joue l'enfant dans ce processus, avec l'uid demandé ; il
// retient le compte et l'état de state_dir avant et après.
func (s *upgradeSystemFake) RunAsAccount(account fsx.Owner, args []string) (string, error) {
	s.children = append(s.children, childRun{account: account, args: args, before: treeOf(s.bench.t, s.bench.stateDir)})
	var out bytes.Buffer
	run := s.bench.newRun(version.Number())
	run.out, run.euid = &out, account.UID
	err := run.command(context.Background(), args[2:])
	s.children[len(s.children)-1].after = treeOf(s.bench.t, s.bench.stateDir)
	return out.String(), err
}

func (s *upgradeSystemFake) RunInUnit(args []string) error {
	s.unitArgs = upgradeUnitLine(s.bench.paths.binary, args)
	state, err := readUpgradeState(s.bench.paths.stateFile)
	if err != nil {
		return err
	}
	s.consentAtRelaunch = state.PolicyConsent
	return s.bench.newRun(version.Number()).command(context.Background(), args)
}

func (s *upgradeSystemFake) HandOver(binary string, args []string) error {
	s.handOver = append([]string{binary}, args...)
	return s.bench.newRun(upgradeTarget).command(context.Background(), args)
}

// R-B2-1 : une version signée par une autre clé, un binaire qui n'a pas sa
// somme, une version téléchargée dont la signature ne tient pas, ou une
// redirection hors de l'adresse des versions : refus, et rien de copié ni
// de demandé à serve.
func TestR_B2_1_UpgradeRefusesAnUnsignedBinaryBeforeAnyCopy(t *testing.T) {
	_, foreign, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		prepare func(b *upgradeBench) []string
		want    string
	}{
		{"folder signed by another key", func(b *upgradeBench) []string {
			return []string{"--from", releasetest.Write(t, foreign, upgradeTarget, b.binaries)}
		}, "aucune des clés de version"},
		{"binary that does not match SHA256SUMS", func(b *upgradeBench) []string {
			folder := releasetest.Write(t, b.private, upgradeTarget, b.binaries)
			writeBenchFile(t, filepath.Join(folder, release.BinaryName(runtime.GOARCH)), "a binary changed after signing")
			return []string{"--from", folder}
		}, "n'a pas la somme"},
		{"download signed by another key", func(b *upgradeBench) []string {
			b.publish(foreign)
			return nil
		}, "aucune des clés de version"},
		{"download redirected to an address that is not https", func(b *upgradeBench) []string {
			b.publish(b.private)
			b.redirectTo = b.releases.URL + "/elsewhere"
			return nil
		}, errRedirectNotHTTPS.Error()},
		{"download redirected over https, signed by another key", func(b *upgradeBench) []string {
			b.publish(foreign)
			b.redirectTo = b.mirror.URL + "/assets"
			return nil
		}, "aucune des clés de version"},
		{"binary without a release key", func(b *upgradeBench) []string {
			b.publish(b.private)
			b.noKeys = true
			return nil
		}, "n'embarque pas de clé de version"},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := newUpgradeBench(t)
			args := append([]string{"--" + inUnitFlag}, test.prepare(b)...)
			var refused *refusal
			if err := b.upgrade(args...); !errors.As(err, &refused) {
				t.Fatalf("upgrade: %v", err)
			}
			if printed := b.terminal.String(); !strings.Contains(printed, "✗ Version trouvée") || !strings.Contains(printed, test.want) {
				t.Fatalf("printed %q, want %q", printed, test.want)
			}
			b.nothingMoved()
		})
	}
}

// R-B2-2 : la base est copiée et la version importée par serve, sur sa socket
// de contrôle ; root n'écrit rien sous state_dir.
func TestR_B2_2_UpgradeNeverWritesInTheStateDirAsRoot(t *testing.T) {
	b := newUpgradeBench(t)
	b.publish(b.private)
	before := treeOf(t, b.stateDir)
	if err := b.upgrade("--" + inUnitFlag); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, b.terminal)
	}
	if after := treeOf(t, b.stateDir); !slices.Equal(before, after) {
		t.Fatalf("state_dir changed:\nbefore %v\nafter  %v", before, after)
	}
	staged := filepath.Join(b.paths.stagingDir, upgradeTarget)
	if b.serve.copies != 1 || !slices.Equal(b.serve.imports, []string{staged}) {
		t.Fatalf("serve copied %d times, imported %v", b.serve.copies, b.serve.imports)
	}
	info, err := os.Stat(b.paths.stateFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state.json: %v %v", info, err)
	}
}

// treeOf rend chaque chemin sous dir avec sa taille, son mode et son heure,
// hors de la socket de contrôle.
func treeOf(t *testing.T, dir string) []string {
	t.Helper()
	var tree []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.Name() == brand.ControlSocketFile {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		tree = append(tree, path+" "+info.Mode().String()+" "+info.ModTime().String()+" "+strconv.FormatInt(info.Size(), 10))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

// R-B2-5 : lancé dans un terminal, upgrade se relance dans son unité
// transitoire ; la session coupée pendant « Serveur redémarré », il finit,
// et --status relit dans state.json une montée faite.
func TestR_B2_5_UpgradeSurvivesTheLossOfItsTerminal(t *testing.T) {
	b := newUpgradeBench(t)
	b.publish(b.private)
	b.afterStep = func(key step.Key) error {
		if key == step.UpgradeRestarted {
			b.terminal.close()
		}
		return nil
	}
	if err := b.upgrade(); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, b.terminal)
	}
	line := strings.Join(b.system.unitArgs, " ")
	if !strings.HasPrefix(line, "--unit="+brand.UpgradeUnit+" --pipe --wait ") || !strings.Contains(line, " upgrade --"+inUnitFlag) {
		t.Fatalf("systemd-run %s", line)
	}
	if !signal.Ignored(syscall.SIGHUP) || !signal.Ignored(syscall.SIGPIPE) {
		t.Fatal("the unit dies with its terminal")
	}
	if printed := b.terminal.String(); !strings.Contains(printed, "✓ Serveur redémarré") || strings.Contains(printed, "Serveur répond") {
		t.Fatalf("the terminal saw %q", printed)
	}
	if got := b.read(b.paths.binary); got != string(b.binaries[release.BinaryName(runtime.GOARCH)]) {
		t.Fatalf("binary %q", got)
	}
	if !slices.Equal(b.system.handOver, []string{b.paths.binary, "--" + inUnitFlag, "--" + finishFlag}) {
		t.Fatalf("hand over %v", b.system.handOver)
	}
	status := b.status()
	for _, label := range []string{"Version trouvée", "Place libre", "Base copiée", "Binaire remplacé", "Serveur redémarré", "Serveur répond", "Unités à jour", "Politique de l'agent"} {
		if !strings.Contains(status, "✓ "+label) {
			t.Errorf("status lacks ✓ %s:\n%s", label, status)
		}
	}
	if !strings.Contains(status, "Kagu est en "+upgradeTarget) {
		t.Fatalf("status %q", status)
	}
	if _, err := os.Stat(filepath.Join(b.paths.stagingDir, upgradeTarget)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("staged version left: %v", err)
	}
}

// R-B2-12 : le lanceur stable est recopié depuis la version vérifiée, jamais
// depuis bin/current de l'agent, que son compte peut réécrire.
func TestR_B2_12_UpgradeCopiesTheGuardFromTheVerifiedRelease(t *testing.T) {
	b := newUpgradeBench(t)
	b.publish(b.private)
	current := filepath.Join(b.paths.agentStateDir, brand.AgentBinDir, brand.AgentCurrentLink)
	writeBenchFile(t, current, "a binary the agent's account rewrote")
	if err := b.upgrade("--" + inUnitFlag); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, b.terminal)
	}
	guard := sha256.Sum256([]byte(b.read(b.paths.guardPath)))
	signed := sha256.Sum256(b.binaries[release.BinaryName(runtime.GOARCH)])
	if guard != signed {
		t.Fatalf("guard %x, signed %x", guard, signed)
	}
	if !strings.Contains(b.terminal.String(), "lanceur stable recopié") {
		t.Fatalf("printed %q", b.terminal)
	}
}

// Une installation faite à la main, sans setup.json : le binaire et la
// configuration se lisent dans l'ExecStart de l'unité ; ses unités ne sont
// pas touchées.
func TestUpgrade_ReadsAManualInstallationFromItsUnit(t *testing.T) {
	b := newUpgradeBench(t)
	b.publish(b.private)
	if err := os.Remove(b.paths.setupStateFile); err != nil {
		t.Fatal(err)
	}
	manual := filepath.Join(b.dir, "opt", brand.Command)
	mkdir(t, filepath.Dir(manual), 0o755)
	writeBenchFile(t, manual, "the binary in place")
	b.installed = manual
	unit := "[Service]\nExecStart=" + manual + " serve -config " + b.paths.configFile + "\n"
	writeBenchFile(t, filepath.Join(b.paths.unitDir, brand.ServerUnit), unit)
	if err := b.upgrade("--" + inUnitFlag); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, b.terminal)
	}
	if got := b.read(manual); got != string(b.binaries[release.BinaryName(runtime.GOARCH)]) {
		t.Fatalf("manual binary %q", got)
	}
	if got := b.read(filepath.Join(b.paths.unitDir, brand.ServerUnit)); got != unit {
		t.Fatalf("unit rewritten: %q", got)
	}
	if !strings.Contains(b.terminal.String(), "– Unités à jour") {
		t.Fatalf("printed %q", b.terminal)
	}
}

// Une version déjà dans la bibliothèque de serve s'installe sans réseau ni
// import ; une unité changée par la nouvelle version est réécrite.
func TestUpgrade_TakesTheLibraryVersionAndRewritesChangedUnits(t *testing.T) {
	b := newUpgradeBench(t)
	stateDir, err := os.OpenRoot(b.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer stateDir.Close()
	if _, err := release.NewLibrary(stateDir, b.keys).Import(releasetest.Write(t, b.private, upgradeTarget, b.binaries)); err != nil {
		t.Fatal(err)
	}
	writeBenchFile(t, filepath.Join(b.paths.unitDir, brand.ServerUnit), "[Service]\nExecStart=an older unit\n")
	if err := b.upgrade("--" + inUnitFlag); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, b.terminal)
	}
	if len(b.serve.imports) != 0 {
		t.Fatalf("imported %v", b.serve.imports)
	}
	if got := b.read(filepath.Join(b.paths.unitDir, brand.ServerUnit)); got != strings.Join(machine.ServerUnitLines(), "\n")+"\n" {
		t.Fatalf("unit %q", got)
	}
	if !slices.Contains(b.system.calls, "systemctl daemon-reload") {
		t.Fatalf("calls %v", b.system.calls)
	}
}

// Rien de plus récent : upgrade le dit et n'écrit pas d'état.
func TestUpgrade_SaysWhenNothingIsNewer(t *testing.T) {
	b := newUpgradeBench(t)
	if err := b.newRun(upgradeTarget).command(context.Background(), []string{"--" + inUnitFlag}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.terminal.String(), "aucune version plus récente que "+upgradeTarget) {
		t.Fatalf("printed %q", b.terminal)
	}
	if _, err := os.Stat(b.paths.stateFile); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("state written: %v", err)
	}
	b.nothingMoved()
}

// Refus : un autre compte que root, une montée qui tient le verrou, une
// version visée plus ancienne, une montée arrêtée après le binaire, la place
// qui manque. Rien ne bouge.
func TestUpgrade_RefusesAndTouchesNothing(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(b *upgradeBench) *upgradeRun
		args    []string
	}{
		{"not root", func(b *upgradeBench) *upgradeRun {
			run := b.newRun(version.Number())
			run.euid = 1000
			return run
		}, nil},
		{"locked", func(b *upgradeBench) *upgradeRun {
			unlock, held, err := holdLock(b.paths.lockFile)
			if err != nil || !held {
				t.Fatal(err)
			}
			t.Cleanup(unlock)
			return b.newRun(version.Number())
		}, []string{"--" + inUnitFlag}},
		{"older target", func(b *upgradeBench) *upgradeRun { return b.newRun(version.Number()) }, []string{"--" + inUnitFlag, "--to", "v0.0.1"}},
		{"interrupted", func(b *upgradeBench) *upgradeRun {
			mkdir(t, b.paths.stagingDir, 0o755)
			replaced := upgradeState{Target: upgradeTarget, Steps: []step.Step{{Key: step.UpgradeReplaced, State: step.StateDone, At: time.Now()}}}
			content, _ := json.Marshal(replaced)
			writeBenchFile(t, b.paths.stateFile, string(content))
			return b.newRun(version.Number())
		}, []string{"--" + inUnitFlag}},
		{"disk full", func(b *upgradeBench) *upgradeRun {
			b.system.free = 10
			return b.newRun(version.Number())
		}, []string{"--" + inUnitFlag}},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := newUpgradeBench(t)
			b.publish(b.private)
			run := test.prepare(b)
			var refused *refusal
			if err := run.command(context.Background(), test.args); !errors.As(err, &refused) {
				t.Fatalf("upgrade: %v", err)
			}
			if b.serve.copies != 0 || len(b.system.calls) != 0 || b.read(b.paths.binary) != "the binary in place" {
				t.Fatalf("something moved: %d copies, %v", b.serve.copies, b.system.calls)
			}
		})
	}
}

// Une redirection https vers un autre hôte est suivie, comme celle de GitHub
// vers son stockage : la signature, vérifiée ensuite, fait l'intégrité.
func TestUpgrade_FollowsAnHTTPSRedirectThenVerifies(t *testing.T) {
	b := newUpgradeBench(t)
	b.publish(b.private)
	b.redirectTo = b.mirror.URL + "/assets"
	if err := b.upgrade("--" + inUnitFlag); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, b.terminal)
	}
	if got := b.read(b.paths.binary); got != string(b.binaries[release.BinaryName(runtime.GOARCH)]) {
		t.Fatalf("binary %q", got)
	}
}

// Un agent qui lit encore ses droits dans identity.json : avant la relance,
// dans le terminal de root, upgrade affiche ce que la migration recopie et
// demande [o/N]. Oui : l'unité migre sans reposer la question. N par
// défaut, ou pas de terminal : arrêt avant la première coche, rien touché,
// la ligne à lancer à la main dite (décision ARB-1).
func TestUpgrade_AsksBeforeMigratingTheAgentPolicy(t *testing.T) {
	for _, test := range []struct {
		name     string
		terminal terminalOpener
		migrated bool
	}{
		{"yes", fakeTerminal("o\n"), true},
		{"no by default", fakeTerminal("\n"), false},
		{"no terminal", noTerminal, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := newUpgradeBench(t)
			b.publish(b.private)
			b.paths.agentStateDir, b.place = legacyState(t, "docker.deploy")
			b.openTerminal = test.terminal
			err := b.upgrade()
			printed := b.terminal.String()
			if !strings.Contains(printed, "+ docker.deploy") {
				t.Fatalf("the change is not told before the question:\n%s", printed)
			}
			if !test.migrated {
				var refused *refusal
				warning := testCatalog(t).Get("rights.paste_only_pending")
				if !errors.As(err, &refused) || !strings.Contains(refused.message, agentpolicy.MigrateLine()+", ") || !strings.HasSuffix(refused.message, "\n"+warning) {
					t.Fatalf("upgrade: %v", err)
				}
				if b.system.unitArgs != nil || strings.Contains(printed, "Version trouvée") || policyContent(t, b.place) != "" {
					t.Fatalf("something moved: unit %v\n%s", b.system.unitArgs, printed)
				}
				b.nothingMoved()
				return
			}
			if err != nil {
				t.Fatalf("upgrade: %v\n%s", err, printed)
			}
			if !b.system.consentAtRelaunch || strings.Count(printed, "[o/N]") != 1 || !strings.Contains(printed, "politique migrée") {
				t.Fatalf("consent at relaunch %v, unit %v\n%s", b.system.consentAtRelaunch, b.system.unitArgs, printed)
			}
			if strings.Contains(strings.Join(b.system.unitArgs, " "), "consent") {
				t.Fatalf("the consent rides on the command line: %v", b.system.unitArgs)
			}
			if state, err := readUpgradeState(b.paths.stateFile); err != nil || state.PolicyConsent || !state.Finished {
				t.Fatalf("the consent is not consumed: %+v %v", state, err)
			}
			if stored := storedPolicy(t, b.place); !slices.ContainsFunc(stored.Rights, func(right agentpolicy.Capability) bool { return right.Name == "docker.deploy" }) {
				t.Fatalf("stored %+v", stored)
			}
		})
	}
}

// Relancée dans l'unité sans l'accord du terminal, la montée ne migre pas la
// politique : la coche le dit.
func TestUpgrade_DoesNotMigrateWithoutConsent(t *testing.T) {
	b := newUpgradeBench(t)
	b.publish(b.private)
	b.paths.agentStateDir, b.place = legacyState(t, "docker.deploy")
	if err := b.upgrade("--" + inUnitFlag); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, b.terminal)
	}
	if policyContent(t, b.place) != "" || !strings.Contains(b.terminal.String(), "politique non migrée") {
		t.Fatalf("printed %q", b.terminal)
	}
}

// ARB-1 : aucune option ne pose le oui de root ; l'ancien drapeau interne est
// refusé par l'analyse des options.
func TestUpgrade_NoOptionCarriesThePolicyConsent(t *testing.T) {
	b := newUpgradeBench(t)
	b.paths.agentStateDir, b.place = legacyState(t, "docker.deploy")
	var refused *refusal
	err := b.upgrade("--"+inUnitFlag, "--policy-consented")
	if !errors.As(err, &refused) || refused.message != testCatalog(t).Get("upgrade.usage") {
		t.Fatalf("upgrade: %v", err)
	}
	if policyContent(t, b.place) != "" {
		t.Fatal("the policy was migrated")
	}
}

// R-B2-11, W-M7 : la version en place, v1.0.1 au plancher v1.0.1, est dans la
// bibliothèque de serve ; --to v1.0.0 est refusé avant toute copie, et le
// refus nomme le plancher.
func TestR_B2_11_UpgradeToBelowTheFloorIsRefused(t *testing.T) {
	b := newUpgradeBench(t)
	stateDir, err := os.OpenRoot(b.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer stateDir.Close()
	inPlace := releasetest.WriteWithFloor(t, b.private, "v1.0.1", "v1.0.1", releasetest.Binaries("v1.0.1", runtime.GOARCH))
	if _, err := release.NewLibrary(stateDir, b.keys).Import(inPlace); err != nil {
		t.Fatal(err)
	}
	var refused *refusal
	if err := b.newRun("v1.0.1").command(context.Background(), []string{"--" + inUnitFlag, "--to", "v1.0.0"}); !errors.As(err, &refused) {
		t.Fatalf("upgrade: %v", err)
	}
	if printed := b.terminal.String(); !strings.Contains(printed, "v1.0.0 est sous le plancher de sécurité v1.0.1 de la version en place (v1.0.1)") {
		t.Fatalf("printed %q", printed)
	}
	b.nothingMoved()
}
