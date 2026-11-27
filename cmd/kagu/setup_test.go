package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/edge/config"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/hostinfo"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/release/releasetest"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/kit/version"
)

// setupAgentUID est l'uid que le banc donne au compte de l'agent : la socket
// des agents n'admet que lui.
const setupAgentUID = 990

// syncBuffer est un journal que le serveur écrit pendant que le test le lit.
type syncBuffer struct {
	lock    sync.Mutex
	content bytes.Buffer
}

func (b *syncBuffer) Write(line []byte) (int, error) {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.content.Write(line)
}

func (b *syncBuffer) String() string {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.content.String()
}

// setupBench est une machine neuve : ses chemins sous un dossier court, un
// faux système (comptes, systemctl, enrôlement), et un vrai serve que
// « systemctl enable --now » démarre, socket de contrôle et socket des agents
// comprises.
type setupBench struct {
	t      *testing.T
	dir    string
	paths  setupPaths
	place  agent.PolicyPlace
	system *setupSystemFake
	logs   *syncBuffer
	parts  *components
	// Ce que setup a demandé à la route du jeton.
	enrollmentRequests int
	// Les clés de version que serve croit ; nil : celles du binaire.
	releaseKeys *release.Keys
	// Les sommes des archives de restic ; nil : celles de brand.
	resticSums map[string]string
}

func newSetupBench(t *testing.T) *setupBench {
	t.Helper()
	dir := shortDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, folder := range []string{"etc", "units"} {
		if err := os.Mkdir(filepath.Join(dir, folder), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, brand.Command)
	if err := os.WriteFile(binary, []byte("#!/bin/false\n"), 0o755); err != nil { // #nosec G306 -- un faux binaire de banc.
		t.Fatal(err)
	}
	b := &setupBench{t: t, dir: dir, logs: &syncBuffer{}}
	b.paths = setupPaths{
		configFile: filepath.Join(dir, "etc", brand.ID, "config.toml"), stateFile: filepath.Join(dir, "etc", brand.ID, "setup.json"),
		lockFile: filepath.Join(dir, "setup.lock"), stateDir: filepath.Join(dir, "state"), agentStateDir: filepath.Join(dir, "agent"),
		policyDir: filepath.Join(dir, "policy"), unitDir: filepath.Join(dir, "units"), binary: binary,
		guardPath: filepath.Join(dir, "guard", brand.AgentGuardBinary), agentSocket: filepath.Join(dir, "agent.sock"),
		releaseDir: filepath.Join(dir, "release"), dockerConfig: filepath.Join(dir, "docker", "daemon.json"),
		dockerKeyring: filepath.Join(dir, "apt", "docker.asc"), dockerSource: filepath.Join(dir, "apt", "docker.list"),
		resticBinary: filepath.Join(dir, "bin", "restic"),
	}
	b.place = agent.PolicyPlace{Dir: b.paths.policyDir, Owner: fsx.Owner{UID: os.Getuid(), GID: os.Getgid()}}
	b.system = &setupSystemFake{
		quietSystem: quietSystem{server: true}, bench: b, os: "Debian GNU/Linux 12", systemd: true,
		accounts: map[string]fsx.Owner{"root": {UID: os.Getuid(), GID: os.Getgid()}}, active: map[string]bool{},
		// Docker et restic déjà là : setup ne pose pas la question Docker.
		files:     map[string]bool{machine.DockerBinary: true, resticSystemBinary: true},
		downloads: map[string][]byte{},
	}
	return b
}

// run lance setup en root avec ces options, sur ce terminal ; cut arrête
// setup après l'étape qu'il nomme (vide : jusqu'au bout).
func (b *setupBench) run(terminal terminalOpener, cut step.Key, args ...string) (string, error) {
	b.t.Helper()
	var out bytes.Buffer
	run := setupRun{
		out: &out, openTerminal: terminal, euid: 0, system: b.system, paths: b.paths,
		place: func(*os.Root) (agent.PolicyPlace, error) { return b.place, nil }, wait: 5 * time.Second, poll: 10 * time.Millisecond,
		resticSums: b.resticSums,
	}
	if cut != "" {
		run.afterStep = func(key step.Key) error {
			if key == cut {
				return errSetupCut
			}
			return nil
		}
	}
	err := run.command(context.Background(), args)
	return out.String(), err
}

var errSetupCut = errors.New("session SSH coupée")

// started est ce que fait « systemctl enable --now » : serve ouvre ses
// sockets, l'agent rapporte ses droits.
func (b *setupBench) started(unit string) {
	switch unit {
	case brand.ServerUnit:
		b.startServe()
	case brand.AgentUnit:
		// Sur une machine ajoutée par join, serve est ailleurs.
		if b.parts != nil {
			b.reportAgent()
		}
	}
}

// startServe fait tourner le vrai serveur sur state_dir, comme l'unité :
// socket de contrôle à root, socket des agents au seul uid de l'agent.
func (b *setupBench) startServe() {
	t := b.t
	logger := slog.New(slog.NewTextHandler(b.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	_, parts, srv := realServerLogging(t, b.paths.stateDir, logger, b.trustReleaseKeys)
	parts.actions.SetKey(action.GenerateKey())
	hostname, _ := os.Hostname()
	parts.machines.SetServerHost(hostinfo.HostFingerprint(), hostname)
	b.parts = parts
	control := startControlSocket(logger, b.paths.stateDir, b.countEnrollments(srv.ControlHandler()), asRootPeer)
	if control == nil {
		t.Fatal("the control socket did not open")
	}
	t.Cleanup(func() { _ = control.Close() })
	agents := startAgentSocket(logger, b.paths.agentSocket, agentAccount{uid: setupAgentUID, gid: os.Getgid()}, srv.AgentSocketHandler(), peerOf(setupAgentUID))
	if agents == nil {
		t.Fatal("the agent socket did not open")
	}
	t.Cleanup(func() { _ = agents.Close() })
}

// trustReleaseKeys donne à la bibliothèque de serve les clés de test du banc.
func (b *setupBench) trustReleaseKeys(parts *components) {
	if b.releaseKeys == nil {
		return
	}
	root, err := os.OpenRoot(b.paths.stateDir)
	if err != nil {
		b.t.Fatal(err)
	}
	b.t.Cleanup(func() { _ = root.Close() })
	parts.releases = release.NewLibrary(root, *b.releaseKeys)
}

// countEnrollments compte les demandes de jeton de la machine Kagu.
func (b *setupBench) countEnrollments(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == controlLocalEnrollmentPath {
			b.enrollmentRequests++
		}
		next.ServeHTTP(w, r)
	})
}

// enroll joue « agent -enroll-only » : le vrai agent, par la vraie socket des
// agents locaux, avec le jeton reçu sur son entrée standard.
func (b *setupBench) enroll(args []string, token string) error {
	server := args[slices.Index(args, "-server")+1]
	serverKey := ""
	if at := slices.Index(args, "-server-key"); at >= 0 {
		serverKey = args[at+1]
	}
	root, err := os.OpenRoot(b.paths.agentStateDir)
	if err != nil {
		return err
	}
	defer root.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return agent.Run(ctx, agent.Options{
		StateDir: root, Server: server, ServerKey: serverKey, Token: token, EnrollOnly: true, Language: lang.French,
		Version: version.Number(), Logger: slog.New(slog.DiscardHandler),
	})
}

// reportAgent est le premier flux de l'agent : il rapporte les droits de sa
// politique, et ceux qu'il ne peut pas exercer.
func (b *setupBench) reportAgent() {
	t := b.t
	ctx := context.Background()
	local, err := b.parts.machines.Get(ctx, machine.LocalID)
	if err != nil {
		t.Fatalf("the agent starts without being the agent of the server machine: %v", err)
	}
	rights := storedPolicy(t, b.place).Rights
	if _, err := b.parts.machines.Connect(ctx, local.Machine, "127.0.0.1", version.Number(), agentpolicy.FormatCapabilities(rights), "",
		machine.FormatUnavailable(b.system.unavailable), "3"); err != nil {
		t.Fatal(err)
	}
}

// setupSystemFake est la machine du banc : quietSystem pour ce que grant
// pose, des comptes, des unités qui démarrent, l'enrôlement par le vrai agent.
type setupSystemFake struct {
	quietSystem
	bench       *setupBench
	os          string
	systemd     bool
	accounts    map[string]fsx.Owner
	active      map[string]bool
	unavailable map[string]string
	calls       []string
	enrollments []string
	// files : les programmes de la machine (Docker, restic) ; downloads : ce
	// que chaque adresse sert.
	files     map[string]bool
	downloads map[string][]byte
}

func (s *setupSystemFake) Exists(path string) bool { return s.files[path] }

func (s *setupSystemFake) Release() hostinfo.Release {
	return hostinfo.Release{ID: "debian", VersionID: "12", Codename: "bookworm"}
}

func (s *setupSystemFake) Download(url string, limit int64) ([]byte, error) {
	s.calls = append(s.calls, "download "+url)
	content, found := s.downloads[url]
	if !found {
		return nil, errors.New("404 Not Found")
	}
	if int64(len(content)) > limit {
		return nil, errors.New("too large")
	}
	return content, nil
}

// InstallPackages pose Docker : son programme et son groupe apparaissent.
// Le plafond des journaux déjà écrit se note : le démon le lit à son premier
// démarrage, celui de l'installation.
func (s *setupSystemFake) InstallPackages(packages []string) error {
	if _, err := os.Stat(s.bench.paths.dockerConfig); err == nil {
		s.calls = append(s.calls, "daemon.json before apt-get")
	}
	s.calls = append(s.calls, "apt-get install "+strings.Join(packages, " "))
	s.files[machine.DockerBinary] = true
	s.noDocker = false
	return nil
}

func (s *setupSystemFake) Account(name string) (fsx.Owner, bool, error) {
	owner, found := s.accounts[name]
	return owner, found, nil
}

func (s *setupSystemFake) Systemd() bool                    { return s.systemd }
func (s *setupSystemFake) FreeBytes(string) (uint64, error) { return 8 << 30, nil }
func (s *setupSystemFake) OSName() string                   { return s.os }
func (s *setupSystemFake) Address() string                  { return "203.0.113.7" }

func (s *setupSystemFake) Run(name string, args ...string) error {
	s.calls = append(s.calls, name+" "+strings.Join(args, " "))
	if name == "useradd" {
		s.accounts[args[len(args)-1]] = fsx.Owner{UID: os.Getuid(), GID: os.Getgid()}
		return nil
	}
	if name != "systemctl" {
		return s.quietSystem.Run(name, args...)
	}
	switch args[0] {
	case "is-active":
		if !s.active[args[len(args)-1]] {
			return errors.New("inactive")
		}
	case "enable", "restart":
		unit := args[len(args)-1]
		s.active[unit] = true
		s.bench.started(unit)
	case "try-restart":
		// Une unité que systemd ne connaît pas : grant échouerait.
		if _, err := os.Stat(filepath.Join(s.bench.paths.unitDir, args[len(args)-1])); err != nil {
			return errors.New("unit not found")
		}
	}
	return nil
}

// MakeFolder crée pour de vrai ce qui est sous le dossier du banc, et note
// le reste (la racine des services, le dossier des sauvegardes de la base).
func (s *setupSystemFake) MakeFolder(path string, mode fs.FileMode, owner fsx.Owner) error {
	if !strings.HasPrefix(path, s.bench.dir+"/") {
		return s.quietSystem.MakeFolder(path, mode, owner)
	}
	s.calls = append(s.calls, "folder "+path)
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return os.Chmod(path, mode)
}

func (s *setupSystemFake) EnrollAgent(_ fsx.Owner, args []string, token string) error {
	s.calls = append(s.calls, "enroll "+strings.Join(args, " "))
	s.enrollments = append(s.enrollments, token)
	return s.bench.enroll(args, token)
}

// gestures rend ce que setup a changé sur le système, dans l'ordre : tout
// sauf les lectures (is-active), le dossier du banc effacé des chemins.
func (s *setupSystemFake) gestures() []string {
	var gestures []string
	for _, call := range s.calls {
		if !strings.HasPrefix(call, "systemctl is-active") {
			gestures = append(gestures, strings.ReplaceAll(call, s.bench.dir, "<banc>"))
		}
	}
	return gestures
}

// count dit combien de gestes du système commencent par prefix.
func (s *setupSystemFake) count(prefix string) int {
	n := 0
	for _, call := range s.calls {
		if strings.HasPrefix(call, prefix) {
			n++
		}
	}
	return n
}

// countSuffix dit combien de gestes commencent par prefix et finissent par
// suffix.
func (s *setupSystemFake) countSuffix(prefix, suffix string) int {
	n := 0
	for _, call := range s.calls {
		if strings.HasPrefix(call, prefix) && strings.HasSuffix(call, suffix) {
			n++
		}
	}
	return n
}

// setupCode lit le code de première configuration à la fin de la sortie.
var setupCode = regexp.MustCompile(`Code de première configuration : (\S+)`)

// R-B1-3 : setup coupé après chaque étape, puis relancé, finit
// l'installation sans doublon : un useradd par compte, chaque unité écrite
// et démarrée une fois, un jeton demandé et servi une fois. Ce qui était
// fait se coche « déjà fait ». Le jeton n'est ni dans setup.json, ni dans
// la sortie, ni dans un argument de processus, ni au journal de serve.
func TestR_B1_3_ResumeAfterACutAtEachStepWithoutDuplicates(t *testing.T) {
	baseline := newSetupBench(t)
	if out, err := baseline.run(noTerminal, ""); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, account := range []string{brand.ServerAccount, brand.AgentAccount} {
		if got := baseline.system.countSuffix("useradd ", " "+account); got != 1 {
			t.Fatalf("useradd %s: %d calls, want 1", account, got)
		}
	}
	for _, unit := range []string{brand.ServerUnit, brand.AgentUnit} {
		if got := baseline.system.count("systemctl enable --now " + unit); got != 1 {
			t.Fatalf("%s enabled %d times, want 1", unit, got)
		}
	}
	steps := (&setupRun{}).steps()
	for index, cut := range steps {
		t.Run(string(cut.key), func(t *testing.T) {
			b := newSetupBench(t)
			first, err := b.run(noTerminal, cut.key)
			if !errors.Is(err, errSetupCut) {
				t.Fatalf("cut after %s: %v\n%s", cut.key, err, first)
			}
			second, err := b.run(noTerminal, "")
			if err != nil {
				t.Fatalf("resume: %v\n%s", err, second)
			}
			for _, done := range steps[1 : index+1] {
				if done.key == step.EnrollWorkspace {
					continue
				}
				line := lineOf(t, second, b.text(t).Get(string(done.key)))
				if !strings.Contains(line, "déjà fait") {
					t.Errorf("resumed %s: %q, want « déjà fait »", done.key, line)
				}
			}
			if got, want := b.system.gestures(), baseline.system.gestures(); !slices.Equal(got, want) {
				t.Errorf("cut and resumed, the system got:\n%s\nin one run:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			if b.enrollmentRequests != 1 || len(b.system.enrollments) != 1 {
				t.Fatalf("%d token requests, %d enrollments, want 1 and 1", b.enrollmentRequests, len(b.system.enrollments))
			}
			requireTokenNowhere(t, b, b.system.enrollments[0], first+second)
		})
	}
}

// requireTokenNowhere : le jeton n'est ni dans setup.json, ni dans la
// sortie, ni dans un argument passé à un processus, ni au journal de serve.
func requireTokenNowhere(t *testing.T, b *setupBench, token, output string) {
	t.Helper()
	if !strings.HasPrefix(token, brand.EnrollmentTokenScheme) {
		t.Fatalf("the agent did not receive an enrollment token: %q", token)
	}
	saved, err := os.ReadFile(b.paths.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	for place, text := range map[string]string{
		"setup.json": string(saved), "the output": output, "the process arguments": strings.Join(b.system.calls, "\n"), "the serve log": b.logs.String(),
	} {
		if strings.Contains(text, token) {
			t.Errorf("the token is in %s", place)
		}
	}
}

// text rend le catalogue de setup.
func (b *setupBench) text(t *testing.T) lang.Catalog {
	t.Helper()
	catalogs, err := lang.Load()
	if err != nil {
		t.Fatal(err)
	}
	return catalogs.For(lang.Default)
}

// lineOf rend la ligne de la sortie qui porte ce libellé.
func lineOf(t *testing.T, output, label string) string {
	t.Helper()
	for line := range strings.SplitSeq(output, "\n") {
		if strings.Contains(line, label) {
			return line
		}
	}
	t.Fatalf("no line %q in:\n%s", label, output)
	return ""
}

// R-B1-3 : deux setup en même temps, le second s'arrête sur le verrou, sans
// rien toucher.
func TestR_B1_3_SecondSetupStopsOnTheLock(t *testing.T) {
	b := newSetupBench(t)
	release, held, err := holdLock(b.paths.lockFile)
	if err != nil || !held {
		t.Fatalf("the first setup did not take the lock: %v %v", held, err)
	}
	defer release()
	out, err := b.run(noTerminal, "")
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "Un autre setup tourne") {
		t.Fatalf("got %v", err)
	}
	if out != "" || len(b.system.calls) != 0 {
		t.Fatalf("the second setup did something: %q %v", out, b.system.calls)
	}
	release()
	if _, err := b.run(noTerminal, ""); err != nil {
		t.Fatalf("the lock released, setup runs: %v", err)
	}
}

// R-B1-1 : une seule question, le jeu ; sans terminal, le jeu par défaut
// vaut sans rien demander. --domain et --proxy sont refusés avant tout.
func TestR_B1_1_SetupAsksOnlyTheRightsAndDefaultsWithoutATerminal(t *testing.T) {
	silent := newSetupBench(t)
	out, err := silent.run(noTerminal, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "?") {
		t.Fatalf("a question without a terminal:\n%s", out)
	}
	if state := savedSetupState(t, silent); state.Rights != defaultSetupRights {
		t.Fatalf("rights %q, want the default %q", state.Rights, defaultSetupRights)
	}

	asked := newSetupBench(t)
	out, err = asked.run(fakeTerminal("1\n"), "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if questions := strings.Count(out, "? "); questions != 1 {
		t.Fatalf("%d questions, want 1:\n%s", questions, out)
	}
	if state := savedSetupState(t, asked); state.Rights != agentpolicy.SetObserve {
		t.Fatalf("rights %q, want observe", state.Rights)
	}

	for _, option := range [][]string{{"--domain", "kagu.exemple.fr"}, {"--domain="}, {"--proxy", "existing"}} {
		b := newSetupBench(t)
		out, err := b.run(noTerminal, "", option...)
		var refused *refusal
		if !errors.As(err, &refused) || !strings.Contains(refused.message, "--domain et --proxy") {
			t.Fatalf("%v: got %v", option, err)
		}
		if out != "" || len(b.system.calls) != 0 {
			t.Fatalf("%v: setup did something: %q %v", option, out, b.system.calls)
		}
	}
	b := newSetupBench(t)
	if _, err := b.run(noTerminal, "", "--rights", "everything"); err == nil || len(b.system.calls) != 0 {
		t.Fatalf("an unknown set: %v %v", err, b.system.calls)
	}
}

func savedSetupState(t *testing.T, b *setupBench) setupState {
	t.Helper()
	state, err := readSetupState(b.paths.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// R-B1-2 : une étape en échec s'écrit avec sa raison, setup dit quoi faire
// et s'arrête là. Sans systemd, rien n'est créé ; sans Docker, « Dossier des
// services » n'est pas cochée en vert, et aucun code n'est donné.
func TestR_B1_2_AFailedStepStopsSetupWithItsReason(t *testing.T) {
	b := newSetupBench(t)
	b.system.systemd = false
	out, err := b.run(noTerminal, "")
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "installez à la main") {
		t.Fatalf("got %v", err)
	}
	if line := lineOf(t, out, "Système reconnu"); !strings.HasPrefix(line, "  ✗") || !strings.Contains(line, "systemd ne mène pas") {
		t.Fatalf("the failed line: %q", line)
	}
	if strings.Contains(out, "Compte") || len(b.system.calls) != 0 {
		t.Fatalf("setup went on after the failure:\n%s\n%v", out, b.system.calls)
	}

	noDocker := newSetupBench(t)
	noDocker.system.unavailable = map[string]string{agentpolicy.CapabilityDockerDeploy: "docker_missing"}
	out, err = noDocker.run(noTerminal, "", "--rights", "manage")
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "Installez Docker") {
		t.Fatalf("got %v\n%s", err, out)
	}
	if line := lineOf(t, out, "Dossier des services"); !strings.HasPrefix(line, "  ✗") || !strings.Contains(line, "Docker n'est pas installé") {
		t.Fatalf("the failed line: %q", line)
	}
	if setupCode.MatchString(out) {
		t.Fatalf("a code after a failed step:\n%s", out)
	}
	state := savedSetupState(t, noDocker)
	if last := state.Steps[len(state.Steps)-1]; last.Key != step.EnrollWorkspace || last.State != step.StateFailed {
		t.Fatalf("setup.json does not keep the failure: %+v", last)
	}
}

// R-B1-6, R-SAUV-2 : quel que soit le jeu, la politique porte ses droits,
// backup.receive sur le dossier des sauvegardes de la base et la clé du
// serveur ; « Gérer en root » se dit avant d'être posé (R-DROIT-5).
func TestR_B1_6_SetupWritesTheRightsSetInThePolicy(t *testing.T) {
	for _, set := range agentpolicy.Sets() {
		t.Run(string(set), func(t *testing.T) {
			b := newSetupBench(t)
			out, err := b.run(noTerminal, "", "--rights", string(set))
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			policy := storedPolicy(t, b.place)
			if !agentpolicy.CoversSet(policy.Rights, set) {
				t.Errorf("the policy lacks the %s set: %v", set, policy.Rights)
			}
			if !agentpolicy.CoversPath(policy.Rights, agentpolicy.CapabilityBackupReceive, brand.AgentDatabaseBackupsDir) {
				t.Errorf("the policy lacks backup.receive=%s: %v", brand.AgentDatabaseBackupsDir, policy.Rights)
			}
			if len(policy.ServerKeys) != 1 {
				t.Errorf("server keys: %v", policy.ServerKeys)
			}
			announce := b.text(t).Get("agent.policy_root_on_server")
			announced := strings.Index(out, announce)
			if (set == agentpolicy.SetRoot) != (announced >= 0) {
				t.Fatalf("%s: announced %v\n%s", set, announced >= 0, out)
			}
			if set == agentpolicy.SetRoot && announced > strings.Index(out, "Agent de cette machine") {
				t.Fatalf("root announced after it was laid:\n%s", out)
			}
		})
	}
}

// R-B1-8 : sans domaine, listen vaut la boucle locale et la fin donne le
// tunnel et l'adresse locale.
func TestR_B1_8_ListenIsLoopbackWithoutDomain(t *testing.T) {
	b := newSetupBench(t)
	out, err := b.run(noTerminal, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cfg, _, err := config.Load(b.paths.configFile)
	if err != nil || cfg.Listen != "127.0.0.1:8080" || cfg.StateDir != b.paths.stateDir {
		t.Fatalf("config %+v %v", cfg, err)
	}
	for _, want := range []string{"ssh -L 8080:127.0.0.1:8080 root@203.0.113.7", "http://localhost:8080"} {
		if !strings.Contains(out, want) {
			t.Errorf("the end lacks %q:\n%s", want, out)
		}
	}
}

// R-B1-9 : le code vient en dernier ; un setup relancé en tire un neuf, qui
// annule l'ancien. Le compte créé, setup le dit et ne donne plus de code.
func TestR_B1_9_TheCodeIsLastAndANewRunReplacesIt(t *testing.T) {
	b := newSetupBench(t)
	first, err := b.run(noTerminal, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, first)
	}
	firstCode := lastSetupCode(t, first)
	second, err := b.run(noTerminal, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, second)
	}
	secondCode := lastSetupCode(t, second)
	if secondCode == firstCode {
		t.Fatalf("the second run gave the same code %s", firstCode)
	}
	ctx := context.Background()
	operator := b.parts.operator
	if _, _, err := operator.SetupNative(ctx, auth.State{Mode: auth.ModeNone}, firstCode, "lucas", "correct horse battery", auth.SessionClient{}); err == nil {
		t.Fatal("the replaced code still opens the first setup")
	}
	if _, _, err := operator.SetupNative(ctx, auth.State{Mode: auth.ModeNone}, secondCode, "lucas", "correct horse battery", auth.SessionClient{}); err != nil {
		t.Fatalf("the new code: %v", err)
	}
	third, err := b.run(noTerminal, "")
	if err != nil || setupCode.MatchString(third) || !strings.Contains(third, b.text(t).Get("admin.setup_already_done")) {
		t.Fatalf("with the account created: %v\n%s", err, third)
	}
}

// lastSetupCode lit le code, et vérifie que rien ne le suit que les lignes
// du même message.
func lastSetupCode(t *testing.T, output string) string {
	t.Helper()
	match := setupCode.FindStringSubmatchIndex(output)
	if match == nil {
		t.Fatalf("no code in:\n%s", output)
	}
	if rest := output[match[1]:]; strings.Contains(rest, "✓") || strings.Contains(rest, "Tunnel") {
		t.Fatalf("something follows the code:\n%s", rest)
	}
	return output[match[2]:match[3]]
}

// R-CNX-5 : setup n'écrit jamais une adresse publique sans HTTPS ; le refus
// dit quoi écrire, et le fichier n'existe pas.
func TestR_CNX_5_SetupRefusesAPublicListenWithoutHTTPS(t *testing.T) {
	b := newSetupBench(t)
	if err := os.Mkdir(filepath.Dir(b.paths.configFile), 0o750); err != nil {
		t.Fatal(err)
	}
	run := setupRun{text: b.text(t), paths: b.paths}
	for _, listen := range []string{"203.0.113.7:8080", "0.0.0.0:8080", "[2001:db8::1]:8080"} {
		_, err := run.writeServerConfig(listen, fsx.Owner{UID: os.Getuid(), GID: os.Getgid()})
		var refused *refusal
		if !errors.As(err, &refused) || !strings.Contains(refused.message, listen) {
			t.Fatalf("%s: got %v", listen, err)
		}
		if _, err := os.Stat(b.paths.configFile); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: the file was written", listen)
		}
	}
	// Un fichier déjà là qui sert en clair hors de la machine arrête setup
	// avant le serveur.
	if err := os.WriteFile(b.paths.configFile, []byte("listen = \"203.0.113.7:8080\"\nstate_dir = \""+b.paths.stateDir+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := b.run(noTerminal, "")
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "203.0.113.7:8080") || b.system.count("systemctl") != 0 {
		t.Fatalf("got %v %v\n%s", err, b.system.calls, out)
	}
}

// setup est réservé à root, refusé avant le verrou et la question.
func TestSetup_RefusesANonRootAccount(t *testing.T) {
	b := newSetupBench(t)
	run := setupRun{out: &bytes.Buffer{}, openTerminal: noTerminal, euid: 1000, system: b.system, paths: b.paths}
	err := run.command(context.Background(), nil)
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "sudo") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(b.paths.lockFile); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a refused account took the lock")
	}
}

// setup.json : root seul le lit, et il ne porte que la réponse et les étapes.
func TestSetup_StateFileIsPrivateAndCarriesNoSecret(t *testing.T) {
	b := newSetupBench(t)
	if out, err := b.run(noTerminal, ""); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	info, err := os.Stat(b.paths.stateFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("setup.json %v %v", info, err)
	}
	content, err := os.ReadFile(b.paths.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"rights", "steps"}) {
		t.Fatalf("setup.json carries %v", keys)
	}
}

// La socket de contrôle sert le jeton à root seul : setup le demande, un
// autre compte reçoit 403.
func TestSetup_LocalEnrollmentIsForRootOnly(t *testing.T) {
	_, _, srv := realServer(t, filepath.Join(shortDir(t), "state"))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://control"+controlLocalEnrollmentPath, nil)
	srv.ControlHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || strings.Contains(recorder.Body.String(), brand.EnrollmentTokenScheme) {
		t.Fatalf("an unknown peer: %d %s", recorder.Code, recorder.Body.String())
	}
}

// setupRelease donne au banc une version signée par une clé de test, posée
// où install.sh la laisse ; serve croit trusted.
func setupRelease(t *testing.T, b *setupBench, signer release.PrivateKey, trusted release.PublicKey) {
	t.Helper()
	b.releaseKeys = &release.Keys{Current: trusted}
	b.paths.releaseDir = releasetest.Write(t, signer, "v1.0.0", releasetest.Binaries("v1.0.0", "amd64", "arm64"))
}

// La version qu'install.sh a vérifiée entre dans la bibliothèque par serve,
// sous son compte ; l'adresse des versions passée par install.sh s'écrit
// dans config.toml. Relancé, setup réimporte sans rien changer.
func TestSetup_ImportsTheReleaseInstallShLeft(t *testing.T) {
	public, private, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := newSetupBench(t)
	setupRelease(t, b, private, public)
	const mirror = "https://mirror.example.org/kagu"
	for range 2 {
		out, err := b.run(noTerminal, "", "--releases-url", mirror)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if line := lineOf(t, out, "Serveur démarré"); !strings.Contains(line, "version v1.0.0 dans la bibliothèque") {
			t.Fatalf("the server line: %q", line)
		}
	}
	versions, err := b.parts.releases.Versions()
	if err != nil || len(versions) != 1 || versions[0].String() != "v1.0.0" {
		t.Fatalf("library %v %v", versions, err)
	}
	cfg, _, err := config.Load(b.paths.configFile)
	if err != nil || cfg.ReleasesURL != mirror {
		t.Fatalf("releases_url %q %v", cfg.ReleasesURL, err)
	}
}

// Sans install.sh, setup n'importe rien et l'adresse des versions reste celle
// par défaut, non écrite.
func TestSetup_WithoutInstallShImportsNothing(t *testing.T) {
	b := newSetupBench(t)
	out, err := b.run(noTerminal, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if line := lineOf(t, out, "Serveur démarré"); strings.Contains(line, "bibliothèque") {
		t.Fatalf("the server line: %q", line)
	}
	content, err := os.ReadFile(b.paths.configFile)
	if err != nil || strings.Contains(string(content), "releases_url") {
		t.Fatalf("config.toml %v:\n%s", err, content)
	}
}

// Une version que serve refuse (signée par une autre clé que les siennes)
// arrête setup sur la ligne du serveur, avec la raison de serve ; rien n'entre
// dans la bibliothèque, et l'agent ne s'installe pas.
func TestSetup_StopsOnAReleaseServeRefuses(t *testing.T) {
	trusted, _, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := newSetupBench(t)
	setupRelease(t, b, other, trusted)
	out, err := b.run(noTerminal, "")
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "install.sh") {
		t.Fatalf("got %v\n%s", err, out)
	}
	if line := lineOf(t, out, "Serveur démarré"); !strings.HasPrefix(line, "  ✗") || !strings.Contains(line, "aucune des clés de version") {
		t.Fatalf("the failed line: %q", line)
	}
	if versions, err := b.parts.releases.Versions(); err != nil || len(versions) != 0 {
		t.Fatalf("library %v %v", versions, err)
	}
	if strings.Contains(out, "Agent de cette machine") {
		t.Fatalf("setup went on:\n%s", out)
	}
}
