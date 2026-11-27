package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/store"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/release/releasetest"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/kit/version"
)

// failingUpgradeBench est la machine Kagu dont la version visée a une
// migration qui échoue : serve copie vraiment sa base, puis y écrit encore
// avant l'arrêt.
func failingUpgradeBench(t *testing.T) *upgradeBench {
	t.Helper()
	b := newUpgradeBench(t)
	b.publish(b.private)
	b.serve.writesCopy = true
	b.system.failingMigration = true
	b.afterStep = func(key step.Key) error {
		if key == step.UpgradeCopied {
			writeBenchFile(t, b.database(), "the database, then what serve wrote after the copy")
		}
		return nil
	}
	return b
}

func (b *upgradeBench) database() string {
	return filepath.Join(b.stateDir, brand.DatabaseFile)
}

func (b *upgradeBench) copyPath() string {
	return filepath.Join(b.stateDir, brand.UpgradeDir, brand.UpgradeCopyPrefix+version.Number()+".db")
}

func (b *upgradeBench) faultyPath(name string) string {
	return filepath.Join(b.stateDir, brand.UpgradeDir, name)
}

// wantRolledBack : une montée ratée revient et le dit.
func (b *upgradeBench) wantRolledBack(err error) {
	t := b.t
	t.Helper()
	var refused *refusal
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "est revenu en "+version.Number()) {
		t.Fatalf("upgrade: %v\n%s", err, b.terminal)
	}
	printed := b.terminal.String()
	for _, want := range []string{"✗ Serveur répond", "✓ Retour arrière", "revenu en " + version.Number(), "est perdu", "Base fautive gardée : "} {
		if !strings.Contains(printed, want) {
			t.Errorf("printed lacks %q:\n%s", want, printed)
		}
	}
}

// R-B2-3 : la nouvelle version ne répond pas (une migration échoue) ;
// upgrade arrête serve, remet l'ancien binaire et la copie, octet pour
// octet, au compte de serve en 0600, sans -wal ni -shm à côté, relance et
// attend la version d'avant.
func TestR_B2_3_ASilentServerBringsBackTheOldBinaryAndTheCopy(t *testing.T) {
	b := failingUpgradeBench(t)
	b.wantRolledBack(b.upgrade("--" + inUnitFlag))
	copied := b.read(b.copyPath())
	if copied != "the database" {
		t.Fatalf("copy %q", copied)
	}
	if got := b.read(b.database()); got != copied {
		t.Fatalf("restored database %q, copy %q", got, copied)
	}
	if b.system.databaseAtStart != copied {
		t.Fatalf("serve started on %q", b.system.databaseAtStart)
	}
	info, err := os.Stat(b.database())
	if err != nil || info.Mode().Perm() != store.UpgradeCopyMode {
		t.Fatalf("restored database: %v %v", info, err)
	}
	if !ownedByCaller(info) {
		t.Fatal("the restored database is not the copy's owner's")
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(b.database() + suffix); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left next to the restored database: %v", suffix, err)
		}
	}
	if got := b.read(b.paths.binary); got != "the binary in place" {
		t.Fatalf("binary %q", got)
	}
	wantCalls := []string{"systemctl restart " + brand.ServerUnit, "systemctl stop " + brand.ServerUnit, "systemctl start " + brand.ServerUnit}
	if !slices.Equal(b.system.calls, wantCalls) {
		t.Fatalf("calls %v", b.system.calls)
	}
	if b.system.handOver != nil {
		t.Fatalf("handed over to %v", b.system.handOver)
	}
	state, err := readUpgradeState(b.paths.stateFile)
	if err != nil || !state.RollbackStarted || state.Finished {
		t.Fatalf("state %+v %v", state, err)
	}
	// Revenue, la montée n'en bloque pas une autre.
	run := b.newRun(version.Number())
	run.state = state
	if run.interrupted() {
		t.Fatal("a rolled back upgrade blocks the next one")
	}
}

// R-B2-4 : la base fautive est gardée sous echec-<version visée>.db, avec
// ses -wal et -shm ; une deuxième montée ratée vers la même version n'écrase
// pas la première.
func TestR_B2_4_TheFaultyDatabaseIsKept(t *testing.T) {
	b := failingUpgradeBench(t)
	b.wantRolledBack(b.upgrade("--" + inUnitFlag))
	first := brand.UpgradeFailedPrefix + upgradeTarget + ".db"
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if got := b.read(b.faultyPath(first + suffix)); got != "faulty"+suffix {
			t.Fatalf("%s%s: %q", first, suffix, got)
		}
	}
	if !strings.Contains(b.terminal.String(), "Base fautive gardée : "+b.faultyPath(first)) {
		t.Fatalf("printed %q", b.terminal)
	}

	b.system.calls = nil
	b.wantRolledBack(b.upgrade("--" + inUnitFlag))
	second := brand.UpgradeFailedPrefix + upgradeTarget + "-2.db"
	if b.read(b.faultyPath(first)) != "faulty" || b.read(b.faultyPath(second)) != "faulty" {
		t.Fatal("the second faulty database is not kept apart")
	}
}

// Un retour raté ne se rejoue pas : upgrade s'arrête, écrit les trois
// commandes à jouer à la main, et ne touche plus à rien, même relancé.
func TestUpgrade_AFailedRollbackStopsAndGivesTheCommands(t *testing.T) {
	b := failingUpgradeBench(t)
	b.system.startFails = true
	err := b.upgrade("--" + inUnitFlag)
	var refused *refusal
	if !errors.As(err, &refused) {
		t.Fatalf("upgrade: %v\n%s", err, b.terminal)
	}
	for _, want := range []string{
		"systemctl stop " + brand.ServerUnit,
		"install -m 0755 " + b.paths.previous + " " + b.paths.binary,
		"install -o " + brand.ServerAccount + " -g " + brand.ServerAccount + " -m 0600 " + b.copyPath() + " " + b.database(),
	} {
		if !strings.Contains(refused.message, want) {
			t.Errorf("message lacks %q:\n%s", want, refused.message)
		}
	}
	if !strings.Contains(b.terminal.String(), "✗ Retour arrière") {
		t.Fatalf("printed %q", b.terminal)
	}

	b.system.calls = nil
	b.system.startFails = false
	before := treeOf(t, b.stateDir)
	err = b.newRun(version.Number()).command(context.Background(), []string{"--" + inUnitFlag, "--" + resumeFlag})
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "install -m 0755") {
		t.Fatalf("resume: %v", err)
	}
	if len(b.system.calls) != 0 || !slices.Equal(before, treeOf(t, b.stateDir)) {
		t.Fatalf("the second try touched something: %v", b.system.calls)
	}
}

// interruptedAt écrit l'état d'une montée coupée (machine redémarrée) après
// last : le nouveau binaire posé, l'ancien gardé, la copie faite.
func (b *upgradeBench) interruptedAt(last step.Key) {
	t := b.t
	t.Helper()
	var steps []step.Step
	for _, current := range startSteps {
		steps = append(steps, step.Step{Key: current.key, State: step.StateDone, At: time.Now().UTC()})
		if current.key == last {
			break
		}
	}
	staged := releasetest.Write(t, b.private, upgradeTarget, b.binaries)
	state := upgradeState{
		Running: version.Number(), Target: upgradeTarget, Binary: b.paths.binary, Previous: b.paths.previous,
		StateDir: b.stateDir, Staged: staged, Copy: b.copyPath(), Steps: steps,
	}
	mkdir(t, filepath.Dir(b.paths.stateFile), 0o755)
	content, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	writeBenchFile(t, b.paths.stateFile, string(content))
	mkdir(t, filepath.Dir(b.copyPath()), 0o700)
	writeBenchFile(t, b.copyPath(), "the database")
	mkdir(t, filepath.Dir(b.paths.previous), 0o755)
	writeBenchFile(t, b.paths.previous, "the binary in place")
	writeBenchFile(t, b.paths.binary, string(b.binaries[release.BinaryName(runtime.GOARCH)]))
}

// --resume part de l'étape écrite : la nouvelle version répond, la montée
// finit ; elle reste muette, upgrade revient ; un retour fait à la main est
// noté ; rien à reprendre, il le dit.
func TestUpgrade_ResumeFinishesOrRollsBackFromTheWrittenStep(t *testing.T) {
	for _, test := range []struct {
		name    string
		last    step.Key
		prepare func(b *upgradeBench)
		check   func(b *upgradeBench, err error)
	}{
		{"rebooted after the binary, the new version answers", step.UpgradeReplaced, func(b *upgradeBench) {}, func(b *upgradeBench, err error) {
			if err != nil {
				t.Fatalf("resume: %v\n%s", err, b.terminal)
			}
			if !slices.Equal(b.system.calls, []string{"systemctl restart " + brand.ServerUnit}) || b.system.handOver == nil {
				t.Fatalf("calls %v, hand over %v", b.system.calls, b.system.handOver)
			}
			if state, _ := readUpgradeState(b.paths.stateFile); !state.Finished {
				t.Fatalf("not finished: %+v", state)
			}
		}},
		{"restarted, the new version stays silent", step.UpgradeRestarted, func(b *upgradeBench) {
			b.serve.stops()
			writeBenchFile(t, b.database(), "faulty")
		}, func(b *upgradeBench, err error) {
			b.wantRolledBack(err)
			if b.read(b.database()) != "the database" || b.read(b.paths.binary) != "the binary in place" {
				t.Fatal("not rolled back")
			}
			if b.read(b.faultyPath(brand.UpgradeFailedPrefix+upgradeTarget+".db")) != "faulty" {
				t.Fatal("faulty database not kept")
			}
		}},
		{"answered, the end not played", step.UpgradeAnswers, func(b *upgradeBench) {
			b.serve.runs(upgradeTarget)
		}, func(b *upgradeBench, err error) {
			if err != nil || len(b.system.calls) != 0 || b.system.handOver == nil {
				t.Fatalf("resume: %v, calls %v, hand over %v", err, b.system.calls, b.system.handOver)
			}
		}},
		{"rollback done by hand", step.UpgradeRestarted, func(b *upgradeBench) {
			state, _ := readUpgradeState(b.paths.stateFile)
			state.RollbackStarted = true
			content, _ := json.Marshal(state)
			writeBenchFile(t, b.paths.stateFile, string(content))
		}, func(b *upgradeBench, err error) {
			if err != nil || len(b.system.calls) != 0 {
				t.Fatalf("resume: %v, calls %v", err, b.system.calls)
			}
			if !strings.Contains(b.terminal.String(), "✓ Retour arrière") || !strings.Contains(b.terminal.String(), "à la main") {
				t.Fatalf("printed %q", b.terminal)
			}
			b.terminal = &cutTerminal{}
			if err := b.newRun(version.Number()).command(context.Background(), []string{"--" + inUnitFlag, "--" + resumeFlag}); err != nil || !strings.Contains(b.terminal.String(), "Rien à reprendre") {
				t.Fatalf("second resume: %v %q", err, b.terminal)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := newUpgradeBench(t)
			b.interruptedAt(test.last)
			test.prepare(b)
			test.check(b, b.newRun(upgradeTarget).command(context.Background(), []string{"--" + resumeFlag}))
		})
	}
}

// --resume se relance dans l'unité, sans question ; il refuse --to, --from et
// --status à côté de lui.
func TestUpgrade_ResumeRunsInTheUnitAlone(t *testing.T) {
	b := newUpgradeBench(t)
	if err := b.upgrade("--" + resumeFlag); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if line := strings.Join(b.system.unitArgs, " "); !strings.HasSuffix(line, " upgrade --"+inUnitFlag+" --"+resumeFlag) {
		t.Fatalf("systemd-run %s", line)
	}
	if !strings.Contains(b.terminal.String(), "Rien à reprendre") {
		t.Fatalf("printed %q", b.terminal)
	}
	for _, args := range [][]string{{"--" + resumeFlag, "--to", upgradeTarget}, {"--" + resumeFlag, "--from", b.dir}, {"--" + resumeFlag, "--status"}} {
		var refused *refusal
		if err := b.upgrade(args...); !errors.As(err, &refused) || refused.message != testCatalog(t).Get("upgrade.usage") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

// Le compte de serve peut réécrire state_dir : une copie remplacée par un
// lien vers un fichier de root n'est jamais remise à sa place. Le retour
// rate et donne la main ; le fichier visé ne devient pas la base.
func TestUpgrade_RollbackRefusesACopyThatIsALink(t *testing.T) {
	b := failingUpgradeBench(t)
	secret := filepath.Join(b.dir, "root-only")
	writeBenchFile(t, secret, "a file of root")
	b.afterStep = func(key step.Key) error {
		if key == step.UpgradeCopied {
			if err := os.Remove(b.copyPath()); err != nil {
				return err
			}
			return os.Symlink(secret, b.copyPath())
		}
		return nil
	}
	var refused *refusal
	if err := b.upgrade("--" + inUnitFlag); !errors.As(err, &refused) || !strings.Contains(refused.message, "install -m 0755") {
		t.Fatalf("upgrade: %v\n%s", err, b.terminal)
	}
	if got, _ := os.ReadFile(b.database()); string(got) == "a file of root" {
		t.Fatal("the linked file became the database")
	}
	if !strings.Contains(b.terminal.String(), "✗ Retour arrière") {
		t.Fatalf("printed %q", b.terminal)
	}
}

// R-B2-2 (ARB-5) : pendant le retour, root arrête serve, remet le binaire,
// relance ; state_dir ne bouge que dans l'enfant, lancé sous le compte du
// service, depuis le binaire remis.
func TestR_B2_2_RootNeverWritesUnderStateDir(t *testing.T) {
	b := failingUpgradeBench(t)
	b.wantRolledBack(b.upgrade("--" + inUnitFlag))
	if !slices.Equal(b.system.accounts, []string{brand.ServerAccount}) || len(b.system.children) != 1 {
		t.Fatalf("accounts %v, children %d", b.system.accounts, len(b.system.children))
	}
	child := b.system.children[0]
	if child.account != serviceAccount() || child.account.UID == 0 {
		t.Fatalf("child account %+v", child.account)
	}
	if child.args[0] != b.paths.binary || !slices.Contains(child.args, "--"+restoreDatabaseFlag) {
		t.Fatalf("child %v", child.args)
	}
	// restart, stop, start : entre stop et l'enfant, puis entre l'enfant et
	// start, seul root agit.
	if len(b.system.treeAtCall) != 3 {
		t.Fatalf("systemctl calls %v", b.system.calls)
	}
	stopped, started := b.system.treeAtCall[1], b.system.treeAtCall[2]
	if stopped != strings.Join(child.before, "\n") {
		t.Fatalf("root wrote under state_dir before the child:\n%s\n---\n%s", stopped, strings.Join(child.before, "\n"))
	}
	if started != strings.Join(child.after, "\n") {
		t.Fatalf("root wrote under state_dir after the child:\n%s\n---\n%s", strings.Join(child.after, "\n"), started)
	}
	if strings.Join(child.before, "\n") == strings.Join(child.after, "\n") {
		t.Fatal("the child changed nothing")
	}
}

// L'enfant refuse de tourner en root : root ne touche jamais la base.
func TestUpgrade_TheDatabaseSwapRefusesRoot(t *testing.T) {
	b := newUpgradeBench(t)
	before := treeOf(t, b.stateDir)
	var refused *refusal
	err := b.upgrade("--"+inUnitFlag, "--"+restoreDatabaseFlag, b.stateDir, version.Number(), upgradeTarget)
	if !errors.As(err, &refused) || refused.message != testCatalog(t).Get("upgrade.restore_as_root") {
		t.Fatalf("swap as root: %v", err)
	}
	if !slices.Equal(before, treeOf(t, b.stateDir)) {
		t.Fatal("state_dir changed")
	}
}
