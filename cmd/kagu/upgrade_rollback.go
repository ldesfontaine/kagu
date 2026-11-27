package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/store"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/kit/untrusted"
)

// Le retour arrière de upgrade (R-B2-3, R-B2-4) : la nouvelle version ne
// répond pas, upgrade remet l'ancien binaire et la copie de la base faite
// par serve. Root arrête serve, remet le binaire, relance et attend ; les
// gestes sous state_dir sont ceux d'un enfant sous le compte du service
// (R-B2-2, ARB-5) : root n'y ouvre rien. Un retour ne se joue qu'une fois ;
// raté, upgrade donne la main.

// restoreDatabaseFlag est l'option interne de l'enfant qui échange les
// bases : upgrade --in-unit --restore-database <state_dir> <avant> <visée>.
const restoreDatabaseFlag = "restore-database"

// Ce qu'on reprend après une montée arrêtée : redémarrer si ce n'est pas
// fait, puis attendre la nouvelle version.
var resumeSteps = []upgradeStep{
	{step.UpgradeRestarted, (*upgradeRun).restartServer},
	{step.UpgradeAnswers, (*upgradeRun).awaitServer},
}

// runStepsOrRollBack joue steps ; une étape en échec entre « Binaire
// remplacé » et « Serveur répond » fait revenir à la version d'avant.
func (r *upgradeRun) runStepsOrRollBack(ctx context.Context, steps []upgradeStep) (handOver bool, err error) {
	handOver, err = r.runSteps(ctx, steps)
	if err != nil && r.mustRollBack() {
		return false, r.rollBack(ctx)
	}
	return handOver, err
}

// mustRollBack : le binaire est remplacé, la nouvelle version n'a pas
// répondu, et aucun retour n'a commencé.
func (r *upgradeRun) mustRollBack() bool {
	return r.stepDone(step.UpgradeReplaced) && !r.stepDone(step.UpgradeAnswers) && !r.state.RollbackStarted
}

// resume reprend une montée arrêtée après « Binaire remplacé » (une machine
// redémarrée, une unité tuée), selon l'étape écrite : la nouvelle version a
// répondu, sa suite est rejouée ; sinon upgrade l'attend, et revient si elle
// reste muette. Un retour commencé ne se rejoue pas : fait à la main et la
// version d'avant répond, il est noté ; sinon les commandes sont redites.
func (r *upgradeRun) resume(ctx context.Context) (handOver bool, err error) {
	if !r.interrupted() {
		fmt.Fprintln(r.out, r.text.Get("upgrade.resume_nothing"))
		return false, nil
	}
	fmt.Fprintln(r.out, r.text.Format("upgrade.status_title", r.state.Running, r.state.Target))
	fmt.Fprintln(r.out)
	if r.state.RollbackStarted {
		r.printSteps()
		return false, r.noteRollbackByHand(ctx)
	}
	if r.stepDone(step.UpgradeAnswers) {
		return true, nil
	}
	steps := resumeSteps
	if r.stepDone(step.UpgradeRestarted) {
		steps = resumeSteps[1:]
	}
	return r.runStepsOrRollBack(ctx, steps)
}

// noteRollbackByHand note le retour quand la version d'avant répond ;
// sinon redit les commandes à jouer à la main, sans rien toucher.
func (r *upgradeRun) noteRollbackByHand(ctx context.Context) error {
	if err := r.awaitVersion(ctx, r.state.Running); err != nil {
		return r.handRecovery()
	}
	r.check(step.UpgradeRolledBack, step.StateDone, r.text.Format("upgrade.rolled_back_by_hand", r.state.Running))
	return r.saveState()
}

// rollBack revient à la version d'avant et le dit, avec ce qui est perdu et
// où est la base fautive. Le retour est écrit commencé avant le premier
// geste : une coupure au milieu ne le fait pas rejouer.
func (r *upgradeRun) rollBack(ctx context.Context) error {
	r.state.RollbackStarted = true
	r.state.PolicyConsent = false
	if err := r.saveState(); err != nil {
		return err
	}
	faulty, lost, err := r.restorePrevious(ctx)
	if err != nil {
		reason, _ := explainStepFailure(err, r.text)
		r.check(step.UpgradeRolledBack, step.StateFailed, reason)
		if err := r.saveState(); err != nil {
			return err
		}
		return r.handRecovery()
	}
	r.check(step.UpgradeRolledBack, step.StateDone, r.text.Format("upgrade.rolled_back_detail", r.state.Running, int(lost.Seconds())))
	fmt.Fprintf(r.out, "    %s\n", r.text.Format("upgrade.faulty_kept", faulty))
	if err := r.saveState(); err != nil {
		return err
	}
	return &refusal{message: r.text.Format("upgrade.rolled_back_todo", r.state.Target, r.state.Running)}
}

// restorePrevious : serve arrêté, l'ancien binaire remis, la base échangée
// contre la copie par l'enfant, serve relancé et attendu. Rend où est gardée
// la base fautive, et ce qui est perdu : ce que serve a écrit entre la copie
// et l'arrêt.
func (r *upgradeRun) restorePrevious(ctx context.Context) (faulty string, lost time.Duration, err error) {
	if err := r.system.Run("systemctl", "stop", brand.ServerUnit); err != nil {
		return "", 0, err
	}
	stopped := time.Now()
	previous, err := os.ReadFile(r.state.Previous)
	if err != nil {
		return "", 0, err
	}
	if err := writeExecutable(r.state.Binary, previous); err != nil {
		return "", 0, err
	}
	if faulty, err = r.swapDatabaseAsService(); err != nil {
		return "", 0, err
	}
	if err := r.system.Run("systemctl", "start", brand.ServerUnit); err != nil {
		return "", 0, err
	}
	if err := r.awaitVersion(ctx, r.state.Running); err != nil {
		return "", 0, err
	}
	copied, _ := r.doneStep(step.UpgradeCopied)
	return faulty, stopped.Sub(copied.At), nil
}

// swapDatabaseAsService fait échanger les bases par le binaire remis, celui
// de root, lancé sous le compte du service : le compte se lit par son nom,
// jamais sur un fichier de state_dir. L'enfant rend le nom de la base
// fautive ; il n'est pris que s'il a la forme attendue.
func (r *upgradeRun) swapDatabaseAsService() (faulty string, err error) {
	account, found, err := r.system.Account(brand.ServerAccount)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("account %s not found", brand.ServerAccount)
	}
	args := []string{r.state.Binary, "upgrade", "--" + inUnitFlag, "--" + restoreDatabaseFlag, r.state.StateDir, r.state.Running, r.state.Target}
	output, err := r.system.RunAsAccount(account, args)
	if err != nil {
		return "", err
	}
	kept := lastLine(output)
	wanted := path.Join(brand.UpgradeDir, brand.UpgradeFailedPrefix+r.state.Target)
	if !strings.HasPrefix(kept, wanted) || untrusted.HasControl(kept) || strings.Contains(kept, "..") {
		return "", fmt.Errorf("unexpected faulty database name: %q", untrusted.Bound(kept, step.MaxDetailRunes))
	}
	return filepath.Join(r.state.StateDir, kept), nil
}

// restoreDatabase est l'enfant, sous le compte du service : il garde la base
// fautive à côté de la copie, remet la copie à sa place, et écrit le nom de
// la base fautive. serve est arrêté. Lancé par root, il refuse (R-B2-2).
func (r *upgradeRun) restoreDatabase(args []string) error {
	if r.euid == 0 {
		return &refusal{message: r.text.Get("upgrade.restore_as_root")}
	}
	if len(args) != 3 {
		return &refusal{message: r.text.Get("upgrade.usage")}
	}
	running, err := release.ParseVersion(args[1])
	if err != nil {
		return err
	}
	target, err := release.ParseVersion(args[2])
	if err != nil {
		return err
	}
	stateDir, err := os.OpenRoot(args[0])
	if err != nil {
		return err
	}
	defer stateDir.Close()
	kept, err := keepFaultyDatabase(stateDir, target)
	if err != nil {
		return err
	}
	if err := restoreDatabaseCopy(stateDir, running); err != nil {
		return err
	}
	_, err = fmt.Fprintln(r.out, kept)
	return err
}

// keepFaultyDatabase déplace la base et ses -wal, -shm sous un nom libre
// d'echec-<version visée> : jamais effacée, jamais écrasée (R-B2-4), et
// plus rien à côté de la place de la base que SQLite rejouerait sur la
// copie.
func keepFaultyDatabase(stateDir *os.Root, target release.Version) (string, error) {
	kept, err := freeFailedName(stateDir, target)
	if err != nil {
		return "", err
	}
	for _, suffix := range append([]string{""}, store.DatabaseJournalSuffixes...) {
		err := stateDir.Rename(brand.DatabaseFile+suffix, kept+suffix)
		if suffix != "" && errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
	}
	if err := fsx.SyncDir(stateDir, "."); err != nil {
		return "", err
	}
	return kept, fsx.SyncDir(stateDir, brand.UpgradeDir)
}

// freeFailedName rend le premier nom de base fautive dont ni la base ni ses
// -wal, -shm n'existent.
func freeFailedName(stateDir *os.Root, target release.Version) (string, error) {
	for attempt := 1; ; attempt++ {
		name := store.FailedUpgradeName(target, attempt)
		taken := false
		for _, suffix := range append([]string{""}, store.DatabaseJournalSuffixes...) {
			_, err := stateDir.Lstat(name + suffix)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return "", err
			}
			taken = taken || err == nil
		}
		if !taken {
			return name, nil
		}
	}
}

// restoreDatabaseCopy remet la copie d'avant la montée à la place de la
// base, octet pour octet, en flux : le fichier naît au compte de l'enfant,
// en 0600, et ne prend son nom qu'écrit. Le nom de la copie se recalcule de
// la version : jamais un chemin que serve aurait dit ; un lien est refusé.
func restoreDatabaseCopy(stateDir *os.Root, running release.Version) error {
	name := store.UpgradeCopyName(running)
	for _, suffix := range store.DatabaseJournalSuffixes {
		if _, err := stateDir.Lstat(brand.DatabaseFile + suffix); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s%s is still next to the database: %w", brand.DatabaseFile, suffix, err)
		}
	}
	copied, err := stateDir.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer copied.Close()
	info, err := copied.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	return fsx.CreateExclusiveFrom(stateDir, brand.DatabaseFile, copied, store.UpgradeCopyMode)
}

// handRecovery arrête upgrade sur un retour raté : les trois commandes à
// jouer à la main, et rien de plus n'est touché.
func (r *upgradeRun) handRecovery() error {
	database := filepath.Join(r.state.StateDir, brand.DatabaseFile)
	copyPath := r.state.Copy
	if running, err := release.ParseVersion(r.state.Running); err == nil {
		copyPath = filepath.Join(r.state.StateDir, store.UpgradeCopyName(running))
	}
	return &refusal{message: r.text.Format("upgrade.rollback_failed_todo",
		r.state.Previous, r.state.Binary, copyPath, database, database, filepath.Join(r.state.StateDir, brand.UpgradeDir))}
}
