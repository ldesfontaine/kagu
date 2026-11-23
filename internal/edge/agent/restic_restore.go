package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/domain/restic"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// La restauration d'un fichier ou d'un dossier, chez la source : À CÔTÉ de
// l'original, jamais par-dessus, sans rien supprimer de ce qui existait. Le
// mot de passe du dépôt est celui du fichier du lien (0600), que la source
// détient déjà : l'ordre n'en porte aucun. restic restaure dans un dossier
// temporaire créé à côté de la destination (même disque), puis l'agent déplace
// le résultat à sa place ; le dossier temporaire est le seul chose effacée, et
// c'est lui qui l'a créé.
//
// À l'écriture, la destination est rejugée sous la racine du droit
// files.write, ouverte une fois (R-A1-10) : un lien posé après l'acceptation
// est refusé, et ni restic ni le déplacement ne sortent du droit. restic
// reçoit le dossier temporaire ouvert (descripteur 3) et y écrit par
// /proc/self/fd/3 : le chemin du dossier n'est plus relu.
const (
	resticRestoreTimeout = 55 * time.Minute
	restoreTempPrefix    = ".restaure-tmp-"
	restoreTempMode      = 0o700
	// restic remplace une cible qui est un lien : /proc/self/fd/3 en est un,
	// il écrit donc dans un sous-dossier qu'il crée.
	restoreInheritedTarget = "/proc/self/fd/3/restic"
	restoreTargetBelowTemp = "restic"
)

type resticRestoreJob struct {
	params      agentwire.ResticRestoreParams
	binary      string
	granted     string
	destination string
}

// acceptResticRestore juge l'ordre vite, avant de rien écrire : sa forme, le
// droit (jugé plus haut), restic présent, le lien provisionné, la destination
// couverte par files.write (liens résolus) et libre. Un refus ne touche à rien.
func (r *orderRunner) acceptResticRestore(order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
	job, refused := judgeRestore(order, r.identity.Capabilities(), r.checks, r.restic.source.isProvisioned)
	if refused != nil {
		r.journal.notAccepted(order, refused.Reason)
		return *refused, nil
	}
	return accepted(order), func(ctx context.Context) {
		output, err := r.restic.source.restore(ctx, job)
		r.results.push(r.finishRestic(order, output, err))
	}
}

func judgeRestore(order judgedOrder, capabilities []agentpolicy.Capability, checks hostChecks, isProvisioned func(string) bool) (resticRestoreJob, *agentwire.ActionResult) {
	refused := func(state agentwire.ActionState, reason string) *agentwire.ActionResult {
		return &agentwire.ActionResult{RunID: order.RunID, State: state, Reason: reason}
	}
	params, ok := order.Params.(agentwire.ResticRestoreParams)
	if !ok || params.Validate() != nil || order.Secret != nil {
		return resticRestoreJob{}, refused(agentwire.ActionFailed, agentwire.ReasonBadOrder)
	}
	binary, err := checks.findRestic()
	if err != nil {
		return resticRestoreJob{}, refused(agentwire.ActionRefused, agentwire.ReasonResticMissing)
	}
	if !isProvisioned(params.Target) {
		return resticRestoreJob{}, refused(agentwire.ActionRefused, agentwire.ReasonResticNotProvisioned)
	}
	destination := agentwire.RestoreDestination(params.Path, params.Stamp)
	if reason := restoreDestinationReason(capabilities, destination); reason != "" {
		return resticRestoreJob{}, refused(agentwire.ActionRefused, reason)
	}
	granted, _ := agentpolicy.CoveringPath(capabilities, agentpolicy.CapabilityFilesWrite, destination)
	return resticRestoreJob{params: params, binary: binary, granted: granted, destination: destination}, nil
}

// restoreDestinationReason : vide si la destination est couverte par files.write,
// son dossier résolu (liens suivis) l'est encore, et rien n'y existe déjà.
func restoreDestinationReason(capabilities []agentpolicy.Capability, destination string) string {
	if !agentpolicy.CoversPath(capabilities, agentpolicy.CapabilityFilesWrite, destination) {
		return agentwire.ReasonPathOutsideRight
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return agentwire.ReasonPathUnwritable
	}
	resolved := filepath.Join(parent, filepath.Base(destination))
	if !agentpolicy.CoversPath(capabilities, agentpolicy.CapabilityFilesWrite, resolved) {
		return agentwire.ReasonPathOutsideRight
	}
	if _, err := os.Lstat(resolved); err == nil {
		return agentwire.ReasonPathExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return agentwire.ReasonPathUnwritable
	}
	return ""
}

// restore lance restic dans un dossier temporaire voisin, puis déplace le
// résultat à la destination, tout sous la racine du droit. Les mots de passe
// sont masqués dans toute sortie.
func (s *resticSource) restore(ctx context.Context, job resticRestoreJob) ([]agentwire.OutputLine, error) {
	ctx, cancel := context.WithTimeout(ctx, resticRestoreTimeout)
	defer cancel()
	files, secrets, err := s.prepareLink(job.params.Target)
	if err != nil {
		if isUntouched(err) {
			return nil, err
		}
		return nil, refuseWith(agentwire.ReasonPathUnwritable, err)
	}
	parent, err := openDestination(job.granted, filepath.Dir(job.destination), false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	tempName, temp, err := makeRestoreTemp(parent)
	if err != nil {
		return nil, refuseWith(agentwire.ReasonPathUnwritable, err)
	}
	defer func() { _ = parent.RemoveAll(tempName) }()
	defer temp.Close()

	choice := restic.Choose(ctx, s.dialer, s.loadTarget(job.params.Target), false)
	s.logger.Info("restic path chosen", "target", job.params.Target, "path", choice.Path, "reason", choice.Reason, "purpose", "restore")
	repository, release, err := s.repositoryFor(choice, job.params.Target, files)
	if err != nil {
		return nil, failWith(agentwire.ReasonResticFailed, err)
	}
	defer release()
	command, err := restic.RestoreSnapshot(job.binary, repository, job.params.Snapshot, restoreInheritedTarget, job.params.Path)
	if err != nil {
		return nil, failWith(agentwire.ReasonBadOrder, err)
	}
	command.Inherited = []*os.File{temp}
	tail := newLineTail(resticTailLines)
	code, runErr := s.runner.run(ctx, command, io.Discard, tail.writer("stderr"))
	tail.flush()
	lines := redactLines(tail.lines(), secrets, redactedSecret)
	if runErr != nil || code != 0 {
		return lines, failWith(agentwire.ReasonRestoreFailed, fmt.Errorf("restic restore exited with code %d: %v", code, runErr))
	}
	restored := path.Join(tempName, restoreTargetBelowTemp, strings.TrimPrefix(job.params.Path, "/"))
	if _, err := parent.Lstat(restored); err != nil {
		return lines, failWith(agentwire.ReasonPathNotInSnapshot, errors.New("the path is not in the snapshot"))
	}
	// Dernier jugement avant d'écrire : rien n'existe à la destination.
	name := filepath.Base(job.destination)
	if _, err := parent.Lstat(name); err == nil {
		return lines, refuseWith(agentwire.ReasonPathExists, errors.New("the destination appeared"))
	}
	if err := parent.Rename(restored, name); err != nil {
		return lines, failWith(agentwire.ReasonPathUnwritable, err)
	}
	return append(lines, stdout("restored "+job.destination)), nil
}

// makeRestoreTemp crée le dossier temporaire sous la racine ouverte (os.Root
// n'a pas de MkdirTemp) et l'ouvre : c'est ce descripteur que restic reçoit.
func makeRestoreTemp(parent *os.Root) (string, *os.File, error) {
	suffix, err := ident.New()
	if err != nil {
		return "", nil, err
	}
	name := restoreTempPrefix + suffix
	if err := parent.Mkdir(name, restoreTempMode); err != nil {
		return "", nil, err
	}
	temp, err := parent.Open(name)
	if err != nil {
		_ = parent.Remove(name)
		return "", nil, err
	}
	return name, temp, nil
}
