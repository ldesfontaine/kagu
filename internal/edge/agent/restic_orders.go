package agent

import (
	"context"
	"errors"
	"net/http"
	"os/exec"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Les ordres restic. La préparation de la cible, ses utilisateurs et le lien
// de la source écrivent quelques fichiers de l'état : ils se font tout de
// suite, sous le verrou du juge. La sauvegarde et la rétention sont des
// ordres longs, faits par le worker. Les mots de passe arrivent dans le
// secret signé de l'ordre, décodé par le juge ; aucun n'est journalisé ni rendu.

// useResticBinaries pose les chemins que l'opérateur a déclarés (-restic,
// -rest-server) ; vides, les binaires se cherchent dans le PATH.
func (r *orderRunner) useResticBinaries(resticBinary, restServerBinary string) {
	r.checks.findRestic = func() (string, error) { return findBinary(resticBinary, resticProgram, exec.LookPath) }
	r.checks.findRestServer = func() (string, error) { return findBinary(restServerBinary, restServerProgram, exec.LookPath) }
}

// startRestic relance rest-server au démarrage de l'agent, si la machine
// est une cible déjà préparée.
func (r *orderRunner) startRestic(ctx context.Context) {
	r.mu.Lock()
	dir, isTarget := resticTargetDir(r.rights())
	checks := r.checks
	r.mu.Unlock()
	if isTarget {
		r.restic.target.start(ctx, dir, checks)
	}
}

// resticTargetDir rend le dossier des dépôts : le chemin du droit
// restic.target, faux sans le droit.
func resticTargetDir(capabilities []agentpolicy.Capability) (string, bool) {
	for _, capability := range capabilities {
		if capability.Name == agentpolicy.CapabilityResticTarget && len(capability.Paths) == 1 {
			return capability.Paths[0], true
		}
	}
	return "", false
}

func (r *orderRunner) resticTargetSetup(order judgedOrder) agentwire.ActionResult {
	params, ok := order.Params.(agentwire.ResticTargetSetupParams)
	if !ok {
		return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionFailed, Reason: agentwire.ReasonBadOrder}
	}
	if err := params.Validate(); err != nil {
		if errors.Is(err, agentwire.ErrResticRetentionInvalid) {
			return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionRefused, Reason: agentwire.ReasonRetentionInvalid}
		}
		return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionFailed, Reason: agentwire.ReasonBadOrder}
	}
	dir, _ := resticTargetDir(r.rights())
	output, err := r.restic.target.setup(params, dir, r.checks)
	return r.finishRestic(order, output, err)
}

// resticUser fait restic.user.add (le mot de passe REST dans le secret de
// l'ordre) et restic.user.remove (sans secret).
func (r *orderRunner) resticUser(order judgedOrder) agentwire.ActionResult {
	bad := agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionFailed, Reason: agentwire.ReasonBadOrder}
	if order.Kind == agentwire.KindResticUserRemove {
		params, ok := order.Params.(agentwire.ResticUserRemoveParams)
		if !ok || params.Validate() != nil || order.Secret != nil {
			return bad
		}
		output, err := r.restic.target.setUser(params.User, "")
		return r.finishRestic(order, output, err)
	}
	params, ok := order.Params.(agentwire.ResticUserAddParams)
	if !ok || params.Validate() != nil {
		return bad
	}
	secret, ok := order.Secret.(agentwire.ResticUserSecret)
	if !ok || secret.Validate() != nil {
		return bad
	}
	output, err := r.restic.target.setUser(params.User, secret.RESTPassword)
	return r.finishRestic(order, output, err)
}

func (r *orderRunner) resticProvision(order judgedOrder) agentwire.ActionResult {
	bad := agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionFailed, Reason: agentwire.ReasonBadOrder}
	params, ok := order.Params.(agentwire.ResticProvisionParams)
	if !ok || params.Validate() != nil {
		return bad
	}
	secret, ok := order.Secret.(agentwire.ResticProvisionSecret)
	if !ok || secret.Validate() != nil {
		return bad
	}
	output, err := r.restic.source.provision(params, secret)
	return r.finishRestic(order, output, err)
}

// finishRestic rapporte un ordre restic fait tout de suite, et réveille le
// rapport : la fiche voit le changement sans attendre la période.
func (r *orderRunner) finishRestic(order judgedOrder, output []agentwire.OutputLine, err error) agentwire.ActionResult {
	if err != nil {
		r.journal.failed(order, err)
	} else {
		r.journal.executed(order)
	}
	r.restic.nudge()
	result := resultOf(order.RunID, output, err)
	if result.State == agentwire.ActionFailed && isUntouched(err) {
		result.State = agentwire.ActionRefused
	}
	return result
}

// acceptResticBackup juge la sauvegarde vite, puis l'accepte : sonder la
// cible et lancer restic est le travail du worker. Droits, racine et
// vérifications sont lus ici, sous le verrou.
func (r *orderRunner) acceptResticBackup(order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
	checks := r.checks
	job, refused := readResticBackup(order, r.rights(), r.identity.Root(), checks)
	if refused == nil && !r.restic.source.isProvisioned(job.params.Target) {
		refused = &agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionRefused, Reason: agentwire.ReasonResticNotProvisioned}
	}
	if refused != nil {
		r.journal.notAccepted(order, refused.Reason)
		return *refused, nil
	}
	return accepted(order), func(ctx context.Context) {
		report, output, err := r.restic.source.backup(ctx, job, checks)
		result := r.finishRestic(order, output, err)
		if report.Path != "" {
			result.Restic = &report
		}
		r.results.push(result)
	}
}

// serveRelay passe une requête relayée à la cible ; sans le droit
// restic.target, elle est refusée sans toucher rest-server. Il se lance à
// part du flux, qui continue de lire.
func (r *orderRunner) serveRelay(ctx context.Context, request agentwire.ResticRelayRequest) {
	server := relayLink{fetch: r.fetch}
	r.mu.Lock()
	isTarget := agentpolicy.HasCapability(r.rights(), agentpolicy.CapabilityResticTarget)
	if !isTarget {
		r.notePendingRight(judgedOrder{}, agentwire.RightMissing(agentpolicy.CapabilityResticTarget))
	}
	r.mu.Unlock()
	if !isTarget {
		r.logger.Warn("restic relay refused", "repo", request.Repo, "reason", agentwire.RightMissing(agentpolicy.CapabilityResticTarget))
		r.restic.target.answerRelay(ctx, server, request.ID, http.StatusForbidden, relayRightMissing)
		return
	}
	r.restic.target.serveRelay(ctx, server, request)
}

// resticReport rend la section restic du signal, faux pour un agent qui n'a
// aucun des deux droits.
func (r *orderRunner) resticReport(ctx context.Context) (agentwire.ResticReport, bool) {
	r.mu.Lock()
	capabilities, checks := r.rights(), r.checks
	r.mu.Unlock()
	var report agentwire.ResticReport
	if dir, isTarget := resticTargetDir(capabilities); isTarget {
		target := r.restic.target.report(ctx, dir, checks)
		report.Target = &target
	}
	if agentpolicy.HasCapability(capabilities, agentpolicy.CapabilityResticProduce) {
		source := r.restic.source.report(ctx, checks)
		report.Source = &source
	}
	return report, report.Target != nil || report.Source != nil
}
