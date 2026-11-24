package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/dockerapi"
	"github.com/ldesfontaine/kagu/internal/kit/hostinfo"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
	"github.com/ldesfontaine/kagu/internal/wire/judge"
)

// orderRunner juge chaque ordre reçu, exécute ceux qui passent et garde
// le résultat pour le signal suivant. Il vit avec l'agent, pas avec le
// flux : le rang du dernier ordre exécuté se garde dans identity.json, et
// un redémarrage ne rouvre pas la porte d'un rejeu.
//
// Un ordre passe (judge.Judge, puis orderRunner.judge) si, dans cet ordre :
// la politique accepte une clé du serveur ; la signature est de l'une
// d'elles ; le corps se lit strictement et porte la version de l'enveloppe
// (agentwire.OrderVersion) ; il vise cette machine et cet agent ; il n'est pas
// périmé ; son rang dépasse le dernier exécuté ; son genre est au registre
// (agentwire.Spec) ; la politique porte le droit qu'il exige (Spec.Right) ; ses paramètres
// et son secret se lisent strictement dans leur type ; les valeurs décodées
// qu'il présente sont dans les ancres de confiance locales. Sinon il est
// refusé, et le refus est rapporté. Les commandes d'observation ne passent
// pas ici : elles exigent observe, que le fichier porte toujours
// (agentpolicy.NormalizeCapabilities l'ajoute).
type orderRunner struct {
	stateDir *os.Root
	version  string
	results  *actionResults
	logger   *slog.Logger
	// journal écrit les lignes locales des ordres (journal.go).
	journal *orderJournal
	now     func() time.Time
	// monotonic lit le démarrage et le temps écoulé depuis : une clé gardée
	// échoit aussi par eux (agentpolicy.Lapsed). Les tests l'avancent.
	monotonic func() (boot string, uptime time.Duration)
	// Les ordres longs, que le juge accepte puis confie à worker ; fetch
	// leur donne les colis du serveur.
	worker *orderWorker
	fetch  *fetcher
	// La mise à jour de l'agent (agent.update) : la clé de version et la
	// relance viennent de Run.
	updater *selfUpdater
	// Docker et le disque, que les déploiements touchent ; les tests les
	// remplacent.
	docker dockerTools
	// Le dossier produce/ de l'état et la table des producteurs, que backup.produce
	// touche ; les tests y mettent les leurs.
	produce produceTools
	// Le jeton local et l'API de Proxmox, que les ordres proxmox.vm.* touchent.
	proxmox proxmoxTools
	// La cible et la source restic, que les ordres restic.* touchent.
	restic *resticTools
	// Ce que la machine répond au compte de l'agent : Docker, les dossiers, son
	// propre dossier bin/. Les mêmes questions que le rapport des droits
	// indisponibles ; un ordre est refusé, avant d'écrire, sur la même raison.
	checks hostChecks

	mu       sync.Mutex
	identity Identity

	// La politique : où la lire, ce que la dernière lecture a laissé (lu sans
	// le verrou par les sondes et le veilleur Docker), et le signal d'un
	// changement, qui fait rouvrir le flux pour le rapporter.
	policyPlace   PolicyPlace
	applied       atomic.Pointer[AppliedPolicy]
	policyChanged chan struct{}
}

func newOrderRunner(stateDir *os.Root, identity Identity, place PolicyPlace, version, dockerSocket string, results *actionResults, logger *slog.Logger) *orderRunner {
	updater := newSelfUpdater(stateDir, version, logger)
	checks := newHostChecks(dockerSocket, updater)
	checks.proxmoxToken = func() string {
		_, reason := readProxmoxToken(stateDir)
		return reason
	}
	if dockerSocket == "" {
		dockerSocket = dockerapi.DefaultSocket
	}
	runner := &orderRunner{
		stateDir: stateDir, identity: identity, version: version, results: results, logger: logger, now: time.Now, monotonic: hostinfo.MonotonicClock,
		worker: newOrderWorker(), fetch: &fetcher{}, updater: updater, docker: newDockerTools(checks, stateDir, dockerSocket, logger), checks: checks,
		produce: newProduceTools(stateDir), proxmox: newProxmoxTools(stateDir), restic: newResticTools(stateDir, logger),
	}
	runner.journal = newOrderJournal(func() *slog.Logger { return runner.logger })
	runner.restic.source.inventory = dockerapi.New(dockerSocket)
	runner.policyPlace, runner.policyChanged = place, make(chan struct{}, 1)
	runner.reloadPolicy()
	return runner
}

// receive juge et exécute un ordre, un à la fois : deux ordres arrivés
// ensemble ne se disputent pas le rang.
func (r *orderRunner) receive(data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	signed, err := agentwire.DecodeSignedOrder(data)
	if err != nil {
		// Sans enveloppe lisible, pas de run à qui répondre.
		r.logger.Warn("order refused", "reason", agentwire.ReasonBadOrder, "error", err)
		return
	}
	order, reason := r.judge(signed)
	if reason != "" {
		r.refuse(signed, order, reason)
		return
	}
	r.journal.received(order, "")
	result, job := r.execute(order)
	// « accepté » part avant que le worker ne puisse finir : la réponse
	// finale ne le précède jamais.
	r.results.push(result)
	if job == nil {
		// Un ordre fait tout de suite n'a plus de ligne à dire.
		r.journal.forget(order.RunID)
		return
	}
	if !r.worker.submit(job) {
		r.journal.refused(order, agentwire.ReasonBusy)
		r.results.push(agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionFailed, Reason: agentwire.ReasonBusy})
	}
}

// judgedOrder est un ordre dont le juge a lu le corps : le run et le rang de
// l'enveloppe signée, et l'ordre que le registre a décodé (genre, paramètres
// et secret dans leur type). Les octets des paramètres et du secret n'y sont
// pas : l'exécuteur et le journal lisent l'objet que le juge a jugé, jamais une
// seconde lecture du JSON (R-A1-5). Refusé avant d'être décodé, il n'a que son
// genre.
type judgedOrder struct {
	RunID string
	Seq   int64
	agentwire.Order
}

// judge rend l'ordre qui passe, ou la raison de son refus. judge.Judge juge
// l'ordre contre la politique ; l'agent visé et le rang vivent dans
// identity.json, l'agent les juge à leur place parmi ses contrôles : juste
// après la machine, juste après l'échéance. Le rang est écrit sur disque
// avant de rendre la main : un ordre exécuté ne se rejoue plus, même après un
// redémarrage.
func (r *orderRunner) judge(signed agentwire.SignedOrder) (judgedOrder, string) {
	policy := r.policy()
	verdict := judge.Judge(signed, policy, r.now())
	if !verdict.Read {
		return judgedOrder{}, verdict.Reason
	}
	body := verdict.Body
	r.journal.remember(body.RunID, factsOf(signed.Body, verdict.SigningKey))
	order := judgedOrder{RunID: body.RunID, Seq: body.Seq, Order: verdict.Order}
	switch {
	case verdict.Reason == agentwire.ReasonWrongMachine:
		return order, verdict.Reason
	case body.AgentID != r.identity.AgentID:
		return order, agentwire.ReasonWrongAgent
	case verdict.Reason == agentwire.ReasonExpired:
		return order, verdict.Reason
	case body.Seq <= r.identity.LastOrderSeq:
		return order, agentwire.ReasonReplayed
	case verdict.Reason != "":
		return order, verdict.Reason
	}
	if !r.keepSeq(order.Seq) {
		return order, agentwire.ReasonStateUnwritable
	}
	return order, ""
}

// policy rend ce que l'agent applique : la politique relue (la machine
// qu'elle nomme, les clés du serveur, les droits, les ancres), pour qu'un
// « agent grant » ou un « agent trust » vaille dès l'ordre suivant, et
// qu'une clé gardée échue tombe. Appelé sous le verrou de l'agent.
func (r *orderRunner) policy() agentpolicy.Policy {
	applied := r.reloadPolicy()
	machineID := r.identity.MachineID
	if applied.MachineID != "" {
		machineID = applied.MachineID
	}
	return agentpolicy.Policy{MachineID: machineID, ServerKeys: applied.ServerKeys, Rights: applied.Rights, Anchors: applied.Anchors}
}

// clock lit l'horloge de la machine : l'heure et l'horloge monotone.
func (r *orderRunner) clock() agentpolicy.Clock {
	boot, uptime := r.monotonic()
	return agentpolicy.Clock{Now: r.now(), Boot: boot, Uptime: uptime}
}

// reloadPolicy relit la politique (et, sur une machine d'avant elle, les
// ancres d'identity.json) et garde ce que l'agent applique désormais. Quand
// ce qu'il rapporte au serveur a changé, il le dit au journal et le signale
// (policyChanged) : le flux se rouvre pour le rapporter. Appelé sous le
// verrou de l'agent.
func (r *orderRunner) reloadPolicy() AppliedPolicy {
	r.reloadAnchors()
	applied, err := readPolicy(r.policyPlace, r.identity, r.clock())
	previous := r.applied.Swap(&applied)
	if previous != nil && previous.report() == applied.report() {
		return applied
	}
	if err != nil {
		r.logger.Warn("agent policy refused, only observe applies", "error", err)
	}
	if previous != nil {
		r.logger.Info("agent policy changed", "source", applied.Source, "digest", applied.Digest, "rights", agentpolicy.FormatCapabilities(applied.Rights))
		select {
		case r.policyChanged <- struct{}{}:
		default:
		}
	}
	return applied
}

// reloadAnchors relit les ancres du fichier d'identité, que lit une machine
// d'avant la politique. Un fichier qui ne se lit pas garde les ancres
// connues : ce que l'agent a appliqué jusque-là ne s'élargit jamais sur une
// erreur de lecture. Appelé sous le verrou de l'agent.
func (r *orderRunner) reloadAnchors() {
	// Sans dossier d'état (les bancs de la boucle du flux), l'identité en mémoire fait foi.
	if r.stateDir == nil {
		return
	}
	if stored, err := LoadIdentity(r.stateDir); err == nil {
		r.identity.Anchors = stored.Anchors
	} else {
		r.logger.Warn("reload anchors", "error", err)
	}
}

// currentPolicy relit la politique, pour l'ouverture du flux et pour la
// relecture sans ordre (watchPolicy).
func (r *orderRunner) currentPolicy() AppliedPolicy {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reloadPolicy()
}

// rights rend les droits que l'agent applique, tels que la dernière lecture
// les a laissés ; sûr hors du verrou.
func (r *orderRunner) rights() []agentpolicy.Capability {
	return r.applied.Load().Rights
}

// allows rend la question « la politique porte-t-elle ce droit ? », posée à
// chaque usage : probe.lan et observe.env suivent la politique sans
// redémarrage (R-A3-4).
func (r *orderRunner) allows(name string) func() bool {
	return func() bool { return agentpolicy.HasCapability(r.rights(), name) }
}

// watchPolicy relit la politique toutes les every et à chaque signal reçu sur
// hangups (SIGHUP), même flux coupé : les sondes et le veilleur Docker suivent
// sans attendre un ordre.
func (r *orderRunner) watchPolicy(ctx context.Context, hangups <-chan os.Signal, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-hangups:
			r.logger.Info("hangup received, reading the agent policy again")
		}
		r.currentPolicy()
	}
}

// keepSeq écrit le nouveau rang ; un échec d'écriture laisse l'ancien en
// mémoire comme sur disque.
func (r *orderRunner) keepSeq(seq int64) bool {
	updated := r.identity
	updated.LastOrderSeq = seq
	saved, err := saveKeepingRootFields(r.stateDir, updated)
	if err != nil {
		r.logger.Error("keep order seq", "seq", seq, "error", err)
		return false
	}
	r.identity = saved
	return true
}

// executor fait ce que l'ordre demande, sur l'ordre décodé par le juge. Un
// ordre long est jugé vite, puis accepté : le travail rendu à part, le worker
// le fera à son tour.
type executor func(r *orderRunner, order judgedOrder) (agentwire.ActionResult, func(ctx context.Context))

// executors est l'exécuteur de chaque genre du registre, et de lui seul
// (TestExecutors_EveryDeclaredKindHasItsExecutor). Le secret de l'ordre est
// signé avec lui ; seul l'exécuteur du genre qui en a besoin le lit, et rien
// ne l'écrit.
var executors = map[agentwire.Kind]executor{
	agentwire.KindAgentPing:             immediate((*orderRunner).ping),
	agentwire.KindBackupReceive:         (*orderRunner).acceptBackupReceive,
	agentwire.KindBackupPrune:           (*orderRunner).acceptBackupPrune,
	agentwire.KindBackupProduce:         (*orderRunner).acceptBackupProduce,
	agentwire.KindAgentUpdate:           (*orderRunner).acceptAgentUpdate,
	agentwire.KindAgentRollback:         (*orderRunner).acceptAgentRollback,
	agentwire.KindProxmoxStart:          (*orderRunner).acceptProxmox,
	agentwire.KindProxmoxShutdown:       (*orderRunner).acceptProxmox,
	agentwire.KindProxmoxSnapshot:       (*orderRunner).acceptProxmox,
	agentwire.KindProxmoxSnapshotDelete: (*orderRunner).acceptProxmox,
	agentwire.KindDockerDeploy:          (*orderRunner).acceptDockerDeploy,
	agentwire.KindDockerUpdate:          (*orderRunner).acceptDockerUpdate,
	agentwire.KindDockerRollback:        immediate((*orderRunner).requestServiceRollback),
	agentwire.KindResticTargetSetup:     immediate((*orderRunner).resticTargetSetup),
	agentwire.KindResticUserAdd:         immediate((*orderRunner).resticUser),
	agentwire.KindResticUserRemove:      immediate((*orderRunner).resticUser),
	agentwire.KindResticProvision:       immediate((*orderRunner).resticProvision),
	agentwire.KindResticBackup:          (*orderRunner).acceptResticBackup,
	agentwire.KindResticRetain:          (*orderRunner).acceptResticRetain,
	agentwire.KindResticVerify:          (*orderRunner).acceptResticVerify,
	agentwire.KindResticBrowse:          (*orderRunner).acceptResticBrowse,
	agentwire.KindResticRestore:         (*orderRunner).acceptResticRestore,
}

// immediate fait un exécuteur d'un ordre fait tout de suite : pas de travail
// rendu au worker.
func immediate(run func(r *orderRunner, order judgedOrder) agentwire.ActionResult) executor {
	return func(r *orderRunner, order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
		return run(r, order), nil
	}
}

// execute confie l'ordre à l'exécuteur de son genre. Un genre sans exécuteur
// est refusé, même avec son droit.
func (r *orderRunner) execute(order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
	run, known := executors[order.Kind]
	if !known {
		r.journal.refused(order, agentwire.ReasonNotImplemented)
		return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionRefused, Reason: agentwire.ReasonNotImplemented}, nil
	}
	return run(r, order)
}

// ping ne change rien : il dit que l'ordre est arrivé, vérifié, et quel agent
// l'a pris.
func (r *orderRunner) ping(order judgedOrder) agentwire.ActionResult {
	r.journal.executed(order)
	return agentwire.ActionResult{
		RunID: order.RunID, State: agentwire.ActionSucceeded,
		Output: []agentwire.OutputLine{{Stream: "stdout", Line: "pong " + r.version}},
	}
}

// coversBackupPath : le chemin est celui du droit backup.receive du fichier
// de l'agent, ou dessous. Le droit est lu ici, sous le verrou : le worker ne
// touche pas à l'identité.
func (r *orderRunner) coversBackupPath() coveringPath {
	capabilities := r.rights()
	return func(path string) (string, bool) {
		return agentpolicy.CoveringPath(capabilities, agentpolicy.CapabilityBackupReceive, path)
	}
}

func accepted(order judgedOrder) agentwire.ActionResult {
	return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionAccepted}
}

func (r *orderRunner) acceptBackupReceive(order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
	params, granted, refused := readBackupReceive(order, r.coversBackupPath(), r.checks.writable, r.checks.freeBytes)
	if refused != nil {
		r.journal.notAccepted(order, refused.Reason)
		return *refused, nil
	}
	return accepted(order), func(ctx context.Context) {
		output, err := receiveBackup(ctx, r.logger, r.fetch, granted, params)
		r.finishLong(order, output, err)
	}
}

func (r *orderRunner) acceptBackupPrune(order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
	params, granted, refused := readBackupPrune(order, r.coversBackupPath(), r.checks.writable)
	if refused != nil {
		r.journal.notAccepted(order, refused.Reason)
		return *refused, nil
	}
	return accepted(order), func(context.Context) {
		output, err := pruneBackups(granted, params)
		r.finishLong(order, output, err)
	}
}

// acceptBackupProduce juge l'ordre vite (le droit nomme le producteur, l'agent
// le connaît, les paramètres sont de la bonne forme), puis l'accepte : lancer
// le producteur, emballer et téléverser est le travail du worker. Les droits
// sont lus ici, sous le verrou.
func (r *orderRunner) acceptBackupProduce(order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
	job, refused := readBackupProduce(order, r.rights(), r.produce.producers)
	if refused != nil {
		r.journal.notAccepted(order, refused.Reason)
		return *refused, nil
	}
	return accepted(order), func(ctx context.Context) {
		output, err := r.produce.produce(ctx, r.checks, r.fetch, job, r.now())
		r.finishProduce(order, output, err)
	}
}

// acceptProxmox juge un geste sur un invité vite (paramètres, jeton local),
// puis l'accepte : appeler l'API et suivre la tâche de Proxmox est le travail
// du worker. Il se juge et se rapporte comme une production.
func (r *orderRunner) acceptProxmox(order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
	job, refused := r.proxmox.readProxmoxOrder(order)
	if refused != nil {
		r.journal.notAccepted(order, refused.Reason)
		return *refused, nil
	}
	return accepted(order), func(ctx context.Context) {
		output, err := r.proxmox.run(ctx, job)
		r.finishProduce(order, output, err)
	}
}

// acceptDocker juge un déploiement vite, puis l'accepte : le dossier, les
// prérequis, les écritures et Compose sont le travail du worker. La racine
// des services est celle du fichier de l'agent, lue ici sous le verrou.
func (r *orderRunner) acceptDockerDeploy(order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
	return r.acceptDocker(order, false)
}

func (r *orderRunner) acceptDockerUpdate(order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
	return r.acceptDocker(order, true)
}

func (r *orderRunner) acceptDocker(order judgedOrder, update bool) (agentwire.ActionResult, func(ctx context.Context)) {
	job, refused := readDockerOrder(order, r.identity.Root(), update)
	if refused != nil {
		r.journal.notAccepted(order, refused.Reason)
		return *refused, nil
	}
	return accepted(order), func(ctx context.Context) {
		output, err := r.docker.deployService(ctx, job)
		if isAgentStopping(err) {
			// Rien à rapporter : la montée reprendra au démarrage, par son marqueur.
			r.logger.Warn("agent stopping during a service update, it will resume", "run_id", order.RunID)
			return
		}
		r.finishDocker(order, output, err)
	}
}

// requestServiceRollback transmet le veto du serveur à la fenêtre de santé
// ouverte du projet : la montée elle-même revient à la version d'avant et
// rapporte. Hors fenêtre, rien à défaire.
func (r *orderRunner) requestServiceRollback(order judgedOrder) agentwire.ActionResult {
	params, ok := order.Params.(agentwire.DockerRollbackParams)
	if !ok || !agentwire.IsComposeProject(params.Project) {
		r.journal.notAccepted(order, agentwire.ReasonBadOrder)
		return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionFailed, Reason: agentwire.ReasonBadOrder}
	}
	if !r.docker.watches.veto(params.Project) {
		r.journal.notAccepted(order, agentwire.ReasonNoPendingUpdate)
		return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionRefused, Reason: agentwire.ReasonNoPendingUpdate}
	}
	r.journal.executed(order)
	return agentwire.ActionResult{
		RunID: order.RunID, State: agentwire.ActionSucceeded,
		Output: []agentwire.OutputLine{stdout("rollback requested for " + params.Project)},
	}
}

// finishDocker rapporte la fin d'un déploiement. Le .env ne passe ici que par
// le job : ni le résultat ni le journal ne le portent.
func (r *orderRunner) finishDocker(order judgedOrder, output []agentwire.OutputLine, err error) {
	if err != nil {
		r.journal.failed(order, err)
	} else {
		r.journal.executed(order)
	}
	r.results.push(dockerResultOf(order.RunID, output, err))
}

// finishLong rapporte la fin d'un ordre long.
func (r *orderRunner) finishLong(order judgedOrder, output []agentwire.OutputLine, err error) {
	if err != nil {
		r.journal.failed(order, err)
	} else {
		r.journal.executed(order)
	}
	r.results.push(resultOf(order.RunID, output, err))
}

// finishProduce rapporte la fin d'une production. Ce que l'agent a refusé avant
// d'écrire (rien ne se lance, pas de place) est « refusé » ; un producteur ou un
// envoi qui échoue est « échoué ».
func (r *orderRunner) finishProduce(order judgedOrder, output []agentwire.OutputLine, err error) {
	if err != nil {
		r.journal.failed(order, err)
	} else {
		r.journal.executed(order)
	}
	result := resultOf(order.RunID, output, err)
	if result.State == agentwire.ActionFailed && isUntouched(err) {
		result.State = agentwire.ActionRefused
	}
	r.results.push(result)
}

// refuse dit le refus d'un ordre : au journal local, avec ce qu'on en sait
// (les empreintes du corps signé, les valeurs décodées si l'ordre s'est
// décodé, jamais ses octets), et au
// serveur s'il y a un run à qui répondre.
func (r *orderRunner) refuse(signed agentwire.SignedOrder, order judgedOrder, reason string) {
	runID := order.RunID
	if runID != "" {
		r.journal.received(order, reason)
	} else {
		runID = runIDOf(signed.Body)
		r.logger.Warn("order refused", "run_id", runID, "reason", reason, "body_sha256", factsOf(signed.Body, nil).bodySHA256)
	}
	if runID == "" {
		return
	}
	r.results.push(agentwire.ActionResult{RunID: runID, State: agentwire.ActionRefused, Reason: reason})
}

// runIDOf lit l'identifiant d'un corps qui n'a pas passé le jugement : le
// refus se rapporte à ce run. Un faux serveur ne gagne rien à le choisir :
// le rapport repart vers le serveur qui tient le flux.
func runIDOf(body []byte) string {
	var unverified struct {
		RunID string `json:"run_id"`
	}
	if json.Unmarshal(body, &unverified) != nil || len(unverified.RunID) > maxRunIDBytes {
		return ""
	}
	return unverified.RunID
}

// Un identifiant de run plus long n'en est pas un : le serveur refuserait
// le rapport entier.
const maxRunIDBytes = 64

// actionResults garde les résultats entre deux signaux et réveille la
// boucle du flux : la réponse à un ordre n'attend pas les 30 s du signal.
type actionResults struct {
	mu      sync.Mutex
	pending []agentwire.ActionResult
	ready   chan struct{}
}

func newActionResults() *actionResults {
	return &actionResults{ready: make(chan struct{}, 1)}
}

func (a *actionResults) push(result agentwire.ActionResult) {
	a.mu.Lock()
	a.pending = appendBounded(a.pending, []agentwire.ActionResult{result}, agentwire.MaxActionResults)
	a.mu.Unlock()
	select {
	case a.ready <- struct{}{}:
	default:
	}
}

// take vide le tampon ; nil s'il n'y a rien à dire.
func (a *actionResults) take() *agentwire.ActionReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.pending) == 0 {
		return nil
	}
	taken := agentwire.ActionReport{Results: a.pending}
	a.pending = nil
	return &taken
}

// restore remet devant ce qu'un signal n'a pas pu livrer.
func (a *actionResults) restore(report *agentwire.ActionReport) {
	if report == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pending = appendBounded(report.Results, a.pending, agentwire.MaxActionResults)
}
