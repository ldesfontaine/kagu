package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/kit/untrusted"
	"github.com/ldesfontaine/kagu/internal/kit/version"
	"github.com/ldesfontaine/kagu/internal/kit/wait"
)

// kagu setup : installe Kagu sur la machine où il tourne, en root (fiche
// B1). Une seule question, le jeu de droits de l'agent de cette machine ;
// puis chaque étape regarde l'état réel, fait ce qui manque, et se coche par
// step.Print avec les clés de l'écran. Relancé, setup reprend : ce qui est
// fait se coche « déjà fait ». Le code de première configuration vient en
// dernier. Le domaine et le proxy viendront avec le proxy géré : d'ici là,
// l'interface n'écoute que la boucle locale, jointe par le tunnel SSH.

const (
	// Ce que setup attend du serveur, puis du premier rapport de l'agent.
	setupWait = 60 * time.Second
	// Entre deux lectures de la socket de contrôle.
	setupPoll = 500 * time.Millisecond
	// Le jeu posé quand personne ne répond : celui que la question propose.
	defaultSetupRights = agentpolicy.SetManage
	setupStateMode     = 0o600
	lockMode           = 0o600
)

// setupPaths : où setup écrit. Chaque chemin se tire de brand ; un test les
// place sous son dossier.
type setupPaths struct {
	configFile    string
	stateFile     string
	lockFile      string
	stateDir      string
	agentStateDir string
	policyDir     string
	unitDir       string
	binary        string
	guardPath     string
	agentSocket   string
	// Les fichiers de la version qu'install.sh a vérifiée.
	releaseDir string
}

func systemSetupPaths() setupPaths {
	return setupPaths{
		configFile: brand.ConfigPath, stateFile: brand.SetupStateFile, lockFile: brand.SetupLockPath,
		stateDir: brand.StateDir, agentStateDir: brand.AgentStateDir, policyDir: brand.AgentPolicyDir,
		unitDir: filepath.Dir(machine.ServerUnitFile), binary: brand.InstalledBinary,
		guardPath: brand.AgentGuardPath, agentSocket: brand.AgentSocketPath, releaseDir: brand.SetupReleaseDir,
	}
}

// setupState est setup.json : la réponse à la question et les étapes cochées,
// rien d'autre. Jamais un jeton ni un code : B2 le relit.
type setupState struct {
	Rights agentpolicy.Set `json:"rights,omitempty"`
	Steps  []step.Step     `json:"steps"`
}

// setupRun porte ce qu'une installation touche ; un test y met un faux
// système, ses chemins et des attentes courtes.
type setupRun struct {
	out          io.Writer
	text         lang.Catalog
	openTerminal terminalOpener
	euid         int
	system       setupSystem
	paths        setupPaths
	place        policyPlacer
	audit        func(message string) error
	wait, poll   time.Duration
	// afterStep est appelé après chaque étape cochée ; nil en vrai. Un test
	// y coupe setup, comme une session SSH perdue.
	afterStep func(step.Key) error
	// report envoie le parcours au serveur après chaque ligne cochée, pour
	// la tuile de la machine qui arrive (R-B1-11) : setup par la socket de
	// contrôle, join par la route de l'agent.
	report func(ctx context.Context, steps []step.Step)

	rights agentpolicy.Set
	// L'adresse des versions qu'install.sh passe (--releases-url) ; vide :
	// celle par défaut.
	releasesURL string
	state       setupState
	listen      string
	control     *controlClient
}

func runSetup(args []string) error {
	run := setupRun{
		out: os.Stdout, openTerminal: openControllingTerminal, euid: os.Geteuid(), system: hostSetupSystem{},
		paths: systemSetupPaths(), place: agent.SystemPolicyPlace, audit: auditToSystemJournal, wait: setupWait, poll: setupPoll,
	}
	return run.command(context.Background(), args)
}

func (r *setupRun) command(ctx context.Context, args []string) error {
	catalogs, err := lang.Load()
	if err != nil {
		return err
	}
	r.text = catalogs.For(lang.Default)
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	// L'aide se dit par setup.usage, dans la langue de la commande.
	flags.SetOutput(io.Discard)
	rights := flags.String("rights", "", "")
	flags.StringVar(&r.releasesURL, "releases-url", "", "")
	flags.String("domain", "", "")
	flags.String("proxy", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 {
		return &refusal{message: r.text.Get("setup.usage")}
	}
	// Sans proxy géré, setup ne sait ni vérifier un domaine ni poser un
	// proxy : il refuse plutôt que d'écouter ailleurs que sur la boucle.
	if flagIsSet(flags, "domain") || flagIsSet(flags, "proxy") {
		return &refusal{message: r.text.Get("setup.domain_later")}
	}
	if r.euid != 0 {
		return rootOnlyRefusal(r.text)
	}
	release, held, err := holdLock(r.paths.lockFile)
	if err != nil {
		return err
	}
	if !held {
		return &refusal{message: r.text.Format("setup.locked", r.paths.lockFile)}
	}
	defer release()
	if r.state, err = readSetupState(r.paths.stateFile); err != nil {
		return err
	}
	fmt.Fprintln(r.out, r.text.Format("setup.title", version.Number()))
	fmt.Fprintln(r.out)
	if r.rights, err = r.chooseRights(*rights); err != nil {
		return err
	}
	r.state.Rights = r.rights
	r.report = r.reportLocalProgress
	if err := r.runSteps(ctx, r.steps()); err != nil {
		return err
	}
	return r.finish(ctx)
}

// holdLock prend le verrou d'une commande root (setup, upgrade) sans
// attendre, par flock comme le verrou de l'identité de l'agent ; il tombe
// avec le processus. held est faux quand une autre le tient.
func holdLock(path string) (release func(), held bool, err error) {
	lock, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, lockMode) // #nosec G304 -- chemin de brand.
	if err != nil {
		return nil, false, fmt.Errorf("open the lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- un descripteur tient dans un int.
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("take the lock %s: %w", path, err)
	}
	return func() { _ = lock.Close() }, true, nil
}

// readSetupState relit setup.json ; absent, setup part de rien.
func readSetupState(path string) (setupState, error) {
	var state setupState
	content, err := os.ReadFile(path) // #nosec G304 -- chemin de brand.
	if errors.Is(err, fs.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(content, &state); err != nil {
		return state, fmt.Errorf("read %s: %w", path, err)
	}
	return state, nil
}

// saveSetupState écrit setup.json d'un coup, à root, en 0600. Tant que le
// dossier de la configuration n'existe pas, rien ne s'écrit : la première
// étape se rejoue toujours.
func (r *setupRun) saveSetupState() error {
	// join ne garde rien : ses étapes relisent la machine.
	if r.paths.stateFile == "" {
		return nil
	}
	dir, err := os.OpenRoot(filepath.Dir(r.paths.stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	content, err := json.MarshalIndent(r.state, "", "  ")
	if err != nil {
		return err
	}
	return fsx.WriteAtomic(dir, filepath.Base(r.paths.stateFile), append(content, '\n'), setupStateMode)
}

// chooseRights rend le jeu de l'agent de cette machine : --rights, sinon la
// réponse d'un setup d'avant, sinon la question, posée sur le terminal (sous
// « curl | sh », l'entrée standard est le script). Sans terminal, le jeu par
// défaut vaut (R-B1-1).
func (r *setupRun) chooseRights(flagValue string) (agentpolicy.Set, error) {
	if flagValue != "" {
		set, err := agentpolicy.ParseSet(flagValue)
		if err != nil {
			return "", &refusal{message: r.text.Get("setup.rights_unknown")}
		}
		return set, nil
	}
	if r.state.Rights != "" {
		return r.state.Rights, nil
	}
	terminal, err := r.openTerminal()
	if err != nil {
		return defaultSetupRights, nil
	}
	defer terminal.Close()
	return r.askRights(terminal)
}

// setHints : la phrase de chaque jeu, celle de l'écran.
var setHints = map[agentpolicy.Set]string{
	agentpolicy.SetObserve: "rights.observe_hint",
	agentpolicy.SetManage:  "rights.manage_risk",
	agentpolicy.SetRoot:    "rights.root_risk",
}

// askRights pose la question des jeux ; Entrée prend celui par défaut.
func (r *setupRun) askRights(terminal io.Reader) (agentpolicy.Set, error) {
	sets := agentpolicy.Sets()
	fmt.Fprintln(r.out, r.text.Get("setup.rights_question"))
	defaultChoice := 0
	for index, set := range sets {
		mark := "  "
		if set == defaultSetupRights {
			mark, defaultChoice = "› ", index+1
		}
		fmt.Fprintf(r.out, "  %s%d  %-15s %s\n", mark, index+1, r.text.Get("rights."+string(set)), r.text.Get(setHints[set]))
	}
	fmt.Fprint(r.out, r.text.Format("setup.rights_choice", defaultChoice))
	answer, _ := bufio.NewReader(terminal).ReadString('\n')
	fmt.Fprintln(r.out)
	answer = strings.TrimSpace(answer)
	if answer == "" {
		return defaultSetupRights, nil
	}
	choice, err := strconv.Atoi(answer)
	if err != nil || choice < 1 || choice > len(sets) {
		return "", &refusal{message: r.text.Get("setup.rights_unknown")}
	}
	return sets[choice-1], nil
}

// stepFailure est une étape en échec : sa raison s'écrit sur la ligne, ce
// qu'il faut faire dans le refus qui arrête la commande (R-B1-2).
type stepFailure struct {
	reason string
	todo   string
}

func (f *stepFailure) Error() string {
	return f.reason
}

// setupStep est une ligne de setup ou de join : sa clé et ce qui la vérifie.
type setupStep struct {
	key step.Key
	run func(ctx context.Context) (step.State, string, error)
}

// steps : celles de setup, dans l'ordre de B1 §5 jusqu'à « Dossier des
// services ». Docker et restic viendront entre le système et les comptes.
func (r *setupRun) steps() []setupStep {
	return []setupStep{
		{step.EnrollSystem, r.checkSystem},
		{step.SetupAccount, r.prepareAccounts},
		{step.SetupServer, r.startServer},
		{step.SetupAgent, r.installLocalAgent},
		{step.EnrollWorkspace, r.checkWorkspace},
	}
}

// runSteps joue chaque étape, la coche, l'écrit dans setup.json, et s'arrête
// à la première en échec.
func (r *setupRun) runSteps(ctx context.Context, steps []setupStep) error {
	for _, current := range steps {
		state, detail, err := current.run(ctx)
		if err != nil {
			reason, todo := explainStepFailure(err, r.text)
			r.check(ctx, current.key, step.StateFailed, reason)
			if err := r.saveSetupState(); err != nil {
				return err
			}
			return &refusal{message: todo}
		}
		r.check(ctx, current.key, state, detail)
		if err := r.saveSetupState(); err != nil {
			return err
		}
		if r.afterStep != nil {
			if err := r.afterStep(current.key); err != nil {
				return err
			}
		}
	}
	return nil
}

// explainStepFailure rend la raison d'une étape en échec et ce qu'il faut
// faire. Un refus de la commande (state_dir ouvert, listen public) dit déjà
// les deux.
func explainStepFailure(err error, text lang.Catalog) (reason, todo string) {
	var failure *stepFailure
	if errors.As(err, &failure) {
		return failure.reason, failure.todo
	}
	var refused *refusal
	if errors.As(err, &refused) {
		return "", refused.message
	}
	return err.Error(), text.Get("setup.failed_todo")
}

// check imprime la ligne d'une étape, la retient pour setup.json et envoie
// le parcours au serveur.
func (r *setupRun) check(ctx context.Context, key step.Key, state step.State, detail string) {
	r.state.Steps = recordStep(r.out, r.text, r.state.Steps, key, state, detail)
	if r.report != nil {
		r.report(ctx, r.state.Steps)
	}
}

// recordStep imprime la ligne d'une étape et rend steps où elle remplace
// celle d'un passage d'avant.
func recordStep(out io.Writer, text lang.Catalog, steps []step.Step, key step.Key, state step.State, detail string) []step.Step {
	checked := step.Step{Key: key, State: state, Detail: untrusted.Bound(detail, step.MaxDetailRunes), At: time.Now().UTC()}
	step.Print(out, text, checked)
	kept := steps[:0]
	for _, previous := range steps {
		if previous.Key != key {
			kept = append(kept, previous)
		}
	}
	return append(kept, checked)
}

// waitFor relit check jusqu'à ce qu'il réponde vrai, au plus r.wait.
func (r *setupRun) waitFor(ctx context.Context, check func(context.Context) (bool, error)) (bool, error) {
	return waitUntil(ctx, r.wait, r.poll, check)
}

// waitUntil relit check toutes les poll jusqu'à ce qu'il réponde vrai, au
// plus limit.
func waitUntil(ctx context.Context, limit, poll time.Duration, check func(context.Context) (bool, error)) (bool, error) {
	deadline := time.Now().Add(limit)
	for {
		done, err := check(ctx)
		if done || err != nil {
			return done, err
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		if !wait.For(ctx, poll) {
			return false, ctx.Err()
		}
	}
}

// finish donne le tunnel, l'adresse à ouvrir, puis le code de première
// configuration, en dernier (R-B1-9) : un setup relancé en tire un neuf, qui
// annule l'ancien. Le compte déjà créé, il n'y a plus de code à donner.
func (r *setupRun) finish(ctx context.Context) error {
	_, port, err := net.SplitHostPort(r.listen)
	if err != nil {
		return err
	}
	fmt.Fprintln(r.out)
	fmt.Fprintln(r.out, r.text.Format("setup.tunnel", port+":"+r.listen, r.system.Address()))
	fmt.Fprintln(r.out, r.text.Format("setup.open", "http://localhost:"+port))
	fmt.Fprintln(r.out)
	admin := adminRun{client: r.control, text: r.text, out: r.out}
	err = admin.issueSetupCode(ctx)
	var refused *refusal
	if errors.As(err, &refused) && refused.message == r.text.Get("admin.setup_already_done") {
		fmt.Fprintln(r.out, refused.message)
		return nil
	}
	return err
}
