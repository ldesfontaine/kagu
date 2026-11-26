package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/kit/version"
)

// kagu upgrade : monte le serveur de la machine Kagu à une version signée,
// en root (fiche B2). Lancé dans un terminal, il se relance dans une unité
// transitoire (systemd-run) qui survit à la session SSH ; la sortie suit dans
// le terminal tant qu'il est ouvert. Chaque étape se coche par step.Print et
// s'écrit dans son état (state.json) : --status le relit. Ce qui touche à
// state_dir passe par serve, sur sa socket de contrôle : root n'y écrit
// jamais (R-B2-2). Après « Serveur répond », la suite est jouée par le
// nouveau binaire : ses unités et son lanceur stable sont les siens.

const (
	// Ce que upgrade attend de health après le redémarrage (R-B2-3).
	upgradeWait = 60 * time.Second
	// Le téléchargement d'une version : deux binaires de quelques dizaines
	// de Mio.
	upgradeDownloadTimeout = 10 * time.Minute
	upgradeStateDirMode    = 0o755
	upgradeStateMode       = 0o600
	// La version vérifiée est publique : serve la lit pour l'importer.
	stagedDirMode  = 0o755
	stagedFileMode = 0o644
	// Les options internes : la commande relancée dans l'unité, puis la
	// suite jouée par le nouveau binaire.
	inUnitFlag = "in-unit"
	finishFlag = "finish"
)

// upgradePaths : où upgrade lit et écrit. Chaque chemin se tire de brand ou
// de machine ; un test les place sous son dossier.
type upgradePaths struct {
	stateFile string
	lockFile  string
	// Le dossier de la version vérifiée, à côté de l'état.
	stagingDir     string
	setupStateFile string
	configFile     string
	binary         string
	previous       string
	unitDir        string
	guardPath      string
	agentStateDir  string
}

func systemUpgradePaths() upgradePaths {
	return upgradePaths{
		stateFile: brand.UpgradeStateFile, lockFile: brand.UpgradeLockPath, stagingDir: brand.UpgradeStateDir,
		setupStateFile: brand.SetupStateFile, configFile: brand.ConfigPath, binary: brand.InstalledBinary,
		previous: brand.PreviousBinary, unitDir: filepath.Dir(machine.ServerUnitFile), guardPath: brand.AgentGuardPath,
		agentStateDir: brand.AgentStateDir,
	}
}

// upgradeState est state.json : la version visée, les étapes cochées, les
// chemins. Root seul le lit (0600) ; il ne porte aucun secret.
type upgradeState struct {
	Running  string      `json:"running"`
	Target   string      `json:"target"`
	Binary   string      `json:"binary"`
	Previous string      `json:"previous"`
	StateDir string      `json:"state_dir"`
	Staged   string      `json:"staged"`
	Copy     string      `json:"copy,omitempty"`
	Steps    []step.Step `json:"steps"`
	Finished bool        `json:"finished"`
}

// upgradeSystem est ce que upgrade demande à la machine ; un test en
// enregistre les gestes.
type upgradeSystem interface {
	// Run lance une commande du système (systemctl) et attend sa fin.
	Run(name string, args ...string) error
	// FreeBytes : la place libre sous path, pour root.
	FreeBytes(path string) (uint64, error)
	// RunInUnit relance upgrade avec ces options dans son unité
	// transitoire, la sortie sur ce terminal, et attend sa fin.
	RunInUnit(args []string) error
	// HandOver remplace ce processus par binary avec ces options.
	HandOver(binary string, args []string) error
}

// upgradeRun porte ce qu'une montée touche ; un test y met un faux système,
// ses chemins, ses clés et des attentes courtes.
type upgradeRun struct {
	out    io.Writer
	text   lang.Catalog
	euid   int
	system upgradeSystem
	paths  upgradePaths
	keys   func() (release.Keys, error)
	// La version de ce binaire.
	running string
	// L'adresse des versions et la page de la dernière.
	releaseBase, latestURL string
	place                  policyPlacer
	audit                  func(message string) error
	wait, poll             time.Duration
	// afterStep est appelé après chaque étape cochée ; nil en vrai.
	afterStep func(step.Key) error

	// --to et --from.
	to, from string
	state    upgradeState
	control  *controlClient
	verified release.Verified
	// La montée vient-elle de la bibliothèque de serve (rien à importer) ?
	fromLibrary bool
	// Le binaire de cette machine dans la version visée, tel que vérifié.
	newBinary []byte
}

func runUpgrade(args []string) error {
	run := upgradeRun{
		out: os.Stdout, euid: os.Geteuid(), system: hostUpgradeSystem{}, paths: systemUpgradePaths(),
		keys: release.TrustedPublicKeys, running: version.Number(),
		releaseBase: brand.ReleaseBaseURL, latestURL: brand.ReleaseLatestURL,
		place: agent.SystemPolicyPlace, audit: auditToSystemJournal, wait: upgradeWait, poll: setupPoll,
	}
	return run.command(context.Background(), args)
}

func (r *upgradeRun) command(ctx context.Context, args []string) error {
	catalogs, err := lang.Load()
	if err != nil {
		return err
	}
	r.text = catalogs.For(lang.Default)
	flags := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	to := flags.String("to", "", "")
	from := flags.String("from", "", "")
	status := flags.Bool("status", false, "")
	inUnit := flags.Bool(inUnitFlag, false, "")
	finish := flags.Bool(finishFlag, false, "")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 {
		return &refusal{message: r.text.Get("upgrade.usage")}
	}
	if r.euid != 0 {
		return rootOnlyRefusal(r.text)
	}
	if *status {
		return r.printStatus()
	}
	if !*inUnit {
		return r.relaunchInUnit(*to, *from)
	}
	// Dans l'unité, la sortie est le terminal de systemd-run : la session
	// coupée, l'écrire échoue, et la montée continue (R-B2-5).
	signal.Ignore(syscall.SIGPIPE, syscall.SIGHUP)
	unlock, held, err := holdLock(r.paths.lockFile)
	if err != nil {
		return err
	}
	if !held {
		return &refusal{message: r.text.Format("upgrade.locked", r.paths.lockFile)}
	}
	if r.state, err = readUpgradeState(r.paths.stateFile); err != nil {
		unlock()
		return err
	}
	if *finish {
		defer unlock()
		return r.finish(ctx)
	}
	r.to, r.from = *to, *from
	handOver, err := r.start(ctx)
	// Le verrou tombe avant la passation : le nouveau binaire le reprend.
	unlock()
	if err != nil || !handOver {
		return err
	}
	return r.system.HandOver(r.state.Binary, []string{"--" + inUnitFlag, "--" + finishFlag})
}

// relaunchInUnit relance la commande dans l'unité transitoire et rend son
// code de sortie. --from se donne en chemin absolu : l'unité part de /.
func (r *upgradeRun) relaunchInUnit(to, from string) error {
	args := []string{"--" + inUnitFlag}
	if to != "" {
		args = append(args, "--to", to)
	}
	if from != "" {
		folder, err := filepath.Abs(from)
		if err != nil {
			return err
		}
		args = append(args, "--from", folder)
	}
	err := r.system.RunInUnit(args)
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		return &exitStatus{code: exited.ExitCode()}
	}
	return err
}

// start joue la montée jusqu'à « Serveur répond » ; handOver dit que la
// suite revient au nouveau binaire. Une montée arrêtée après « Binaire
// remplacé » ne se relance pas par-dessus : le retour arrière et --resume
// viendront.
func (r *upgradeRun) start(ctx context.Context) (handOver bool, err error) {
	if r.interrupted() {
		r.printSteps()
		return false, &refusal{message: r.text.Format("upgrade.interrupted", r.state.Target, brand.InstallDocURL)}
	}
	r.state = upgradeState{Running: r.running}
	fmt.Fprintln(r.out, r.text.Format("upgrade.title", r.running))
	fmt.Fprintln(r.out)
	return r.runSteps(ctx, startSteps)
}

// interrupted : une montée a remplacé le binaire sans finir.
func (r *upgradeRun) interrupted() bool {
	if r.state.Finished {
		return false
	}
	for _, checked := range r.state.Steps {
		if checked.Key == step.UpgradeReplaced && checked.State == step.StateDone {
			return true
		}
	}
	return false
}

// finish est la suite jouée par le nouveau binaire : il relit l'état, pose
// ses unités et son lanceur stable, puis note la montée finie.
func (r *upgradeRun) finish(ctx context.Context) error {
	if r.state.Target != r.running || r.state.Finished {
		return &refusal{message: r.text.Format("upgrade.finish_mismatch", r.state.Target, r.running)}
	}
	done, err := r.runSteps(ctx, finishSteps)
	if err != nil || !done {
		return err
	}
	r.state.Finished = true
	if err := r.saveState(); err != nil {
		return err
	}
	if err := os.RemoveAll(r.state.Staged); err != nil {
		return err
	}
	fmt.Fprintln(r.out)
	fmt.Fprintln(r.out, r.text.Format("upgrade.done", r.state.Target))
	return nil
}

// upgradeStep est une coche de upgrade : sa clé et ce qui la fait.
type upgradeStep struct {
	key step.Key
	run func(r *upgradeRun, ctx context.Context) (step.State, string, error)
}

// runSteps joue chaque étape, la coche, l'écrit dans state.json, et s'arrête
// à la première en échec. done est faux quand il n'y a rien à monter : rien
// n'est écrit.
func (r *upgradeRun) runSteps(ctx context.Context, steps []upgradeStep) (done bool, err error) {
	for _, current := range steps {
		state, detail, err := current.run(r, ctx)
		if err != nil {
			reason, todo := explainStepFailure(err, r.text)
			r.check(current.key, step.StateFailed, reason)
			if r.state.Target != "" {
				if err := r.saveState(); err != nil {
					return false, err
				}
			}
			return false, &refusal{message: todo}
		}
		r.check(current.key, state, detail)
		if r.state.Target == "" {
			return false, nil
		}
		if err := r.saveState(); err != nil {
			return false, err
		}
		if r.afterStep != nil {
			if err := r.afterStep(current.key); err != nil {
				return false, err
			}
		}
	}
	return true, nil
}

func (r *upgradeRun) check(key step.Key, state step.State, detail string) {
	r.state.Steps = recordStep(r.out, r.text, r.state.Steps, key, state, detail)
}

// readUpgradeState relit state.json ; absent, aucune montée n'a commencé.
func readUpgradeState(path string) (upgradeState, error) {
	var state upgradeState
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

// saveState écrit state.json d'un coup, à root, en 0600, dans le dossier de
// upgrade (root, 0755).
func (r *upgradeRun) saveState() error {
	dir, err := openUpgradeDir(filepath.Dir(r.paths.stateFile))
	if err != nil {
		return err
	}
	defer dir.Close()
	content, err := json.MarshalIndent(r.state, "", "  ")
	if err != nil {
		return err
	}
	return fsx.WriteAtomic(dir, filepath.Base(r.paths.stateFile), append(content, '\n'), upgradeStateMode)
}

// openUpgradeDir ouvre le dossier de upgrade, créé s'il manque.
func openUpgradeDir(path string) (*os.Root, error) {
	if err := os.MkdirAll(path, upgradeStateDirMode); err != nil {
		return nil, err
	}
	return os.OpenRoot(path)
}

// printStatus dit où en est la dernière montée : ses coches, et si elle
// tourne encore (son verrou est tenu) ou s'est arrêtée.
func (r *upgradeRun) printStatus() error {
	state, err := readUpgradeState(r.paths.stateFile)
	if err != nil {
		return err
	}
	if state.Target == "" {
		fmt.Fprintln(r.out, r.text.Get("upgrade.status_none"))
		return nil
	}
	r.state = state
	fmt.Fprintln(r.out, r.text.Format("upgrade.status_title", state.Running, state.Target))
	fmt.Fprintln(r.out)
	r.printSteps()
	fmt.Fprintln(r.out)
	switch {
	case state.Finished:
		fmt.Fprintln(r.out, r.text.Format("upgrade.done", state.Target))
	case r.lockHeld():
		fmt.Fprintln(r.out, r.text.Get("upgrade.status_running"))
	default:
		fmt.Fprintln(r.out, r.text.Get("upgrade.status_stopped"))
	}
	return nil
}

func (r *upgradeRun) printSteps() {
	for _, checked := range r.state.Steps {
		step.Print(r.out, r.text, checked)
	}
}

// lockHeld : une montée tient le verrou.
func (r *upgradeRun) lockHeld() bool {
	unlock, held, err := holdLock(r.paths.lockFile)
	if err != nil {
		return false
	}
	if held {
		unlock()
	}
	return !held
}

// hostUpgradeSystem est la vraie machine.
type hostUpgradeSystem struct {
	hostSetupSystem
}

// RunInUnit : systemd-run --pipe garde le terminal tant qu'il est ouvert ;
// l'unité, elle, ne dépend pas de lui. --collect l'efface même en échec,
// pour que la suivante reprenne son nom.
func (hostUpgradeSystem) RunInUnit(args []string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.Command("systemd-run", upgradeUnitLine(self, args)...) // #nosec G204 -- ce binaire et ses propres options.
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}

// upgradeUnitLine sont les options de systemd-run qui relancent self upgrade
// dans l'unité transitoire.
func upgradeUnitLine(self string, args []string) []string {
	return append([]string{"--unit=" + brand.UpgradeUnit, "--pipe", "--wait", "--collect", "--quiet", "--", self, "upgrade"}, args...)
}

// HandOver : exec garde le processus de l'unité, son terminal et son nom.
func (hostUpgradeSystem) HandOver(binary string, args []string) error {
	return syscall.Exec(binary, append([]string{binary, "upgrade"}, args...), os.Environ()) // #nosec G204 -- le binaire que upgrade vient de poser, vérifié.
}

// releaseClient télécharge sous l'adresse des versions, et ne suit aucune
// redirection qui en sort.
func (r *upgradeRun) releaseClient() *http.Client {
	return &http.Client{
		Timeout: upgradeDownloadTimeout,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if !isUnder(request.URL.String(), r.releaseBase) {
				return fmt.Errorf("%w: %s", errRedirectOutside, request.URL.Redacted())
			}
			return nil
		},
	}
}

var errRedirectOutside = errors.New("redirect outside the release address")
