package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/kit/version"
)

// kagu join : ajoute cette machine à un Kagu distant, en root (fiche B1 §5,
// étapes 1 à 6). La ligne collée porte le serveur, l'empreinte de sa clé et
// le jeu ; le jeton vient à part, sur le terminal ou dans un fichier, jamais
// dans la ligne (R-B1-10). La clé du serveur est comparée avant que le jeton
// parte, puis encore à l'enrôlement (R-B1-13). Puis les étapes de la machine,
// celles de setup pour un agent, se cochent ; relancé, join reprend.

// tokenFileMode : le fichier du jeton n'est lisible que de root.
const tokenFileMode = 0o600

// joinRun est un setupRun qui n'installe pas de serveur : mêmes étapes de
// l'agent, même verrou, même question.
type joinRun struct {
	setupRun
	// openSilent ouvre le terminal sans écho, pour le jeton.
	openSilent terminalOpener
	server     string
	serverKey  string
	tokenFile  string
	yes        bool
	token      string
	// L'unité de l'agent vient d'être écrite : son démarrage la relance.
	unitWritten bool
}

func runJoin(args []string) error {
	paths := systemSetupPaths()
	// join ne garde pas d'état : ses étapes relisent la machine.
	paths.stateFile = ""
	run := joinRun{
		setupRun: setupRun{
			out: os.Stdout, openTerminal: openControllingTerminal, euid: os.Geteuid(), system: hostSetupSystem{},
			paths: paths, place: agent.SystemPolicyPlace, audit: auditToSystemJournal, wait: setupWait, poll: setupPoll,
		},
		openSilent: openSilentTerminal,
	}
	return run.command(context.Background(), args)
}

func (r *joinRun) command(ctx context.Context, args []string) error {
	catalogs, err := lang.Load()
	if err != nil {
		return err
	}
	r.text = catalogs.For(lang.Default)
	if err := r.parse(args); err != nil {
		return err
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
	fmt.Fprintln(r.out, r.text.Format("join.title", version.Number(), hostOf(r.server)))
	fmt.Fprintln(r.out)
	// Le jeton d'abord : lu après la question, la réponse prendrait la
	// seconde ligne collée.
	if r.token, err = r.readToken(); err != nil {
		return err
	}
	fmt.Fprintln(r.out, r.text.Get("join.token_read"))
	if err := confirmOnTerminal(r.out, r.openTerminal, r.yes, r.text, r.describeChange); err != nil {
		return err
	}
	if err := r.recognizeServerKey(ctx); err != nil {
		return err
	}
	return r.runSteps(ctx, r.steps())
}

// parse lit la ligne : --server, --server-key et --rights, sans valeur par
// défaut, puis --token-file et --yes pour cloud-init. Tout se juge ici,
// avant le jeton.
func (r *joinRun) parse(args []string) error {
	flags := flag.NewFlagSet("join", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&r.server, "server", "", "")
	flags.StringVar(&r.serverKey, "server-key", "", "")
	rights := flags.String("rights", "", "")
	flags.StringVar(&r.tokenFile, "token-file", "", "")
	flags.BoolVar(&r.yes, "yes", false, "")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 || r.server == "" || r.serverKey == "" {
		return &refusal{message: r.text.Get("join.usage")}
	}
	// Le jeu vient de la ligne, jamais du jeton (R-DROIT-6) : sans lui, rien
	// ne s'écrit.
	if *rights == "" {
		return &refusal{message: r.text.Get("join.rights_missing")}
	}
	set, err := agentpolicy.ParseSet(*rights)
	if err != nil {
		return &refusal{message: r.text.Get("setup.rights_unknown")}
	}
	r.rights = set
	if !strings.HasPrefix(r.server, "https://") {
		return &refusal{message: r.text.Get("join.server_not_https")}
	}
	if !ident.IsKeyFingerprint(r.serverKey) {
		return &refusal{message: r.text.Get("agent.server_key_invalid")}
	}
	return nil
}

// hostOf rend le nom du serveur, pour le titre.
func hostOf(server string) string {
	parsed, err := url.Parse(server)
	if err != nil {
		return server
	}
	return parsed.Host
}

// readToken lit le jeton : dans --token-file, effacé aussitôt lu ; sinon sur
// le terminal, écho coupé, où le collage a laissé la seconde ligne (s'il ne
// l'a pas fait, join attend qu'on la tape). Sans terminal ni fichier, join
// refuse : il ne lit jamais l'entrée standard, qui est le script.
func (r *joinRun) readToken() (string, error) {
	if r.tokenFile != "" {
		return r.readTokenFile()
	}
	terminal, err := r.openSilent()
	if err != nil {
		return "", &refusal{message: r.text.Get("join.token_needs_file")}
	}
	defer terminal.Close()
	fmt.Fprint(r.out, r.text.Get("join.token_prompt"))
	token, err := readEnrollmentToken(terminal)
	// L'écho coupé n'a pas rendu le retour à la ligne.
	fmt.Fprintln(r.out)
	if errors.Is(err, agent.ErrTokenMissing) {
		return "", &refusal{message: r.text.Get("join.token_missing")}
	}
	return token, err
}

// readTokenFile lit le fichier du jeton s'il est à root et fermé aux autres
// (0600), puis l'efface, qu'il soit bon ou non : le jeton ne reste pas sur le
// disque (R-B1-10, W-F4).
func (r *joinRun) readTokenFile() (string, error) {
	file, err := os.OpenFile(r.tokenFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", &refusal{message: r.text.Format("join.token_file_unreadable", r.tokenFile)}
	}
	defer file.Close()
	removeErr := os.Remove(r.tokenFile)
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&^tokenFileMode != 0 || !ownedByCaller(info) {
		return "", &refusal{message: r.text.Format("join.token_file_open", r.tokenFile)}
	}
	if removeErr != nil {
		return "", fmt.Errorf("remove %s: %w", r.tokenFile, removeErr)
	}
	token, err := readEnrollmentToken(file)
	if errors.Is(err, agent.ErrTokenMissing) {
		return "", &refusal{message: r.text.Get("join.token_missing")}
	}
	return token, err
}

// ownedByCaller dit si le fichier est au compte qui lance join : root, qui
// seul a pu l'écrire là.
func ownedByCaller(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

// describeChange dit ce que join va changer, avant la question : le compte,
// l'agent, le jeu et sa phrase de risque (R-A3-15, R-DROIT-8).
func (r *joinRun) describeChange() {
	hostname, _ := os.Hostname()
	fmt.Fprintln(r.out, r.text.Format("join.change", hostname))
	fmt.Fprintln(r.out, r.text.Format("join.change_detail", brand.AgentAccount, r.text.Get("rights."+string(r.rights))))
	fmt.Fprintln(r.out, "    ("+r.text.Get(setHints[r.rights])+")")
}

// recognizeServerKey lit la clé que le serveur présente et la compare à
// l'empreinte de la ligne, avant que le jeton parte : un écart arrête tout,
// le jeton reste valable (R-B1-13).
func (r *joinRun) recognizeServerKey(ctx context.Context) error {
	client, err := agent.NewClient(r.server, version.Number())
	if err != nil {
		return explainJoinError(err, r.text)
	}
	if _, err := agent.CheckServerKey(ctx, client, r.serverKey); err != nil {
		return explainJoinError(err, r.text)
	}
	fmt.Fprintln(r.out, r.text.Format("join.server_key_ok", r.serverKey))
	return nil
}

// explainJoinError dit un échec de l'agent dans la langue de join.
func explainJoinError(err error, text lang.Catalog) error {
	message, refused := agent.Explain(err, text)
	if refused {
		return &refusal{message: message}
	}
	return errors.New(message)
}

// steps : celles d'une machine qui arrive (B1 §3), dans l'ordre où le code
// les tient : l'enrôlement avant les droits, que grant ne pose que sur une
// identité. Docker, restic, le dossier des services et le premier signal
// viendront avec leurs étapes.
func (r *joinRun) steps() []setupStep {
	return []setupStep{
		{step.EnrollSystem, r.checkSystem},
		{step.EnrollAccount, r.prepareAgentAccount},
		{step.EnrollEnrolled, r.enrollAgent},
		{step.EnrollRights, r.layRights},
		{step.EnrollUnit, r.startAgent},
	}
}

// prepareAgentAccount : le compte de l'agent, le dossier de la politique (il
// marque une machine installée avec elle, R-A3-16), l'état de l'agent fermé
// à son compte, son binaire et le lanceur stable.
func (r *joinRun) prepareAgentAccount(context.Context) (step.State, string, error) {
	changed, err := r.ensureAccount(brand.AgentAccount, r.paths.agentStateDir)
	if err != nil {
		return "", "", err
	}
	root, err := r.account("root")
	if err != nil {
		return "", "", err
	}
	agentAccount, err := r.account(brand.AgentAccount)
	if err != nil {
		return "", "", err
	}
	for _, folder := range []struct {
		path  string
		mode  fs.FileMode
		owner fsx.Owner
	}{{r.paths.policyDir, policyDirMode, root}, {r.paths.agentStateDir, privateDirMode, agentAccount}} {
		made, err := r.ensureFolder(folder.path, folder.mode, folder.owner)
		if err != nil {
			return "", "", err
		}
		changed = changed || made
	}
	stateRoot, err := os.OpenRoot(r.paths.agentStateDir)
	if err != nil {
		return "", "", err
	}
	defer stateRoot.Close()
	installed, err := r.installAgentBinary(stateRoot, agentAccount)
	if err != nil {
		return "", "", err
	}
	guarded, err := r.installGuard(root)
	if err != nil {
		return "", "", err
	}
	return step.StateDone, r.doneDetail(changed || installed || guarded, brand.AgentAccount), nil
}

// enrollAgent lance « agent -enroll-only » sous le compte de l'agent, le
// jeton sur son entrée standard : il recompare la clé avant d'envoyer le
// jeton, puis celle de la réponse, et tire sa paire X25519 (R-B1-18). Une
// identité déjà là pour ce serveur et cette clé, c'est fait ; pour un autre,
// join ne la remplace pas.
func (r *joinRun) enrollAgent(context.Context) (step.State, string, error) {
	agentAccount, err := r.account(brand.AgentAccount)
	if err != nil {
		return "", "", err
	}
	stateRoot, err := os.OpenRoot(r.paths.agentStateDir)
	if err != nil {
		return "", "", err
	}
	defer stateRoot.Close()
	identity, err := agent.LoadIdentity(stateRoot)
	changed := errors.Is(err, agent.ErrNotEnrolled)
	switch {
	case changed:
		current := filepath.Join(r.paths.agentStateDir, brand.AgentBinDir, brand.AgentCurrentLink)
		args := []string{current, "agent", "-enroll-only", "-server", r.server, "-server-key", r.serverKey, "-state", r.paths.agentStateDir}
		if err := r.system.EnrollAgent(agentAccount, args, r.token); err != nil {
			return "", "", &stepFailure{reason: r.text.Get("setup.enroll_failed") + " : " + err.Error(), todo: r.text.Get("setup.failed_todo")}
		}
		if identity, err = agent.LoadIdentity(stateRoot); err != nil {
			return "", "", err
		}
	case err != nil:
		return "", "", err
	case identity.Server != r.server || identity.ServerKeyFingerprint() != r.serverKey:
		return "", "", &stepFailure{
			reason: r.text.Format("join.enrolled_elsewhere", identity.Server),
			todo:   r.text.Format("join.enrolled_elsewhere_todo", strings.Join(machine.ReenrollLines(), "\n")),
		}
	}
	// L'empreinte que la fiche de la machine montre aussi (R-B1-10).
	return step.StateDone, r.doneDetail(changed, r.text.Format("join.agent_key", ident.KeyFingerprint(identity.PublicKey))), nil
}

// layRights pose l'unité, sans la démarrer (grant relance l'agent par
// « try-restart », qui ne vaut rien pour une unité inconnue), puis la
// politique : le jeu de la ligne et la clé du serveur épinglée, comparée à la
// ligne à l'enrôlement.
func (r *joinRun) layRights(context.Context) (step.State, string, error) {
	stateRoot, err := os.OpenRoot(r.paths.agentStateDir)
	if err != nil {
		return "", "", err
	}
	defer stateRoot.Close()
	identity, err := agent.LoadIdentity(stateRoot)
	if err != nil {
		return "", "", err
	}
	if r.unitWritten, err = r.installUnit(brand.AgentUnit, machine.AgentUnitLines()); err != nil {
		return "", "", err
	}
	laid, err := r.layPolicy(stateRoot, identity, nil)
	if err != nil {
		return "", "", err
	}
	return step.StateDone, r.doneDetail(laid || r.unitWritten, r.text.Get("rights."+string(r.rights))), nil
}

// startAgent démarre l'agent, ou le relance si son unité vient de changer.
func (r *joinRun) startAgent(context.Context) (step.State, string, error) {
	started, err := r.ensureRunning(brand.AgentUnit, r.unitWritten)
	if err != nil {
		return "", "", err
	}
	return step.StateDone, r.doneDetail(started, brand.AgentUnit), nil
}
