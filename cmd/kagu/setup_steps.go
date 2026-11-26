package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/edge/config"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/hostinfo"
	refusals "github.com/ldesfontaine/kagu/internal/kit/refusal"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/kit/version"
)

// Les étapes de setup. Chacune lit d'abord l'état réel de la machine et ne
// fait que ce qui manque : relancée, elle se coche « déjà fait » (R-B1-3).
// Une coche dit un état vérifié, jamais une commande lancée (R-B1-2).

// Les systèmes que setup connaît, tels que hostinfo.OSName les nomme.
var supportedSystems = []string{"Debian GNU/Linux 12", "Debian GNU/Linux 13", "Ubuntu 22.04", "Ubuntu 24.04"}

const (
	// La place qu'il faut sous /var/lib : la base, les versions importées.
	minFreeBytes = 1 << 30
	// Les dossiers et fichiers que setup pose.
	configDirMode  = 0o750
	configFileMode = 0o640
	policyDirMode  = 0o755
	privateDirMode = 0o700
	guardDirMode   = 0o755
	binaryMode     = 0o755
	unitFileMode   = 0o644
	// Le shell d'un compte système, qui ne se connecte pas.
	noLoginShell = "/usr/sbin/nologin"
)

// setupSystem est ce que setup demande à la machine, en plus de ce que
// « agent grant » lui demande ; un test en enregistre les gestes.
type setupSystem interface {
	agent.System
	// Account rend le compte du système ; found est faux s'il n'existe pas.
	Account(name string) (owner fsx.Owner, found bool, err error)
	// Systemd dit si systemd mène la machine.
	Systemd() bool
	// FreeBytes : la place libre sous path, pour root.
	FreeBytes(path string) (uint64, error)
	OSName() string
	// Address est l'adresse de la machine que le tunnel SSH vise.
	Address() string
	// EnrollAgent lance l'agent sous son compte avec ces arguments, le jeton
	// sur l'entrée standard : jamais dans les arguments, que tout compte lit
	// dans /proc.
	EnrollAgent(account fsx.Owner, args []string, token string) error
}

// checkSystem : un système connu, mené par systemd, avec de la place.
// Rejouée à chaque setup.
func (r *setupRun) checkSystem(context.Context) (step.State, string, error) {
	name := r.system.OSName()
	if !slices.Contains(supportedSystems, name) {
		return "", "", &stepFailure{reason: r.text.Format("setup.system_unknown", name), todo: r.text.Format("setup.system_unknown_todo", brand.InstallDocURL)}
	}
	if !r.system.Systemd() {
		return "", "", &stepFailure{reason: r.text.Get("setup.no_systemd"), todo: r.text.Format("setup.no_systemd_todo", brand.InstallDocURL)}
	}
	under := filepath.Dir(r.paths.stateDir)
	free, err := r.system.FreeBytes(under)
	if err != nil {
		return "", "", err
	}
	if free < minFreeBytes {
		return "", "", &stepFailure{reason: r.text.Format("setup.disk_full", free>>20, under), todo: r.text.Format("setup.disk_full_todo", under)}
	}
	return step.StateDone, r.text.Format("setup.system_detail", name, runtime.GOARCH), nil
}

// prepareAccounts : les comptes du serveur et de l'agent, le dossier de la
// politique (il marque une machine installée avec la politique, R-A3-16), la
// configuration, et les dossiers d'état fermés (0700) à leur compte.
func (r *setupRun) prepareAccounts(context.Context) (step.State, string, error) {
	changed := false
	for _, account := range []struct{ name, home string }{
		{brand.ServerAccount, r.paths.stateDir},
		{brand.AgentAccount, r.paths.agentStateDir},
	} {
		_, found, err := r.system.Account(account.name)
		if err != nil {
			return "", "", err
		}
		if !found {
			if err := r.system.Run("useradd", "--system", "--home-dir", account.home, "--shell", noLoginShell, account.name); err != nil {
				return "", "", err
			}
			changed = true
		}
	}
	root, server, agentAccount, err := r.accounts()
	if err != nil {
		return "", "", err
	}
	folders := []struct {
		path  string
		mode  fs.FileMode
		owner fsx.Owner
	}{
		{r.paths.policyDir, policyDirMode, root},
		{filepath.Dir(r.paths.configFile), configDirMode, fsx.Owner{UID: root.UID, GID: server.GID}},
	}
	for _, folder := range folders {
		made, err := r.ensureFolder(folder.path, folder.mode, folder.owner)
		if err != nil {
			return "", "", err
		}
		changed = changed || made
	}
	written, err := r.writeServerConfig(config.DefaultListen, fsx.Owner{UID: root.UID, GID: server.GID})
	if err != nil {
		return "", "", err
	}
	changed = changed || written
	for _, folder := range []struct {
		path  string
		owner fsx.Owner
	}{{r.paths.stateDir, server}, {r.paths.agentStateDir, agentAccount}} {
		made, err := r.ensureFolder(folder.path, privateDirMode, folder.owner)
		if err != nil {
			return "", "", err
		}
		changed = changed || made
	}
	r.control = newControlClient(r.paths.stateDir)
	return step.StateDone, r.doneDetail(changed, ""), nil
}

// accounts rend root, le compte du serveur et celui de l'agent.
func (r *setupRun) accounts() (root, server, agentAccount fsx.Owner, err error) {
	owners := make([]fsx.Owner, 0, 3)
	for _, name := range []string{"root", brand.ServerAccount, brand.AgentAccount} {
		owner, found, err := r.system.Account(name)
		if err != nil {
			return root, server, agentAccount, err
		}
		if !found {
			return root, server, agentAccount, fmt.Errorf("account %s is missing", name)
		}
		owners = append(owners, owner)
	}
	return owners[0], owners[1], owners[2], nil
}

// doneDetail dit « déjà fait » quand l'étape n'a rien eu à faire.
func (r *setupRun) doneDetail(changed bool, detail string) string {
	if changed {
		return detail
	}
	return r.text.Get("setup.already_done")
}

// ensureFolder crée le dossier, ou remet celui qui existe à ce compte et à ce
// mode (agent.System.MakeFolder : jamais à travers un lien). Rend vrai s'il a
// fallu y toucher.
func (r *setupRun) ensureFolder(path string, mode fs.FileMode, owner fsx.Owner) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if err == nil && info.IsDir() && info.Mode().Perm() == mode && ownedBy(info, owner) {
		return false, nil
	}
	return true, r.system.MakeFolder(path, mode, owner)
}

func ownedBy(info fs.FileInfo, owner fsx.Owner) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == owner.UID && int(stat.Gid) == owner.GID
}

// writeServerConfig écrit config.toml s'il manque : listen, state_dir, et
// rien d'autre tant qu'il n'y a pas de domaine. Un fichier présent n'est pas
// réécrit, mais setup refuse d'aller plus loin s'il sert l'interface en clair
// hors de la machine (R-CNX-5), comme serve refuserait de démarrer.
func (r *setupRun) writeServerConfig(listen string, owner fsx.Owner) (bool, error) {
	dir, err := os.OpenRoot(filepath.Dir(r.paths.configFile))
	if err != nil {
		return false, err
	}
	defer dir.Close()
	name := filepath.Base(r.paths.configFile)
	existing, err := dir.ReadFile(name)
	if err == nil {
		cfg, _, err := config.Parse(existing)
		if err != nil {
			return false, fmt.Errorf("%s: %w", r.paths.configFile, err)
		}
		if cfg.ServesClearHTTPBeyondLoopback() {
			return false, refuseClearListen(cfg.Listen)
		}
		// Le state_dir du fichier est celui où serve ouvrira sa socket.
		r.listen, r.paths.stateDir = cfg.Listen, cfg.StateDir
		return false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	content, err := config.RenderForSetup(listen, "", r.paths.stateDir, r.releasesURL)
	if errors.Is(err, config.ErrServesClearHTTP) {
		return false, refuseClearListen(listen)
	}
	if err != nil {
		return false, err
	}
	if err := fsx.WriteAtomicOwned(dir, name, content, configFileMode, owner); err != nil {
		return false, err
	}
	r.listen = listen
	return true, nil
}

// startServer pose l'unité de serve, attend sa socket de contrôle, puis lui
// fait importer la version qu'install.sh a vérifiée. Déjà fait si
// /control/admin/health répond ; l'import se rejoue, il ne change rien
// à une version déjà là.
func (r *setupRun) startServer(ctx context.Context) (step.State, string, error) {
	detail, err := r.runServer(ctx)
	if err != nil {
		return "", "", err
	}
	imported, err := r.importDownloadedRelease(ctx)
	if err != nil {
		return "", "", err
	}
	if imported != "" {
		detail = r.text.Format("setup.release_imported", detail, imported)
	}
	return step.StateDone, detail, nil
}

// runServer démarre serve s'il ne répond pas, et rend le détail de la ligne.
func (r *setupRun) runServer(ctx context.Context) (string, error) {
	if r.serverAnswers(ctx) {
		return r.doneDetail(false, ""), nil
	}
	if _, err := os.Stat(r.paths.binary); err != nil {
		return "", &stepFailure{reason: r.text.Format("setup.binary_missing", r.paths.binary), todo: r.text.Format("setup.binary_missing_todo", r.paths.binary)}
	}
	// La règle que serve juge au démarrage, vérifiée avant de le lancer : un
	// dossier ouvert l'arrêterait sans canal local.
	stateDir, err := os.OpenRoot(r.paths.stateDir)
	if err != nil {
		return "", err
	}
	defer stateDir.Close()
	if err := requirePrivateStateDir(stateDir, r.paths.stateDir); err != nil {
		return "", err
	}
	if _, err := r.startUnit(brand.ServerUnit, machine.ServerUnitLines()); err != nil {
		return "", err
	}
	answered, err := r.waitFor(ctx, func(ctx context.Context) (bool, error) { return r.serverAnswers(ctx), nil })
	if err != nil {
		return "", err
	}
	if !answered {
		silent := r.text.Format("setup.server_silent", r.control.socket, int(r.wait.Seconds()))
		return "", &stepFailure{reason: silent, todo: r.text.Get("setup.server_silent_todo")}
	}
	return r.text.Get("setup.server_detail"), nil
}

// importDownloadedRelease fait importer par serve, sous son compte, les
// fichiers de la version qu'install.sh a vérifiée (Library.Import les
// revérifie avec les clés du binaire). Rend la version importée ; rien sans
// dossier, quand setup est lancé sans install.sh.
func (r *setupRun) importDownloadedRelease(ctx context.Context) (string, error) {
	if _, err := os.Stat(r.paths.releaseDir); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	request := struct {
		Folder string `json:"folder"`
	}{Folder: r.paths.releaseDir}
	status, body, err := r.control.post(ctx, controlReleaseImportPath, request, controlTimeout)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		// Le refus dit dans la langue de setup, comme admin le dit.
		refused := adminRun{client: r.control, text: r.text, out: r.out}.refusalOf(status, body)
		return "", &stepFailure{
			reason: r.text.Format("setup.release_refused", r.paths.releaseDir, refused.Error()),
			todo:   r.text.Get("setup.release_refused_todo"),
		}
	}
	var imported struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &imported); err != nil || imported.Version == "" {
		return "", fmt.Errorf("read the imported release: %w", err)
	}
	return imported.Version, nil
}

func (r *setupRun) serverAnswers(ctx context.Context) bool {
	_, err := r.control.get(ctx, controlHealthPath)
	return err == nil
}

// startUnit pose l'unité puis la démarre (ensureRunning). Rend vrai s'il a
// fallu y toucher.
func (r *setupRun) startUnit(unit string, lines []string) (bool, error) {
	written, err := r.installUnit(unit, lines)
	if err != nil {
		return false, err
	}
	started, err := r.ensureRunning(unit, written)
	return written || started, err
}

// installUnit écrit l'unité si elle diffère, et la fait relire à systemd.
func (r *setupRun) installUnit(unit string, lines []string) (bool, error) {
	written, err := writeUnitFile(r.paths.unitDir, unit, lines)
	if err != nil || !written {
		return false, err
	}
	return true, r.system.Run("systemctl", "daemon-reload")
}

// ensureRunning démarre l'unité si elle ne tourne pas, ou la relance si elle
// vient de changer. Rend vrai s'il a fallu y toucher.
func (r *setupRun) ensureRunning(unit string, changed bool) (bool, error) {
	if r.system.Run("systemctl", "is-active", "--quiet", unit) != nil {
		return true, r.system.Run("systemctl", "enable", "--now", unit)
	}
	if changed {
		return true, r.system.Run("systemctl", "restart", unit)
	}
	return false, nil
}

// writeUnitFile écrit l'unité si elle diffère de ces lignes ; ses drop-ins
// ne sont jamais touchés. Rend vrai s'il a fallu l'écrire.
func writeUnitFile(unitDir, unit string, lines []string) (bool, error) {
	dir, err := os.OpenRoot(unitDir)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	content := []byte(strings.Join(lines, "\n") + "\n")
	if existing, err := dir.ReadFile(unit); err == nil && bytes.Equal(existing, content) {
		return false, nil
	}
	return true, fsx.WriteAtomic(dir, unit, content, unitFileMode)
}

// installLocalAgent installe l'agent de la machine Kagu : son binaire et son
// lanceur stable, l'enrôlement par la socket des agents locaux (R-B1-7), le
// jeu et backup.receive dans la politique, la clé du serveur, puis l'unité
// démarrée, jusqu'à son premier rapport.
func (r *setupRun) installLocalAgent(ctx context.Context) (step.State, string, error) {
	root, _, agentAccount, err := r.accounts()
	if err != nil {
		return "", "", err
	}
	stateRoot, err := os.OpenRoot(r.paths.agentStateDir)
	if err != nil {
		return "", "", err
	}
	defer stateRoot.Close()
	changed, err := r.installAgentBinary(stateRoot, agentAccount)
	if err != nil {
		return "", "", err
	}
	guarded, err := r.installGuard(root)
	if err != nil {
		return "", "", err
	}
	changed = changed || guarded
	_, err = agent.LoadIdentity(stateRoot)
	if errors.Is(err, agent.ErrNotEnrolled) {
		if err := r.enrollLocalAgent(ctx, agentAccount); err != nil {
			return "", "", err
		}
		changed = true
	} else if err != nil {
		return "", "", err
	}
	identity, err := agent.LoadIdentity(stateRoot)
	if err != nil {
		return "", "", err
	}
	// L'unité est posée avant la politique : grant relance l'agent par
	// « try-restart », qui ne vaut rien pour une unité inconnue de systemd.
	written, err := r.installUnit(brand.AgentUnit, machine.AgentUnitLines())
	if err != nil {
		return "", "", err
	}
	laid, err := r.layLocalPolicy(stateRoot, identity)
	if err != nil {
		return "", "", err
	}
	started, err := r.ensureRunning(brand.AgentUnit, written)
	if err != nil {
		return "", "", err
	}
	reported, err := r.waitFor(ctx, func(ctx context.Context) (bool, error) {
		local, err := r.readLocalAgent(ctx)
		return local.Reported, err
	})
	if err != nil {
		return "", "", err
	}
	if !reported {
		return "", "", &stepFailure{reason: r.text.Format("setup.agent_silent", int(r.wait.Seconds())), todo: r.text.Get("setup.agent_silent_todo")}
	}
	detail := r.text.Format("setup.agent_detail", r.text.Get("rights."+string(r.rights)))
	if !changed && !laid && !started {
		detail = r.text.Get("setup.already_done") + ", " + detail
	}
	return step.StateDone, detail, nil
}

// installAgentBinary pose bin/<version> et le lien bin/current dans l'état de
// l'agent, à son compte, s'ils manquent. Par os.Root : root n'y suit aucun
// lien que le compte aurait posé.
func (r *setupRun) installAgentBinary(stateRoot *os.Root, owner fsx.Owner) (bool, error) {
	changed := false
	binDir := brand.AgentBinDir
	if _, err := stateRoot.Lstat(binDir); errors.Is(err, fs.ErrNotExist) {
		if err := stateRoot.Mkdir(binDir, privateDirMode); err != nil {
			return false, err
		}
		if err := stateRoot.Chown(binDir, owner.UID, owner.GID); err != nil {
			return false, err
		}
		changed = true
	}
	binaryName := brand.AgentBinaryPrefix + version.Number()
	if _, err := stateRoot.Lstat(binDir + "/" + binaryName); errors.Is(err, fs.ErrNotExist) {
		content, err := os.ReadFile(r.paths.binary)
		if err != nil {
			return false, err
		}
		if err := fsx.WriteAtomicOwned(stateRoot, binDir+"/"+binaryName, content, binaryMode, owner); err != nil {
			return false, err
		}
		changed = true
	}
	link := binDir + "/" + brand.AgentCurrentLink
	if _, err := stateRoot.Lstat(link); errors.Is(err, fs.ErrNotExist) {
		if err := stateRoot.Symlink(binaryName, link); err != nil {
			return false, err
		}
		if err := stateRoot.Lchown(link, owner.UID, owner.GID); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

// installGuard pose le lanceur stable, à root hors de l'état de l'agent, s'il
// manque : l'unité le lance, et l'agent ne le remplace jamais.
func (r *setupRun) installGuard(root fsx.Owner) (bool, error) {
	guardDir := filepath.Dir(r.paths.guardPath)
	changed, err := r.ensureFolder(guardDir, guardDirMode, root)
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(r.paths.guardPath); !errors.Is(err, fs.ErrNotExist) {
		return changed, err
	}
	content, err := os.ReadFile(r.paths.binary)
	if err != nil {
		return false, err
	}
	dir, err := os.OpenRoot(guardDir)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	return true, fsx.WriteAtomic(dir, filepath.Base(r.paths.guardPath), content, binaryMode)
}

// enrollLocalAgent demande le jeton de la machine Kagu par la socket de
// contrôle, puis lance « agent -enroll-only » sous le compte de l'agent, par
// la socket des agents locaux : c'est par elle seule qu'il devient l'agent de
// la machine Kagu. Le jeton ne passe que par l'entrée standard.
func (r *setupRun) enrollLocalAgent(ctx context.Context, account fsx.Owner) error {
	token, err := r.localEnrollmentToken(ctx)
	if err != nil {
		return err
	}
	current := filepath.Join(r.paths.agentStateDir, brand.AgentBinDir, brand.AgentCurrentLink)
	args := []string{current, "agent", "-enroll-only", "-server", "unix:" + r.paths.agentSocket, "-state", r.paths.agentStateDir}
	if err := r.system.EnrollAgent(account, args, token); err != nil {
		return &stepFailure{reason: r.text.Get("setup.enroll_failed") + " : " + err.Error(), todo: r.text.Get("setup.failed_todo")}
	}
	return nil
}

// localEnrollmentToken rend le jeton que serve offre à l'agent de la machine
// Kagu : celui qui attend encore, sinon un neuf. Il ne vit qu'en mémoire.
func (r *setupRun) localEnrollmentToken(ctx context.Context) (string, error) {
	status, body, err := r.control.post(ctx, controlLocalEnrollmentPath, struct{}{}, controlTimeout)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated {
		if isRefusal(body, machine.ErrLocalEnrolled) {
			return "", &stepFailure{reason: r.text.Get("setup.local_enrolled"), todo: r.text.Get("setup.local_enrolled_todo")}
		}
		return "", serverRefusal(status, body)
	}
	var offered struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &offered); err != nil || offered.Token == "" {
		return "", fmt.Errorf("read the local enrollment token: %w", err)
	}
	return offered.Token, nil
}

// isRefusal dit si le corps d'un refus du serveur porte la clé de sentinel.
func isRefusal(body []byte, sentinel error) bool {
	var refused struct {
		Error string `json:"error"`
	}
	key, _ := refusals.KeyOf(sentinel)
	return json.Unmarshal(body, &refused) == nil && refused.Error == key
}

// layLocalPolicy écrit la politique de l'agent de la machine Kagu par le
// chemin de « agent grant » (R-B1-6) : le jeu, puis backup.receive sur le
// dossier des sauvegardes de la base, quel que soit le jeu (R-SAUV-2), puis
// la clé du serveur que l'agent a reçue par la socket. Rend vrai si quelque
// chose a changé ou a été posé.
func (r *setupRun) layLocalPolicy(stateRoot *os.Root, identity agent.Identity) (bool, error) {
	place, err := r.place(stateRoot)
	if err != nil {
		return false, err
	}
	opts := agent.PolicyOptions{StateDir: stateRoot, StatePath: r.paths.agentStateDir, Place: place, EUID: r.euid, Audit: r.audit, System: r.system}
	backups := []agentpolicy.Capability{{Name: agentpolicy.CapabilityBackupReceive, Paths: []string{brand.AgentDatabaseBackupsDir}}}
	serverKey := agent.TrustRequest{Verb: agent.TrustSet, Kind: agentpolicy.TrustServerKey, Value: base64.StdEncoding.EncodeToString(identity.ServerKey)}
	gestures := []func() (agent.PolicyChange, error){
		func() (agent.PolicyChange, error) { return agent.GrantSet(opts, r.rights, r.announceRoot) },
		func() (agent.PolicyChange, error) {
			return agent.GrantRights(opts, backups, agentpolicy.Term{}, r.announceRoot)
		},
		func() (agent.PolicyChange, error) { return agent.Trust(opts, serverKey, r.announceRoot) },
	}
	changed := false
	for _, gesture := range gestures {
		change, err := gesture()
		var partial *agent.PrerequisiteError
		if errors.As(err, &partial) {
			return false, &stepFailure{reason: partial.Err.Error(), todo: r.text.Get("setup.failed_todo")}
		}
		if err != nil {
			return false, explainPolicyError(err, r.text)
		}
		changed = changed || change.Changed() || len(change.Laid) > 0
	}
	return changed, nil
}

// announceRoot est l'accord des gestes de la politique : la réponse à la
// question de setup le donne. « Gérer en root » sur la machine Kagu se dit
// avant d'être posé (R-B1-6, R-DROIT-5).
func (r *setupRun) announceRoot(change agent.PolicyChange) error {
	if change.RootOnServer {
		fmt.Fprintln(r.out, r.text.Get("agent.policy_root_on_server"))
	}
	return nil
}

// localAgent est ce que serve dit de l'agent de la machine Kagu.
type localAgent struct {
	Enrolled bool `json:"enrolled"`
	Online   bool `json:"online"`
	Reported bool `json:"reported"`
	Deploy   struct {
		State  agentpolicy.FitState `json:"state"`
		Reason string               `json:"reason"`
	} `json:"deploy"`
}

func (r *setupRun) readLocalAgent(ctx context.Context) (localAgent, error) {
	var local localAgent
	body, err := r.control.get(ctx, controlLocalAgentPath)
	if err != nil {
		return local, err
	}
	if err := json.Unmarshal(body, &local); err != nil {
		return local, fmt.Errorf("read the local agent: %w", err)
	}
	return local, nil
}

// checkWorkspace : la coche verte attend que l'agent dise docker.deploy
// exerçable dans son rapport ; sous « Observer », sans objet.
func (r *setupRun) checkWorkspace(ctx context.Context) (step.State, string, error) {
	if r.rights == agentpolicy.SetObserve {
		return step.StateSkipped, r.text.Get("setup.workspace_observe"), nil
	}
	var last localAgent
	exercisable, err := r.waitFor(ctx, func(ctx context.Context) (bool, error) {
		local, err := r.readLocalAgent(ctx)
		last = local
		return local.Deploy.State == agentpolicy.FitOK, err
	})
	if err != nil {
		return "", "", err
	}
	if exercisable {
		return step.StateDone, brand.WorkspaceRoot, nil
	}
	if last.Deploy.State == agentpolicy.FitUnavailable {
		return "", "", &stepFailure{reason: r.unavailableText(last.Deploy.Reason), todo: r.text.Get("setup.workspace_todo")}
	}
	return "", "", &stepFailure{reason: r.text.Format("setup.workspace_unknown", int(r.wait.Seconds())), todo: r.text.Get("setup.workspace_todo")}
}

// unavailableText dit pourquoi l'agent ne peut pas exercer un droit, avec la
// phrase de l'écran (web/src/lib/machines.ts, describeUnavailable).
func (r *setupRun) unavailableText(reason string) string {
	if !slices.Contains(machine.UnavailableReasons(), reason) {
		return reason
	}
	if reason == "path_denied" {
		return r.text.Format("machine.capability_unavailable_path_denied", brand.AgentAccount)
	}
	return r.text.Get("machine.capability_unavailable_" + reason)
}

// hostSetupSystem est la vraie machine.
type hostSetupSystem struct {
	agent.HostSystem
}

func (hostSetupSystem) Account(name string) (fsx.Owner, bool, error) {
	account, err := user.Lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		return fsx.Owner{}, false, nil
	}
	if err != nil {
		return fsx.Owner{}, false, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return fsx.Owner{}, false, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return fsx.Owner{}, false, err
	}
	return fsx.Owner{UID: uid, GID: gid}, true, nil
}

func (hostSetupSystem) Systemd() bool {
	info, err := os.Stat("/run/systemd/system")
	return err == nil && info.IsDir()
}

func (hostSetupSystem) FreeBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil // #nosec G115 -- une taille de bloc, positive.
}

func (hostSetupSystem) OSName() string {
	return hostinfo.OSName()
}

func (hostSetupSystem) Address() string {
	info := hostinfo.Collect()
	if info.Address == "" {
		return info.Hostname
	}
	return info.Address
}

// EnrollAgent : le compte de l'agent, sans groupe en plus, un PATH fixe ; ce
// que l'agent écrit en sortant dit pourquoi il a refusé.
func (hostSetupSystem) EnrollAgent(account fsx.Owner, args []string, token string) error {
	command := exec.Command(args[0], args[1:]...) // #nosec G204 -- le binaire de l'agent et les options de setup, aucune valeur de l'opérateur.
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uint32(account.UID), Gid: uint32(account.GID), Groups: []uint32{}, // #nosec G115 -- un uid et un gid.
	}}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.Dir = "/"
	command.Stdin = strings.NewReader(token + "\n")
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, lastLine(output.String()))
	}
	return nil
}

// lastLine rend la dernière ligne non vide d'une sortie.
func lastLine(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	return lines[len(lines)-1]
}
