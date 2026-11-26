package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/edge/config"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	refusals "github.com/ldesfontaine/kagu/internal/kit/refusal"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/step"
)

// Les coches de upgrade, dans l'ordre de B2 §5. Les deux dernières sont
// jouées par le nouveau binaire (finishSteps).
var startSteps = []upgradeStep{
	{step.UpgradeFound, (*upgradeRun).findVersion},
	{step.UpgradeSpace, (*upgradeRun).checkSpace},
	{step.UpgradeCopied, (*upgradeRun).copyDatabase},
	{step.UpgradeReplaced, (*upgradeRun).replaceBinary},
	{step.UpgradeRestarted, (*upgradeRun).restartServer},
	{step.UpgradeAnswers, (*upgradeRun).awaitServer},
}

var finishSteps = []upgradeStep{
	{step.UpgradeUnits, (*upgradeRun).updateUnits},
	{step.UpgradePolicy, (*upgradeRun).updateAgentPolicy},
}

// findVersion trouve la version visée et la vérifie avec les clés de ce
// binaire, celui en place, jamais celles du binaire qui arrive (R-B2-1) :
// --from, sinon la plus haute de la bibliothèque au-dessus de celle en place,
// sinon le téléchargement. La version vérifiée est posée à côté de l'état,
// puis importée par serve quand elle ne vient pas de sa bibliothèque.
func (r *upgradeRun) findVersion(ctx context.Context) (step.State, string, error) {
	keys, err := r.keys()
	if errors.Is(err, release.ErrNoTrustedKey) {
		return "", "", &stepFailure{reason: r.text.Get("upgrade.no_key"), todo: r.text.Format("upgrade.no_key_todo", brand.InstallDocURL)}
	}
	if err != nil {
		return "", "", err
	}
	running, err := release.ParseVersion(r.running)
	if err != nil {
		return "", "", err
	}
	if err := r.findInstallation(); err != nil {
		return "", "", err
	}
	wanted, err := r.wantedVersion(running)
	if err != nil {
		return "", "", err
	}
	verified, err := r.readTarget(ctx, keys, running, wanted)
	if err != nil {
		return "", "", r.explainVerification(err)
	}
	if verified.Version.Compare(running) <= 0 {
		return step.StateDone, r.text.Format("upgrade.found_none", r.running), nil
	}
	binaryName := release.BinaryName(runtime.GOARCH)
	r.newBinary = verified.Binaries[binaryName]
	if r.newBinary == nil {
		return "", "", &stepFailure{reason: r.text.Format("upgrade.no_binary", binaryName), todo: r.text.Get("upgrade.verify_todo")}
	}
	r.verified = verified
	r.state.Target = verified.Version.String()
	r.state.Previous = r.paths.previous
	if err := r.stage(); err != nil {
		return "", "", err
	}
	// Importée par serve, la version est celle qu'il tend ensuite aux agents
	// (R-B2-6).
	if !r.fromLibrary {
		_, err := importReleaseByServe(ctx, r.control, r.text, r.state.Staged)
		var refused *refusal
		if errors.As(err, &refused) {
			return "", "", &stepFailure{reason: refused.Error(), todo: r.text.Get("upgrade.verify_todo")}
		}
		if err != nil {
			return "", "", err
		}
	}
	return step.StateDone, r.text.Format("upgrade.found_detail", r.state.Target, r.running), nil
}

// findInstallation lit où est le serveur : avec setup.json, aux chemins de
// setup ; posé à la main, d'après l'ExecStart de son unité et le
// config.toml qu'elle cite.
func (r *upgradeRun) findInstallation() error {
	binary, configPath := r.paths.binary, r.paths.configFile
	if _, err := os.Stat(r.paths.setupStateFile); errors.Is(err, fs.ErrNotExist) {
		var found bool
		binary, configPath, found = readServerExecStart(filepath.Join(r.paths.unitDir, brand.ServerUnit))
		if !found {
			return &stepFailure{reason: r.text.Format("upgrade.not_installed", brand.ServerUnit), todo: r.text.Format("upgrade.not_installed_todo", brand.InstallDocURL)}
		}
	}
	cfg, _, err := config.Load(configPath)
	if err != nil {
		return err
	}
	r.state.Binary, r.state.StateDir = binary, cfg.StateDir
	r.control = newControlClient(cfg.StateDir)
	return nil
}

// readServerExecStart lit dans l'unité du serveur le binaire lancé et son
// -config (le chemin par défaut s'il n'en a pas). found est faux sans unité
// ou sans « serve ».
func readServerExecStart(unitFile string) (binary, configPath string, found bool) {
	file, err := os.Open(unitFile) // #nosec G304 -- l'unité du serveur, à root.
	if err != nil {
		return "", "", false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line, isExecStart := strings.CutPrefix(strings.TrimSpace(scanner.Text()), "ExecStart=")
		fields := strings.Fields(line)
		if !isExecStart || len(fields) < 2 || fields[1] != "serve" {
			continue
		}
		configPath = config.DefaultPath
		for index, field := range fields {
			if (field == "-config" || field == "--config") && index+1 < len(fields) {
				configPath = fields[index+1]
			}
		}
		return fields[0], configPath, true
	}
	return "", "", false
}

// wantedVersion lit --to : une version plus récente que celle en place.
// Descendre est le retour arrière, pas une montée.
func (r *upgradeRun) wantedVersion(running release.Version) (release.Version, error) {
	if r.to == "" {
		return release.Version{}, nil
	}
	wanted, err := release.ParseVersion(r.to)
	if err != nil {
		return release.Version{}, &refusal{message: r.text.Get("upgrade.usage")}
	}
	if wanted.Compare(running) <= 0 {
		return release.Version{}, &stepFailure{reason: r.text.Format("upgrade.not_newer", r.to, r.running), todo: r.text.Get("upgrade.not_newer_todo")}
	}
	return wanted, nil
}

// readTarget lit et vérifie la version visée, en entier : --from, sinon la
// bibliothèque de serve, sinon l'adresse des versions. wanted vide : la plus
// récente. Une version plus ancienne que celle en place est rendue telle
// quelle : il n'y a rien à monter.
func (r *upgradeRun) readTarget(ctx context.Context, keys release.Keys, running, wanted release.Version) (release.Verified, error) {
	if r.from != "" {
		return r.readFolder(keys, wanted)
	}
	verified, found, err := r.readLibrary(keys, running, wanted)
	if err != nil || found {
		r.fromLibrary = found
		return verified, err
	}
	if wanted == (release.Version{}) {
		if wanted, err = r.latestVersion(ctx); err != nil {
			return release.Verified{}, err
		}
		if wanted.Compare(running) <= 0 {
			return release.Verified{Release: release.Release{Version: wanted}}, nil
		}
	}
	return r.download(ctx, keys, wanted)
}

// readFolder lit --from, un dossier de root : la version qu'il porte doit
// être celle de --to quand il est donné.
func (r *upgradeRun) readFolder(keys release.Keys, wanted release.Version) (release.Verified, error) {
	folder, err := os.OpenRoot(r.from)
	if err != nil {
		return release.Verified{}, err
	}
	defer folder.Close()
	verified, err := release.ReadVerified(release.RootOpener(folder), keys)
	if err != nil {
		return release.Verified{}, err
	}
	if wanted != (release.Version{}) && verified.Version != wanted {
		return release.Verified{}, &stepFailure{reason: r.text.Format("upgrade.other_version", r.from, verified.Version, wanted), todo: r.text.Get("upgrade.verify_todo")}
	}
	return verified, nil
}

// readLibrary cherche la version dans la bibliothèque de serve : root la lit,
// sans y écrire, et la revérifie avec ses propres clés. found est faux
// quand elle n'y est pas.
func (r *upgradeRun) readLibrary(keys release.Keys, running, wanted release.Version) (release.Verified, bool, error) {
	stateDir, err := os.OpenRoot(r.state.StateDir)
	if err != nil {
		return release.Verified{}, false, err
	}
	defer stateDir.Close()
	library := release.NewLibrary(stateDir, keys)
	versions, err := library.Versions()
	if err != nil {
		return release.Verified{}, false, err
	}
	var chosen release.Version
	for _, imported := range versions {
		if imported.Compare(running) > 0 && (wanted == (release.Version{}) || imported == wanted) {
			chosen = imported
		}
	}
	if chosen == (release.Version{}) {
		return release.Verified{}, false, nil
	}
	verified, err := library.Read(chosen)
	return verified, err == nil, err
}

// latestVersion lit le numéro de la dernière version publiée : la page
// « latest » renvoie vers celle de son tag, qui n'est pas suivie.
func (r *upgradeRun) latestVersion(ctx context.Context) (release.Version, error) {
	client := &http.Client{
		Timeout:       upgradeDownloadTimeout,
		Transport:     r.transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.latestURL, nil)
	if err != nil {
		return release.Version{}, err
	}
	request.Header.Set("User-Agent", brand.UserAgent)
	response, err := client.Do(request)
	if err != nil {
		return release.Version{}, r.downloadFailure(err)
	}
	defer response.Body.Close()
	location, err := response.Location()
	if err != nil {
		return release.Version{}, r.downloadFailure(fmt.Errorf("%s: %s", r.latestURL, response.Status))
	}
	return release.ParseVersion(filepath.Base(location.Path))
}

// download lit la version à l'adresse des versions, et la vérifie avant d'en
// rien poser : sa signature, chaque binaire, et qu'elle est bien celle
// demandée.
func (r *upgradeRun) download(ctx context.Context, keys release.Keys, wanted release.Version) (release.Verified, error) {
	client := r.releaseClient()
	open := func(name string) (io.ReadCloser, error) {
		address := r.releaseBase + "/" + wanted.String() + "/" + name
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("User-Agent", brand.UserAgent)
		response, err := client.Do(request)
		if err != nil {
			return nil, r.downloadFailure(err)
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return nil, r.downloadFailure(fmt.Errorf("%s: %s", address, response.Status))
		}
		return response.Body, nil
	}
	verified, err := release.ReadVerified(open, keys)
	if err != nil {
		return release.Verified{}, err
	}
	if verified.Version != wanted {
		return release.Verified{}, &stepFailure{reason: r.text.Format("upgrade.other_version", r.releaseBase, verified.Version, wanted), todo: r.text.Get("upgrade.verify_todo")}
	}
	return verified, nil
}

func (r *upgradeRun) downloadFailure(err error) error {
	return &stepFailure{reason: err.Error(), todo: r.text.Get("upgrade.download_todo")}
}

// explainVerification dit pourquoi une version est refusée : la phrase de sa
// clé de refus, ou l'erreur telle quelle.
func (r *upgradeRun) explainVerification(err error) error {
	var failure *stepFailure
	var refused *refusal
	if errors.As(err, &failure) || errors.As(err, &refused) {
		return err
	}
	reason := err.Error()
	if key, keyed := refusals.KeyOf(err); keyed {
		reason = r.text.Get(key)
	}
	return &stepFailure{reason: reason, todo: r.text.Get("upgrade.verify_todo")}
}

// stage pose la version vérifiée à côté de l'état, à root, lisible de tous :
// serve l'importe de là, et le nouveau binaire y reprend son lanceur stable.
// Les octets posés sont ceux qui ont été vérifiés.
func (r *upgradeRun) stage() error {
	stagingDir, err := openUpgradeDir(r.paths.stagingDir)
	if err != nil {
		return err
	}
	defer stagingDir.Close()
	folder := r.state.Target
	if err := stagingDir.MkdirAll(folder, stagedDirMode); err != nil {
		return err
	}
	files := map[string][]byte{brand.ReleaseSumsFile: r.verified.SumsFile, brand.ReleaseSignatureFile: r.verified.Signature}
	for _, name := range r.verified.BinaryNames() {
		files[name] = r.verified.Binaries[name]
	}
	for name, content := range files {
		if err := fsx.WriteAtomic(stagingDir, filepath.Join(folder, name), content, stagedFileMode); err != nil {
			return err
		}
	}
	r.state.Staged = filepath.Join(r.paths.stagingDir, folder)
	return nil
}

// checkSpace : deux fois la base (la copie, et ce que les migrations
// écrivent), plus le binaire, sous state_dir comme sous le binaire.
func (r *upgradeRun) checkSpace(context.Context) (step.State, string, error) {
	database, err := os.Lstat(filepath.Join(r.state.StateDir, brand.DatabaseFile))
	if err != nil {
		return "", "", err
	}
	needed := 2*uint64(database.Size()) + uint64(len(r.newBinary)) // #nosec G115 -- une taille de fichier, positive.
	free := uint64(0)
	for index, under := range []string{r.state.StateDir, filepath.Dir(r.state.Binary)} {
		available, err := r.system.FreeBytes(under)
		if err != nil {
			return "", "", err
		}
		if available < needed {
			return "", "", &stepFailure{
				reason: r.text.Format("upgrade.space_short", mebibytes(available), under, mebibytes(needed)),
				todo:   r.text.Format("upgrade.space_todo", under),
			}
		}
		if index == 0 || available < free {
			free = available
		}
	}
	return step.StateDone, r.text.Format("upgrade.space_detail", mebibytes(free), mebibytes(needed)), nil
}

func mebibytes(size uint64) uint64 {
	return (size + 1<<20 - 1) >> 20
}

// copyDatabase demande la copie de la base à serve, qui la fait sous son
// compte : root ne lit ni n'écrit la base (R-B2-2).
func (r *upgradeRun) copyDatabase(ctx context.Context) (step.State, string, error) {
	status, body, err := r.control.post(ctx, controlPreUpgradePath, struct{}{}, controlTimeout)
	if err != nil {
		return "", "", err
	}
	if status != http.StatusCreated {
		return "", "", serverRefusal(status, body)
	}
	var copied upgradeCopy
	if err := json.Unmarshal(body, &copied); err != nil || copied.Path == "" {
		return "", "", fmt.Errorf("read the copy of the database: %w", err)
	}
	r.state.Copy = copied.Path
	return step.StateDone, copied.Path, nil
}

type upgradeCopy struct {
	Path string `json:"path"`
}

// replaceBinary garde l'ancien binaire à part, puis pose le nouveau par
// rename : systemd lance l'un ou l'autre, jamais un fichier à moitié écrit.
func (r *upgradeRun) replaceBinary(context.Context) (step.State, string, error) {
	current, err := os.ReadFile(r.state.Binary)
	if err != nil {
		return "", "", err
	}
	if err := writeExecutable(r.state.Previous, current); err != nil {
		return "", "", err
	}
	if err := writeExecutable(r.state.Binary, r.newBinary); err != nil {
		return "", "", err
	}
	return step.StateDone, r.text.Format("upgrade.replaced_detail", r.state.Previous), nil
}

// writeExecutable écrit un binaire de root d'un coup, son dossier créé s'il
// manque.
func writeExecutable(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), guardDirMode); err != nil {
		return err
	}
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return fsx.WriteAtomic(dir, filepath.Base(path), content, binaryMode)
}

func (r *upgradeRun) restartServer(context.Context) (step.State, string, error) {
	if err := r.system.Run("systemctl", "restart", brand.ServerUnit); err != nil {
		return "", "", err
	}
	return step.StateDone, "", nil
}

// awaitServer attend que health rende la version visée.
func (r *upgradeRun) awaitServer(ctx context.Context) (step.State, string, error) {
	answered, err := waitUntil(ctx, r.wait, r.poll, func(ctx context.Context) (bool, error) {
		body, err := r.control.get(ctx, controlHealthPath)
		if err != nil {
			return false, nil
		}
		var health struct {
			Version string `json:"version"`
		}
		return json.Unmarshal(body, &health) == nil && health.Version == r.state.Target, nil
	})
	if err != nil {
		return "", "", err
	}
	if !answered {
		return "", "", &stepFailure{
			reason: r.text.Format("upgrade.silent", int(r.wait.Seconds())),
			todo:   r.text.Format("upgrade.silent_todo", r.state.Previous, r.state.Copy, brand.InstallDocURL),
		}
	}
	return step.StateDone, r.state.Target, nil
}

// updateUnits compare les unités que setup a posées à celles de ce binaire,
// le nouveau, et réécrit celles qui diffèrent. Les drop-ins ne sont jamais
// touchés ; une installation faite à la main garde ses unités.
func (r *upgradeRun) updateUnits(context.Context) (step.State, string, error) {
	if _, err := os.Stat(r.paths.setupStateFile); errors.Is(err, fs.ErrNotExist) {
		return step.StateSkipped, r.text.Get("upgrade.units_manual"), nil
	}
	units := []struct {
		name  string
		lines []string
	}{
		{brand.ServerUnit, machine.ServerUnitLines()},
		{brand.AgentUnit, machine.AgentUnitLines()},
	}
	rewritten := false
	for _, unit := range units {
		if _, err := os.Lstat(filepath.Join(r.paths.unitDir, unit.name)); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		written, err := writeUnitFile(r.paths.unitDir, unit.name, unit.lines)
		if err != nil {
			return "", "", err
		}
		rewritten = rewritten || written
	}
	if !rewritten {
		return step.StateDone, r.text.Get("upgrade.units_same"), nil
	}
	if err := r.system.Run("systemctl", "daemon-reload"); err != nil {
		return "", "", err
	}
	return step.StateDone, r.text.Get("upgrade.units_rewritten"), nil
}

// updateAgentPolicy, pour l'agent de la machine Kagu : la politique migrée
// s'il lit encore ses droits dans identity.json, puis le lanceur stable
// recopié depuis la version vérifiée (R-B2-12).
func (r *upgradeRun) updateAgentPolicy(context.Context) (step.State, string, error) {
	var done []string
	migrated, pending, err := r.migrateAgentPolicy()
	if err != nil {
		return "", "", err
	}
	if migrated {
		done = append(done, r.text.Get("upgrade.policy_migrated"))
	}
	if pending {
		done = append(done, r.text.Format("upgrade.policy_not_migrated", agentpolicy.MigrateLine()))
	}
	refreshed, err := r.refreshGuard()
	if err != nil {
		return "", "", err
	}
	if refreshed {
		done = append(done, r.text.Get("upgrade.guard_copied"))
	}
	if len(done) == 0 {
		return step.StateDone, r.text.Get("upgrade.policy_same"), nil
	}
	return step.StateDone, strings.Join(done, ", "), nil
}

// migrateAgentPolicy joue « agent policy migrate » sur un agent qui lit
// encore ses droits dans identity.json, si root a dit oui au terminal avant
// la relance (askPolicyMigration) : ce qui est recopié est redit, la question
// ne se repose pas. Sans cet accord, rien n'est migré : pending le dit. Le
// oui est consommé, migration faite ou refusée.
func (r *upgradeRun) migrateAgentPolicy() (migrated, pending bool, err error) {
	defer func() { r.state.PolicyConsent = false }()
	pending, err = r.withPendingMigration(func(opts agent.PolicyOptions) error {
		if !r.state.PolicyConsent {
			return nil
		}
		announce := func(change agent.PolicyChange) error {
			printPolicyChange(r.out, r.text, change)
			return nil
		}
		if _, err := agent.MigratePolicy(opts, announce); err != nil {
			return explainPolicyError(err, r.text)
		}
		migrated = true
		return nil
	})
	return migrated, pending && !migrated, err
}

// askPolicyMigration pose, dans le terminal de root et avant la relance, la
// question de la migration de la politique : le changement affiché, puis
// [o/N] par le chemin de confirmChange. Non, ou pas de terminal : upgrade
// s'arrête avant la première coche, la ligne à lancer à la main dite. Oui :
// le oui est écrit dans state.json, d'où l'unité le prend.
func (r *upgradeRun) askPolicyMigration() error {
	_, err := r.withPendingMigration(func(opts agent.PolicyOptions) error {
		confirm := confirmChange(r.out, r.openTerminal, false, r.text)
		ask := func(change agent.PolicyChange) error {
			if err := confirm(change); err != nil {
				return policyByHandRefusal(r.text)
			}
			return errPolicyConsented
		}
		_, err := agent.MigratePolicy(opts, ask)
		return err
	})
	if errors.Is(err, errPolicyConsented) {
		return r.recordPolicyConsent()
	}
	var refused *refusal
	if err != nil && !errors.As(err, &refused) {
		return explainPolicyError(err, r.text)
	}
	return err
}

// policyByHandRefusal dit la ligne canonique de la migration à lancer à la
// main, avec l'avertissement qui suit toute ligne à coller en root
// (R-DROIT-8, ARB-1).
func policyByHandRefusal(text lang.Catalog) error {
	return &refusal{message: text.Format("upgrade.policy_by_hand", agentpolicy.MigrateLine()) + "\n" + text.Get("rights.paste_only_pending")}
}

// errPolicyConsented arrête la migration après le oui de root : elle se fait
// dans l'unité.
var errPolicyConsented = errors.New("policy migration consented")

// withPendingMigration appelle migrate quand l'agent de cette machine est
// enrôlé et que sa politique n'existe pas encore ; pending le dit.
func (r *upgradeRun) withPendingMigration(migrate func(agent.PolicyOptions) error) (pending bool, err error) {
	stateRoot, err := os.OpenRoot(r.paths.agentStateDir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer stateRoot.Close()
	if _, err := agent.LoadIdentity(stateRoot); err != nil {
		if errors.Is(err, agent.ErrNotEnrolled) {
			return false, nil
		}
		return false, err
	}
	place, err := r.place(stateRoot)
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(place.Dir); !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	opts := agent.PolicyOptions{StateDir: stateRoot, StatePath: r.paths.agentStateDir, Place: place, EUID: r.euid, Audit: r.audit}
	return true, migrate(opts)
}

// refreshGuard recopie le lanceur stable, s'il est installé, depuis la
// version posée par upgrade et revérifiée ici, au moment de la copie, avec
// les clés de ce binaire : jamais depuis bin/ de l'agent, que son compte
// peut réécrire (R-A5-10).
func (r *upgradeRun) refreshGuard() (bool, error) {
	installed, err := os.ReadFile(r.paths.guardPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	keys, err := r.keys()
	if err != nil {
		return false, err
	}
	staged, err := os.OpenRoot(r.state.Staged)
	if err != nil {
		return false, err
	}
	defer staged.Close()
	verified, err := release.ReadVerified(release.RootOpener(staged), keys)
	if err != nil {
		return false, r.explainVerification(err)
	}
	if verified.Version.String() != r.state.Target {
		return false, &stepFailure{reason: r.text.Format("upgrade.other_version", r.state.Staged, verified.Version, r.state.Target), todo: r.text.Get("upgrade.verify_todo")}
	}
	binary := verified.Binaries[release.BinaryName(runtime.GOARCH)]
	if bytes.Equal(installed, binary) {
		return false, nil
	}
	return true, writeExecutable(r.paths.guardPath, binary)
}
