package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/rollback"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// ErrUpdated : l'agent a installé une version plus récente et bascule son lien
// current. Run le rend pour que la commande sorte avec le code 3, que systemd
// relance (Restart=on-failure ; seul le code 2 l'en empêche).
var ErrUpdated = errors.New("agent updated: restart")

const (
	// L'agent est relancé par systemd en quelques secondes ; le téléchargement
	// et l'épreuve tiennent largement dans la durée d'un ordre long.
	updateTimeout    = 20 * time.Minute
	selfCheckTimeout = 10 * time.Second
	selfCheckOutput  = 4 << 10
	// Les sommes et leur signature tiennent en quelques centaines d'octets.
	maxSignedFileBytes = 64 << 10
	// Un binaire tient en dizaines de Mio ; au-delà, ce n'est pas le nôtre.
	maxUpdateBinaryBytes = 256 << 20
	incomingPrefix       = ".incoming-"
	binaryMode           = 0o755
	retiredKeysMode      = 0o600
	releaseFloorMode     = 0o600
	incomingDirMode      = 0o700
	binDirMode           = 0o755
)

// updateBinaryName : « kagu-linux- » et une architecture, rien d'autre.
var updateBinaryName = regexp.MustCompile(`^` + regexp.QuoteMeta(brand.ReleaseBinaryPrefix) + `[a-z0-9]{2,16}$`)

// selfUpdater remplace le binaire que l'agent lance. L'agent tourne depuis
// <état>/bin/current, un lien vers <état>/bin/kagu-<version> : l'unité
// systemd n'autorise d'écrire que dans l'état, jamais dans /usr. Le serveur ne
// se met jamais à jour ainsi : seul un agent le fait.
type selfUpdater struct {
	stateDir *os.Root
	// La version du binaire qui tourne.
	version string
	// Les clés de version que ce binaire embarque ; sans elles, rien ne se
	// vérifie.
	keys   release.Keys
	hasKey bool
	logger *slog.Logger
	// guarded : l'agent tourne sous le lanceur stable (rollback.Guard), le seul
	// qui rebascule si la nouvelle version ne confirme pas. Sans lui, aucune
	// bascule : jamais de mise à jour sans retour arrière.
	guarded bool
	now     func() time.Time
	// Ce qui sort du processus, remplaçable par les tests : le chemin du
	// binaire qui tourne, l'épreuve d'une version installée, et la relance.
	executable func() (string, error)
	selfCheck  func(ctx context.Context, binary, version string) error
	restart    func()
}

func newSelfUpdater(stateDir *os.Root, version string, logger *slog.Logger) *selfUpdater {
	return &selfUpdater{
		stateDir: stateDir, version: version, logger: logger,
		executable: os.Executable, selfCheck: runSelfCheck, restart: func() {}, now: time.Now,
	}
}

// binDir est <état>/bin, en chemin absolu.
func (u *selfUpdater) binDir() (string, error) {
	state, err := filepath.Abs(u.stateDir.Name())
	if err != nil {
		return "", err
	}
	return filepath.Join(state, brand.AgentBinDir), nil
}

// isSelfUpdatable : le binaire qui tourne est dans <état>/bin/ (une fois les
// liens suivis). Un agent installé avant, lancé depuis /usr/local/bin, ne
// pourrait que remplacer un lien que rien ne lance : il refuse.
func (u *selfUpdater) isSelfUpdatable() bool {
	executable, err := u.executable()
	if err != nil {
		return false
	}
	real, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return false
	}
	binDir, err := u.binDir()
	if err != nil {
		return false
	}
	realBinDir, err := filepath.EvalSymlinks(binDir)
	if err != nil {
		return false
	}
	return filepath.Dir(real) == realBinDir
}

// unavailableReason dit pourquoi cet agent ne peut pas se mettre à jour, vide
// s'il le peut : il ne tourne pas depuis son dossier bin/ (not_self_updatable),
// ou son compte ne peut pas y écrire (judgeBin). Le dossier se juge une fois
// ses liens suivis, comme isSelfUpdatable le compare.
func (u *selfUpdater) unavailableReason(judgeBin func(path string) string) string {
	if !u.isSelfUpdatable() {
		return agentwire.ReasonNotSelfUpdatable
	}
	binDir, err := u.binDir()
	if err != nil {
		return agentwire.ReasonPathUnwritable
	}
	realBinDir, err := filepath.EvalSymlinks(binDir)
	if err != nil {
		return agentwire.ReasonPathUnwritable
	}
	return judgeBin(realBinDir)
}

// readAgentUpdate lit les paramètres de agent.update : une version, un colis
// de trois fichiers (sommes, signature, un binaire d'architecture), chacun
// avec sa taille et sa somme. Ce que l'ordre ne dit pas comme il faut est
// refusé avant de télécharger quoi que ce soit.
func readAgentUpdate(order judgedOrder) (agentwire.AgentUpdateParams, bool) {
	params, ok := order.Params.(agentwire.AgentUpdateParams)
	if !ok || params.Parcel == "" {
		return params, false
	}
	if _, err := release.ParseVersion(params.Version); err != nil || !updateBinaryName.MatchString(params.Binary) {
		return params, false
	}
	limits := map[string]int64{
		params.Binary: maxUpdateBinaryBytes, brand.ReleaseSumsFile: maxSignedFileBytes, brand.ReleaseSignatureFile: maxSignedFileBytes,
	}
	if len(params.Files) != len(limits) {
		return params, false
	}
	seen := map[string]bool{}
	for _, file := range params.Files {
		limit, expected := limits[file.Name]
		if !expected || seen[file.Name] || file.Size < 0 || file.Size > limit || !isSHA256(file.SHA256) {
			return params, false
		}
		seen[file.Name] = true
	}
	return params, true
}

// update installe la version que l'ordre décrit, et ne rend nil que lorsque le
// lien current pointe sur elle. Dans l'ordre : le colis est téléchargé dans
// bin/.incoming-<version>/ (taille et somme signées par l'ordre) ; la
// signature des sommes est vérifiée avec les clés que CE binaire embarque, pas
// celles du serveur ; la version signée est celle demandée, et pas plus ancienne
// que la sienne, ni sous le plancher noté ; la somme du binaire est dans les
// sommes signées ; le binaire est installé et éprouvé ; signé par la clé de
// secours, il fait retirer la courante ; son plancher est noté ; le marqueur
// d'attente de confirmation et le lien previous sont écrits ; le lien bascule
// d'un coup. Avant la bascule, tout échec laisse l'ancien lien et efface ce
// qui a été posé.
func (u *selfUpdater) update(ctx context.Context, source parcelSource, params agentwire.AgentUpdateParams, runID string) error {
	if !u.hasKey {
		return failWith(agentwire.ReasonReleaseKeyMissing, errors.New("no release key embedded"))
	}
	keys, err := u.trustedKeys()
	if err != nil {
		return failWith(agentwire.ReasonReleaseKeyMissing, err)
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()
	bin, err := u.openBin()
	if err != nil {
		return err
	}
	defer bin.Close()
	incomingName := incomingPrefix + params.Version
	incoming, err := openIncoming(bin, incomingName)
	if err != nil {
		return err
	}
	// Le dossier d'arrivée ne survit à aucune issue : réussi, le binaire en est
	// déjà sorti.
	defer func() {
		_ = incoming.Close()
		_ = bin.RemoveAll(incomingName)
	}()
	for _, file := range params.Files {
		if err := downloadTo(ctx, source, incoming, params.Parcel, file, file.Name); err != nil {
			return err
		}
	}
	signed, err := u.verifyDownload(incoming, params, keys)
	if err != nil {
		return err
	}
	target := rollback.BinaryName(signed.Version.String())
	previous := rollback.LinkTarget(bin, brand.AgentCurrentLink)
	// Jamais par-dessus le binaire que current lance : une épreuve ratée
	// l'effacerait, et systemd n'aurait plus rien à relancer.
	if target == previous {
		return failWith(agentwire.ReasonDowngrade, fmt.Errorf("%s is the running version", target))
	}
	// Sans version d'avant lisible, il n'y a rien à quoi revenir : pas de
	// bascule.
	previousVersion, hasPrevious := rollback.VersionOf(previous)
	if !hasPrevious {
		return failWith(agentwire.ReasonNoPrevious, fmt.Errorf("current points to %q", previous))
	}
	if err := u.install(ctx, bin, incomingName, target, params); err != nil {
		return err
	}
	if signed.ByBackup {
		if err := u.retireKey(keys.Current); err != nil {
			_ = bin.Remove(target)
			return failWith(agentwire.ReasonPathUnwritable, err)
		}
	}
	if err := raiseReleaseFloor(u.stateDir, signed.Floor); err != nil {
		_ = bin.Remove(target)
		return failWith(agentwire.ReasonPathUnwritable, err)
	}
	marker := u.newMarker(rollback.KindUpdate, runID, signed.Version.String(), previousVersion)
	if err := u.switchWithMarker(bin, marker, target); err != nil {
		return err
	}
	u.prune(bin, target, previous)
	return nil
}

// trustedKeys rend les clés que l'agent croit : celles de ce binaire, moins
// celles qu'il a retirées (release-keys-retired, dans son état). La note
// survit au retour arrière : un binaire d'avant ne recroit pas une clé
// retirée. Illisible, rien n'est cru.
func (u *selfUpdater) trustedKeys() (release.Keys, error) {
	retired, err := u.retiredKeys()
	if err != nil {
		return release.Keys{}, err
	}
	return u.keys.Without(retired)
}

func (u *selfUpdater) retiredKeys() ([]release.PublicKey, error) {
	text, err := u.stateDir.ReadFile(brand.AgentRetiredKeysFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read retired release keys: %w", err)
	}
	var retired []release.PublicKey
	for _, line := range strings.Fields(string(text)) {
		key, err := release.ParsePublicKey(line)
		if err != nil {
			return nil, fmt.Errorf("retired release key: %w", err)
		}
		retired = append(retired, key)
	}
	return retired, nil
}

// retireKey ajoute key aux clés que l'agent ne croit plus.
func (u *selfUpdater) retireKey(key release.PublicKey) error {
	retired, err := u.retiredKeys()
	if err != nil {
		return err
	}
	if slices.ContainsFunc(retired, key.Equal) {
		return nil
	}
	var text strings.Builder
	for _, kept := range append(retired, key) {
		text.WriteString(kept.String() + "\n")
	}
	if err := fsx.WriteAtomic(u.stateDir, brand.AgentRetiredKeysFile, []byte(text.String()), retiredKeysMode); err != nil {
		return fmt.Errorf("retire release key: %w", err)
	}
	return nil
}

// readReleaseFloor lit le plancher que l'agent a noté (release-floor, dans
// son état) ; zéro s'il n'en a pas. Comme les clés retirées, la note survit au
// retour arrière : un binaire d'avant revenu ne redescend pas plus bas.
func readReleaseFloor(stateDir *os.Root) (release.Version, error) {
	text, err := stateDir.ReadFile(brand.AgentReleaseFloorFile)
	if errors.Is(err, fs.ErrNotExist) {
		return release.Version{}, nil
	}
	if err != nil {
		return release.Version{}, fmt.Errorf("read release floor: %w", err)
	}
	floor, err := release.ParseVersion(strings.TrimSpace(string(text)))
	if err != nil {
		return release.Version{}, fmt.Errorf("release floor: %w", err)
	}
	return floor, nil
}

// raiseReleaseFloor note floor, le plancher signé d'une version installée,
// s'il dépasse celui déjà noté : le plancher ne descend jamais. Il se note dès
// l'installation ; la version d'avant reste un retour possible pour le
// lanceur jusqu'à la confirmation (eraseBelowFloor).
func raiseReleaseFloor(stateDir *os.Root, floor release.Version) error {
	noted, err := readReleaseFloor(stateDir)
	if err != nil {
		return err
	}
	if !release.IsBelowFloor(noted, floor) {
		return nil
	}
	if err := fsx.WriteAtomic(stateDir, brand.AgentReleaseFloorFile, []byte(floor.String()+"\n"), releaseFloorMode); err != nil {
		return fmt.Errorf("note release floor: %w", err)
	}
	return nil
}

// refuseBelowFloor rend une erreur si version est sous le plancher noté
// (R-B2-11). Un plancher illisible ne se devine pas : rien ne passe.
func (u *selfUpdater) refuseBelowFloor(version release.Version) error {
	floor, err := readReleaseFloor(u.stateDir)
	if err != nil {
		return err
	}
	if release.IsBelowFloor(version, floor) {
		return fmt.Errorf("%s is below the release floor %s", version, floor)
	}
	return nil
}

// eraseBelowFloor efface le binaire de la version d'avant s'il est sous le
// plancher noté : appelé une fois la version qui tourne confirmée, quand le
// lanceur n'a plus à y revenir. Le lien previous reste : agent.rollback le
// refuse alors below_floor, pas no_previous. Jamais le binaire que current
// lance.
func eraseBelowFloor(stateDir *os.Root) error {
	floor, err := readReleaseFloor(stateDir)
	if err != nil {
		return err
	}
	bin, err := stateDir.OpenRoot(brand.AgentBinDir)
	if err != nil {
		return err
	}
	defer bin.Close()
	previous := rollback.LinkTarget(bin, brand.AgentPreviousLink)
	versionText, found := rollback.VersionOf(previous)
	if !found || previous == rollback.LinkTarget(bin, brand.AgentCurrentLink) {
		return nil
	}
	// VersionOf ne rend qu'une version qui se lit.
	version, _ := release.ParseVersion(versionText)
	if !release.IsBelowFloor(version, floor) {
		return nil
	}
	if err := bin.Remove(previous); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return fsx.SyncDir(bin, ".")
}

// newMarker écrit l'attente de confirmation qui commence maintenant, avec le
// délai du produit : le serveur ne le règle pas.
func (u *selfUpdater) newMarker(kind rollback.Kind, runID, target, previous string) rollback.Marker {
	now := u.now().UTC()
	return rollback.Marker{
		State: rollback.StatePending, Kind: kind, RunID: runID, Target: target, Previous: previous,
		StartedAt: now, Deadline: now.Add(rollback.GracePeriod),
	}
}

// switchWithMarker arme le retour (lien previous, marqueur) puis bascule
// current. Si la bascule échoue, le marqueur part : il n'y a rien à confirmer.
func (u *selfUpdater) switchWithMarker(bin *os.Root, marker rollback.Marker, target string) error {
	if err := rollback.Arm(u.stateDir, bin, marker); err != nil {
		return failWith(agentwire.ReasonPathUnwritable, err)
	}
	if err := rollback.SwitchLink(bin, brand.AgentCurrentLink, target); err != nil {
		if removeErr := rollback.Remove(u.stateDir); removeErr != nil {
			u.logger.Error("remove update marker", "error", removeErr)
		}
		return failWith(agentwire.ReasonPathUnwritable, err)
	}
	return nil
}

// rollback rebascule current sur previous, comme une mise à jour qui se
// confirme : le même marqueur, la même attente, mais jamais de seconde remise
// en état si la version d'avant ne revient pas (elle le dit). Il refuse sans
// rien toucher s'il n'y a pas de précédent, s'il est la version qui tourne, ou
// s'il est sous le plancher noté (R-B2-11) : le plancher ne vient que des
// versions signées installées, jamais de l'ordre.
func (u *selfUpdater) rollback(ctx context.Context, runID string) error {
	bin, err := u.openBin()
	if err != nil {
		return err
	}
	defer bin.Close()
	previous := rollback.LinkTarget(bin, brand.AgentPreviousLink)
	running := rollback.LinkTarget(bin, brand.AgentCurrentLink)
	previousVersion, hasPrevious := rollback.VersionOf(previous)
	runningVersion, hasRunning := rollback.VersionOf(running)
	if !hasPrevious || !hasRunning {
		return refuseWith(agentwire.ReasonNoPrevious, fmt.Errorf("previous %q, current %q", previous, running))
	}
	if previous == running {
		return refuseWith(agentwire.ReasonPreviousIdentical, fmt.Errorf("%s is the running version", previous))
	}
	// VersionOf ne rend qu'une version qui se lit.
	parsedPrevious, _ := release.ParseVersion(previousVersion)
	if err := u.refuseBelowFloor(parsedPrevious); err != nil {
		return refuseWith(agentwire.ReasonBelowFloor, err)
	}
	binDir, err := u.binDir()
	if err != nil {
		return failWith(agentwire.ReasonPathUnwritable, err)
	}
	// Elle s'éprouve comme une version neuve : elle doit se lancer ici, aujourd'hui.
	if err := u.selfCheck(ctx, filepath.Join(binDir, previous), previousVersion); err != nil {
		return failWith(agentwire.ReasonSelfCheckFailed, err)
	}
	marker := u.newMarker(rollback.KindRollback, runID, previousVersion, runningVersion)
	if err := u.switchWithMarker(bin, marker, previous); err != nil {
		return err
	}
	u.prune(bin, previous, running)
	return nil
}

func (u *selfUpdater) openBin() (*os.Root, error) {
	if err := u.stateDir.MkdirAll(brand.AgentBinDir, binDirMode); err != nil {
		return nil, failWith(agentwire.ReasonPathUnwritable, err)
	}
	bin, err := u.stateDir.OpenRoot(brand.AgentBinDir)
	if err != nil {
		return nil, failWith(agentwire.ReasonPathUnwritable, err)
	}
	return bin, nil
}

// openIncoming repart d'un dossier d'arrivée vide : celui d'une mise à jour
// coupée est jeté.
func openIncoming(bin *os.Root, name string) (*os.Root, error) {
	if err := bin.RemoveAll(name); err != nil {
		return nil, failWith(agentwire.ReasonPathUnwritable, err)
	}
	if err := bin.Mkdir(name, incomingDirMode); err != nil {
		return nil, failWith(agentwire.ReasonPathUnwritable, err)
	}
	incoming, err := bin.OpenRoot(name)
	if err != nil {
		return nil, failWith(agentwire.ReasonPathUnwritable, err)
	}
	return incoming, nil
}

// verifyDownload juge ce qui est arrivé, avec les clés que l'agent croit.
func (u *selfUpdater) verifyDownload(incoming *os.Root, params agentwire.AgentUpdateParams, keys release.Keys) (release.Release, error) {
	sums, err := incoming.ReadFile(brand.ReleaseSumsFile)
	if err != nil {
		return release.Release{}, failWith(agentwire.ReasonPathUnwritable, err)
	}
	signature, err := incoming.ReadFile(brand.ReleaseSignatureFile)
	if err != nil {
		return release.Release{}, failWith(agentwire.ReasonPathUnwritable, err)
	}
	signed, err := release.VerifySums(sums, signature, keys)
	if err != nil {
		return release.Release{}, failWith(agentwire.ReasonSignatureInvalid, err)
	}
	if signed.Version.String() != params.Version {
		return release.Release{}, failWith(agentwire.ReasonVersionMismatch, fmt.Errorf("signed %s, asked %s", signed.Version, params.Version))
	}
	// Sous le plancher, le refus le dit avant celui de descendre : c'est la
	// raison qui compte.
	if err := u.refuseBelowFloor(signed.Version); err != nil {
		return release.Release{}, failWith(agentwire.ReasonBelowFloor, err)
	}
	// Une version propre illisible (un binaire de développement) compte comme
	// plus ancienne : la mise à jour la corrige. La même version n'a rien à
	// faire : la réinstaller écraserait le binaire qui tourne.
	if own, err := release.ParseVersion(u.version); err == nil && signed.Version.Compare(own) <= 0 {
		return release.Release{}, failWith(agentwire.ReasonDowngrade, fmt.Errorf("%s is not newer than %s", signed.Version, own))
	}
	binary, err := incoming.Open(params.Binary)
	if err != nil {
		return release.Release{}, failWith(agentwire.ReasonPathUnwritable, err)
	}
	defer binary.Close()
	if err := signed.Check(params.Binary, binary); err != nil {
		return release.Release{}, failWith(agentwire.ReasonDigestMismatch, err)
	}
	return signed, nil
}

// install pose le binaire vérifié sous son nom définitif dans bin/, puis
// l'éprouve. Une version qui ne se lance pas est retirée : le lien n'a pas
// bougé, l'agent reste sur l'ancienne.
func (u *selfUpdater) install(ctx context.Context, bin *os.Root, incomingName, target string, params agentwire.AgentUpdateParams) error {
	downloaded := filepath.Join(incomingName, params.Binary)
	if err := bin.Chmod(downloaded, binaryMode); err != nil { // #nosec G302 -- un binaire doit être exécutable
		return failWith(agentwire.ReasonPathUnwritable, err)
	}
	if err := bin.Rename(downloaded, target); err != nil {
		return failWith(agentwire.ReasonPathUnwritable, err)
	}
	if err := fsx.SyncDir(bin, "."); err != nil {
		return failWith(agentwire.ReasonPathUnwritable, err)
	}
	binDir, err := u.binDir()
	if err != nil {
		return failWith(agentwire.ReasonPathUnwritable, err)
	}
	if err := u.selfCheck(ctx, filepath.Join(binDir, target), params.Version); err != nil {
		_ = bin.Remove(target)
		return failWith(agentwire.ReasonSelfCheckFailed, err)
	}
	return nil
}

// prune garde la version installée et la précédente (de quoi revenir en
// arrière à la main), efface les autres binaires que l'agent a posés et les
// dossiers d'arrivée d'une mise à jour coupée. Un échec n'en est pas un : la
// bascule est faite.
func (u *selfUpdater) prune(bin *os.Root, keep ...string) {
	entries, err := fs.ReadDir(bin.FS(), ".")
	if err != nil {
		u.logger.Warn("list installed versions", "error", err)
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if !isUpdateLeftover(entry, name, keep) {
			continue
		}
		if err := bin.RemoveAll(name); err != nil {
			u.logger.Warn("remove old version", "name", name, "error", err)
		}
	}
}

func isUpdateLeftover(entry fs.DirEntry, name string, keep []string) bool {
	if entry.IsDir() {
		return strings.HasPrefix(name, incomingPrefix)
	}
	version, installed := strings.CutPrefix(name, brand.AgentBinaryPrefix)
	if _, err := release.ParseVersion(version); !installed || err != nil || !entry.Type().IsRegular() {
		return false
	}
	for _, kept := range keep {
		if kept == name {
			return false
		}
	}
	return true
}

// runSelfCheck lance le binaire installé avec « version » et demande qu'il
// dise la version attendue : il s'exécute sur cette machine (architecture,
// bibliothèques), sans rien d'hérité de l'agent. L'environnement est remplacé,
// la sortie bornée, la durée aussi.
func runSelfCheck(ctx context.Context, binary, version string) error {
	ctx, cancel := context.WithTimeout(ctx, selfCheckTimeout)
	defer cancel()
	// bounded: binary est bin/<préfixe>-<version>, que release.ParseVersion a jugée.
	command := exec.CommandContext(ctx, binary, "version") // #nosec G204 G702 -- chemin posé par l'agent sous son état, version jugée par release.ParseVersion
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.WaitDelay = time.Second
	var output cappedBuffer
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return fmt.Errorf("run %s version: %w", filepath.Base(binary), err)
	}
	// « kagu v0.0.2 (commit) » : la commande, puis la version.
	fields := strings.Fields(output.String())
	if len(fields) < 2 || fields[1] != version {
		return fmt.Errorf("%s says %q, want %s", filepath.Base(binary), strings.TrimSpace(output.String()), version)
	}
	return nil
}

// cappedBuffer garde le début d'une sortie et jette le reste sans faire échouer
// l'écriture du processus.
type cappedBuffer struct {
	buffer bytes.Buffer
}

func (c *cappedBuffer) Write(content []byte) (int, error) {
	if room := selfCheckOutput - c.buffer.Len(); room > 0 {
		c.buffer.Write(content[:min(len(content), room)])
	}
	return len(content), nil
}

func (c *cappedBuffer) String() string {
	return c.buffer.String()
}

// acceptAgentUpdate juge agent.update : un agent qui ne tourne pas depuis son
// dossier bin/, ou dont le compte n'y écrit pas, le refuse d'emblée, et l'ordre
// mal formé échoue ; sinon il est accepté et la mise à jour se fait à son tour
// dans le worker. Réussie, elle ne rapporte rien : l'agent s'arrête, et c'est
// son retour avec la nouvelle version que le serveur prend pour la fin de
// l'ordre.
func (r *orderRunner) acceptAgentUpdate(order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
	// Hors de bin/, jamais : la règle ne dépend pas d'un juge qu'un banc
	// remplace. Puis le compte de l'agent doit pouvoir écrire dans bin/ :
	// refusé avant de télécharger quoi que ce soit.
	reason := r.updater.refusalReason(r.checks.agentUpdate)
	if reason != "" {
		r.journal.notAccepted(order, reason)
		return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionRefused, Reason: reason}, nil
	}
	params, readable := readAgentUpdate(order)
	if !readable {
		return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionFailed, Reason: agentwire.ReasonBadOrder}, nil
	}
	return accepted(order), func(ctx context.Context) {
		if err := r.updater.update(ctx, r.fetch, params, order.RunID); err != nil {
			r.finishLong(order, nil, err)
			return
		}
		r.logger.Info("agent updated, restarting", "run_id", order.RunID, "version", params.Version, "seq", order.Seq)
		r.updater.restart()
	}
}

// refusalReason dit pourquoi cet agent refuse de basculer son lien, vide s'il
// le peut : hors de son dossier bin/, sans le lanceur stable (jamais de
// bascule sans retour arrière), ou parce que son compte n'y écrit pas.
func (u *selfUpdater) refusalReason(judgeBin func() string) string {
	switch {
	case !u.isSelfUpdatable():
		return agentwire.ReasonNotSelfUpdatable
	case !u.guarded:
		return agentwire.ReasonGuardMissing
	}
	return judgeBin()
}

// acceptAgentRollback juge agent.rollback comme agent.update, sans colis : le
// retour est un lien à rebasculer, rien à télécharger. Réussi, il ne rapporte
// rien : l'agent s'arrête, et c'est la version d'avant, revenue et confirmée,
// qui dit au serveur que l'ordre est fait.
func (r *orderRunner) acceptAgentRollback(order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
	if reason := r.updater.refusalReason(r.checks.agentUpdate); reason != "" {
		r.journal.notAccepted(order, reason)
		return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionRefused, Reason: reason}, nil
	}
	// Le précédent ne se juge que dans le worker, avec la même bascule : un
	// refus sans précédent arrive juste après « accepté », avant toute écriture.
	return accepted(order), func(ctx context.Context) {
		if err := r.updater.rollback(ctx, order.RunID); err != nil {
			r.finishProduce(order, nil, err)
			return
		}
		r.logger.Info("agent rolled back, restarting", "run_id", order.RunID, "seq", order.Seq)
		r.updater.restart()
	}
}
