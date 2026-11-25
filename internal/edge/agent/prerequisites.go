package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/fact/role"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
)

// Ce que « agent grant » et « agent revoke » font aussi sur le système
// (R-A3-8, fiche A3 §5) : le groupe docker, les dossiers des droits au nom du
// compte de l'agent, le drop-in ReadWritePaths (machine.RightsDropInFile),
// puis daemon-reload et la relance de l'agent, qui reprend un geste en cours
// (resumeUpdates). Le plan se refait à chaque grant et revoke, même quand
// les droits ne changent pas ; il se lit avant la question, se dit avec ce
// qui change, et se pose après l'écriture de la politique. Jamais
// NoNewPrivileges=false : ce qui demande root passera par la porte (A5,
// étape 14) ; ni sudoers ni produce.conf ne sont posés ou retirés ici.

// PrerequisiteKind dit ce qu'un pas de la pose fait, ou ce qu'elle laisse.
type PrerequisiteKind string

const (
	// Le compte de l'agent entre dans le groupe docker (usermod -aG).
	PrerequisiteDockerJoin PrerequisiteKind = "docker_join"
	// Il en sort : plus aucun droit ne le demande (gpasswd -d).
	PrerequisiteDockerLeave PrerequisiteKind = "docker_leave"
	// Un droit demande docker, la machine n'a pas de groupe docker : laissé.
	PrerequisiteDockerMissing PrerequisiteKind = "docker_missing"
	// Un dossier de droit, créé ou rendu au compte de l'agent.
	PrerequisiteFolder PrerequisiteKind = "folder"
	// Le drop-in des droits, écrit, ou retiré quand plus rien ne s'écrit ailleurs.
	PrerequisiteDropIn        PrerequisiteKind = "drop_in"
	PrerequisiteDropInRemoved PrerequisiteKind = "drop_in_removed"
	// Un autre drop-in de l'unité, posé à la main : dit, jamais touché ;
	// systemd additionne ses ReadWritePaths à ceux de grant.
	PrerequisiteOtherDropIn PrerequisiteKind = "other_drop_in"
	// Un droit qui passe par la porte root : la porte arrive à l'étape 14.
	PrerequisiteRootGate PrerequisiteKind = "root_gate"
	// daemon-reload, puis la relance de l'agent.
	PrerequisiteRestart PrerequisiteKind = "restart"
)

// Prerequisite est un pas de la pose : ce qu'il fait, sur quoi (un dossier,
// un drop-in, un droit), et le geste ; sans geste, il n'est que dit.
type Prerequisite struct {
	Kind   PrerequisiteKind
	Detail string
	lay    func(System) error
}

// System est ce que la pose demande à la machine ; un test en enregistre les
// gestes sans rien lancer. Rien n'y vient du serveur : les noms sont des
// constantes, le compte vient du propriétaire de l'état, les chemins des
// droits normalisés (agentpolicy.ValidCapabilityPath).
type System interface {
	// GroupExists dit si le groupe existe sur la machine.
	GroupExists(group string) (bool, error)
	// InGroup dit si le compte est membre du groupe.
	InGroup(account, group string) (bool, error)
	// Run lance une commande du système (usermod, gpasswd, runuser,
	// systemctl) et attend sa fin.
	Run(name string, args ...string) error
	// MakeFolder crée un dossier à root, ou reprend celui qui existe, et le
	// donne à owner avec ce mode ; il refuse un lien, et un dossier sous un
	// parent qui n'est pas à root.
	MakeFolder(path string, mode fs.FileMode, owner fsx.Owner) error
	// DropIns rend les noms des fichiers du dossier des drop-ins de l'unité.
	DropIns() ([]string, error)
	// ReadDropIn rend un drop-in ; fs.ErrNotExist s'il manque.
	ReadDropIn(name string) ([]byte, error)
	// WriteDropIn écrit un drop-in d'un coup, à root, en 0644.
	WriteDropIn(name string, content []byte) error
	// RemoveDropIn retire un drop-in ; un absent n'est pas une erreur.
	RemoveDropIn(name string) error
	// Proxmox dit si la machine est un hôte Proxmox VE (role.Detect).
	Proxmox() bool
	// ServerMachine dit si le serveur tourne sur cette machine : sa
	// configuration, à root, est là.
	ServerMachine() bool
}

// hostAccount est le compte de l'agent, celui qui possède son état.
type hostAccount struct {
	name  string
	owner fsx.Owner
}

func (a hostAccount) isRoot() bool { return a.owner.UID == 0 }

// planPrerequisites dit ce que le passage des droits before aux droits after
// demande au système ; before et after égaux, il refait ce qui manque (le
// groupe d'un Docker installé après coup, un drop-in effacé : E03-10). Le
// groupe docker se pose quand un droit d'après le demande ; il se retire
// quand un droit d'avant le demandait et qu'aucun d'après ne le demande. Les
// dossiers se font pour les droits posés ; ceux des droits retirés restent
// (ce sont des données). Le drop-in dit les dossiers des droits d'après.
func planPrerequisites(system System, account hostAccount, servicesRoot string, before, after []agentpolicy.Capability) ([]Prerequisite, error) {
	added := addedRights(before, after)
	plan, err := planDockerGroup(system, account, before, after)
	if err != nil {
		return nil, err
	}
	plan = append(plan, planFolders(account, machine.RightFolders(added, servicesRoot), machine.RightFolders(after, servicesRoot))...)
	dropIns, err := planDropIns(system, machine.RightFolders(after, servicesRoot))
	if err != nil {
		return nil, err
	}
	plan = append(plan, dropIns...)
	if slices.ContainsFunc(plan, Prerequisite.needsRestart) {
		plan = append(plan, Prerequisite{Kind: PrerequisiteRestart, Detail: brand.AgentUnit, lay: restartAgent})
	}
	for _, name := range agentpolicy.RootGateRights(added) {
		plan = append(plan, Prerequisite{Kind: PrerequisiteRootGate, Detail: name})
	}
	return plan, nil
}

// needsRestart : un groupe ou un drop-in ne se lit qu'au démarrage de l'unité.
func (p Prerequisite) needsRestart() bool {
	return p.lay != nil && p.Kind != PrerequisiteFolder
}

// addedRights rend les droits d'après qui n'étaient pas avant, avec leur
// valeur : un droit dont la valeur change est posé de nouveau.
func addedRights(before, after []agentpolicy.Capability) []agentpolicy.Capability {
	var added []agentpolicy.Capability
	for _, right := range after {
		if !slices.ContainsFunc(before, func(held agentpolicy.Capability) bool {
			return agentpolicy.SameCapabilities([]agentpolicy.Capability{held}, []agentpolicy.Capability{right})
		}) {
			added = append(added, right)
		}
	}
	return added
}

// planDockerGroup : root n'a pas de groupe à prendre.
func planDockerGroup(system System, account hostAccount, before, after []agentpolicy.Capability) ([]Prerequisite, error) {
	wanted, held := agentpolicy.NeedsDockerGroup(after), agentpolicy.NeedsDockerGroup(before)
	if account.isRoot() || (!wanted && !held) {
		return nil, nil
	}
	exists, err := system.GroupExists(machine.DockerGroup)
	if err != nil {
		return nil, err
	}
	if !exists {
		if wanted {
			return []Prerequisite{{Kind: PrerequisiteDockerMissing, Detail: machine.DockerGroup}}, nil
		}
		return nil, nil
	}
	member, err := system.InGroup(account.name, machine.DockerGroup)
	if err != nil {
		return nil, err
	}
	switch {
	case wanted && !member:
		return []Prerequisite{{Kind: PrerequisiteDockerJoin, Detail: account.name, lay: func(system System) error {
			return system.Run("usermod", "-aG", machine.DockerGroup, account.name)
		}}}, nil
	case !wanted && held && member:
		return []Prerequisite{{Kind: PrerequisiteDockerLeave, Detail: account.name, lay: func(system System) error {
			return system.Run("gpasswd", "-d", account.name, machine.DockerGroup)
		}}}, nil
	}
	return nil, nil
}

// planFolders fait les dossiers des droits posés. Root n'agit jamais sur un
// nom que le compte contrôle : un dossier sous l'état ou sous un autre
// dossier du compte se fait sous le compte (runuser), après lui ; les autres,
// root les crée et les donne, sans suivre un lien (System.MakeFolder).
func planFolders(account hostAccount, folders, accountFolders []machine.RightFolder) []Prerequisite {
	var plan, nested []Prerequisite
	for _, folder := range folders {
		step := Prerequisite{Kind: PrerequisiteFolder, Detail: folder.Path}
		if machine.UnderAccountFolder(folder.Path, accountFolders) && !account.isRoot() {
			step.lay = func(system System) error {
				return system.Run("runuser", "-u", account.name, "--", "install", "-d", "-m", fmt.Sprintf("%04o", folder.Mode), folder.Path)
			}
			nested = append(nested, step)
			continue
		}
		step.lay = func(system System) error { return system.MakeFolder(folder.Path, folder.Mode, account.owner) }
		plan = append(plan, step)
	}
	return append(plan, nested...)
}

// planDropIns écrit le drop-in des droits quand son contenu change, le retire
// quand plus rien ne s'écrit ailleurs, et dit les autres drop-ins de l'unité,
// qui s'ajoutent à lui (produce.conf, root.conf, un droits posé à la main
// sous un autre nom).
func planDropIns(system System, folders []machine.RightFolder) ([]Prerequisite, error) {
	name := filepath.Base(machine.RightsDropInFile)
	var wanted []byte
	if lines := machine.RightsDropInLines(folders); lines != nil {
		wanted = []byte(strings.Join(lines, "\n") + "\n")
	}
	current, err := system.ReadDropIn(name)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	var plan []Prerequisite
	switch {
	case bytes.Equal(current, wanted):
	case wanted == nil:
		plan = append(plan, Prerequisite{Kind: PrerequisiteDropInRemoved, Detail: machine.RightsDropInFile, lay: func(system System) error {
			return system.RemoveDropIn(name)
		}})
	default:
		plan = append(plan, Prerequisite{Kind: PrerequisiteDropIn, Detail: machine.RightsDropInFile, lay: func(system System) error {
			return system.WriteDropIn(name, wanted)
		}})
	}
	others, err := system.DropIns()
	if err != nil {
		return nil, err
	}
	for _, other := range others {
		if other != name && strings.HasSuffix(other, ".conf") {
			plan = append(plan, Prerequisite{Kind: PrerequisiteOtherDropIn, Detail: filepath.Join(machine.UnitDropInDir, other)})
		}
	}
	return plan, nil
}

// restartAgent relit les unités, puis relance l'agent s'il tourne : le
// groupe et le drop-in ne se lisent qu'au démarrage. Un geste coupé reprend
// au démarrage (resumeUpdates).
func restartAgent(system System) error {
	if err := system.Run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	return system.Run("systemctl", "try-restart", brand.AgentUnit)
}

// layPrerequisites pose le plan dans l'ordre et s'arrête au premier échec :
// rend ce qui est posé, et l'échec.
func layPrerequisites(system System, plan []Prerequisite) ([]Prerequisite, error) {
	var laid []Prerequisite
	for _, step := range plan {
		if step.lay == nil {
			continue
		}
		if err := step.lay(system); err != nil {
			return laid, fmt.Errorf("%s %s: %w", step.Kind, step.Detail, err)
		}
		laid = append(laid, step)
	}
	return laid, nil
}

// agentAccountOf rend le compte qui possède l'état de l'agent.
func agentAccountOf(stateDir *os.Root) (hostAccount, error) {
	owner, err := stateOwner(stateDir)
	if err != nil {
		return hostAccount{}, err
	}
	account := accountOf(owner.UID, user.LookupId)
	if account.Name == "" && owner.UID != 0 {
		return hostAccount{}, fmt.Errorf("the account %d that owns the agent state has no name", owner.UID)
	}
	return hostAccount{name: account.Name, owner: owner}, nil
}

// HostSystem est le système de la machine, celui que « agent grant » touche.
// judgeDir juge chaque dossier traversé pour créer un dossier ou un drop-in ;
// nil : rootOnlyDir, la garde de production. Un test y met la sienne pour
// tourner hors root.
type HostSystem struct {
	judgeDir dirJudge
}

// dirJudge juge un dossier ouvert, sur son descripteur : nil s'il est sûr.
type dirJudge func(path string, stat *syscall.Stat_t) error

// rootOnlyDir : un dossier que root seul peut changer, à root et sans
// écriture pour le groupe ni pour les autres. Sinon, le compte de l'agent
// pourrait y poser un lien (/tmp, un 0775).
func rootOnlyDir(path string, stat *syscall.Stat_t) error {
	return judgeOwnedDir(path, stat, 0)
}

// judgeOwnedDir est rootOnlyDir pour un propriétaire donné.
func judgeOwnedDir(path string, stat *syscall.Stat_t, owner uint32) error {
	if stat.Uid != owner {
		return fmt.Errorf("%s does not belong to root (uid %d)", path, stat.Uid)
	}
	if stat.Mode&0o022 != 0 {
		return fmt.Errorf("%s is writable by its group or others (mode %04o)", path, stat.Mode&0o7777)
	}
	return nil
}

func (h HostSystem) judge() dirJudge {
	if h.judgeDir == nil {
		return rootOnlyDir
	}
	return h.judgeDir
}

func (HostSystem) GroupExists(group string) (bool, error) {
	_, err := user.LookupGroup(group)
	var unknown user.UnknownGroupError
	if errors.As(err, &unknown) {
		return false, nil
	}
	return err == nil, err
}

func (HostSystem) InGroup(account, group string) (bool, error) {
	found, err := user.Lookup(account)
	if err != nil {
		return false, err
	}
	wanted, err := user.LookupGroup(group)
	if err != nil {
		return false, err
	}
	groups, err := found.GroupIds()
	if err != nil {
		return false, err
	}
	return slices.Contains(groups, wanted.Gid), nil
}

// Run lance la commande avec un PATH fixe : root ne prend pas celui de
// l'environnement.
func (HostSystem) Run(name string, args ...string) error {
	command := exec.Command(name, args...) // #nosec G204 -- bounded: un programme constant de planPrerequisites, un compte et des chemins jugés.
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// MakeFolder : les parents s'ouvrent depuis « / », un par un, jugés
// (openTrustedDir) ; le dossier se crée sous le dernier, s'ouvre sans suivre
// de lien, puis se donne par son descripteur.
func (h HostSystem) MakeFolder(path string, mode fs.FileMode, owner fsx.Owner) error {
	parent, err := openTrustedDir(filepath.Dir(path), h.judge())
	if err != nil {
		return err
	}
	defer syscall.Close(parent)
	name := filepath.Base(path)
	if err := syscall.Mkdirat(parent, name, uint32(mode.Perm())); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("create %s: %w", path, err)
	}
	descriptor, err := syscall.Openat(parent, name, trustedDirFlags, 0)
	if err != nil {
		return fmt.Errorf("open %s without following a link: %w", path, err)
	}
	defer syscall.Close(descriptor)
	if err := syscall.Fchown(descriptor, owner.UID, owner.GID); err != nil {
		return err
	}
	return syscall.Fchmod(descriptor, uint32(mode.Perm()))
}

// trustedDirFlags : un dossier, jamais un lien, à chaque niveau.
const trustedDirFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

// openTrustedDir ouvre dir depuis « / », composant par composant, chacun
// relatif au descripteur du précédent et sans suivre de lien : jamais un
// chemin que le noyau résout en entier. Ce qui manque se crée à root en
// 0755. Chaque dossier ouvert, « / » compris, est jugé sur son descripteur
// (judge) : un dossier changé entre deux composants est soit déjà ouvert
// (le changement ne le touche pas), soit refusé. Rend le descripteur de dir.
func openTrustedDir(dir string, judge dirJudge) (int, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return -1, fmt.Errorf("%s is not an absolute clean path", dir)
	}
	descriptor, err := syscall.Open("/", trustedDirFlags, 0)
	if err != nil {
		return -1, err
	}
	current := "/"
	for _, name := range append([]string{""}, strings.Split(strings.TrimPrefix(dir, "/"), "/")...) {
		if name != "" {
			current = filepath.Join(current, name)
			next, err := openOrCreateDir(descriptor, name, current)
			_ = syscall.Close(descriptor)
			if err != nil {
				return -1, err
			}
			descriptor = next
		}
		var stat syscall.Stat_t
		if err := syscall.Fstat(descriptor, &stat); err != nil {
			_ = syscall.Close(descriptor)
			return -1, err
		}
		if err := judge(current, &stat); err != nil {
			_ = syscall.Close(descriptor)
			return -1, err
		}
	}
	return descriptor, nil
}

// openOrCreateDir ouvre name sous parent, le crée à root en 0755 s'il manque.
func openOrCreateDir(parent int, name, path string) (int, error) {
	if err := syscall.Mkdirat(parent, name, 0o755); err != nil && !errors.Is(err, syscall.EEXIST) {
		return -1, fmt.Errorf("create %s: %w", path, err)
	}
	descriptor, err := syscall.Openat(parent, name, trustedDirFlags, 0)
	if err != nil {
		return -1, fmt.Errorf("%s is a link or not a directory: %w", path, err)
	}
	return descriptor, nil
}

func (HostSystem) DropIns() ([]string, error) {
	entries, err := os.ReadDir(machine.UnitDropInDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, err
}

func (HostSystem) ReadDropIn(name string) ([]byte, error) {
	dir, err := os.OpenRoot(machine.UnitDropInDir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return dir.ReadFile(name)
}

// WriteDropIn crée le dossier des drop-ins à root s'il manque, par le même
// parcours jugé que MakeFolder, lui compris : à root, fermé au groupe et aux
// autres, personne d'autre que root ne le change ensuite.
func (h HostSystem) WriteDropIn(name string, content []byte) error {
	descriptor, err := openTrustedDir(machine.UnitDropInDir, h.judge())
	if err != nil {
		return err
	}
	_ = syscall.Close(descriptor)
	dir, err := os.OpenRoot(machine.UnitDropInDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return fsx.WriteAtomic(dir, name, content, 0o644)
}

func (HostSystem) RemoveDropIn(name string) error {
	dir, err := os.OpenRoot(machine.UnitDropInDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (HostSystem) Proxmox() bool {
	return slices.ContainsFunc(detectRoles().Roles, func(found role.Role) bool { return found.Name == role.ProxmoxVE })
}

func (HostSystem) ServerMachine() bool {
	_, err := os.Stat(brand.ConfigPath)
	return err == nil
}
