package agent

import (
	"context"
	"errors"
	"io/fs"
	"math"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/dockerapi"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Un droit coché n'est pas un droit exerçable : le compte sous lequel l'agent
// tourne peut ne pas ouvrir la socket de Docker, ne pas posséder un dossier.
// L'agent le juge deux fois avec les mêmes questions : avant d'ouvrir le flux,
// pour le dire au serveur (judgeRights), et au moment de l'ordre, pour le
// refuser avant d'écrire quoi que ce soit, avec la même raison.

const (
	dockerDialTimeout = 2 * time.Second
	// access(2) : écrire dans un dossier et le traverser. Créer dessous exige
	// les deux ; syscall n'en nomme pas les constantes.
	accessWrite  = 0x2
	accessSearch = 0x1
)

// hostChecks est ce que l'agent demande à sa machine pour juger un droit.
// Chaque réponse est vide quand tout va bien, sinon une raison de refus
// (agentwire.Reason*). Les tests les remplacent.
type hostChecks struct {
	// docker : la socket s'ouvre et /usr/bin/docker est là.
	docker func(ctx context.Context) string
	// writable : le dossier existe et s'écrit, ou se crée sous le plus proche
	// parent qui existe.
	writable func(path string) string
	// freeBytes : l'espace libre sous un chemin, même s'il n'existe pas encore.
	freeBytes func(path string) (uint64, error)
	// agentUpdate : l'agent tourne depuis <état>/bin/ et ce dossier s'écrit.
	agentUpdate func() string
	// lookPath : un programme du PATH, ou un chemin absolu, que le compte peut
	// lancer (exec.LookPath).
	lookPath func(name string) (string, error)
	// vzdumpGate : la socket de la porte vzdump est là et le compte peut
	// l'ouvrir (gate_missing, gate_denied), sans s'y connecter : une
	// connexion lancerait une unité de root.
	vzdumpGate func() string
	// proxmoxToken : le jeton local de Proxmox est posé, lisible du seul compte
	// de l'agent, avec l'empreinte du certificat.
	proxmoxToken func() string
	// findRestic, findRestServer : le chemin absolu du binaire, cherché au
	// chemin que l'opérateur a déclaré, sinon dans le PATH de l'agent.
	findRestic     func() (string, error)
	findRestServer func() (string, error)
	// dockerMember : le processus est dans le groupe docker (ses groupes
	// supplémentaires, lus au démarrage de l'unité).
	dockerMember func() bool
}

// newHostChecks branche les vérifications sur la vraie machine.
func newHostChecks(socket string, updater *selfUpdater) hostChecks {
	return hostChecks{
		docker:      func(ctx context.Context) string { return dockerReason(ctx, dockerBinary, socket) },
		writable:    writableOrCreatable,
		freeBytes:   freeBytesUnder,
		agentUpdate: func() string { return updater.unavailableReason(writableOrCreatable) },
		lookPath:    exec.LookPath,
		vzdumpGate:  func() string { return vzdumpGateReason(brand.VzdumpGateSocket) },
		// Branché par newOrderRunner : il lit l'état de l'agent.
		proxmoxToken:   func() string { return "" },
		findRestic:     func() (string, error) { return findBinary("", resticProgram, exec.LookPath) },
		findRestServer: func() (string, error) { return findBinary("", restServerProgram, exec.LookPath) },
		dockerMember:   inDockerGroup,
	}
}

// allowAll est des vérifications qui ne refusent jamais : un banc sans compte
// à juger.
func allowAll() hostChecks {
	return hostChecks{
		docker:         func(context.Context) string { return "" },
		writable:       func(string) string { return "" },
		freeBytes:      func(string) (uint64, error) { return math.MaxUint64, nil },
		agentUpdate:    func() string { return "" },
		lookPath:       func(name string) (string, error) { return name, nil },
		vzdumpGate:     func() string { return "" },
		proxmoxToken:   func() string { return "" },
		findRestic:     func() (string, error) { return "/usr/bin/" + resticProgram, nil },
		findRestServer: func() (string, error) { return "/usr/bin/" + restServerProgram, nil },
		dockerMember:   func() bool { return false },
	}
}

// inDockerGroup dit si le processus porte le groupe docker.
func inDockerGroup() bool {
	group, err := user.LookupGroup(machine.DockerGroup)
	if err != nil {
		return false
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return false
	}
	groups, err := os.Getgroups()
	return err == nil && (slices.Contains(groups, gid) || os.Getegid() == gid)
}

// rootEquivalent dit si le compte de l'agent vaut root sur sa machine
// (R-A3-12, R-DROIT-7) : il l'est (euid 0), il est dans le groupe docker, ou
// la politique lui donne terminal.host, l'égal de root au premier terminal.
// La porte root (A5, étape 14) s'y ajoutera.
func rootEquivalent(euid int, rights []agentpolicy.Capability, checks hostChecks) bool {
	return euid == 0 || checks.dockerMember() || agentpolicy.HasCapability(rights, agentpolicy.CapabilityTerminalHost)
}

// vzdumpGateReason juge la socket de la porte par access(2) : se connecter
// à une socket Unix demande d'y écrire.
func vzdumpGateReason(socket string) string {
	err := syscall.Access(socket, accessWrite)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return agentwire.ReasonGateDenied
	}
	return agentwire.ReasonGateMissing
}

// dockerReason dit si le compte de l'agent peut parler à Docker : docker_missing
// sans programme ou sans socket, docker_denied si la socket lui est fermée.
// Docker arrêté (la socket est là, le démon ne répond pas) n'est pas un droit
// indisponible : compose up le dira.
func dockerReason(ctx context.Context, binary, socket string) string {
	if _, err := os.Stat(binary); err != nil {
		return agentwire.ReasonDockerMissing
	}
	return dockerReasonOf(dialDocker(ctx, socket))
}

func dialDocker(ctx context.Context, socket string) error {
	dialer := net.Dialer{Timeout: dockerDialTimeout}
	connection, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	return connection.Close()
}

// dockerReasonOf traduit l'erreur d'une ouverture de socket. Séparée de
// l'ouverture : un test lui donne un EACCES fabriqué, sans dépendre du compte
// qui le lance.
func dockerReasonOf(err error) string {
	if err == nil {
		return ""
	}
	classified := dockerapi.ClassifyDial(err)
	switch {
	case errors.Is(classified, dockerapi.ErrSocketDenied):
		return agentwire.ReasonDockerDenied
	case errors.Is(classified, dockerapi.ErrNoSocket):
		return agentwire.ReasonDockerMissing
	}
	return ""
}

// writableOrCreatable juge un dossier sur la machine, avec le compte du
// processus. access juge l'uid réel ; sous systemd et sous « sudo -u », réel et
// effectif sont le même. C'est un pré-contrôle lisible : l'écriture reste
// confinée par os.Root et peut encore échouer (path_unwritable).
func writableOrCreatable(path string) string {
	return judgeWritable(path, os.Stat, accessWritable)
}

func accessWritable(dir string) error {
	return syscall.Access(dir, accessWrite|accessSearch) // #nosec G703 -- un chemin de droit, lu dans le fichier de l'agent ; access ne lit ni n'écrit rien.
}

// judgeWritable remonte jusqu'au plus proche chemin qui existe, puis demande à
// access : EROFS (l'unité ne l'ouvre pas, ReadWritePaths) est path_unwritable,
// EACCES et EPERM (le compte n'a pas ce dossier) path_denied. Les liens se
// suivent, comme os.OpenRoot suit le chemin du droit lui-même : seul ce qui
// est dessous est confiné, et l'écriture le confine encore.
func judgeWritable(path string, stat func(string) (fs.FileInfo, error), access func(string) error) string {
	existing := path
	for {
		info, err := stat(existing)
		switch {
		case err == nil && !info.IsDir():
			return agentwire.ReasonPathUnwritable
		case err == nil:
			return writableReason(access(existing))
		case errors.Is(err, fs.ErrNotExist):
			parent := filepath.Dir(existing)
			if parent == existing {
				return agentwire.ReasonPathUnwritable
			}
			existing = parent
		case errors.Is(err, fs.ErrPermission):
			// Un dossier au-dessus ne se traverse pas.
			return agentwire.ReasonPathDenied
		default:
			return agentwire.ReasonPathUnwritable
		}
	}
}

func writableReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, syscall.EROFS):
		return agentwire.ReasonPathUnwritable
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return agentwire.ReasonPathDenied
	}
	return agentwire.ReasonPathUnwritable
}

// judgeRights dit, pour chaque droit que l'agent applique, pourquoi son compte
// ne peut pas l'exercer sur la machine ; un droit réalisable n'y figure pas.
// observe n'est pas jugé : l'état de Docker se lit déjà par le moteur. Un
// état mal gardé (narrowed) ne laisse que observe : rien à juger. root est la
// racine des services.
func judgeRights(ctx context.Context, rights []agentpolicy.Capability, root string, checks hostChecks) map[string]string {
	unavailable := map[string]string{}
	note := func(right, reason string) {
		if reason != "" {
			unavailable[right] = reason
		}
	}
	for _, capability := range rights {
		switch capability.Name {
		case agentpolicy.CapabilityAgentUpdate:
			note(capability.Name, checks.agentUpdate())
		case agentpolicy.CapabilityDockerDeploy, agentpolicy.CapabilityDockerUpdate:
			note(capability.Name, dockerRightReason(ctx, checks, root))
		case agentpolicy.CapabilityBackupReceive, agentpolicy.CapabilityFilesWrite:
			note(capability.Name, firstPathReason(checks, capability.Paths))
		case agentpolicy.CapabilityBackupProduce:
			note(capability.Name, firstProducerReason(checks, capability.Paths))
		case agentpolicy.CapabilityProxmoxPower, agentpolicy.CapabilityProxmoxSnapshot:
			note(capability.Name, checks.proxmoxToken())
		case agentpolicy.CapabilityResticTarget:
			note(capability.Name, resticTargetReason(checks, capability.Paths))
		case agentpolicy.CapabilityResticProduce:
			note(capability.Name, binaryReason(checks.findRestic, agentwire.ReasonResticMissing))
		case agentpolicy.CapabilityResticDocker:
			note(capability.Name, resticDockerReason(ctx, checks))
		case agentpolicy.CapabilityResticVerify, agentpolicy.CapabilityResticBrowse, agentpolicy.CapabilityResticRestore:
			note(capability.Name, binaryReason(checks.findRestic, agentwire.ReasonResticMissing))
		}
	}
	return unavailable
}

// resticTargetReason : le dossier des dépôts d'abord, puis rest-server.
func resticTargetReason(checks hostChecks, paths []string) string {
	if reason := firstPathReason(checks, paths); reason != "" {
		return reason
	}
	return binaryReason(checks.findRestServer, agentwire.ReasonRestServerMissing)
}

// resticDockerReason : la socket et le programme docker d'abord (docker cp,
// docker exec), puis restic, qui les lance.
func resticDockerReason(ctx context.Context, checks hostChecks) string {
	if reason := checks.docker(ctx); reason != "" {
		return reason
	}
	return binaryReason(checks.findRestic, agentwire.ReasonResticMissing)
}

// binaryReason rend missing quand le binaire ne se trouve pas, ou ne se
// lance pas sous le compte de l'agent.
func binaryReason(find func() (string, error), missing string) string {
	if _, err := find(); err != nil {
		return missing
	}
	return ""
}

// dockerRightReason : la socket d'abord, puis la racine des services.
func dockerRightReason(ctx context.Context, checks hostChecks, root string) string {
	if reason := checks.docker(ctx); reason != "" {
		return reason
	}
	return checks.writable(root)
}

// firstPathReason rend la raison du premier dossier du droit qui ne s'écrit pas.
func firstPathReason(checks hostChecks, paths []string) string {
	for _, path := range paths {
		if reason := checks.writable(path); reason != "" {
			return reason
		}
	}
	return ""
}

// firstProducerReason rend la raison du premier producteur du droit que la
// machine ne sait pas lancer.
func firstProducerReason(checks hostChecks, producers []string) string {
	for _, producer := range producers {
		if reason := producerReason(checks, producer); reason != "" {
			return reason
		}
	}
	return ""
}

// producerReason dit pourquoi le compte ne peut pas lancer ce producteur :
// vzdump manque, ou la porte vzdump n'est pas posée ou lui est fermée. vzdump
// avant la porte : sans lui, grant ne pose pas la porte. Un producteur que
// l'agent ne sait pas lancer manque : le fichier de l'agent n'en porte pas
// (ParseCapabilities), mais un oubli ici ne doit pas le dire disponible.
func producerReason(checks hostChecks, producer string) string {
	if producer != agentpolicy.ProducerProxmoxVzdump {
		return agentwire.ReasonProducerMissing
	}
	if _, err := checks.lookPath(machine.VzdumpBinary); err != nil {
		return agentwire.ReasonProducerMissing
	}
	return checks.vzdumpGate()
}
