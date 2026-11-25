package server

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ldesfontaine/kagu/internal/domain/alert"
	"github.com/ldesfontaine/kagu/internal/domain/backup"
	"github.com/ldesfontaine/kagu/internal/domain/directory"
	"github.com/ldesfontaine/kagu/internal/domain/heartbeat"
	"github.com/ldesfontaine/kagu/internal/domain/proxmox"
	"github.com/ldesfontaine/kagu/internal/domain/restic"
	"github.com/ldesfontaine/kagu/internal/domain/settings"
	"github.com/ldesfontaine/kagu/internal/edge/server/agentapi"
	pingapi "github.com/ldesfontaine/kagu/internal/edge/server/ping" // ping : l'aide des tests du même nom
	"github.com/ldesfontaine/kagu/internal/edge/server/public"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/container"
	"github.com/ldesfontaine/kagu/internal/fact/firewall"
	"github.com/ldesfontaine/kagu/internal/fact/lifecycle"
	"github.com/ldesfontaine/kagu/internal/fact/link"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/fact/policy"
	"github.com/ldesfontaine/kagu/internal/fact/probe"
	"github.com/ldesfontaine/kagu/internal/fact/resource"
	"github.com/ldesfontaine/kagu/internal/fact/sshkeys"
	"github.com/ldesfontaine/kagu/internal/fact/systemdunits"
	"github.com/ldesfontaine/kagu/internal/fact/update"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/kit/deletion"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/live"
	"github.com/ldesfontaine/kagu/internal/kit/mail"
	"github.com/ldesfontaine/kagu/internal/kit/mcpcheck"
	"github.com/ldesfontaine/kagu/internal/kit/ratelimit"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/sampler"
	"github.com/ldesfontaine/kagu/internal/view/manifest"
	"github.com/ldesfontaine/kagu/internal/view/reader"
	"github.com/ldesfontaine/kagu/internal/view/status"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
	"github.com/ldesfontaine/kagu/web"
)

// Ce que le serveur attend du composant des réglages.
type SettingsService interface {
	Language(ctx context.Context) (lang.Code, error)
	SetLanguage(ctx context.Context, code lang.Code) error
	MailRelay(ctx context.Context) (mail.Relay, error)
	SetMailRelay(ctx context.Context, change settings.MailRelayChange) (mail.Relay, error)
	DangerReminderHours(ctx context.Context) (int, error)
	SetDangerReminderHours(ctx context.Context, hours int) error
	LifecycleEnabled(ctx context.Context) (bool, error)
	// SetLifecycleEnabled dit si la fin de support vient d'être rallumée.
	SetLifecycleEnabled(ctx context.Context, enabled bool) (isTurnedOn bool, err error)
}

// Ce que le serveur attend du composant machine : l'API d'un côté,
// l'agent de l'autre.
type MachineService interface {
	List(ctx context.Context) ([]machine.Status, error)
	Get(ctx context.Context, id string) (machine.Status, error)
	Count(ctx context.Context) (total, online int, err error)
	CreateToken(ctx context.Context, name string, role machine.Role, capabilities []agentpolicy.Capability) (string, machine.Token, error)
	CreateReenrollToken(ctx context.Context, machineID string, capabilities []agentpolicy.Capability) (string, machine.Token, error)
	OfferLocalEnrollment(ctx context.Context) (string, machine.Token, error)
	PendingTokens(ctx context.Context) ([]machine.Token, error)
	CancelToken(ctx context.Context, id string) error
	Remove(ctx context.Context, id string, options machine.RemoveOptions) error
	DeletePlan(ctx context.Context, id string) (deletion.Plan, error)
	Enroll(ctx context.Context, request machine.Enrollment) (machine.Machine, error)
	Authenticate(ctx context.Context, proof machine.Proof) (machine.Machine, error)
	Connect(ctx context.Context, authenticated machine.Machine, address, agentVersion, capabilities, account, unavailable, protocol string) (*machine.Session, error)
	NoteSystem(ctx context.Context, machineID, system string) error
	NoteServerKey(ctx context.Context, agentID, fingerprint string) error
	NoteProtocol(ctx context.Context, agentID, protocol string) error
	NoteOrderKinds(ctx context.Context, agentID, announced string) error
	NoteRootDir(ctx context.Context, agentID, root string) error
	NoteRollbackVersion(ctx context.Context, agentID, reported string) error
	NoteServiceRollbackVersion(ctx context.Context, agentID, reported string) error
	NoteAnchors(ctx context.Context, agentID, reported string) error
	NotePolicy(ctx context.Context, agentID, source, digest string) error
	NoteRightsUntil(ctx context.Context, agentID, until string) error
	NoteRootEquivalent(ctx context.Context, agentID, reported string) error
	SetUpdateLast(ctx context.Context, machineID string, updateLast bool) (machine.Machine, error)
	SetRole(ctx context.Context, machineID string, role machine.Role) (machine.Machine, error)
	SetPlacement(ctx context.Context, machineID string, kindOverride machine.Kind, hostOverride string) (machine.Machine, error)
	Disconnect(session *machine.Session)
	Signal(ctx context.Context, sessionToken string) (machineID string, err error)
	SessionMachine(sessionToken string) (machineID string, err error)
	Push(machineID string, event machine.StreamEvent) error
}

// Ce que le serveur attend du composant conteneur : l'API lit ce qui porte
// une règle (les vivants, une fiche vérifiée, la topologie, la fraîcheur),
// le signal de l'agent écrit, les journaux passent dans les deux sens. Le
// reste se lit par le Reader.
type ContainerTracker interface {
	Record(ctx context.Context, machineID string, report container.Report) error
	List(ctx context.Context, machineID string) ([]container.Container, error)
	Transitions(ctx context.Context, id string, limit int) ([]container.Transition, error)
	Topology(ctx context.Context, machineID string) (container.Topology, error)
	CurrentAll(ctx context.Context) ([]container.Current, error)
	FollowLogs(ctx context.Context, containerID string, tail int) (<-chan container.LogBatch, error)
	FetchLogs(ctx context.Context, containerID string, tail int) ([]container.LogLine, error)
	DeliverLogs(ctx context.Context, machineID, requestID string, batch container.LogBatch) error
}

// Ce que le serveur attend du composant resource : l'API lit, le signal de
// l'agent écrit.
type ResourceService interface {
	Record(ctx context.Context, machineID string, readings []sampler.Reading) error
	Current(ctx context.Context, machineID string) (resource.Current, error)
	CurrentAll(ctx context.Context) ([]resource.Current, error)
	History(ctx context.Context, machineID, window string) (resource.Window, []sampler.Reading, error)
}

// Ce que le serveur attend du composant probe : l'API agit et lit ce qui
// porte une fenêtre, le signal de l'agent écrit, et le flux qui s'ouvre
// repart avec le jeu de sondes de sa machine. Les listes se lisent par le
// Reader.
type ProbeService interface {
	// Certificates compte les certificats vus et ceux qui approchent de
	// leur fin, pour la vue d'ensemble.
	Certificates(ctx context.Context) (probe.Certificates, error)
	Create(ctx context.Context, definition probe.Definition) (probe.Probe, error)
	Update(ctx context.Context, id string, definition probe.Definition) (probe.Probe, error)
	Delete(ctx context.Context, id string) error
	DeletePlan(ctx context.Context, id string) (deletion.Plan, error)
	Pause(ctx context.Context, id string) error
	Resume(ctx context.Context, id string) error
	Days(ctx context.Context, id string, span time.Duration) ([]probe.Day, error)
	Uptimes(ctx context.Context, id string) ([]probe.Uptime, error)
	Assign(ctx context.Context, machineID string)
	Record(ctx context.Context, machineID string, report probe.Report) error
}

// Ce que le serveur attend de l'annuaire : l'API écrit les services que
// l'opérateur déclare et leurs projets, et lit ce que l'annuaire dérive
// (l'écart, une proposition, le rattachement d'une fiche). Les listes se
// lisent par le Reader.
type DirectoryService interface {
	CreateService(ctx context.Context, definition directory.ServiceDefinition) (directory.Service, error)
	UpdateService(ctx context.Context, id string, definition directory.ServiceDefinition) (directory.Service, error)
	// DeleteService refuse avec un *deletion.RefusedError tant que des
	// sondes ou des composants de statut visent le service.
	DeleteService(ctx context.Context, id string) error
	// DeleteServiceAndIgnore retire le service puis ignore les clés que ses
	// conteneurs laissent non déclarés : ils ne reviennent pas en proposition.
	DeleteServiceAndIgnore(ctx context.Context, id string) error
	DeleteServicePlan(ctx context.Context, id string) (deletion.Plan, error)
	SetUnitUpdatePolicy(ctx context.Context, unitID string, policy container.UpdatePolicy) (directory.Service, error)
	CreateProject(ctx context.Context, definition directory.ProjectDefinition) (directory.Project, error)
	UpdateProject(ctx context.Context, id string, definition directory.ProjectDefinition) (directory.Project, error)
	DeleteProject(ctx context.Context, id string) error
	DeleteProjectPlan(ctx context.Context, id string) (deletion.Plan, error)
	// L'écart entre ce qui est déclaré et ce que les machines montrent, et
	// ce qui en découle : accepter une proposition, ignorer une clé, dire à quoi
	// se rattache une fiche.
	Gaps(ctx context.Context, filter directory.Filter) (directory.GapReport, error)
	Propose(ctx context.Context, containerID string) (directory.Proposal, error)
	Ignore(ctx context.Context, key directory.IgnoredKey) error
	Unignore(ctx context.Context, key directory.IgnoredKey) error
	ContainerLink(ctx context.Context, item container.Container) (directory.ContainerLink, error)
	// Les unités systemd relevées : celles d'une machine avec le service
	// déclaré qui les porte, l'état des unités binaires déclarées, et la
	// proposition pour une unité non déclarée.
	MachineUnits(ctx context.Context, machineID string) (systemdunits.Snapshot, []directory.MachineUnit, error)
	ObservedUnits(ctx context.Context, services []directory.Service) (map[string]directory.UnitObservation, error)
	ProposeUnit(ctx context.Context, machineID, unitName string) (directory.Proposal, error)
	// Les liens des instances d'un service, et ceux que l'opérateur écrit ou
	// retire. Un lien tiré d'une configuration d'outil ne se retire pas.
	ServiceLinks(ctx context.Context, serviceID string) ([]directory.ServiceLink, error)
	RunsInContainers(ctx context.Context, serviceID string) (machineID string, runs bool, err error)
	DeclareLink(ctx context.Context, definition directory.LinkDefinition) (link.Link, error)
	RemoveLink(ctx context.Context, id string) error
	ConfirmLink(ctx context.Context, id string) error
	DismissLink(ctx context.Context, id string) error
	RestoreLink(ctx context.Context, id string) error
}

// Ce que le serveur attend du composant link : la lecture des liens stockés,
// pour la carte Réseau de la vue d'ensemble. L'écriture passe par l'annuaire,
// qui sait nommer les extrémités.
type LinkService interface {
	List(ctx context.Context, machineID string) ([]link.Link, error)
}

// Ce que le serveur attend du composant manifest : le fichier de l'annuaire,
// de l'export au journal des passages.
type ManifestService interface {
	// Export écrit tout l'annuaire, commentaires dans la langue donnée par
	// les annotations, avec en plus des propositions si les options le disent.
	// Jamais un secret.
	Export(ctx context.Context, annotations manifest.Annotations, options manifest.ExportOptions) ([]byte, error)
	// Plan dit ce que le fichier changerait, sans rien écrire.
	Plan(ctx context.Context, request manifest.Request) (manifest.Plan, error)
	// Apply écrit ce que le fichier demande si le plan est celui que
	// l'opérateur a confirmé (request.PlanHash). Sur ErrPlanChanged et
	// ErrNotApplicable, le plan rendu est celui d'aujourd'hui.
	Apply(ctx context.Context, request manifest.Request, actor manifest.Actor) (manifest.Apply, manifest.Plan, error)
	Applies(ctx context.Context, limit int) ([]manifest.Apply, error)
	GetApply(ctx context.Context, id string) (manifest.Apply, error)
}

// Ce que le serveur attend du composant update : l'API lit et règle, le
// signal de l'agent écrit, et le flux qui s'ouvre repart avec les
// exclusions de sa machine.
type UpdateService interface {
	Record(ctx context.Context, machineID string, report update.Report) error
	Checks(ctx context.Context, machineID string) (map[string]update.Check, error)
	CheckNow(ctx context.Context, machineID string) error
	Assign(ctx context.Context, machineID string)
}

// Ce que le serveur attend du composant lifecycle : la fiche lit le support
// d'une image, Paramètres lit l'état de la dernière lecture et en demande
// une quand le réglage vient d'être activé.
type LifecycleService interface {
	Of(image string) lifecycle.Verdict
	OfSystem(system string) lifecycle.Verdict
	State() lifecycle.State
	Kick()
}

// Ce que le serveur attend du composant heartbeat : les gestes de l'API
// d'un côté, les pings publics de l'autre. Les listes se lisent par le
// Reader.
type HeartbeatService interface {
	Create(ctx context.Context, definition heartbeat.Definition) (heartbeat.Heartbeat, error)
	Update(ctx context.Context, id string, definition heartbeat.Definition) (heartbeat.Heartbeat, error)
	RegenerateToken(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
	DeletePlan(ctx context.Context, id string) (deletion.Plan, error)
	Pause(ctx context.Context, id string) error
	Resume(ctx context.Context, id string) error
	Receive(ctx context.Context, token string, ping heartbeat.Ping) (heartbeat.Heartbeat, error)
	IsKnownToken(ctx context.Context, token string) (bool, error)
}

// Ce que le serveur attend du composant statut : l'instantané public d'un
// projet publié d'un côté, l'administration des composants et des incidents
// de l'autre.
type StatusService interface {
	Snapshot(ctx context.Context, projectID string) (status.Snapshot, error)
	Publications(ctx context.Context) ([]status.Publication, error)
	PublicationBySlug(ctx context.Context, slug string) (status.Publication, error)
	Components(ctx context.Context, projectID string) ([]status.Component, error)
	GetComponent(ctx context.Context, id string) (status.Component, error)
	CreateComponent(ctx context.Context, definition status.ComponentDefinition) (status.Component, error)
	UpdateComponent(ctx context.Context, id string, definition status.ComponentDefinition) (status.Component, error)
	DeleteComponent(ctx context.Context, id string) error
	DeleteComponentPlan(ctx context.Context, id string) (deletion.Plan, error)
	Incidents(ctx context.Context, projectID string) ([]status.Incident, error)
	GetIncident(ctx context.Context, id string) (status.Incident, error)
	OpenIncident(ctx context.Context, definition status.IncidentDefinition) (status.Incident, error)
	AddUpdate(ctx context.Context, id string, next status.IncidentStatus, message string) (status.Incident, error)
	ChangeIncident(ctx context.Context, id string, change status.IncidentChange) (status.Incident, error)
	DeleteIncident(ctx context.Context, id string) error
	CountOpenIncidents(ctx context.Context) (int, error)
}

// Ce que le serveur attend du moteur des alertes : la page (une liste
// bornée) et la fiche, avec ce qui les tait ; la lecture d'une alerte, l'écriture des
// canaux et des fenêtres pour taire. Le reste se lit par le Reader.
type AlertService interface {
	List(ctx context.Context, status alert.Status) ([]alert.Alert, error)
	Get(ctx context.Context, id int64) (alert.Alert, error)
	Acknowledge(ctx context.Context, id int64) (alert.Alert, error)
	AcknowledgeMany(ctx context.Context, ids []int64) (int, error)
	// Les seuils des alertes de ressources : par machine, sinon global.
	Rules(ctx context.Context, machineID string) ([]alert.Applied, error)
	SetRule(ctx context.Context, machineID string, rule alert.Rule) error
	ClearRule(ctx context.Context, machineID string, resource alert.Resource) error
	CreateChannel(ctx context.Context, definition alert.ChannelDefinition) (alert.Channel, error)
	UpdateChannel(ctx context.Context, id int64, definition alert.ChannelDefinition) (alert.Channel, error)
	DeleteChannel(ctx context.Context, id int64) error
	CreateMute(ctx context.Context, definition alert.MuteDefinition) (alert.Mute, error)
	DeleteMute(ctx context.Context, id int64) error
}

// Ce que le serveur attend du notifieur : tester un canal, ou le relais
// d'e-mails, tout de suite.
type Notifier interface {
	Test(ctx context.Context, channel alert.Channel) (alert.Outcome, error)
	TestMail(ctx context.Context, recipient string) (alert.Outcome, error)
}

// Ce que le serveur attend du composant action : envoyer un ordre, montrer
// la clé qui les signe, et, pour l'agent, écrire ce qu'il en a fait. Les
// runs se lisent par le Reader.
type ActionService interface {
	Ping(ctx context.Context, machineID string) (action.Run, error)
	ServerKey() (public []byte, fingerprint string, err error)
	PreviousServerKey() string
	Record(ctx context.Context, machineID string, report agentwire.ActionReport) error
	OpenParcel(machineID, parcelID, name string) (*os.File, int64, error)
	ReceiveParcel(uploaderID, parcelID, name string, content io.Reader, size int64, sum string) error
	// La mise à jour de l'agent : ce que la fiche propose, l'ordre, et la
	// fin de l'ordre au retour de l'agent (voir agentapi).
	OfferUpdate(ctx context.Context, machineID string) (action.UpdateOffer, error)
	UpdateAgent(ctx context.Context, machineID string) (action.Run, error)
	RollbackAgent(ctx context.Context, machineID string) (action.Run, error)
	// Le plan : où en est l'agent de chaque machine, dans quel ordre les mettre
	// à jour, et ce qui est en vol. Rien ne s'exécute.
	UpdatePlan(ctx context.Context) ([]action.PlanEntry, error)
	UpdateInFlight(ctx context.Context) (action.Run, bool, error)
	TargetVersion() string
	// Où en est un agent face au serveur (R-B2-9), et la version importée
	// plus récente que le serveur, que root n'a pas installée.
	StandingOf(agent machine.Agent) action.AgentStanding
	ImportedAhead() (string, error)
	ConfirmAgentUpdate(ctx context.Context, machineID, agentID, reported string) error
}

// Ce que le serveur attend du composant sshkeys : le relevé d'une machine et
// la matrice des machines. Le signal de l'agent l'écrit (agentapi).
type SSHKeysService interface {
	Record(ctx context.Context, machineID string, report sshkeys.Report) error
	Machine(ctx context.Context, machineID string) (sshkeys.Snapshot, error)
	Matrix(ctx context.Context) ([]sshkeys.Snapshot, error)
}

// Ce que le serveur attend du composant systemdunits : le relevé d'une machine
// et celui de toutes, pour l'état des unités déclarées. Le signal de l'agent
// l'écrit (agentapi).
type SystemdUnitsService interface {
	Record(ctx context.Context, machineID string, report systemdunits.Report) error
	Machine(ctx context.Context, machineID string) (systemdunits.Snapshot, error)
	All(ctx context.Context) ([]systemdunits.Snapshot, error)
}

// Ce que le serveur attend du composant proxmox : déclarer et retirer l'hôte
// d'une machine. Ce que la fiche lit passe par le Reader.
type ProxmoxService interface {
	Declare(ctx context.Context, machineID string, definition proxmox.Definition) error
	Remove(ctx context.Context, machineID string) error
	// Refresh relit l'hôte tout de suite ; un refus de l'hôte se garde sur sa fiche.
	Refresh(ctx context.Context, machineID string) error
	// Act envoie à l'agent de l'hôte le geste sur un invité (démarrer, arrêter,
	// instantané) et rend l'ordre écrit.
	Act(ctx context.Context, machineID string, vmid int, verb proxmox.Verb, snapshot string) (action.Run, error)
	// Networks rend les cartes réseau des invités du dernier relevé d'un hôte,
	// par numéro d'invité : la carte du réseau en tire les zones.
	Networks(machineID string) map[int][]proxmox.NIC
}

// Ce que le serveur attend du composant firewall : déclarer, redéclarer et
// retirer un pare-feu. Ce que la page lit passe par le Reader.
type FirewallService interface {
	Declare(ctx context.Context, definition firewall.Definition) (string, error)
	Redeclare(ctx context.Context, id string, definition firewall.Definition) error
	Remove(ctx context.Context, id string) error
	// Policy traduit la fiche vers le modèle des échanges (internal/fact/policy).
	Policy(view firewall.View) (policy.Model, error)
}

// Ce que le serveur attend du composant backup : les gestes de la page
// Sauvegardes. Le dernier ordre du plan se lit par le Reader.
type Backups interface {
	Overview(ctx context.Context) (backup.Overview, error)
	CreateKeyring(ctx context.Context, passphrase string, replace bool) (backup.Keyring, error)
	CreateDestination(ctx context.Context, definition backup.DestinationDefinition) (backup.Destination, error)
	DeleteDestination(ctx context.Context, id string) error
	SavePlan(ctx context.Context, definition backup.PlanDefinition) (backup.Plan, error)
	DeletePlan(ctx context.Context, subject string) error
	RunNow(ctx context.Context, subject string) (action.Run, error)
	// Runs est une lecture : l'historique des exécutions.
	Runs(ctx context.Context, query backup.RunQuery) ([]backup.RunRecord, error)
}

// Ce que le serveur attend de la base pour la montée de serve : sa copie,
// écrite sous le compte du service (R-B2-2).
type UpgradeCopier interface {
	CopyBeforeUpgrade(ctx context.Context, running release.Version) (string, error)
}

// Ce que le serveur attend du composant restic : l'aperçu de la page
// Sauvegardes, les cibles et les sauvegardes restic. Le relais et le signal
// passent par agentapi.
type ResticService interface {
	Overview(ctx context.Context) (restic.Overview, error)
	SetupTarget(ctx context.Context, machineID string, setup restic.TargetSetup) (restic.TargetRecord, error)
	RemoveTarget(ctx context.Context, machineID string) error
	CreateBackup(ctx context.Context, definition restic.Definition) (restic.Backup, error)
	UpdateBackup(ctx context.Context, sourceID, id, name string, retention restic.Retention, confirmName string) (restic.Backup, error)
	DeleteBackup(ctx context.Context, sourceID, id string) error
	RunNow(ctx context.Context, sourceID, id string) (action.Run, error)
	OwnedBackup(ctx context.Context, sourceID, id string) (restic.Backup, error)
	VerifyNow(ctx context.Context, sourceID, id string) (action.Run, error)
	Browse(ctx context.Context, sourceID, id string, request restic.BrowseRequest) (agentwire.ResticBrowseReport, error)
	Restore(ctx context.Context, sourceID, id string, request restic.RestoreRequest) (action.Run, error)
}

// Ce que le serveur attend du bus du direct : un abonnement par onglet.
type Live interface {
	Subscribe() *live.Subscription
}

type Server struct {
	logger   *slog.Logger
	version  string
	commit   string
	catalogs lang.Catalogs
	// reader est la base, pour les lectures sans règle : listes, objets,
	// comptes. Ce qui porte une règle passe par le composant.
	reader     reader.Reader
	settings   SettingsService
	machines   MachineService
	heartbeats HeartbeatService
	resources  ResourceService
	containers ContainerTracker
	probes     ProbeService
	directory  DirectoryService
	manifest   ManifestService
	updates    UpdateService
	lifecycle  LifecycleService
	status     StatusService
	alerts     AlertService
	notifier   Notifier
	apiTokens  APITokenService
	// verbRequests tient les demandes des verbes à confirmation.
	verbRequests VerbRequestService
	mcpCheck     *mcpcheck.Checker
	mcpURL       string
	auth         AuthService
	actions      ActionService
	sshKeys      SSHKeysService
	systemd      SystemdUnitsService
	links        LinkService
	proxmox      ProxmoxService
	firewalls    FirewallService
	backups      Backups
	// upgradeCopies et releases servent les routes de root qui préparent une
	// montée (control_upgrade.go) ; releases est nil sans clé de version.
	upgradeCopies UpgradeCopier
	releases      *release.Library
	restic        ResticService
	deploy        Deployer
	live          Live
	logStreams    atomic.Int32
	// Le limiteur de la racine, par source : les connexions, les changements
	// de mot de passe et les jetons d'API.
	authLimit *ratelimit.BySource
	// Le débit des gestes d'un jeton d'API, et celui de la trace de ses
	// refus, par jeton (api_tokens.go).
	verbLimit     *ratelimit.Limiter
	verbDenyLimit *ratelimit.Limiter
	// Les routes de l'agent, des pings et de la page publique, chacune dans
	// son paquet avec ses seules dépendances et ses limiteurs ; montées par
	// routes.go.
	agent  *agentapi.Handler
	pings  *pingapi.Handler
	public *public.Handler
	// authTransition sépare l'activation de l'authentification (changement
	// d'état puis révocation) des écritures qui accordent une autorité :
	// voir grantsAuthority.
	authTransition sync.RWMutex
	// Les onglets en direct de l'administration ; ceux de la page publique
	// sont comptés dans son paquet.
	eventTabs *ratelimit.Slots
	// clientSlots compte les requêtes ouvertes par client derrière un
	// mandataire de confiance (limits.go) ; refusals dit ces refus au journal.
	clientSlots *ratelimit.SourceSlots
	refusals    *refusalLog
	// La socket de commande ne sert que les routes du fichier de l'annuaire.
	controlHandler http.Handler
	// La socket des agents locaux ne sert que les routes de l'agent.
	agentSocketHandler http.Handler
	publicURL          string
	trustedProxies     []netip.Prefix
	// Le secret que le mandataire pose dans brand.ProxySecretHeader ; vide :
	// aucun n'est configuré, l'adresse du pair seule décide (voir auth.go).
	forwardSecret string
	// Les identités admises en mode forward ; vide : toute identité que le
	// mandataire transmet. Construit une fois, jamais modifié.
	forwardUsers map[string]bool
	listen       string
	// operatorFromAnyPeer lève la garde du pair (refuseUnproxiedPeer). Aucune
	// option ne le pose : seul le banc de test, qui joue l'opérateur depuis
	// 192.0.2.1, l'écrit.
	operatorFromAnyPeer bool
	// Le front compilé, embarqué : voir spa.go.
	app     fs.FS
	handler http.Handler
	clock   func() time.Time
}

type Options struct {
	Logger     *slog.Logger
	Version    string
	Commit     string
	Reader     reader.Reader
	Settings   SettingsService
	Machines   MachineService
	Heartbeats HeartbeatService
	Resources  ResourceService
	Containers ContainerTracker
	Probes     ProbeService
	Directory  DirectoryService
	Manifest   ManifestService
	Updates    UpdateService
	Lifecycle  LifecycleService
	Status     StatusService
	Alerts     AlertService
	Notifier   Notifier
	// APITokens crée et vérifie les jetons d'API ; voir api_tokens.go.
	APITokens APITokenService
	// VerbRequests tient les demandes de verbe à confirmation ; voir api_verb_requests.go.
	VerbRequests VerbRequestService
	// MCPURL est l'adresse de mcp-maison, vide : aucun ; voir api_settings_mcp.go.
	MCPURL string
	// Auth garde l'interface de l'opérateur ; voir auth.go.
	Auth AuthService
	// Actions envoie les ordres signés aux agents ; voir api_actions.go.
	Actions ActionService
	// SSHKeys garde le relevé des clés SSH autorisées ; voir api_sshkeys.go.
	SSHKeys SSHKeysService
	// Systemd garde le relevé des unités systemd ; voir api_systemd.go.
	Systemd SystemdUnitsService
	// HostConnections garde qui joint les ports de l'hôte ; le signal l'écrit.
	HostConnections agentapi.HostConnectionsService
	// Links garde les liens entre instances ; voir api_links.go.
	Links LinkService
	// Roles garde ce que l'agent reconnaît sur sa machine ; le signal l'écrit.
	Roles agentapi.RolesService
	// Host garde où tourne la machine et ses disques ; le signal l'écrit.
	Host agentapi.HostService
	// Proxmox déclare l'hôte Proxmox d'une machine ; voir api_proxmox.go.
	Proxmox ProxmoxService
	// Firewalls déclare les pare-feu lus en lecture seule ; voir api_firewalls.go.
	Firewalls FirewallService
	// Backups pilote la page Sauvegardes ; voir api_backups.go.
	Backups Backups
	// UpgradeCopies copie la base avant une montée ; Releases importe une
	// version, vérifiée par les clés de ce binaire, nil s'il n'en a pas. Voir
	// control_upgrade.go.
	UpgradeCopies UpgradeCopier
	Releases      *release.Library
	// Restic rend l'aperçu de la page Sauvegardes et ses gestes restic ; voir
	// api_restic.go. ResticAgent écrit la section restic du signal et les
	// résultats des sauvegardes ; ResticRelay est le relais des sources qui ne
	// joignent pas leur cible.
	Restic      ResticService
	ResticAgent agentapi.ResticService
	ResticRelay agentapi.RelayBroker
	// Deploy déploie les services déclarés ; voir api_deploy.go.
	Deploy Deployer
	Live   Live
	// PublicLive est le bus des visiteurs de la page de statut : à part,
	// pour que leurs connexions ne comptent pas parmi les onglets.
	PublicLive Live
	// Adresse publique d'openCloud pour la commande d'installation ; vide :
	// déduite de la requête.
	PublicURL      string
	TrustedProxies []netip.Prefix
	// ForwardSecret est le secret partagé avec le mandataire du mode forward,
	// lu par proxysecret.Load ; vide : aucun.
	ForwardSecret string
	// ForwardUsers est la liste blanche du mode forward (config.toml) ; vide :
	// toute identité transmise est admise.
	ForwardUsers []string
	// Listen est l'adresse d'écoute : son hôte est un Host reconnu.
	Listen string
	// ResponseWriteTimeout est le temps qu'une réponse hors flux a pour
	// partir (limits.go) ; zéro : aucune borne, pour les tests.
	ResponseWriteTimeout time.Duration
	// RequestReadTimeout est le temps qu'une requête hors flux a pour être
	// lue en entier (limits.go) ; zéro : aucune borne, pour les tests.
	RequestReadTimeout time.Duration
	// ConnectionsPerSource est la borne par client derrière un mandataire de
	// confiance (limits.go) ; zéro : aucune, pour les tests.
	ConnectionsPerSource int
	// AuthGlobalPerMinute borne les tentatives de connexion de toutes les
	// adresses ensemble, boucle locale exceptée ; 0 vaut DefaultAuthGlobalPerMinute.
	AuthGlobalPerMinute int
	// PingGlobalPerMinute : la même borne pour /ping ; 0 vaut ping.DefaultGlobalPerMinute.
	PingGlobalPerMinute int
	// Clock remplace l'horloge, pour les tests ; nil = time.Now.
	Clock func() time.Time
}

func New(opts Options) (*Server, error) {
	catalogs, err := lang.Load()
	if err != nil {
		return nil, fmt.Errorf("load languages: %w", err)
	}
	app, err := web.Dist()
	if err != nil {
		return nil, fmt.Errorf("open front: %w", err)
	}
	// La table MIME de Go ignore woff2 ; sans cela le navigateur reçoit un
	// octet-stream et certains refusent la police.
	if err := mime.AddExtensionType(".woff2", "font/woff2"); err != nil {
		return nil, fmt.Errorf("register woff2 type: %w", err)
	}
	server := &Server{
		logger:        opts.Logger,
		version:       opts.Version,
		commit:        opts.Commit,
		catalogs:      catalogs,
		reader:        opts.Reader,
		settings:      opts.Settings,
		machines:      opts.Machines,
		heartbeats:    opts.Heartbeats,
		resources:     opts.Resources,
		containers:    opts.Containers,
		probes:        opts.Probes,
		directory:     opts.Directory,
		manifest:      opts.Manifest,
		updates:       opts.Updates,
		lifecycle:     opts.Lifecycle,
		status:        opts.Status,
		alerts:        opts.Alerts,
		notifier:      opts.Notifier,
		apiTokens:     opts.APITokens,
		verbRequests:  opts.VerbRequests,
		mcpURL:        opts.MCPURL,
		auth:          opts.Auth,
		actions:       opts.Actions,
		sshKeys:       opts.SSHKeys,
		systemd:       opts.Systemd,
		links:         opts.Links,
		proxmox:       opts.Proxmox,
		firewalls:     opts.Firewalls,
		backups:       opts.Backups,
		upgradeCopies: opts.UpgradeCopies,
		releases:      opts.Releases,
		restic:        opts.Restic,
		deploy:        opts.Deploy,
		live:          opts.Live,
		authLimit: ratelimit.NewBySourceWithGlobal(authAttemptRate, authAttemptBurst, authIdle, ratelimit.GlobalLimit{
			PerMinute: cmp.Or(opts.AuthGlobalPerMinute, DefaultAuthGlobalPerMinute),
			Exempt:    isLoopbackAddress,
		}),
		verbLimit:      ratelimit.New(apiVerbRate, apiVerbBurst, apiVerbIdle),
		verbDenyLimit:  ratelimit.New(apiVerbDenyRate, apiVerbDenyBurst, apiVerbIdle),
		eventTabs:      ratelimit.NewSlots(maxEventSubscribers),
		publicURL:      opts.PublicURL,
		trustedProxies: opts.TrustedProxies,
		forwardSecret:  opts.ForwardSecret,
		forwardUsers:   forwardUserSet(opts.ForwardUsers),
		listen:         opts.Listen,
		app:            app,
		clock:          opts.Clock,
	}
	if opts.Clock != nil {
		server.authLimit.SetClock(opts.Clock)
		server.verbLimit.SetClock(opts.Clock)
		server.verbDenyLimit.SetClock(opts.Clock)
	}
	server.agent = agentapi.New(agentapi.Options{
		Logger:          opts.Logger,
		Machines:        opts.Machines,
		Resources:       opts.Resources,
		Containers:      opts.Containers,
		Probes:          opts.Probes,
		Updates:         opts.Updates,
		Actions:         opts.Actions,
		SSHKeys:         opts.SSHKeys,
		Systemd:         opts.Systemd,
		HostConnections: opts.HostConnections,
		Roles:           opts.Roles,
		Host:            opts.Host,
		Restic:          opts.ResticAgent,
		Relay:           opts.ResticRelay,
		ClientAddress:   server.clientAddress,
		Clock:           opts.Clock,
	})
	server.pings = pingapi.New(pingapi.Options{
		Logger:          opts.Logger,
		Heartbeats:      opts.Heartbeats,
		ClientAddress:   server.clientAddress,
		GlobalPerMinute: opts.PingGlobalPerMinute,
		Clock:           opts.Clock,
	})
	server.public = public.New(public.Options{
		Logger:        opts.Logger,
		Status:        opts.Status,
		Catalogs:      catalogs,
		Live:          opts.PublicLive,
		Page:          server.readStatusPage,
		ClientAddress: server.clientAddress,
		Clock:         opts.Clock,
	})
	server.mcpCheck = mcpcheck.New(opts.MCPURL, server.now)
	routed := server.refuseEncodedSlash(server.mux())
	if opts.ResponseWriteTimeout > 0 {
		routed = boundResponseWrite(opts.ResponseWriteTimeout, routed)
	}
	if opts.ConnectionsPerSource > 0 {
		server.clientSlots = ratelimit.NewSourceSlots(opts.ConnectionsPerSource)
		server.refusals = newRefusalLog(opts.Logger)
		routed = server.limitClientsBehindProxy(routed)
	}
	// Hors de la borne par client : une requête refusée (429) laisse aussi
	// son corps à drainer.
	if opts.RequestReadTimeout > 0 {
		routed = boundRequestRead(opts.RequestReadTimeout, routed)
	}
	server.handler = server.chain(server.securityHeaders(routed))
	server.controlHandler = server.chain(server.controlMux())
	agentRouted := http.Handler(server.agentSocketMux())
	if opts.ResponseWriteTimeout > 0 {
		agentRouted = boundResponseWrite(opts.ResponseWriteTimeout, agentRouted)
	}
	if opts.RequestReadTimeout > 0 {
		agentRouted = boundRequestRead(opts.RequestReadTimeout, agentRouted)
	}
	server.agentSocketHandler = server.chain(agentRouted)
	return server, nil
}

// AgentSocketHandler est ce que serve sert sur brand.AgentSocketPath : les
// routes de l'agent, et elles seules, avec les durées du port. Enrôlement,
// preuve signée et flux y sont ceux de HTTPS ; seul le transport change. Le
// jugement du pair (son uid) est à qui ouvre la socket.
func (s *Server) AgentSocketHandler() http.Handler {
	return s.agentSocketHandler
}

// agentSocketMux monte les routes d'agentapi.Handler.Routes une seconde fois,
// hors de mux() : ni /api/, ni /control/, ni l'interface n'y passent.
func (s *Server) agentSocketMux() *http.ServeMux {
	mux := http.NewServeMux()
	s.agent.Routes(func(method, pattern string, handler http.HandlerFunc) {
		bounded := boundByKind(method, pattern, handler)
		if method != anyMethod {
			pattern = method + " " + pattern
		}
		mux.HandleFunc(pattern, bounded)
	})
	mux.HandleFunc("/", http.NotFound)
	return mux
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// now est l'horloge du serveur : celle des tests quand ils en donnent une.
func (s *Server) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// language rend la langue de l'interface, relue dans la base à chaque
// usage : voir settings.Service.
func (s *Server) language(ctx context.Context) (lang.Code, error) {
	return s.settings.Language(ctx)
}
