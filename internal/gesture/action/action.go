package action

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

const (
	// OrderLifetime est le temps qu'un ordre a pour arriver et être pris :
	// passé not_after, l'agent le refuse et la boucle de fond le dit expiré.
	OrderLifetime = 2 * time.Minute
	// Retention : un run et sa sortie partent à cet âge.
	Retention = 90 * 24 * time.Hour
	// Une raison tient sur une ligne courte : au-delà, ce n'est pas un agent
	// qui parle.
	maxReasonBytes = 200
	maxRunIDBytes  = 64
	// MaxRunDuration est le temps qu'un ordre long a pour finir une fois
	// accepté : au-delà, la boucle de fond le dit échoué (ReasonTimeout).
	MaxRunDuration = time.Hour
)

// State est l'état d'un run. Le serveur pose queued, sent et expired ;
// l'agent rapporte les autres.
type State string

const (
	StateQueued    State = "queued"
	StateSent      State = "sent"
	StateAccepted  State = "accepted"
	StateRefused   State = "refused"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	StateExpired   State = "expired"
)

// States rend la liste fermée, dans l'ordre de la vie d'un run.
func States() []State {
	return []State{StateQueued, StateSent, StateAccepted, StateRefused, StateSucceeded, StateFailed, StateExpired}
}

// IsFinished : rien ne change plus un run dans cet état.
func (s State) IsFinished() bool {
	switch s {
	case StateRefused, StateSucceeded, StateFailed, StateExpired:
		return true
	}
	return false
}

// ReasonUndelivered : l'ordre écrit n'a pas pu partir (flux tombé, file
// pleine). La seule raison que pose le serveur ; les autres viennent de
// l'agent (agentwire.RefusalReasons).
const ReasonUndelivered = "undelivered"

// ReasonTimeout : l'agent a accepté l'ordre et n'a pas répondu dans
// MaxRunDuration. Posée aussi par le serveur.
const ReasonTimeout = "timeout"

// Run est un ordre et ce qu'il est devenu. Il survit à sa machine et à son
// agent : MachineID et AgentID se vident, le nom reste.
type Run struct {
	ID          string
	Kind        agentwire.Kind
	Params      json.RawMessage
	MachineID   string
	MachineName string
	AgentID     string
	State       State
	Reason      string
	NotAfter    time.Time
	Seq         int64
	// L'acteur du journal d'audit, recopié et signé : « operator:<session> »
	// pour un opérateur connecté (A2 §5), « api:<jeton> » pour un jeton.
	RequestedBy string
	// Le nom lisible de cet acteur à l'instant de la demande (Actor.Label) :
	// le compte de la session, le nom du jeton. C'est lui que l'écran montre.
	RequestedByLabel string
	RequestedAt      time.Time
	// Zéro tant que le run n'est pas fini.
	FinishedAt time.Time
	Output     []LogLine
	// Le service déclaré que l'ordre vise (un déploiement) ; vide pour un
	// ordre qui vise la machine, et après la suppression du service.
	ServiceID string
}

// LogLine est une ligne de la sortie d'un run.
type LogLine struct {
	At     time.Time
	Stream string
	Line   string
}

// Order est ce que la clé du serveur signe pour un run.
type Order struct {
	RunID     string
	MachineID string
	AgentID   string
	Kind      agentwire.Kind
	Params    json.RawMessage
	// Signé avec l'ordre, jamais gardé : il n'est pas dans le Run.
	Secret   json.RawMessage
	NotAfter time.Time
	Seq      int64
	// L'acteur du run (Run.RequestedBy), signé dans l'enveloppe v2.
	Actor string
	// La forme de l'enveloppe : agentwire.LegacyOrderVersion pour agent.update
	// vers un agent du protocole 2 (envelopeFor), la courante sinon.
	Version int
}

func (r Run) order() Order {
	return Order{
		RunID: r.ID, MachineID: r.MachineID, AgentID: r.AgentID, Kind: r.Kind,
		Params: r.Params, NotAfter: r.NotAfter, Seq: r.Seq, Actor: r.RequestedBy,
	}
}

// encode écrit le corps dans l'enveloppe de sa version, toujours par
// json.Marshal du type : jamais une carte à la main. Le secret part signé vers
// l'agent, c'est son rôle : ces octets ne vont qu'à la signature et au flux,
// jamais à la base ni à un journal.
func (o Order) encode() ([]byte, error) {
	if o.Version == agentwire.LegacyOrderVersion {
		legacy := agentwire.OrderBodyV1{
			RunID: o.RunID, MachineID: o.MachineID, AgentID: o.AgentID, Kind: o.Kind,
			Params: o.Params, Secret: o.Secret, NotAfter: o.NotAfter.Unix(), Seq: o.Seq,
		}
		return json.Marshal(legacy) // #nosec G117 -- le corps signé porte le secret jusqu'à l'agent, rien d'autre ne le garde.
	}
	// Level reste 0 tant que les gestes ne portent pas de niveau (A4).
	body := agentwire.OrderBody{
		V: agentwire.OrderVersion, RunID: o.RunID, MachineID: o.MachineID, AgentID: o.AgentID, Kind: o.Kind,
		Params: o.Params, Secret: o.Secret, NotAfter: o.NotAfter.Unix(), Seq: o.Seq, Actor: o.Actor,
	}
	return json.Marshal(body) // #nosec G117 -- le corps signé porte le secret jusqu'à l'agent, rien d'autre ne le garde.
}

// envelopeFor rend l'enveloppe qu'un agent lit pour ce genre, ou le refus,
// avant que rien ne soit écrit ni signé (R-B2-8). Un agent du protocole 2 ne
// lit que la v1 et ne reçoit qu'agent.update, pour se mettre à jour ;
// l'exception disparaît à la version suivante. Un autre ne reçoit que les
// genres qu'il a annoncés, à leur numéro : seul ce qu'il annonce compte,
// jamais sa version.
func envelopeFor(protocol string, announced machine.OrderKinds, spec agentwire.Spec) (int, error) {
	if protocol == agentwire.LegacyProtocolVersion {
		if spec.Kind != agentwire.KindAgentUpdate {
			return 0, ErrAgentOutdated
		}
		return agentwire.LegacyOrderVersion, nil
	}
	if !announced.Announces(string(spec.Kind), spec.Revision) {
		return 0, ErrAgentOutdated
	}
	return agentwire.OrderVersion, nil
}

// Query choisit les runs d'une liste, du plus récent au plus ancien.
type Query struct {
	MachineID string
	// Vide : tous les genres.
	Kinds []agentwire.Kind
	Limit int
}

var (
	// ErrRightMissing : l'agent a rapporté ses droits et celui de l'ordre
	// n'y est pas ; il le refuserait. Rien n'est écrit.
	ErrRightMissing = refusal.Conflict("action.right_missing", "the agent does not hold the right this order needs: re-enroll it with that right")
	// ErrAgentOutdated : l'agent n'a pas annoncé le genre de l'ordre, ou parle
	// encore le protocole 2 et ne reçoit qu'agent.update. Rien n'est écrit.
	ErrAgentOutdated = refusal.Conflict("action.agent_outdated", "the agent does not know this kind of order: update the agent")
	// ErrMachineOffline : alias de machine.ErrOffline, le temps que les appelants passent au nom neuf.
	ErrMachineOffline = machine.ErrOffline
	// ErrReportInvalid : la section actions d'un signal sort de ce qu'un
	// agent peut rapporter.
	ErrReportInvalid = errors.New("action report invalid")
	// ErrNoServerKey : le serveur n'a pas de clé pour signer (une commande
	// hors ligne, qui n'envoie rien).
	ErrNoServerKey = errors.New("no server key to sign orders")
	// ErrSecretTooLarge : le secret d'un ordre dépasse ce qu'un agent lit.
	ErrSecretTooLarge = errors.New("order secret larger than an agent reads")
	// ErrUnknownKind : le genre n'est pas un ordre de la liste fermée.
	ErrUnknownKind = errors.New("not an order kind")
)
