package agentwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
)

// Spec est un genre d'ordre, déclaré une fois (R-A1-1) : le type de ses
// paramètres, le droit qu'il exige de l'agent, les ancres qui le bornent et
// les champs que le journal local en garde. Le serveur et l'agent lisent ce
// registre ; aucune autre table ne dit ces faits d'un genre.
type Spec struct {
	Kind Kind
	// Un nom de droit d'agentpolicy, toujours par sa constante (R-A1-14).
	Right string
	// Les ancres qui bornent ce genre, et la valeur de l'ordre que chacune juge.
	Anchors []AnchorCheck
	// Les champs des paramètres que le journal local retient : jamais un
	// secret, jamais un contenu (compose, certificat, clés). Vide : rien.
	Journal []string
	// decodeParams lit les paramètres dans leur type, strictement.
	decodeParams func(raw []byte) (any, error)
	// decodeSecret lit le champ secret dans son type ; nil : le genre n'en
	// porte pas.
	decodeSecret func(raw []byte) (any, error)
}

// AnchorCheck dit quelle valeur de l'ordre décodé un type d'ancre juge.
type AnchorCheck struct {
	Anchor string
	// value rend la valeur ; vide quand l'ordre n'en donne pas de lisible.
	value func(params any) string
	// applies dit si l'ancre borne cet ordre. Des paramètres
	// qui ne se lisent pas sont bornés : seul un ordre lu qui n'est pas du
	// ressort de l'ancre n'en présente aucune valeur.
	applies func(params any) bool
}

// Option complète la déclaration d'un genre.
type Option func(*Spec)

// Journal nomme les champs que le journal local retient.
func Journal(fields ...string) Option {
	return func(spec *Spec) { spec.Journal = fields }
}

// Anchored dit qu'un type d'ancre borne le genre, sur la valeur que value tire
// des paramètres décodés. P doit être le type des paramètres du genre : un
// autre type ne présente aucune valeur, et l'ordre sort de l'ancre.
func Anchored[P any](name string, value func(P) string) Option {
	return AnchoredWhen(name, func(P) bool { return true }, value)
}

// AnchoredWhen fait comme Anchored, mais l'ancre ne borne que les ordres pour
// lesquels applies est vrai (restic.backup : l'invité, pas le service). Pour
// les autres, l'ordre ne présente rien à cette ancre, pas même une valeur vide.
func AnchoredWhen[P any](name string, applies func(P) bool, value func(P) string) Option {
	check := AnchorCheck{
		Anchor: name,
		value: func(params any) string {
			typed, ok := params.(P)
			if !ok {
				return ""
			}
			return value(typed)
		},
		applies: func(params any) bool {
			typed, ok := params.(P)
			return !ok || applies(typed)
		},
	}
	return func(spec *Spec) { spec.Anchors = append(spec.Anchors, check) }
}

// WithSecret dit que le genre porte un champ secret, du type S.
func WithSecret[S any]() Option {
	return func(spec *Spec) {
		spec.decodeSecret = func(raw []byte) (any, error) {
			var secret S
			if err := StrictDecode(raw, &secret); err != nil {
				return nil, err
			}
			return secret, nil
		}
	}
}

// Define déclare un genre dont les paramètres sont du type P.
func Define[P any](kind Kind, right string, options ...Option) Spec {
	decode := func(raw []byte) (any, error) {
		var params P
		if err := StrictDecode(raw, &params); err != nil {
			return nil, err
		}
		return params, nil
	}
	return newSpec(kind, right, decode, options)
}

// DefineWithoutParams déclare un genre qui ne porte aucun paramètre.
func DefineWithoutParams(kind Kind, right string, options ...Option) Spec {
	decode := func(raw []byte) (any, error) {
		if len(raw) != 0 {
			return nil, ErrNotCanonical
		}
		return nil, nil
	}
	return newSpec(kind, right, decode, options)
}

func newSpec(kind Kind, right string, decode func([]byte) (any, error), options []Option) Spec {
	spec := Spec{Kind: kind, Right: right, decodeParams: decode}
	for _, option := range options {
		option(&spec)
	}
	return spec
}

// registry est la liste des genres d'ordres, dans l'ordre où ils s'affichent.
// Les observations (logs, logs_stop, probes, image_checks, restic_relay) n'y
// sont pas : elles ne sont pas signées. agent.server_key y reste, droit
// observe, tant que la rotation de clé l'envoie (A3).
var registry = []Spec{
	DefineWithoutParams(KindAgentPing, agentpolicy.CapabilityObserve),
	Define[AgentUpdateParams](KindAgentUpdate, agentpolicy.CapabilityAgentUpdate, Journal("version", "parcel")),
	DefineWithoutParams(KindAgentRollback, agentpolicy.CapabilityAgentUpdate),
	Define[ServerKeyParams](KindServerKey, agentpolicy.CapabilityObserve, Journal("public_key")),
	Define[BackupReceiveParams](KindBackupReceive, agentpolicy.CapabilityBackupReceive, Journal("parcel", "path")),
	Define[BackupPruneParams](KindBackupPrune, agentpolicy.CapabilityBackupReceive, Journal("path", "prefix", "keep")),
	Define[BackupProduceParams](KindBackupProduce, agentpolicy.CapabilityBackupProduce,
		Journal("producer", "target", "prefix", "recipient", "parcel"),
		Anchored(anchor.BackupRecipient, func(params BackupProduceParams) string { return params.Recipient }),
		Anchored(anchor.BackupGuest, func(params BackupProduceParams) string { return params.Target })),
	Define[DockerParams](KindDockerDeploy, agentpolicy.CapabilityDockerDeploy, Journal("service_id", "project"), WithSecret[DockerSecret]()),
	Define[DockerParams](KindDockerUpdate, agentpolicy.CapabilityDockerUpdate, Journal("service_id", "project"), WithSecret[DockerSecret]()),
	Define[DockerRollbackParams](KindDockerRollback, agentpolicy.CapabilityDockerUpdate, Journal("project")),
	Define[ProxmoxGuestParams](KindProxmoxStart, agentpolicy.CapabilityProxmoxPower, Journal("vmid", "type")),
	Define[ProxmoxGuestParams](KindProxmoxShutdown, agentpolicy.CapabilityProxmoxPower, Journal("vmid", "type")),
	Define[ProxmoxGuestParams](KindProxmoxSnapshot, agentpolicy.CapabilityProxmoxSnapshot, Journal("vmid", "type", "snapshot")),
	Define[ProxmoxGuestParams](KindProxmoxSnapshotDelete, agentpolicy.CapabilityProxmoxSnapshot, Journal("vmid", "type", "snapshot")),
	Define[ResticTargetSetupParams](KindResticTargetSetup, agentpolicy.CapabilityResticTarget, Journal("listen", "port")),
	Define[ResticUserAddParams](KindResticUserAdd, agentpolicy.CapabilityResticTarget, Journal("user"), WithSecret[ResticUserSecret]()),
	Define[ResticUserRemoveParams](KindResticUserRemove, agentpolicy.CapabilityResticTarget, Journal("user")),
	Define[ResticProvisionParams](KindResticProvision, agentpolicy.CapabilityResticProduce,
		Journal("target", "host", "port", "user"), WithSecret[ResticProvisionSecret](),
		Anchored(anchor.ResticTargetCert, func(params ResticProvisionParams) string { return PEMFingerprint(params.Certificate) })),
	Define[ResticBackupParams](KindResticBackup, agentpolicy.CapabilityResticProduce,
		Journal("target", "scope", "vmid", "guest_type", "service", "force_relay"),
		AnchoredWhen(anchor.BackupGuest,
			func(params ResticBackupParams) bool { return params.Scope == ResticScopeVM },
			func(params ResticBackupParams) string { return strconv.Itoa(params.VMID) })),
	Define[ResticRetainParams](KindResticRetain, agentpolicy.CapabilityResticTarget,
		Journal("user", "keep_last", "keep_daily", "keep_weekly", "keep_monthly", "keep_yearly"), WithSecret[ResticRetainSecret]()),
	Define[ResticVerifyParams](KindResticVerify, agentpolicy.CapabilityResticVerify, Journal("user"), WithSecret[ResticVerifySecret]()),
	Define[ResticBrowseParams](KindResticBrowse, agentpolicy.CapabilityResticBrowse, Journal("user", "snapshot", "path"), WithSecret[ResticBrowseSecret]()),
	Define[ResticRestoreParams](KindResticRestore, agentpolicy.CapabilityResticRestore, Journal("target", "snapshot", "path", "stamp")),
}

// SpecOf rend la déclaration d'un genre ; faux pour un genre hors du registre.
func SpecOf(kind Kind) (Spec, bool) {
	for _, spec := range registry {
		if spec.Kind == kind {
			return spec, true
		}
	}
	return Spec{}, false
}

// ErrNotCanonical : des octets qui ne sont pas ceux que json.Marshal écrit
// pour leur type (clé inconnue, répétée, d'une autre casse, espace, ordre des
// clés). L'agent refuse l'ordre bad_order.
var ErrNotCanonical = errors.New("not the canonical encoding of its type")

// StrictDecode lit raw dans into, puis exige que json.Marshal le réécrive
// octet pour octet (R-A1-2, R-A1-3) : ce que l'agent juge et exécute est
// alors exactement ce que le serveur a signé. Comme CheckCompose, on rend à
// nouveau et on compare.
func StrictDecode(raw []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("%w: %w", ErrNotCanonical, err)
	}
	encoded, err := json.Marshal(into)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotCanonical, err)
	}
	if !bytes.Equal(encoded, raw) {
		return ErrNotCanonical
	}
	return nil
}

// ErrNotAnOrder : le genre n'est pas dans le registre.
var ErrNotAnOrder = errors.New("not an order kind")

// Order est un ordre lu : son genre, ses paramètres et son secret décodés
// dans leur type. Le juge, les ancres, le journal et l'exécuteur lisent cet
// objet-là, jamais les octets (R-A1-5).
type Order struct {
	Kind   Kind
	Params any
	// Nil quand l'ordre n'en porte pas.
	Secret any
	spec   Spec
}

// Decode lit les paramètres d'un ordre de ce genre, strictement.
func Decode(kind Kind, params json.RawMessage) (Order, error) {
	spec, known := SpecOf(kind)
	if !known {
		return Order{}, fmt.Errorf("%q: %w", kind, ErrNotAnOrder)
	}
	decoded, err := spec.decodeParams(params)
	if err != nil {
		return Order{}, fmt.Errorf("%s params: %w", kind, err)
	}
	return Order{Kind: kind, Params: decoded, spec: spec}, nil
}

// DecodeSecret lit le champ secret d'un ordre de ce genre, strictement
// (R-A1-4). Absent, il rend nil : l'exécuteur dit s'il le lui faut. Présent
// sur un genre qui n'en porte pas, il est refusé.
func DecodeSecret(kind Kind, secret json.RawMessage) (any, error) {
	spec, known := SpecOf(kind)
	switch {
	case !known:
		return nil, fmt.Errorf("%q: %w", kind, ErrNotAnOrder)
	case len(secret) == 0:
		return nil, nil
	case spec.decodeSecret == nil:
		return nil, fmt.Errorf("%s carries no secret: %w", kind, ErrNotCanonical)
	}
	decoded, err := spec.decodeSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("%s secret: %w", kind, err)
	}
	return decoded, nil
}

// Presented rend, pour chaque ancre qui borne l'ordre, la valeur qu'il lui
// présente.
func (o Order) Presented() []anchor.Presented {
	return o.spec.presented(o.Params)
}

// PresentedOf fait comme Presented sur des paramètres encore en JSON (ceux
// d'un run gardé, ceux que le serveur va signer). Des paramètres qui ne se
// lisent pas ne présentent aucune valeur : l'ordre sort de chaque ancre qui
// borne son genre.
func PresentedOf(kind Kind, params json.RawMessage) []anchor.Presented {
	spec, known := SpecOf(kind)
	if !known {
		return nil
	}
	decoded, err := spec.decodeParams(params)
	if err != nil {
		decoded = nil
	}
	return spec.presented(decoded)
}

func (s Spec) presented(params any) []anchor.Presented {
	presented := make([]anchor.Presented, 0, len(s.Anchors))
	for _, check := range s.Anchors {
		if !check.applies(params) {
			continue
		}
		presented = append(presented, anchor.Presented{Name: check.Anchor, Value: check.value(params)})
	}
	return presented
}
