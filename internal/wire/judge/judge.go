// Package judge est le seul juge d'un ordre signé (brique B-11) : l'agent
// l'appelle avant chaque ordre, la porte root (A5) et le relais (E7)
// l'importeront tel quel. Il lit l'ordre par agentwire et la politique par
// agentpolicy, et ne lit aucun fichier : il reçoit la politique.
package judge

import (
	"crypto/ed25519"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Verdict est ce que le juge dit d'un ordre.
type Verdict struct {
	// Vrai une fois la signature vérifiée et le corps lu : Body vaut alors
	// ce que le serveur a signé.
	Read bool
	Body agentwire.OrderBody
	// La clé de la politique qui a signé l'ordre, une fois vérifiée.
	SigningKey []byte
	// L'ordre décodé par le registre des genres ; avant le décodage, son
	// genre seul.
	Order agentwire.Order
	// Vide : l'ordre passe. Sinon une raison d'agentwire, la première
	// rencontrée.
	Reason string
}

// Judge juge un ordre contre la politique, dans cet ordre : une clé du
// serveur ; la signature de l'une de ses clés (une clé échue n'y est plus) ; le corps lu strictement, à la version
// de l'enveloppe (R-A1-9) ; la machine visée ; l'échéance ; le genre au
// registre ; le droit qu'il exige ; ses paramètres et son secret lus
// strictement ; les valeurs qu'il présente aux ancres. L'agent visé et le
// rang vivent avec l'agent : il les juge lui-même, à leur place.
func Judge(signed agentwire.SignedOrder, policy agentpolicy.Policy, now time.Time) Verdict {
	if len(policy.ServerKeys) == 0 {
		return Verdict{Reason: agentwire.ReasonServerKeyMissing}
	}
	signingKey := signingKeyOf(signed, policy.ServerKeys)
	if signingKey == nil {
		return Verdict{Reason: agentwire.ReasonBadSignature}
	}
	// Sans « v », le corps ne se réécrit pas à l'identique : la lecture stricte
	// le refuse ; une autre version est refusée ici.
	var body agentwire.OrderBody
	if err := agentwire.StrictDecode(signed.Body, &body); err != nil || body.V != agentwire.OrderVersion || body.RunID == "" {
		return Verdict{Reason: agentwire.ReasonBadOrder}
	}
	verdict := Verdict{Read: true, Body: body, SigningKey: signingKey, Order: agentwire.Order{Kind: body.Kind}}
	verdict.Reason = verdict.judgeBody(policy, now)
	return verdict
}

// signingKeyOf rend la clé qui a signé l'ordre, nil si aucune. Vérifié sous
// l'étiquette v2 seule : un corps v1, signé sous la sienne, ne passe pas
// (R-A1-9).
func signingKeyOf(signed agentwire.SignedOrder, keys [][]byte) []byte {
	signedBytes := agentwire.OrderSigningBytes(agentwire.OrderVersion, signed.Body)
	for _, key := range keys {
		if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, signedBytes, signed.Signature) {
			return key
		}
	}
	return nil
}

// judgeBody juge un corps lu ; il garde l'ordre décodé dès qu'il l'est.
func (v *Verdict) judgeBody(policy agentpolicy.Policy, now time.Time) string {
	switch {
	case v.Body.MachineID != policy.MachineID:
		return agentwire.ReasonWrongMachine
	case !now.Before(time.Unix(v.Body.NotAfter, 0)):
		return agentwire.ReasonExpired
	}
	spec, known := agentwire.SpecOf(v.Body.Kind)
	if !known {
		return agentwire.ReasonUnknownKind
	}
	// Un genre au droit calculé (right.request) se lit d'abord : son droit
	// vient de ses paramètres décodés (R-A1-1). Les autres jugent le droit
	// avant de lire.
	right := spec.Right
	if spec.RightIsComputed() {
		if reason := v.decode(); reason != "" {
			return reason
		}
		if right = v.Order.Right(); right == "" {
			return agentwire.ReasonBadOrder
		}
	}
	if !agentpolicy.HasCapability(policy.Rights, right) {
		return agentwire.RightMissing(right)
	}
	if !spec.RightIsComputed() {
		if reason := v.decode(); reason != "" {
			return reason
		}
	}
	// Les ancres de la politique : le registre des genres dit lesquelles
	// bornent l'ordre et sur quelle valeur.
	if finding := anchor.Judge(anchor.FromFile(policy.Anchors), v.Order.Presented()); finding != nil {
		return agentwire.AnchorRefusal(*finding)
	}
	return ""
}

// decode lit l'ordre et le garde ; une clé inconnue, répétée ou d'une autre
// casse ne se lit pas : refusée avant les ancres, qui jugent la valeur
// décodée.
func (v *Verdict) decode() string {
	order, err := Decode(v.Body)
	if err != nil {
		return agentwire.ReasonBadOrder
	}
	v.Order = order
	return ""
}

// Decode lit les paramètres et le secret d'un corps par le registre des
// genres, strictement : la seule lecture de ces octets.
func Decode(body agentwire.OrderBody) (agentwire.Order, error) {
	order, err := agentwire.Decode(body.Kind, body.Params)
	if err != nil {
		return agentwire.Order{}, err
	}
	if order.Secret, err = agentwire.DecodeSecret(body.Kind, body.Secret); err != nil {
		return agentwire.Order{}, err
	}
	return order, nil
}
