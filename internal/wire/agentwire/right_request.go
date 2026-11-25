package agentwire

import "github.com/ldesfontaine/kagu/internal/fact/agentpolicy"

// KindRightRequest demande un droit à l'agent (R-DROIT-8, ARB-1) : rien à
// exécuter. L'agent qui ne le tient pas le refuse right_missing:<droit> et
// le note pour « agent grant --pending » ; celui qui le tient réussit à vide.
// Seul genre que le serveur ne juge pas d'avance (Spec.AgentJudgesAlone).
const KindRightRequest Kind = "right.request"

// RightRequestParams sont les paramètres de right.request : le droit demandé,
// un nom d'agentpolicy, et sa valeur quand elle vient de la liste fermée des
// producteurs (agentpolicy.CheckRequested).
type RightRequestParams struct {
	Right string `json:"right"`
	Value string `json:"value,omitempty"`
}

// requestedRight est le droit qu'exige l'ordre : celui qu'il demande. Vide
// quand la demande ne passe pas agentpolicy.CheckRequested : l'ordre ne se
// lit pas.
func requestedRight(params RightRequestParams) string {
	if agentpolicy.CheckRequested(params.Right, params.Value) != nil {
		return ""
	}
	return params.Right
}
