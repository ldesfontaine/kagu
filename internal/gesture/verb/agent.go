package verb

import (
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Les gestes de mise à jour de l'agent d'une machine : mettre à jour et revenir
// en arrière se défont l'un l'autre. Ni l'un ni l'autre ne signe ni n'importe
// de version : le serveur n'envoie que sa propre version, déjà importée et
// signée par l'opérateur (`release import` n'est pas un verbe et ne le sera
// pas). Le serveur refuse tout agent qui ne sait pas revenir seul à sa version
// d'avant, et ne met jamais deux agents à jour en même temps.
func init() {
	Default.MustRegister(Verb{
		ID: "agent.update", Route: "POST /api/machines/{id}/actions/update-agent", Params: []string{"id"}, Body: []string{}, Target: TargetMachine,
		Label: "api_token.verb_agent_update", Summary: "api_token.verb_agent_update_text", Reverse: "agent.rollback",
		Level: 1, Token: true, Order: agentwire.KindAgentUpdate, Right: agentpolicy.CapabilityAgentUpdate, Audit: audit.ActionOrder,
	})
	Default.MustRegister(Verb{
		ID: "agent.rollback", Route: "POST /api/machines/{id}/actions/rollback-agent", Params: []string{"id"}, Body: []string{}, Target: TargetMachine,
		Label: "api_token.verb_agent_rollback", Summary: "api_token.verb_agent_rollback_text", Reverse: "agent.update",
		Level: 1, Token: true, Order: agentwire.KindAgentRollback, Right: agentpolicy.CapabilityAgentUpdate, Audit: audit.ActionOrder,
	})
	// Demander un droit à la machine (R-DROIT-8, ARB-1) : niveau 3, interface
	// seulement. L'ordre part sans jugement d'avance ; seul root le pose ensuite,
	// sur la machine. Pas de droit : le genre le calcule sur ce qu'il demande.
	Default.MustRegister(Verb{
		ID: "right.request", Route: "POST /api/machines/{id}/actions/request-right", Params: []string{"id"}, Body: []string{"right", "value"}, Target: TargetMachine,
		Label: "api_token.verb_right_request", Summary: "api_token.verb_right_request_text",
		Level: 3, Reason: "api_token.verb_right_request_reason", Order: agentwire.KindRightRequest, Audit: audit.ActionOrder,
	})
}
