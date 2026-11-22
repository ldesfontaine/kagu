package alert

import (
	"context"
	"fmt"

	"github.com/ldesfontaine/kagu/internal/fact/probe"
)

// RedactProbeTargets retire le mot de passe de la cible que gardent les alertes
// de sonde écrites avant son masquage (R-D5-19) ; rend combien en ont changé.
// Rejouée à chaque démarrage, elle ne touche plus une alerte déjà nettoyée :
// le démarrage ne compacte que si elle a changé quelque chose.
func (e *Engine) RedactProbeTargets(ctx context.Context) (int, error) {
	found, err := e.store.ListAlerts(ctx, Filter{Kind: KindProbeDown})
	if err != nil {
		return 0, fmt.Errorf("list probe alerts: %w", err)
	}
	redacted := 0
	for _, stale := range found {
		target := probe.RedactTarget(stale.Details.Target)
		if target == stale.Details.Target {
			continue
		}
		stale.Details.Target = target
		if err := e.store.UpdateAlert(ctx, stale); err != nil {
			return redacted, fmt.Errorf("redact target of alert %d: %w", stale.ID, err)
		}
		redacted++
	}
	return redacted, nil
}
