package alert

import (
	"context"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
)

// TOTPLocked signale le code à six chiffres suspendu : trop de codes faux
// d'affilée, de n'importe quelles sources (R-A2-16). L'alerte nomme la source
// du dernier et l'heure de la fin ; une suspension qui en suit une autre met
// l'alerte ouverte à jour.
func (e *Engine) TOTPLocked(ctx context.Context, lock auth.TOTPLock) {
	e.Open(ctx, Fact{
		Kind: KindTOTPLocked, Severity: SeverityDanger, Object: accountObject(lock.Username),
		Details: Details{Target: lock.Source, Until: lock.Until},
	})
}

// TOTPUnlocked résout l'alerte : root a levé la suspension, ou un code juste a
// rouvert la connexion.
func (e *Engine) TOTPUnlocked(ctx context.Context, username string) {
	e.Resolve(ctx, KindTOTPLocked, accountObject(username))
}

func accountObject(username string) Object {
	return Object{Kind: ObjectAccount, ID: username, Name: username}
}
