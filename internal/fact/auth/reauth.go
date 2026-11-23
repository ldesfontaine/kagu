package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/ident"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// La redemande d'un geste de niveau 4 (R-A2-7, R-A2-8, R-CNX-6) : en native,
// le mot de passe, et le code s'il est actif, redonnés depuis moins de cinq
// minutes, sur la session qui porte le geste.
const ReauthLifetime = 5 * time.Minute

// ErrReauthRequired : le geste attend une redemande fraîche. Déclaré Invalid
// pour porter sa clé ; le serveur le rend en 403.
var ErrReauthRequired = refusal.Invalid("auth.reauth_required", "auth: password asked again for this gesture")

// reauthenticatedAt dit si la redemande de cette session vaut encore à now.
func (s Session) reauthenticatedAt(now time.Time) bool {
	return !s.ReauthAt.IsZero() && now.Before(s.ReauthAt.Add(ReauthLifetime))
}

// RequireFreshReauth est la garde des gestes de niveau 4. En forward, rien
// n'est redemandé : le SSO règle la fraîcheur de sa session (R-A2-8). En
// native, la session de la requête, et elle seule, doit avoir redonné son mot
// de passe depuis moins de ReauthLifetime (R-A2-7).
func (s *Service) RequireFreshReauth(state State, session Session) error {
	if state.Mode == ModeForward {
		return nil
	}
	if state.Mode == ModeNative && session.reauthenticatedAt(s.now()) {
		return nil
	}
	return ErrReauthRequired
}

// Reauth juge le mot de passe, puis le code s'il est actif, et pose
// reauth_at sur la session sessionID ; source est l'adresse de la requête, que
// l'alerte d'un code suspendu nomme. Son jeton est tiré à neuf et rendu pour
// le cookie (R-A2-3) : celui présenté avant ne vaut plus. L'identifiant reste,
// les flux et l'audit de la session la suivent.
func (s *Service) Reauth(ctx context.Context, expected State, sessionID, source, password, code string) (string, error) {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return "", err
	}
	if !current.Same(expected) {
		return "", ErrStateChanged
	}
	if err := requireNative(current); err != nil {
		return "", err
	}
	if err := s.requirePassword(ctx, current, password); err != nil {
		return "", err
	}
	if err := s.requireTOTP(ctx, current, code, source); err != nil {
		return "", err
	}
	token, err := ident.NewSecret()
	if err != nil {
		return "", fmt.Errorf("draw session token: %w", err)
	}
	renewed, err := s.store.RenewSessionToken(ctx, sessionID, ident.HashToken(token), s.now())
	if err != nil {
		return "", err
	}
	if !renewed {
		return "", ErrSessionNotFound
	}
	s.logger.Info("operator session re-authenticated", "session", sessionID)
	return token, nil
}
