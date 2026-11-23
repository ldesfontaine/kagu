package server

import (
	"net/http"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
)

// withOperatorActor pose l'opérateur dans le contexte, une fois la requête
// admise par requireOperator : chaque geste qu'elle appelle le journalise
// sous son identité, sans que les signatures aient à la porter. Une requête
// admise par jeton d'API a déjà son acteur (admitAPIToken).
func (s *Server) withOperatorActor(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, byToken := apiTokenFrom(r.Context()); byToken {
			next(w, r)
			return
		}
		next(w, r.WithContext(audit.WithActor(r.Context(), operatorActor(r))))
	}
}

// operatorActor nomme l'opérateur par sa session en connexion native, le
// compte en nom lisible ; par l'en-tête du mandataire en SSO.
func operatorActor(r *http.Request) audit.Actor {
	if session, found := sessionFrom(r.Context()); found {
		return audit.OperatorSession(session.ID, operatorName(r))
	}
	return audit.Operator(operatorName(r))
}

// operatorName est l'identité que l'authentification a vue : le compte de la
// session native, ou l'en-tête du mandataire. À la première configuration, ou
// sans session, personne. Ce nom est indicatif, borné et sans caractère de
// contrôle ; le journal d'audit nomme en plus la session (operatorActor).
func operatorName(r *http.Request) string {
	state, _ := authorizingStateFrom(r.Context())
	name := ""
	switch state.Mode {
	case auth.ModeNative:
		session, _ := sessionFrom(r.Context())
		name = session.Identity
	case auth.ModeForward:
		name = identityFrom(r.Context())
	}
	return printable(name, maxActorNameRunes)
}
