package auth

import (
	"strconv"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/audit"
)

// L'objet du journal : l'accès à l'interface, qui n'a qu'une instance.
const auditObjectID = "interface"

// SetAuditor branche le journal d'audit ; nil est toléré.
func (s *Service) SetAuditor(auditor *audit.Recorder) {
	s.auditor = auditor
}

// authEvent dit le mode, l'identifiant et l'en-tête ; jamais le mot de passe
// ni son empreinte.
func authEvent(action audit.Action, state State) audit.Event {
	return audit.Event{
		Action: action, ObjectID: auditObjectID, ObjectName: auditObjectID,
		Details: audit.Details{"mode": string(state.Mode), "username": state.Username, "header": state.Header},
	}
}

// setupCodeEvent dit l'échéance du code tiré ; jamais le code ni son empreinte.
func setupCodeEvent(expiresAt time.Time) audit.Event {
	return audit.Event{
		Action: audit.AuthSetupCodeIssue, ObjectID: auditObjectID, ObjectName: auditObjectID,
		Details: audit.Details{"expires_at": expiresAt.UTC().Format(time.RFC3339)},
	}
}

// closedSessionEvent dit la session fermée, ou combien l'ont été autour de
// celle gardée ; jamais un jeton.
func closedSessionEvent(details audit.Details) audit.Event {
	return audit.Event{Action: audit.AuthCloseSession, ObjectID: auditObjectID, ObjectName: auditObjectID, Details: details}
}

// closedOthersDetails : la session gardée et le nombre de fermées.
func closedOthersDetails(keptID string, closed int) audit.Details {
	return audit.Details{"kept": keptID, "closed": strconv.Itoa(closed)}
}
