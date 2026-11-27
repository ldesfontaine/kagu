package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Les routes de root dont setup a besoin pour l'agent de la machine Kagu
// (B1) : le jeton qui l'enrôle, puis ce qu'il rapporte.

// localEnrollmentResponse porte le jeton en clair : il ne part que vers root,
// par la socket, et n'entre jamais au journal.
type localEnrollmentResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// offerLocalEnrollmentToRoot rend le jeton de l'agent de la machine Kagu
// (machine.OfferLocalEnrollment) : celui qui attend encore, sinon un neuf.
// 409 machine.local_enrolled quand elle a, ou a eu, un agent.
func (s *Server) offerLocalEnrollmentToRoot(w http.ResponseWriter, r *http.Request) {
	if !s.readEmptyBody(w, r) {
		return
	}
	cleartext, token, err := s.machines.OfferLocalEnrollment(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusCreated, localEnrollmentResponse{Token: cleartext, ExpiresAt: token.ExpiresAt})
}

// localAgentResponse dit où en est l'agent de la machine Kagu : enrôlé, en
// ligne, ses droits rapportés, et s'il peut déployer dans la racine des
// services (le verdict de agentpolicy.Fit, que setup affiche sans le
// recalculer).
type localAgentResponse struct {
	Enrolled bool    `json:"enrolled"`
	Online   bool    `json:"online"`
	Reported bool    `json:"reported"`
	Deploy   fitJSON `json:"deploy"`
}

func (s *Server) readLocalAgent(w http.ResponseWriter, r *http.Request) {
	local, err := s.machines.Get(r.Context(), machine.LocalID)
	if errors.Is(err, machine.ErrNotFound) {
		s.writeAPI(w, http.StatusOK, localAgentResponse{Deploy: fitJSON{State: string(agentpolicy.FitMissing)}})
		return
	}
	if s.failed(w, r, err, nil) {
		return
	}
	agent := local.Agent
	deploy := agent.Fit(agentpolicy.CapabilityDockerDeploy, "")
	s.writeAPI(w, http.StatusOK, localAgentResponse{
		Enrolled: agent.IsActive(), Online: local.Online, Reported: !agent.ReportedAt.IsZero(),
		Deploy: fitJSON{State: string(deploy.State), Reason: deploy.Reason},
	})
}

// recordLocalProgress écrit le parcours de setup sous le jeton de l'agent de
// la machine Kagu (R-B1-11), dans le corps de join : toutes ses lignes
// depuis la première. 404 tant qu'aucun jeton ne lui est offert.
func (s *Server) recordLocalProgress(w http.ResponseWriter, r *http.Request) {
	var request agentwire.JoinProgress
	if !s.readAPI(w, r, &request) {
		return
	}
	err := s.machines.RecordLocalProgress(r.Context(), request.Steps)
	if errors.Is(err, machine.ErrBadField) {
		s.apiRefuse(w, http.StatusBadRequest, codeBadJSON)
		return
	}
	if s.failed(w, r, err, machine.ErrTokenNotFound) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
