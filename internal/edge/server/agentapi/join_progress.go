package agentapi

import (
	"net/http"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/server/httpx"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Les envois de join : dix par minute et par jeton (B1 §5). Un join envoie
// son parcours une fois par étape cochée ; relancé, il le renvoie. Le seau
// d'un jeton se compte avant de lire la base, d'où la borne du nombre de
// jetons suivis : le seau par source passe avant et en freine l'invention.
const (
	joinProgressBurst     = 10
	joinProgressRate      = joinProgressBurst / 60.0
	joinProgressIdle      = 2 * time.Minute
	joinProgressMaxTokens = 1024
)

// joinProgress écrit sous le jeton le parcours que join rapporte (R-B1-11).
// Le jeton vient de l'en-tête, est comparé par empreinte, et n'est jamais
// consommé : seul l'enrôlement le sert. Les refus sont ceux de
// l'enrôlement.
func (h *Handler) joinProgress(w http.ResponseWriter, r *http.Request) {
	if !h.speaksProtocol(w, r) {
		return
	}
	if !h.sourceLimit.Allow(h.clientAddress(r)) {
		w.Header().Set("Retry-After", httpx.RetryAfterSeconds)
		h.writeError(w, http.StatusTooManyRequests, "too_many_requests")
		return
	}
	cleartext := r.Header.Get(agentwire.HeaderEnrollmentToken)
	if cleartext == "" {
		h.writeError(w, http.StatusNotFound, "token_not_found")
		return
	}
	if !h.joinLimit.Allow(machine.TokenIDOf(cleartext)) {
		w.Header().Set("Retry-After", httpx.RetryAfterSeconds)
		h.writeError(w, http.StatusTooManyRequests, "too_many_requests")
		return
	}
	var progress agentwire.JoinProgress
	if !h.readJSON(w, r, &progress) {
		return
	}
	if err := h.machines.RecordJoinProgress(r.Context(), cleartext, progress.Steps); err != nil {
		h.writeEnrollError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
