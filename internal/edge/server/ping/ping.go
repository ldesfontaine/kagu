package ping

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ldesfontaine/kagu/internal/domain/heartbeat"
	"github.com/ldesfontaine/kagu/internal/edge/server/httpx"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
)

// Les bornes du débit sur /ping : par IP source résolue, pour freiner
// l'énumération de jetons, et par jeton, pour qu'un jeton fuité ne
// remplisse pas la base. Derrière Traefik sans trusted_proxies, tous les
// pings semblent venir de la boucle locale et partagent un seul seau.
const (
	pingPerSourceRate  = 10
	pingPerSourceBurst = 20
	pingPerTokenRate   = 0.5
	pingPerTokenBurst  = 30
	pingIdle           = 10 * time.Minute
	// Un vrai jeton fait 29 octets ; la marge laisse passer les jetons hérités
	// en clair, dont le format n'a jamais été garanti. Au-delà, le jeton ne
	// peut pas exister : il est refusé sans rien retenir.
	maxPingTokenLength = 256
	// Tous les pings de toutes les sources : une table pleine d'adresses
	// inventées oublie les plus anciennes, et c'est cette borne qui empêche
	// une rafale d'y regagner du crédit sans fin. Un ping coûte une lecture
	// indexée, 100 par seconde se tiennent ; une tâche réelle en fait
	// quelques-uns par jour, et 6 000 d'un coup couvrent des milliers de
	// tâches lancées à la même minute. Le coût : une rafale qui la sature
	// fait refuser (429) aussi les vrais pings, jusqu'à ce que le crédit
	// revienne (une minute pour tout rendre) ; la tâche réessaie.
	DefaultGlobalPerMinute = 6000
	// Un seau par jeton reconnu : le plafond dépasse le nombre de moniteurs
	// d'une machine Kagu.
	maxPingTokenBuckets = 4096
)

// admitPing rend le refus à répondre, ou nil si le ping peut s'écrire.
//
// Le seau par source compte d'abord : un jeton inconnu essayé en rafale
// s'arrête là. Le seau par jeton ne compte qu'un jeton reconnu : le jeton
// vient de l'URL, un anonyme l'invente, et un seau par jeton inventé
// remplirait la mémoire. Il compte avant l'écriture, pour que la base soit
// protégée : reconnaître, compter, puis écrire. Sa clé est l'empreinte du
// jeton, qui pèse toujours la même chose.
func (h *Handler) admitPing(ctx context.Context, source, token string) *pingRefusal {
	if !h.sourceLimit.Allow(source) {
		return &tooManyPings
	}
	// Au-delà, le jeton ne peut pas exister : il est refusé sans rien lire.
	if len(token) > maxPingTokenLength {
		return &unknownToken
	}
	known, err := h.heartbeats.IsKnownToken(ctx, token)
	if err != nil {
		h.logger.Error("look up ping token", "error", err)
		return &pingFailed
	}
	if !known {
		return &unknownToken
	}
	if !h.tokenLimit.Allow(ident.HashToken(token)) {
		return &tooManyPings
	}
	return nil
}

type pingRefusal struct {
	status int
	text   string
}

var (
	tooManyPings = pingRefusal{http.StatusTooManyRequests, "too many pings"}
	unknownToken = pingRefusal{http.StatusNotFound, "unknown token"}
	pingFailed   = pingRefusal{http.StatusInternalServerError, "error"}
)

// GET ou POST /ping/{token} : la tâche a fini.
func (h *Handler) finish(w http.ResponseWriter, r *http.Request) {
	h.receivePing(w, r, heartbeat.Ping{Kind: heartbeat.KindFinish})
}

// GET ou POST /ping/{token}/start : la tâche démarre.
func (h *Handler) start(w http.ResponseWriter, r *http.Request) {
	h.receivePing(w, r, heartbeat.Ping{Kind: heartbeat.KindStart})
}

// GET ou POST /ping/{token}/{code} : la tâche a fini avec ce code de sortie.
// Le mux donne la priorité au segment littéral : « start » n'arrive pas ici.
// Le code est lu après la limitation, pour qu'un code faux ne soit pas
// une route illimitée ; hors bornes, le service le refuse.
func (h *Handler) exitCode(w http.ResponseWriter, r *http.Request) {
	code, err := strconv.Atoi(r.PathValue("code"))
	if err != nil {
		code = -1
	}
	h.receivePing(w, r, heartbeat.Ping{Kind: heartbeat.KindExitCode, ExitCode: &code})
}

// La réponse est du texte court, sans cookie ni JSON : un cron ne lit rien.
func (h *Handler) receivePing(w http.ResponseWriter, r *http.Request, ping heartbeat.Ping) {
	token := r.PathValue("token")
	ping.Source = h.clientAddress(r)
	ping.Method = r.Method
	if refusal := h.admitPing(r.Context(), ping.Source, token); refusal != nil {
		if refusal.status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", httpx.RetryAfterSeconds)
		}
		h.writePing(w, refusal.status, refusal.text)
		return
	}
	if r.Method == http.MethodPost {
		body, err := io.ReadAll(io.LimitReader(r.Body, heartbeat.MaxPayloadBytes))
		if err != nil {
			h.writePing(w, http.StatusBadRequest, "bad body")
			return
		}
		ping.Payload = string(body)
	}
	_, err := h.heartbeats.Receive(r.Context(), token, ping)
	switch {
	case errors.Is(err, heartbeat.ErrNotFound):
		h.writePing(w, http.StatusNotFound, "unknown token")
	case errors.Is(err, heartbeat.ErrExitCodeInvalid):
		h.writePing(w, http.StatusBadRequest, "bad exit code")
	case err != nil:
		h.logger.Error("receive ping", "error", err)
		h.writePing(w, http.StatusInternalServerError, "error")
	default:
		h.writePing(w, http.StatusOK, "ok")
	}
}

func (h *Handler) writePing(w http.ResponseWriter, status int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(text + "\n")); err != nil {
		h.logger.Warn("write ping response", "error", err)
	}
}
