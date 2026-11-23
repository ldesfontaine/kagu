package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/server/httpx"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/kit/deletion"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// Ce que le navigateur peut envoyer d'un coup : un formulaire, jamais plus.
const maxAPIBody = 64 << 10

// Une réponse d'erreur de l'API : un seul mot. Quand l'opérateur doit le
// lire, c'est une clé du catalogue (machine.name_invalid) et le front la
// traduit ; sinon un code court (not_found, bad_json, internal).
type apiError struct {
	Error string `json:"error"`
	// Ce qui lève un refus de droit ou d'ancre ; absent pour les autres.
	Fix *fixJSON `json:"fix,omitempty"`
	// La fin de la suspension du code, pour auth.totp_locked : la page de
	// connexion dit « Code suspendu jusqu'à 14:32 ».
	Until time.Time `json:"until,omitzero"`
}

const (
	codeNotFound     = "not_found"
	codeBadJSON      = "bad_json"
	codeInternal     = "internal"
	codeOrigin       = "bad_origin"
	codeHost         = "bad_host"
	codeEncodedSlash = "bad_path"
)

func (s *Server) readAPI(w http.ResponseWriter, r *http.Request, into any) bool {
	if !readBounded(w, r, into, maxAPIBody) {
		s.writeAPIError(w, http.StatusBadRequest, codeBadJSON)
		return false
	}
	return true
}

// readBounded lit le corps JSON, d'au plus limit octets, sans champ inconnu.
func readBounded(w http.ResponseWriter, r *http.Request, into any, limit int64) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into) == nil
}

func (s *Server) writeAPI(w http.ResponseWriter, status int, payload any) {
	if err := httpx.WriteJSONNoStore(w, status, payload); err != nil {
		s.logger.Warn("write json", "error", err)
	}
}

func (s *Server) writeAPIError(w http.ResponseWriter, status int, code string) {
	s.writeAPI(w, status, apiError{Error: code})
}

// Une erreur qu'on n'avait pas prévue : journal complet, réponse muette.
func (s *Server) apiInternalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("internal error", "path", r.URL.Path, "error", err)
	s.writeAPIError(w, http.StatusInternalServerError, codeInternal)
}

// apiRefuse répond un refus que le serveur décide lui-même (un paramètre de
// requête, un en-tête, une limite du serveur), ou celui d'un composant dont
// le statut n'est ni 422 ni 409 (404 à clé propre, 403, 503). Une règle
// métier refuse par refusal.*, et la réponse passe par failed.
func (s *Server) apiRefuse(w http.ResponseWriter, status int, key string) {
	s.writeAPIError(w, status, key)
}

// apiNotFound sert aussi le 404 d'un composant : errors.Is(err, ErrNotFound).
func (s *Server) apiNotFound(w http.ResponseWriter) {
	s.writeAPIError(w, http.StatusNotFound, codeNotFound)
}

// failed répond à l'erreur d'un composant et dit si la réponse est partie :
// 404 sur notFound, la clé d'un refus en 422 ou 409, sinon 500. notFound est
// nil quand la route n'a pas de 404.
func (s *Server) failed(w http.ResponseWriter, r *http.Request, err, notFound error) bool {
	if err == nil {
		return false
	}
	if notFound != nil && errors.Is(err, notFound) {
		s.apiNotFound(w)
		return true
	}
	if key, ok := refusal.KeyOf(err); ok {
		// Une suppression retenue rend aussi son plan : ce qui la retient.
		var refused *deletion.RefusedError
		if errors.As(err, &refused) {
			s.writeAPI(w, refusalStatus(err), deletionRefusalJSON{Error: key, Plan: deletionPlanToJSON(refused.Plan)})
			return true
		}
		s.writeAPI(w, refusalStatus(err), apiError{Error: key, Fix: fixOf(err)})
		return true
	}
	s.apiInternalError(w, r, err)
	return true
}

// fixJSON dit ce qui lève un refus (brique B-6), le même champ pour un droit
// et pour une ancre : le droit qui manque et la machine dont l'agent doit le
// tenir, et la ligne à lancer en root sur elle. Une ligne refusée par
// R-A3-15 est absente : le refus part sans ligne. Pour une ancre, exact dit
// que la ligne pose la valeur de l'ordre (faux : « trust list », l'écran
// renvoie alors à la fiche de la machine).
type fixJSON struct {
	Right   string `json:"right,omitempty"`
	Machine string `json:"machine,omitempty"`
	Command string `json:"command,omitempty"`
	Exact   bool   `json:"exact,omitempty"`
}

// fixOf rend ce qui lève le refus err ; nil pour un refus sans geste.
func fixOf(err error) *fixJSON {
	var anchored *anchor.Refused
	if errors.As(err, &anchored) {
		command, exact := anchored.Fix()
		return anchorFixJSON("", command, exact)
	}
	if fix, ok := refusal.FixOf(err); ok {
		return rightFixJSON(fix)
	}
	return nil
}

// rightFixJSON écrit la ligne grant du droit, sans valeur : celle d'un droit
// borné (files.write=<chemin>) remplacerait les chemins déjà posés.
func rightFixJSON(fix refusal.Fix) *fixJSON {
	return &fixJSON{Right: fix.Right, Machine: fix.Machine, Command: agentpolicy.GrantLine(fix.Right, "")}
}

// anchorFixJSON rend la commande d'une ancre et la machine où la lancer, vide
// quand le refus ne la dit pas ; nil sans commande.
func anchorFixJSON(machineID, command string, exact bool) *fixJSON {
	if command == "" {
		return nil
	}
	return &fixJSON{Machine: machineID, Command: command, Exact: exact}
}

// refusalStatus rend le statut HTTP d'un refus : 409 s'il vient de l'état
// présent, 422 sinon.
func refusalStatus(err error) int {
	if refusal.IsConflict(err) {
		return http.StatusConflict
	}
	return http.StatusUnprocessableEntity
}

// finishAPIAction répond à une action sans contenu : 204, ou l'échec.
func (s *Server) finishAPIAction(w http.ResponseWriter, r *http.Request, err, notFound error) {
	if s.failed(w, r, err, notFound) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requireSameOrigin remplace le jeton anti-CSRF des formulaires : toute
// écriture porte application/json, corps vide compris, et un navigateur ne
// peut pas l'envoyer à un autre site sans une pré-requête CORS que rien
// n'accepte. Un Sec-Fetch-Site présent dit en plus d'où vient la requête.
// Les deux garde-fous se cumulent ; les GET ne changent rien et passent.
func (s *Server) requireSameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				s.writeAPIError(w, http.StatusForbidden, codeOrigin)
				return
			}
			if !isJSON(r.Header.Get("Content-Type")) {
				s.writeAPIError(w, http.StatusForbidden, codeOrigin)
				return
			}
		}
		next(w, r)
	}
}

// requireStreamOrigin garde un flux de l'opérateur, qu'un GET ouvre : il
// tient la session ouverte et pousse ce qui change, une page d'un autre site
// n'a pas à l'ouvrir. La lecture de Sec-Fetch-Site est celle des écritures,
// plus stricte : « none » (une adresse tapée) est refusé aussi, un
// EventSource ne l'envoie jamais. Un Origin présent doit être le nôtre.
func (s *Server) requireStreamOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			s.writeAPIError(w, http.StatusForbidden, codeOrigin)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !s.isOwnOrigin(r, origin) {
			s.writeAPIError(w, http.StatusForbidden, codeOrigin)
			return
		}
		next(w, r)
	}
}

// isOwnOrigin compare un Origin à public_url, ou, sans public_url, à
// l'adresse par laquelle on lit la page (resolvePublicURL).
func (s *Server) isOwnOrigin(r *http.Request, origin string) bool {
	own := originOf(s.resolvePublicURL(r).URL)
	return own != "" && strings.EqualFold(origin, own)
}

func isJSON(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	return strings.TrimSpace(mediaType) == "application/json"
}

// Une liste nulle s'écrit [] : le front n'a pas à distinguer null de vide.
func orEmpty[T any](list []T) []T {
	if list == nil {
		return []T{}
	}
	return list
}
