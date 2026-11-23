package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/server/httpx"
	"github.com/ldesfontaine/kagu/internal/gesture/apitoken"
	"github.com/ldesfontaine/kagu/internal/gesture/verb"
	"github.com/ldesfontaine/kagu/internal/gesture/verbrequest"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
)

// Ce que le serveur attend du composant des demandes de verbe à confirmation.
type VerbRequestService interface {
	Submit(ctx context.Context, submission verbrequest.Submission) (verbrequest.Request, error)
	ListPending(ctx context.Context) ([]verbrequest.Request, error)
	Confirm(ctx context.Context, id string, offered func(verb string) bool, holds func(verbrequest.Request) (bool, error)) (verbrequest.Request, error)
	Reject(ctx context.Context, id string) (verbrequest.Request, error)
}

// Le plus long segment de chemin qu'une demande garde : un identifiant
// d'openCloud est bien plus court.
const maxVerbParamRunes = 64

// --- La demande d'un jeton ---

// verbRequestReplyJSON est la réponse d'un verbe à confirmation à un jeton :
// rien n'a été exécuté, la demande attend l'opérateur jusqu'à ExpiresAt.
type verbRequestReplyJSON struct {
	Verb      string    `json:"verb"`
	RequestID string    `json:"request_id"`
	State     string    `json:"state"`
	ExpiresAt time.Time `json:"expires_at"`
}

// askConfirmation remplace l'exécution d'un verbe à confirmation quand un
// jeton l'appelle : la demande est déposée, le handler de l'opérateur n'est
// pas appelé. L'opérateur qui appelle la même route (le bouton de l'écran)
// passe, lui, par le handler tel quel.
func (s *Server) askConfirmation(offered verb.Verb, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, byToken := apiTokenFrom(r.Context())
		if !byToken {
			next(w, r)
			return
		}
		body, ok := s.readVerbBody(w, r, offered)
		if !ok {
			return
		}
		params := map[string]string{}
		for _, name := range offered.Params {
			value := r.PathValue(name)
			if printable(value, maxVerbParamRunes) != value {
				s.apiNotFound(w)
				return
			}
			params[name] = value
		}
		names, err := s.reader.MachineNames(r.Context())
		if s.failed(w, r, err, nil) {
			return
		}
		name, found := names[params["id"]]
		if !found {
			s.apiNotFound(w)
			return
		}
		request, err := s.verbRequests.Submit(r.Context(), verbrequest.Submission{
			Verb: offered.ID, ObjectName: name, Params: params, Body: body,
			TokenID: token.ID, TokenName: token.Name, OnBehalfOf: onBehalfOf(r),
		})
		if s.failed(w, r, err, nil) {
			return
		}
		s.writeAPI(w, http.StatusAccepted, verbRequestReplyJSON{
			Verb: request.Verb, RequestID: request.ID, State: string(request.State), ExpiresAt: request.ExpiresAt.UTC(),
		})
	}
}

// readVerbBody lit le corps que le jeton envoie : vide, ou un objet JSON dont
// les champs sont ceux que le verbe déclare. Il est rendu sous une forme
// canonique (clés triées), la même pour deux demandes identiques.
func (s *Server) readVerbBody(w http.ResponseWriter, r *http.Request, offered verb.Verb) (string, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAPIBody))
	if err != nil {
		s.writeAPIError(w, http.StatusBadRequest, codeBadJSON)
		return "", false
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return "", true
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		s.writeAPIError(w, http.StatusBadRequest, codeBadJSON)
		return "", false
	}
	for name := range fields {
		if !slices.Contains(offered.Body, name) {
			s.writeAPIError(w, http.StatusBadRequest, codeBadJSON)
			return "", false
		}
	}
	canonical, err := json.Marshal(fields)
	if err != nil {
		s.apiInternalError(w, r, err)
		return "", false
	}
	return string(canonical), true
}

// --- Les demandes, vues par l'opérateur ---

type verbRequestObjectJSON struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type verbRequestJSON struct {
	ID         string                `json:"id"`
	Verb       string                `json:"verb"`
	Object     verbRequestObjectJSON `json:"object"`
	TokenName  string                `json:"token_name"`
	OnBehalfOf string                `json:"on_behalf_of"`
	// Les champs que le jeton a envoyés, tels que la confirmation les
	// rejouera : l'opérateur voit ce qu'il confirme (keep_history).
	Body      json.RawMessage `json:"body"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

type verbRequestsResponse struct {
	Requests []verbRequestJSON `json:"requests"`
}

func verbRequestToJSON(request verbrequest.Request) verbRequestJSON {
	body := json.RawMessage(request.Body)
	if request.Body == "" {
		body = json.RawMessage("{}")
	}
	return verbRequestJSON{
		ID: request.ID, Verb: request.Verb, Object: verbRequestObjectJSON{ID: request.ObjectID(), Name: request.ObjectName},
		TokenName: request.TokenName, OnBehalfOf: request.OnBehalfOf, Body: body,
		CreatedAt: request.CreatedAt.UTC(), ExpiresAt: request.ExpiresAt.UTC(),
	}
}

// listVerbRequests rend ce qui attend l'opérateur. Route d'opérateur : un
// jeton la reçoit en 403, il n'a pas à lire les demandes des autres.
func (s *Server) listVerbRequests(w http.ResponseWriter, r *http.Request) {
	pending, err := s.verbRequests.ListPending(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, verbRequestsResponse{Requests: httpx.ConvertAll(pending, verbRequestToJSON)})
}

// rejectVerbRequest refuse la demande : rien n'est exécuté.
func (s *Server) rejectVerbRequest(w http.ResponseWriter, r *http.Request) {
	_, err := s.verbRequests.Reject(r.Context(), r.PathValue("id"))
	s.finishAPIAction(w, r, err, verbrequest.ErrNotFound)
}

// confirmVerbRequest confirme la demande puis la rejoue sous le jeton qui l'a
// déposée (R-A4-16) : le jeton est relu, sa portée, son verbe et sa portée
// d'objet rejugés, et le handler du verbe reçoit le jeton dans son contexte,
// comme à l'aller, pour juger lui-même les champs réservés à la personne. La
// personne n'ajoute que son accord, son identité reste l'acteur de l'audit.
// Un jeton qui ne tient plus (échu, portée rétrécie, verbe retiré) clôt la
// demande « caduque » : rien n'est rejoué. Confirmée, la demande ne se rejoue
// plus ; si le geste échoue (409, 404…), l'opérateur reçoit cet échec et un
// nouvel appel du jeton dépose une nouvelle demande.
func (s *Server) confirmVerbRequest(w http.ResponseWriter, r *http.Request) {
	var replay *http.Request
	var handler http.HandlerFunc
	_, err := s.verbRequests.Confirm(r.Context(), r.PathValue("id"), func(id string) bool {
		offered, found := verb.Default.Lookup(id)
		return found && offered.Token
	}, func(request verbrequest.Request) (holding bool, err error) {
		replay, handler, holding, err = s.prepareReplay(r, request)
		return holding, err
	})
	if s.failed(w, r, err, verbrequest.ErrNotFound) {
		return
	}
	captured := &capturedReply{header: http.Header{}}
	handler(captured, replay)
	captured.replayTo(w)
}

// prepareReplay relit le jeton de la demande et en bâtit le rejeu : la requête
// d'opérateur du verbe, avec le jeton dans son contexte. holding dit si le jeton
// tient encore : vivant, et la garde de l'aller (portée, verbe, objet) le
// laisse passer. Le débit n'est pas rejugé : c'est la personne qui confirme.
func (s *Server) prepareReplay(r *http.Request, request verbrequest.Request) (replay *http.Request, handler http.HandlerFunc, holding bool, err error) {
	offered, _ := verb.Default.Lookup(request.Verb)
	method, pattern, _ := strings.Cut(offered.Route, " ")
	handler, routed := s.handlerOf(method, pattern)
	if !routed {
		return nil, nil, false, fmt.Errorf("verb request %s: verb %q has no operator route", request.ID, request.Verb)
	}
	token, found, err := s.tokenOf(r.Context(), request.TokenID)
	if err != nil || !found {
		return nil, nil, false, err
	}
	replay, err = verbReplayOf(r.Context(), request, token, method, pattern)
	if err != nil {
		return nil, nil, false, err
	}
	return replay, handler, s.admitVerbRights(&capturedReply{header: http.Header{}}, replay, token, request.Verb), nil
}

// tokenOf relit un jeton vivant par son identifiant ; found faux s'il est
// révoqué ou échu.
func (s *Server) tokenOf(ctx context.Context, id string) (token apitoken.Token, found bool, err error) {
	tokens, err := s.apiTokens.List(ctx)
	if err != nil {
		return apitoken.Token{}, false, err
	}
	index := slices.IndexFunc(tokens, func(candidate apitoken.Token) bool { return candidate.ID == id })
	if index < 0 {
		return apitoken.Token{}, false, nil
	}
	return tokens[index], true, nil
}

// verbReplayOf bâtit la requête que la confirmation rejoue : les paramètres et
// le corps gardés, le jeton de la demande dans le contexte, l'acteur de la
// personne qui confirme avec la demande et pour qui le jeton appelait.
func verbReplayOf(ctx context.Context, request verbrequest.Request, token apitoken.Token, method, pattern string) (*http.Request, error) {
	path := pattern
	for name, value := range request.Params {
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(value))
	}
	actor := audit.ActorFrom(ctx)
	actor.OnBehalfOf = request.OnBehalfOf
	ctx = audit.WithVerbRequest(audit.WithActor(context.WithValue(ctx, apiTokenKey{}, token), actor), request.ID)
	replay, err := http.NewRequestWithContext(ctx, method, path, strings.NewReader(request.Body))
	if err != nil {
		return nil, err
	}
	replay.Header.Set("Content-Type", "application/json")
	for name, value := range request.Params {
		replay.SetPathValue(name, value)
	}
	return replay, nil
}

// handlerOf rend le handler d'une route du serveur, tel que la table des
// routes le donne : sans l'accès ni la garde du mux, déjà passés par la
// requête de confirmation.
func (s *Server) handlerOf(method, pattern string) (http.HandlerFunc, bool) {
	for _, candidate := range s.routes() {
		if candidate.method == method && candidate.pattern == pattern {
			return candidate.handler, true
		}
	}
	return nil, false
}
