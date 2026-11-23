package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/server/httpx"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

type authResponse struct {
	Mode string `json:"mode"`
	// En native, le compte, à qui a une session ; en forward, l'identité
	// transmise avec cette requête : rien ne la stocke.
	Username string `json:"username"`
	// Le nom de l'en-tête d'identité, en forward seulement.
	Header    string     `json:"header,omitempty"`
	EnabledAt *time.Time `json:"enabled_at"`
	// Vrai quand la requête est admise comme l'opérateur : une session native
	// vivante, ou le mandataire en forward. Faux sans compte.
	SignedIn bool `json:"signed_in"`
	// La session native de la requête : la liste des sessions la marque.
	Session string `json:"session,omitempty"`
	// En forward, vrai quand rien ne prouve que la requête passe par le
	// mandataire : pas de secret, et la boucle locale est de confiance. Le
	// mode reste actif (le couper enfermerait l'opérateur), la page le dit.
	ForwardInsecure bool `json:"forward_insecure,omitempty"`
	// En forward, la liste blanche de forward_users ; null quand elle est vide
	// (toute identité du mandataire est admise) et dans les autres modes.
	AllowedUsers []string `json:"allowed_users"`
	// La longueur minimale, pour que le front la dise et la vérifie avant
	// d'envoyer ; le serveur reste le juge.
	PasswordMinLength int `json:"password_min_length"`
}

// La première configuration révoque tous les jetons d'API : la réponse dit
// combien sont tombés, l'interface le montre.
type authSetupResponse struct {
	authResponse
	APITokensRevoked int `json:"api_tokens_revoked"`
}

// Mode vide vaut native. Header ne sert qu'en forward, Remote-User s'il est
// vide. SetupCode est le code de première configuration, exigé dans les deux
// modes.
type authSetupRequest struct {
	Mode      string `json:"mode"`
	SetupCode string `json:"setup_code"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Header    string `json:"header"`
}

type authLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Current est le mot de passe en vigueur : sans lui juste, rien ne change.
type authPasswordRequest struct {
	Current  string `json:"current"`
	Password string `json:"password"`
}

// Changer le mot de passe ne révoque pas les jetons d'API : la réponse dit
// combien vivent, l'écran propose de les révoquer.
type authPasswordResponse struct {
	authResponse
	APITokens int `json:"api_tokens"`
}

// Le corps d'une action qui n'a rien à dire : {} ou rien.
type emptyRequest struct{}

// authViewer dit qui lit l'état d'accès : l'identité transmise par le
// mandataire (forward), ou la session native de la requête.
type authViewer struct {
	identity string
	session  string
}

// viewerOf lit l'identité et la session que la garde a posées sur la requête.
func viewerOf(r *http.Request) authViewer {
	session, _ := sessionFrom(r.Context())
	return authViewer{identity: identityFrom(r.Context()), session: session.ID}
}

// authToJSON ne dit le compte qu'à qui a une session : la page de connexion ne
// le donne pas à qui atteint le port.
func authToJSON(state auth.State, viewer authViewer) authResponse {
	response := authResponse{Mode: string(state.Mode), PasswordMinLength: auth.MinPasswordLength}
	switch state.Mode {
	case auth.ModeNative:
		if viewer.session == "" {
			return response
		}
		response.SignedIn = true
		response.Session = viewer.session
		response.Username = state.Username
		response.EnabledAt = httpx.TimeOrNil(state.EnabledAt)
	case auth.ModeForward:
		response.SignedIn = true
		response.Username = viewer.identity
		response.Header = state.Header
		response.EnabledAt = httpx.TimeOrNil(state.EnabledAt)
	}
	return response
}

func (s *Server) getAuth(w http.ResponseWriter, r *http.Request) {
	state, err := s.auth.State(r.Context())
	if err != nil {
		s.apiInternalError(w, r, err)
		return
	}
	response := s.authJSON(state, viewerOf(r))
	response.ForwardInsecure = state.Mode == auth.ModeForward && s.forwardSecretRequired()
	s.writeAPI(w, http.StatusOK, response)
}

// authJSON ajoute à authToJSON ce que seul le serveur sait : la liste blanche
// de config.toml, qui ne vaut qu'en forward.
func (s *Server) authJSON(state auth.State, viewer authViewer) authResponse {
	response := authToJSON(state, viewer)
	if state.Mode == auth.ModeForward {
		response.AllowedUsers = s.allowedUsers()
	}
	return response
}

// allowedUsers rend la liste blanche triée, ou nil quand elle est vide : le
// JSON dit alors null, « toute identité du mandataire ».
func (s *Server) allowedUsers() []string {
	if len(s.forwardUsers) == 0 {
		return nil
	}
	users := make([]string, 0, len(s.forwardUsers))
	for user := range s.forwardUsers {
		users = append(users, user)
	}
	slices.Sort(users)
	return users
}

// setupAuth crée le compte de la première configuration, ou fait confiance au
// mandataire ; en native, elle ouvre la première session.
func (s *Server) setupAuth(w http.ResponseWriter, r *http.Request) {
	var request authSetupRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	// Le changement d'état et la révocation forment un seul pas pour les
	// écritures qui accordent une autorité : voir grantsAuthority.
	s.authTransition.Lock()
	defer s.authTransition.Unlock()
	state, viewer, ok := s.setupMode(w, r, request)
	if !ok {
		return
	}
	// Un jeton d'API tiré sous un accès d'avant (laissé par la commande de
	// secours) ne survit pas à la première configuration. Après elle, et non
	// avant, pour qu'un jeton créé entre les deux tombe aussi.
	revoked, err := s.apiTokens.RevokeAll(r.Context())
	if err != nil {
		s.apiInternalError(w, r, err)
		return
	}
	s.writeAPI(w, http.StatusOK, authSetupResponse{
		authResponse:     s.authJSON(state, viewer),
		APITokensRevoked: revoked,
	})
}

// setupMode pose le mode demandé et rend qui lira la réponse ; il répond
// lui-même quand il refuse.
func (s *Server) setupMode(w http.ResponseWriter, r *http.Request, request authSetupRequest) (auth.State, authViewer, bool) {
	switch auth.Mode(request.Mode) {
	case "", auth.ModeNative:
		return s.setupNative(w, r, request)
	case auth.ModeForward:
		state, identity, ok := s.enableForward(w, r, request.SetupCode, request.Header)
		return state, authViewer{identity: identity}, ok
	default:
		s.apiRefuse(w, http.StatusUnprocessableEntity, "auth.mode_invalid")
		return auth.State{}, authViewer{}, false
	}
}

// setupNative refuse avant de juger le code quand aucune session ne pourrait
// s'ouvrir (R-A2-4) : le compte créé resterait sans personne pour s'y
// connecter, et le code serait usé pour rien.
func (s *Server) setupNative(w http.ResponseWriter, r *http.Request, request authSetupRequest) (auth.State, authViewer, bool) {
	cookieName, ok := s.sessionCookieName(r)
	if !ok {
		s.apiRefuse(w, http.StatusForbidden, codeHTTPSRequired)
		return auth.State{}, authViewer{}, false
	}
	authorizing, _ := authorizingStateFrom(r.Context())
	state, opened, err := s.auth.SetupNative(r.Context(), authorizing, request.SetupCode, request.Username, request.Password, sessionClientOf(r, s.clientAddress(r)))
	if s.failed(w, r, err, nil) {
		return auth.State{}, authViewer{}, false
	}
	setSessionCookie(w, cookieName, opened.Token)
	return state, authViewer{session: opened.ID}, true
}

// enableForward refuse d'activer depuis une requête qui ne porte pas déjà
// l'identité d'un mandataire de confiance : sitôt le mode posé, tout le
// reste répond 401, et l'opérateur se serait fermé la porte.
func (s *Server) enableForward(w http.ResponseWriter, r *http.Request, setupCode, header string) (auth.State, string, bool) {
	if header == "" {
		header = auth.DefaultForwardHeader
	}
	err := auth.ValidateHeader(header)
	if s.failed(w, r, err, nil) {
		return auth.State{}, "", false
	}
	// Avant l'identité : sans secret, aucun en-tête reçu de la boucle locale
	// ne prouve rien, et l'opérateur doit savoir quoi poser, pas seulement
	// que l'en-tête manque.
	if s.forwardSecretRequired() {
		s.apiRefuse(w, http.StatusUnprocessableEntity, "auth.forward_secret_required")
		return auth.State{}, "", false
	}
	identity := s.trustedIdentity(r, header)
	if identity == "" {
		s.apiRefuse(w, http.StatusUnprocessableEntity, "auth.forward_header_missing")
		return auth.State{}, "", false
	}
	// Même garde-fou que l'en-tête : une identité que la liste refuserait
	// aussitôt se fermerait la porte en activant.
	if !s.admitsForwardUser(identity) {
		s.apiRefuse(w, http.StatusUnprocessableEntity, "auth.forward_user_not_listed")
		return auth.State{}, "", false
	}
	authorizing, _ := authorizingStateFrom(r.Context())
	state, err := s.auth.EnableForward(r.Context(), authorizing, setupCode, header)
	if s.failed(w, r, err, nil) {
		return auth.State{}, "", false
	}
	return state, identity, true
}

// login ouvre une session neuve, jamais reprise d'un cookie présenté (W-F1) :
// la session que la requête portait, s'il y en avait une, est fermée.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var request authLoginRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	cookieName, ok := s.sessionCookieName(r)
	if !ok {
		s.apiRefuse(w, http.StatusForbidden, codeHTTPSRequired)
		return
	}
	source := s.clientAddress(r)
	if !s.authLimit.Allow(source) {
		s.logger.Warn("interface sign-in rate limited", "source", source)
		httpx.WriteTooMany(w)
		return
	}
	authorizing, _ := authorizingStateFrom(r.Context())
	opened, err := s.auth.Login(r.Context(), authorizing, request.Username, request.Password, sessionClientOf(r, source))
	switch {
	case errors.Is(err, auth.ErrLoginFailed):
		s.logger.Warn("interface sign-in failed", "source", source)
		key, _ := refusal.KeyOf(err)
		s.apiRefuse(w, http.StatusUnauthorized, key)
		return
	case errors.Is(err, auth.ErrVerificationQueueFull):
		// Même réponse que le limiteur : l'attente de bcrypt est bornée, et
		// l'opérateur qui retombe là réessaie après Retry-After.
		s.logger.Warn("interface sign-in queue full", "source", source)
		httpx.WriteTooMany(w)
		return
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// La requête a pris fin pendant l'attente : ce n'est pas un mauvais
		// mot de passe, et personne ne lira la réponse.
		http.Error(w, "request canceled", http.StatusServiceUnavailable)
		return
	case s.failed(w, r, err, nil):
		return
	}
	if !s.closePresentedSession(w, r) {
		return
	}
	setSessionCookie(w, cookieName, opened.Token)
	s.writeAPI(w, http.StatusOK, s.authJSON(authorizing, authViewer{session: opened.ID}))
}

// logout ferme la session de la requête et efface le cookie ; sans session,
// il n'efface que le cookie.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 {
		var request emptyRequest
		if !s.readAPI(w, r, &request) {
			return
		}
	}
	if !s.closePresentedSession(w, r) {
		return
	}
	clearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

// closePresentedSession ferme la session que la garde a reconnue sur la
// requête. Il répond lui-même quand il échoue.
func (s *Server) closePresentedSession(w http.ResponseWriter, r *http.Request) bool {
	presented, found := sessionFrom(r.Context())
	if !found {
		return true
	}
	err := s.auth.CloseSession(r.Context(), presented.ID)
	if err != nil && !errors.Is(err, auth.ErrSessionNotFound) {
		s.apiInternalError(w, r, err)
		return false
	}
	return true
}

// sessionClientOf dit d'où vient la requête qui ouvre une session.
func sessionClientOf(r *http.Request, source string) auth.SessionClient {
	return auth.SessionClient{Address: source, UserAgent: r.UserAgent()}
}

type operatorSessionJSON struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	SeenAt    time.Time `json:"seen_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Source    string    `json:"source"`
	UserAgent string    `json:"user_agent"`
	// Celle de la requête : l'écran la marque et ne propose pas de la fermer.
	Current bool `json:"current"`
}

type operatorSessionsResponse struct {
	Sessions []operatorSessionJSON `json:"sessions"`
}

func (s *Server) listOperatorSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.auth.Sessions(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	current, _ := sessionFrom(r.Context())
	response := operatorSessionsResponse{Sessions: httpx.ConvertAll(sessions, func(session auth.Session) operatorSessionJSON {
		return operatorSessionJSON{
			ID:        session.ID,
			CreatedAt: session.CreatedAt.UTC(),
			SeenAt:    session.SeenAt.UTC(),
			ExpiresAt: session.ExpiresAt.UTC(),
			Source:    session.Source,
			UserAgent: session.UserAgent,
			Current:   session.ID == current.ID,
		}
	})}
	s.writeAPI(w, http.StatusOK, response)
}

// closeOperatorSession ferme une session de la liste ; la sienne propre
// efface aussi le cookie, comme la déconnexion.
func (s *Server) closeOperatorSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.auth.CloseSession(r.Context(), id)
	if current, found := sessionFrom(r.Context()); err == nil && found && current.ID == id {
		clearSessionCookies(w)
	}
	s.finishAPIAction(w, r, err, auth.ErrSessionNotFound)
}

type closedSessionsResponse struct {
	Closed int `json:"closed"`
}

// closeOtherSessions garde la session de la requête et ferme toutes les autres.
func (s *Server) closeOtherSessions(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 {
		var request emptyRequest
		if !s.readAPI(w, r, &request) {
			return
		}
	}
	current, _ := sessionFrom(r.Context())
	closed, err := s.auth.CloseOtherSessions(r.Context(), current.ID)
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, closedSessionsResponse{Closed: closed})
}

func (s *Server) changeAuthPassword(w http.ResponseWriter, r *http.Request) {
	var request authPasswordRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	// Le mot de passe actuel faux compte comme un échec de connexion : sans
	// ce frein, la route serait un oracle de mot de passe.
	source := s.clientAddress(r)
	if !s.authLimit.Allow(source) {
		s.logger.Warn("interface password change rate limited", "source", source)
		httpx.WriteTooMany(w)
		return
	}
	authorizing, _ := authorizingStateFrom(r.Context())
	current, _ := sessionFrom(r.Context())
	state, err := s.auth.ChangePassword(r.Context(), authorizing, current.ID, request.Current, request.Password)
	switch {
	case errors.Is(err, auth.ErrCurrentPasswordWrong):
		s.logger.Warn("interface password change refused: current password wrong", "source", source)
		key, _ := refusal.KeyOf(err)
		s.apiRefuse(w, http.StatusForbidden, key)
		return
	case errors.Is(err, auth.ErrVerificationQueueFull):
		s.logger.Warn("interface password change queue full", "source", source)
		httpx.WriteTooMany(w)
		return
	case s.failed(w, r, err, nil):
		return
	}
	tokens, err := s.apiTokens.List(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, authPasswordResponse{authResponse: authToJSON(state, viewerOf(r)), APITokens: len(tokens)})
}

func (s *Server) disableAuth(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 {
		var request emptyRequest
		if !s.readAPI(w, r, &request) {
			return
		}
	}
	authorizing, _ := authorizingStateFrom(r.Context())
	if s.failed(w, r, s.auth.Disable(r.Context(), authorizing), nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, authToJSON(auth.State{Mode: auth.ModeNone}, authViewer{}))
}

type setupCodeResponse struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// issueSetupCode tire le code de première configuration. Il ne se sert que
// par la socket locale (controlMux) : la page ne peut pas le demander, sans
// quoi le code ne prouverait rien.
func (s *Server) issueSetupCode(w http.ResponseWriter, r *http.Request) {
	issued, err := s.auth.IssueSetupCode(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusCreated, setupCodeResponse{Code: issued.Code, ExpiresAt: issued.ExpiresAt})
}
