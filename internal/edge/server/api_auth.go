package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"rsc.io/qr"

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
	// En native, présent et vrai quand le code à six chiffres est actif, dit
	// par GET /api/auth à qui a une session : la redemande le demande aussi.
	TOTP bool `json:"totp,omitempty"`
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

// Code est le code à six chiffres, vide au premier écran : le serveur le
// demande (auth.totp_required) quand il est actif.
type authLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code"`
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

// readEmptyBody accepte un corps absent ou {} ; tout autre corps est refusé
// (400), et le handler n'a plus qu'à rendre la main.
func (s *Server) readEmptyBody(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength == 0 {
		return true
	}
	var request emptyRequest
	return s.readAPI(w, r, &request)
}

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
	if state.Mode == auth.ModeNative && response.SignedIn {
		response.TOTP, err = s.auth.TOTPActive(r.Context())
		if err != nil {
			s.apiInternalError(w, r, err)
			return
		}
	}
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
	// Un jeton d'API tiré sous un accès d'avant (une base reprise d'une
	// autre installation) ne survit pas à la première configuration. Après elle, et non
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
		s.failed(w, r, auth.ErrModeInvalid, nil)
		return auth.State{}, authViewer{}, false
	}
}

// setupNative refuse avant de juger le code quand aucune session ne pourrait
// s'ouvrir (R-A2-4) : le compte créé resterait sans personne pour s'y
// connecter, et le code serait usé pour rien.
func (s *Server) setupNative(w http.ResponseWriter, r *http.Request, request authSetupRequest) (auth.State, authViewer, bool) {
	cookie, ok := s.sessionCookieKind(r)
	if !ok {
		s.apiRefuse(w, http.StatusForbidden, codeHTTPSRequired)
		return auth.State{}, authViewer{}, false
	}
	authorizing, _ := authorizingStateFrom(r.Context())
	state, opened, err := s.auth.SetupNative(r.Context(), authorizing, request.SetupCode, request.Username, request.Password, sessionClientOf(r, s.clientAddress(r), cookie))
	if s.failed(w, r, err, nil) {
		return auth.State{}, authViewer{}, false
	}
	setSessionCookie(w, cookie, opened.Token)
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
	cookie, ok := s.sessionCookieKind(r)
	if !ok {
		s.apiRefuse(w, http.StatusForbidden, codeHTTPSRequired)
		return
	}
	if !s.allowPasswordAttempt(w, r, "interface sign-in rate limited") {
		return
	}
	source := s.clientAddress(r)
	authorizing, _ := authorizingStateFrom(r.Context())
	opened, err := s.auth.Login(r.Context(), authorizing, request.Username, request.Password, request.Code, sessionClientOf(r, source, cookie))
	switch {
	case errors.Is(err, auth.ErrLoginFailed), errors.Is(err, auth.ErrTOTPRequired), errors.Is(err, auth.ErrTOTPWrong):
		s.logger.Warn("interface sign-in failed", "source", source, "error", err)
		key, _ := refusal.KeyOf(err)
		s.apiRefuse(w, http.StatusUnauthorized, key)
		return
	case s.answeredAccountRefusal(w, err, http.StatusUnauthorized):
		s.logger.Warn("interface sign-in refused by the account", "source", source, "error", err)
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
	setSessionCookie(w, cookie, opened.Token)
	s.writeAPI(w, http.StatusOK, s.authJSON(authorizing, authViewer{session: opened.ID}))
}

// logout ferme la session de la requête et efface le cookie ; sans session,
// il n'efface que le cookie.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.readEmptyBody(w, r) {
		return
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

// sessionClientOf dit d'où vient la requête qui ouvre une session, et sous
// quel cookie elle la portera.
func sessionClientOf(r *http.Request, source string, cookie auth.CookieKind) auth.SessionClient {
	return auth.SessionClient{Address: source, UserAgent: r.UserAgent(), Cookie: cookie}
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
	if !s.readEmptyBody(w, r) {
		return
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
	if !s.allowPasswordAttempt(w, r, "interface password change rate limited") {
		return
	}
	authorizing, _ := authorizingStateFrom(r.Context())
	current, _ := sessionFrom(r.Context())
	state, err := s.auth.ChangePassword(r.Context(), authorizing, current.ID, request.Current, request.Password)
	if !s.passwordAccepted(w, r, err) {
		return
	}
	tokens, err := s.apiTokens.List(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, authPasswordResponse{authResponse: authToJSON(state, viewerOf(r)), APITokens: len(tokens)})
}

// La redemande d'un geste de niveau 4 : le mot de passe, et le code s'il est
// actif.
type reauthRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// reauth pose reauth_at sur la session de la requête (R-A2-7) et lui donne un
// jeton neuf, dans un cookie neuf (R-A2-3). Le mot de passe faux compte comme
// un échec de connexion, comme au changement de mot de passe.
func (s *Server) reauth(w http.ResponseWriter, r *http.Request) {
	var request reauthRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	cookie, ok := s.sessionCookieKind(r)
	if !ok {
		s.apiRefuse(w, http.StatusForbidden, codeHTTPSRequired)
		return
	}
	if !s.allowPasswordAttempt(w, r, "interface re-authentication rate limited") {
		return
	}
	authorizing, _ := authorizingStateFrom(r.Context())
	current, _ := sessionFrom(r.Context())
	token, err := s.auth.Reauth(r.Context(), authorizing, current.ID, s.clientAddress(r), request.Password, request.Code)
	if !s.passwordAccepted(w, r, err) {
		return
	}
	setSessionCookie(w, cookie, token)
	w.WriteHeader(http.StatusNoContent)
}

type totpProposalResponse struct {
	// Le secret en base 32, à saisir à la main si le QR code ne se lit pas.
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	// L'image du QR code de URI, en data URI PNG : l'écran l'affiche telle quelle.
	QRCode string `json:"qr_code"`
}

// proposeTOTP tire un secret à scanner ; rien n'est gardé tant que le premier
// code juste ne revient pas par enableTOTP.
func (s *Server) proposeTOTP(w http.ResponseWriter, r *http.Request) {
	authorizing, _ := authorizingStateFrom(r.Context())
	proposal, err := s.auth.ProposeTOTP(r.Context(), authorizing)
	if s.failed(w, r, err, nil) {
		return
	}
	image, err := qrCodeDataURI(proposal.URI)
	if err != nil {
		s.apiInternalError(w, r, err)
		return
	}
	s.writeAPI(w, http.StatusOK, totpProposalResponse{Secret: proposal.Secret, URI: proposal.URI, QRCode: image})
}

// qrCodeDataURI dessine le QR code du texte, en PNG, bordure comprise.
func qrCodeDataURI(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", fmt.Errorf("encode qr code: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()), nil
}

// Le secret proposé et un premier code de l'application.
type totpEnableRequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

func (s *Server) enableTOTP(w http.ResponseWriter, r *http.Request) {
	var request totpEnableRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	authorizing, _ := authorizingStateFrom(r.Context())
	err := s.auth.EnableTOTP(r.Context(), authorizing, request.Secret, request.Code)
	s.finishAPIAction(w, r, err, nil)
}

type totpDisableRequest struct {
	Password string `json:"password"`
}

// disableTOTP retire le code, sur le mot de passe ; un mot de passe faux
// compte comme un échec de connexion.
func (s *Server) disableTOTP(w http.ResponseWriter, r *http.Request) {
	var request totpDisableRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	if !s.allowPasswordAttempt(w, r, "interface code removal rate limited") {
		return
	}
	authorizing, _ := authorizingStateFrom(r.Context())
	err := s.auth.DisableTOTP(r.Context(), authorizing, request.Password)
	if !s.passwordAccepted(w, r, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// allowPasswordAttempt passe la requête au limiteur de la connexion : sans
// ce frein, une route qui juge le mot de passe serait un oracle. Il répond
// lui-même 429.
func (s *Server) allowPasswordAttempt(w http.ResponseWriter, r *http.Request, limitedMessage string) bool {
	source := s.clientAddress(r)
	if !s.authLimit.Allow(source) {
		s.logger.Warn(limitedMessage, "source", source)
		httpx.WriteTooMany(w)
		return false
	}
	return true
}

// passwordAccepted répond à l'échec d'une route qui redemande le mot de passe
// (et le code) à la personne connectée : 403 avec la clé, 429 si la file
// bcrypt est pleine. Il dit si la route peut continuer.
func (s *Server) passwordAccepted(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, auth.ErrCurrentPasswordWrong), errors.Is(err, auth.ErrTOTPRequired), errors.Is(err, auth.ErrTOTPWrong):
		s.logger.Warn("interface password asked again: refused", "source", s.clientAddress(r), "error", err)
		key, _ := refusal.KeyOf(err)
		s.apiRefuse(w, http.StatusForbidden, key)
	case s.answeredAccountRefusal(w, err, http.StatusForbidden):
		s.logger.Warn("interface password asked again: refused by the account", "source", s.clientAddress(r), "error", err)
	case errors.Is(err, auth.ErrVerificationQueueFull):
		s.logger.Warn("interface verification queue full", "source", s.clientAddress(r))
		httpx.WriteTooMany(w)
	default:
		s.failed(w, r, err, nil)
	}
	return false
}

// answeredAccountRefusal répond au refus que le compte oppose (R-A2-16) et dit
// s'il l'a fait : le code suspendu, avec l'heure de sa fin, sous le statut que
// la route donne à un code faux ; le compte ralenti, en 429, quelle que soit
// la route.
func (s *Server) answeredAccountRefusal(w http.ResponseWriter, err error, lockedStatus int) bool {
	switch {
	case errors.Is(err, auth.ErrTOTPLocked):
		key, _ := refusal.KeyOf(err)
		refused := apiError{Error: key}
		var locked *auth.TOTPLockedError
		if errors.As(err, &locked) {
			refused.Until = locked.Until.UTC()
		}
		s.writeAPI(w, lockedStatus, refused)
	case errors.Is(err, auth.ErrAccountSlowed):
		key, _ := refusal.KeyOf(err)
		s.writeAPIError(w, http.StatusTooManyRequests, key)
	default:
		return false
	}
	return true
}

// unlockAccount remet à zéro les échecs du compte, le code suspendu comme le
// compte ralenti : root, par la socket seulement (R-A2-16).
func (s *Server) unlockAccount(w http.ResponseWriter, r *http.Request) {
	if !s.readEmptyBody(w, r) {
		return
	}
	s.finishAPIAction(w, r, s.auth.Unlock(r.Context()), nil)
}

// resetTOTP retire le code sans rien demander : root, par la socket seulement
// (R-CNX-4). Pas de codes de secours : c'est le secours.
func (s *Server) resetTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.readEmptyBody(w, r) {
		return
	}
	s.finishAPIAction(w, r, s.auth.ResetTOTP(r.Context()), nil)
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

// Le nouveau mot de passe, que la commande a demandé deux fois.
type resetPasswordRequest struct {
	Password string `json:"password"`
}

// resetPassword refait le mot de passe et ferme toutes les sessions : root,
// par la socket seulement (R-A2-10, R-CNX-4).
func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	var request resetPasswordRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	closed, err := s.auth.ResetPassword(r.Context(), request.Password)
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, closedSessionsResponse{Closed: closed})
}

// Mode vaut native ou forward. Username et Password ne servent qu'en native,
// Header qu'en forward.
type authModeRequest struct {
	Mode     string `json:"mode"`
	Header   string `json:"header"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type authModeResponse struct {
	Mode     string `json:"mode"`
	Username string `json:"username,omitempty"`
	Header   string `json:"header,omitempty"`
	Closed   int    `json:"closed"`
}

// setAuthMode change le mode d'accès d'une installation configurée : root,
// par la socket seulement. Elle ne ramène jamais à la première configuration.
func (s *Server) setAuthMode(w http.ResponseWriter, r *http.Request) {
	var request authModeRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	state, closed, err := s.auth.SetMode(r.Context(), auth.ModeChange{
		Mode: auth.Mode(request.Mode), Header: request.Header, Username: request.Username, Password: request.Password,
	})
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, authModeResponse{Mode: string(state.Mode), Username: state.Username, Header: state.Header, Closed: closed})
}

// closeAllSessions ferme toutes les sessions : root, par la socket seulement.
func (s *Server) closeAllSessions(w http.ResponseWriter, r *http.Request) {
	if !s.readEmptyBody(w, r) {
		return
	}
	closed, err := s.auth.CloseAllSessions(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, closedSessionsResponse{Closed: closed})
}
