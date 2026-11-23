package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/server/httpx"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// L'accès de l'opérateur à l'interface. En mode native, une session (le
// cookie que pose la connexion, session_cookie.go) garde tout ce que
// l'opérateur appelle : l'API, le direct et les flux de journaux ; sans elle,
// seules les routes qui servent à se connecter passent. En mode forward, les
// mêmes routes exigent, à chaque requête, l'en-tête d'identité posé par un
// mandataire de trusted_proxies ; la session qui s'y ajoute lie flux et audit,
// sans jamais remplacer l'en-tête (R-A2-17). En mode none, l'installation attend sa première
// configuration : seules les routes qui servent à créer le compte passent, et
// la création exige le code que `admin setup-code` tire par la socket locale.
// Un en-tête Authorization: Basic n'est lu par aucun mode (R-CNX-1).
// Un jeton d'API (Authorization: Bearer) remplace l'un et l'autre, sur une
// liste fermée de lectures (apiTokenRoutes) : voir admitAPIToken.
// Restent ouverts ceux qui ont leur propre preuve ou n'en ont pas
// besoin : l'agent (sa clé), les pings (le jeton dans l'URL) et la page de
// statut (publique).

const (
	codeUnauthorized = "unauthorized"
	// Une vérification lente coûte ~100 ms : dix d'un coup, puis une toutes
	// les six secondes par adresse. Seules la connexion et le changement de
	// mot de passe en paient une.
	authAttemptRate  = 1.0 / 6
	authAttemptBurst = 10
	authIdle         = 30 * time.Minute
)

// Ce que le serveur attend du composant auth.
type AuthService interface {
	State(ctx context.Context) (auth.State, error)
	SetupNative(ctx context.Context, expected auth.State, setupCode, username, password string, client auth.SessionClient) (auth.State, auth.OpenedSession, error)
	EnableForward(ctx context.Context, expected auth.State, setupCode, header string) (auth.State, error)
	IssueSetupCode(ctx context.Context) (auth.IssuedSetupCode, error)
	Login(ctx context.Context, expected auth.State, username, password, code string, client auth.SessionClient) (auth.OpenedSession, error)
	ResumeSession(ctx context.Context, state auth.State, token string) (auth.Session, bool, error)
	OpenForwardSession(ctx context.Context, expected auth.State, identity string, client auth.SessionClient) (auth.OpenedSession, error)
	ResumeForwardSession(ctx context.Context, state auth.State, token, identity string) (auth.Session, bool, error)
	ClosePresentedSession(ctx context.Context, token string) error
	SessionAlive(ctx context.Context, id string) (bool, error)
	WatchSession(ctx context.Context, id string) (<-chan struct{}, func(), error)
	Sessions(ctx context.Context) ([]auth.Session, error)
	CloseSession(ctx context.Context, id string) error
	CloseOtherSessions(ctx context.Context, keepID string) (int, error)
	ChangePassword(ctx context.Context, expected auth.State, keepSession, currentPassword, password string) (auth.State, error)
	ResetPassword(ctx context.Context, password string) (int, error)
	SetMode(ctx context.Context, change auth.ModeChange) (auth.State, int, error)
	CloseAllSessions(ctx context.Context) (int, error)
	TOTPActive(ctx context.Context) (bool, error)
	ProposeTOTP(ctx context.Context, state auth.State) (auth.TOTPProposal, error)
	EnableTOTP(ctx context.Context, expected auth.State, secret, code string) error
	DisableTOTP(ctx context.Context, expected auth.State, password string) error
	ResetTOTP(ctx context.Context) error
	Unlock(ctx context.Context) error
	Reauth(ctx context.Context, expected auth.State, sessionID, source, password, code string) (string, error)
	RequireFreshReauth(state auth.State, session auth.Session) error
}

// codeAuthStateChanged est le refus d'une écriture autorisée sous un état
// d'authentification qui n'est plus le bon.
const codeAuthStateChanged = "auth.state_changed"

// codeSetupRequired est le refus de toute route de l'opérateur tant que le
// compte n'est pas créé : le front y reconnaît l'écran de première
// configuration.
const codeSetupRequired = "auth.setup_required"

// codeForwardForbidden est le refus d'une identité du mandataire absente de
// forward_users. Son texte ne nomme pas l'identité : le front qui le lit ne
// la connaît pas. La page, elle, la nomme (forwardForbiddenPage).
const codeForwardForbidden = "auth.forward_forbidden"

// forwardForbiddenPage est le texte du même refus pour une page, qui dit
// l'identité reçue (%s).
const forwardForbiddenPage = "auth.forward_forbidden_identity"

// Les routes de l'opérateur servies sans session, à qui atteint le port,
// tant qu'aucun compte n'existe (mode none) ou que personne n'est connecté
// (mode native) : le front, sa session et ses catalogues pour s'afficher dans
// la langue réglée, l'état de l'accès, la création du compte, la connexion
// et la déconnexion. Chacune refuse elle-même ce qui ne vaut pas dans le mode
// du moment. Tout le reste attend : un avertissement n'est pas un contrôle.
var beforeSignInRoutes = []string{
	"GET /api/session",
	"GET /api/i18n/{code}",
	"GET /api/auth",
	"POST /api/auth/setup",
	"POST /api/auth/login",
	"POST /api/auth/logout",
	anyMethod + " /",
}

// isBeforeSignInRoute dit si la route est servie sans session.
func isBeforeSignInRoute(method, pattern string) bool {
	return slices.Contains(beforeSignInRoutes, method+" "+pattern)
}

// Les préfixes qui ne passent jamais par l'authentification de
// l'opérateur. Tout le reste, fourre-tout du front compris, y passe.
var openRoutePrefixes = []string{"/agent/", "/ping/", "/statut"}

// isOperatorRoute dit si le motif de route est réservé à l'opérateur. Le
// jugement porte sur le motif enregistré, pas sur le chemin reçu : un
// chemin détourné (/ping/../api) est d'abord nettoyé par le mux.
func isOperatorRoute(pattern string) bool {
	for _, prefix := range openRoutePrefixes {
		if strings.HasPrefix(pattern, prefix) {
			return false
		}
	}
	return true
}

// requireOperator relit le mode à chaque requête : root le change par le
// canal local (`admin auth-mode`, `admin reset-password`), et la requête
// suivante suit le nouvel état sans redémarrer.
// beforeSignIn dit si la route est servie sans session, access ce qu'un jeton
// d'API en obtient.
func (s *Server) requireOperator(next http.HandlerFunc, beforeSignIn bool, access tokenAccess) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := s.auth.State(r.Context())
		if err != nil {
			s.apiInternalError(w, r, err)
			return
		}
		// Un Bearer est jugé avant le mode : en native comme en forward, il
		// passe par le jeton, ni par la session ni par l'en-tête du mandataire.
		// En none, il est ignoré : la première configuration seule est servie.
		if bearer, presented := bearerOf(r); presented && state.Mode != auth.ModeNone {
			s.admitAPIToken(w, r, bearer, access, next)
			return
		}
		switch state.Mode {
		case auth.ModeNone:
			if !beforeSignIn {
				s.writeSetupRequired(w, r)
				return
			}
			s.admitOperator(w, r, state, next)
		case auth.ModeNative:
			s.admitSession(w, r, state, beforeSignIn, next)
		case auth.ModeForward:
			s.admitForward(w, r, state, next)
		default:
			// Un mode inconnu dans la base : fermer plutôt que deviner.
			s.logger.Error("interface authentication mode not supported", "mode", string(state.Mode))
			http.Error(w, "authentication mode not supported", http.StatusServiceUnavailable)
		}
	}
}

// admitOperator laisse passer une requête admise sous state, et pose cet
// état dans son contexte : les écritures qui accordent une autorité et les
// flux s'y comparent à l'état du moment.
//
// Un client peut retenir le corps d'une écriture jusqu'à l'échéance de
// lecture (boundRequestRead) : un jugement rendu à l'arrivée des en-têtes vaudrait
// encore une fois l'authentification activée. Le corps est donc lu en entier,
// puis l'état relu ; s'il a changé entre-temps, 409. La lecture vient après
// le jugement, et non avant, pour qu'un anonyme face à une interface gardée
// reçoive son 401 sans faire tenir un Mio par connexion au serveur.
func (s *Server) admitOperator(w http.ResponseWriter, r *http.Request, state auth.State, next http.HandlerFunc) {
	if readWholeBody(w, r) {
		current, err := s.auth.State(r.Context())
		if err != nil {
			s.apiInternalError(w, r, err)
			return
		}
		if !current.Same(state) {
			s.apiRefuse(w, http.StatusConflict, codeAuthStateChanged)
			return
		}
	}
	next(w, r.WithContext(context.WithValue(r.Context(), authorizingStateKey{}, state)))
}

// readWholeBody lit le corps d'une écriture, le remet à la disposition du
// handler et dit s'il y en avait un. La borne est celle de limitBody, la plus
// large des routes : les bornes plus serrées de chaque handler (readAPI)
// jouent ensuite sur la copie. Un corps trop gros ou illisible n'est pas jugé
// ici : l'erreur est rendue au handler à la fin de ce qui a été lu, et la
// réponse reste la sienne (400 pour readAPI, 422 pour un fichier d'annuaire).
func readWholeBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Body == nil || r.Body == http.NoBody {
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), failingReader{err: err}))
		return true
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return true
}

// failingReader rend toujours la même erreur.
type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) {
	return 0, f.err
}

// authorizingStateKey porte, dans le contexte de la requête, l'état
// d'authentification sous lequel requireOperator l'a laissée passer.
type authorizingStateKey struct{}

// authorizingStateFrom rend cet état. Une route ouverte n'en a pas : l'état
// nul, qui n'égale aucun état stocké.
func authorizingStateFrom(ctx context.Context) (auth.State, bool) {
	state, ok := ctx.Value(authorizingStateKey{}).(auth.State)
	return state, ok
}

// grantsAuthority garde une écriture qui accorde une autorité durable (un
// jeton d'API, un jeton d'enrôlement) : si
// l'état d'authentification n'est plus celui qui a admis la requête, 409.
//
// L'activation révoque après avoir changé l'état : sans verrou, une écriture
// qui a vu l'ancien état pourrait se glisser entre les deux, par exemple en
// attendant le verrou de la base pendant que l'activation écrit, et survivre
// à la révocation. Sous authTransition, elle s'écrit soit avant l'activation,
// et la révocation l'emporte, soit après, et elle voit le nouvel état. Le
// corps est déjà lu (admitOperator) : un client lent ne tient pas le verrou.
func (s *Server) grantsAuthority(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.authTransition.RLock()
		defer s.authTransition.RUnlock()
		current, err := s.auth.State(r.Context())
		if err != nil {
			s.apiInternalError(w, r, err)
			return
		}
		authorizing, _ := authorizingStateFrom(r.Context())
		if !current.Same(authorizing) {
			s.apiRefuse(w, http.StatusConflict, codeAuthStateChanged)
			return
		}
		next(w, r)
	}
}

// requireFreshReauth garde un geste de niveau 4 (R-A2-7, R-A2-8) : en native,
// la session qui l'a admis doit avoir redonné son mot de passe depuis moins de
// cinq minutes, sinon 403 auth.reauth_required, et le front ouvre la fenêtre
// de redemande ; en forward, rien n'est redemandé. Le jugement est celui du
// composant (auth.RequireFreshReauth).
func (s *Server) requireFreshReauth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorizing, _ := authorizingStateFrom(r.Context())
		session, _ := sessionFrom(r.Context())
		if err := s.auth.RequireFreshReauth(authorizing, session); err != nil {
			key, _ := refusal.KeyOf(err)
			s.apiRefuse(w, http.StatusForbidden, key)
			return
		}
		next(w, r)
	}
}

// authorizationLapsed dit si un flux ouvert sur une route de l'opérateur ne
// doit plus continuer : l'état d'authentification n'est plus celui qui l'a
// autorisé, la session qui l'a ouvert est morte, ou l'un des deux n'a pas pu
// être relu. Un flux hors des routes de l'opérateur n'a rien à perdre. La
// mort d'une session ferme déjà ses flux (bindStreamToSession) ; ce jugement
// au ping voit en plus une session effacée par un autre processus.
func (s *Server) authorizationLapsed(r *http.Request) bool {
	authorizing, ok := authorizingStateFrom(r.Context())
	if !ok {
		return false
	}
	current, err := s.auth.State(r.Context())
	if err != nil || !current.Same(authorizing) {
		return true
	}
	session, found := sessionFrom(r.Context())
	if !found {
		return false
	}
	alive, err := s.auth.SessionAlive(r.Context(), session.ID)
	return err != nil || !alive
}

// bindStreamToSession rend la requête d'un flux dont le contexte prend fin
// avec la session qui l'a ouvert (R-A2-12) : déconnexion, échéance, mot de
// passe changé, autre identité. Le flux se ferme alors tout de suite, sans
// attendre son ping. stop se diffère au départ du flux. Sans session, ou en
// erreur, la requête est rendue telle quelle.
func (s *Server) bindStreamToSession(r *http.Request) (*http.Request, func(), error) {
	session, found := sessionFrom(r.Context())
	if !found {
		return r, func() {}, nil
	}
	ended, unwatch, err := s.auth.WatchSession(r.Context(), session.ID)
	if err != nil {
		return r, func() {}, err
	}
	ctx, cancel := context.WithCancel(r.Context())
	go func() {
		select {
		case <-ended:
			cancel()
		case <-ctx.Done():
		}
	}()
	stop := func() {
		cancel()
		unwatch()
	}
	return r.WithContext(ctx), stop, nil
}

// openCompiledAssets sert sans identifiants les fichiers du front compilé,
// hors index.html : la page de statut publique charge ses scripts, ses styles
// et ses polices par le même fourre-tout que l'interface, et un visiteur sans
// identifiants verrait une page vide. Ces fichiers sont le même code pour
// tous, embarqué dans le binaire : les données restent derrière /api. Seule
// la route du front est enveloppée : un fichier compilé n'ouvre aucune autre.
func (s *Server) openCompiledAssets(open, guarded http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.isCompiledAsset(r) {
			open(w, r)
			return
		}
		guarded(w, r)
	}
}

// isCompiledAsset juge le chemin encodé : un %2F n'est pas un séparateur, le
// nettoyer après décodage ferait passer /..%2Ftheme.js pour /theme.js.
func (s *Server) isCompiledAsset(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	name := strings.TrimPrefix(path.Clean(r.URL.EscapedPath()), "/")
	if name == legacyFavicon {
		name = brandFavicon
	}
	// Même règle que serveApp : une page HTML n'est jamais un fichier libre.
	return name != "" && path.Ext(name) != ".html" && s.isAppFile(name)
}

// refuseEncodedSlash ferme /api aux chemins qui cachent un séparateur : aucun
// identifiant de l'API n'en contient, et le mux les décode après avoir choisi
// la route. Il juge le chemin brut, comme isCompiledAsset, avant tout routage.
func (s *Server) refuseEncodedSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped := r.URL.EscapedPath()
		if strings.HasPrefix(escaped, "/api/") && strings.Contains(strings.ToLower(escaped), "%2f") {
			s.writeAPIError(w, http.StatusBadRequest, codeEncodedSlash)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// admitSession admet la requête que porte une session vivante, et la pose
// dans son contexte. Sans session, seules les routes d'avant la connexion
// passent ; les autres répondent 401.
func (s *Server) admitSession(w http.ResponseWriter, r *http.Request, state auth.State, beforeSignIn bool, next http.HandlerFunc) {
	session, signedIn, err := s.auth.ResumeSession(r.Context(), state, s.presentedSessionToken(r))
	if err != nil {
		s.apiInternalError(w, r, err)
		return
	}
	if !signedIn && !beforeSignIn {
		s.writeAPIError(w, http.StatusUnauthorized, codeUnauthorized)
		return
	}
	if signedIn {
		r = r.WithContext(context.WithValue(r.Context(), operatorSessionKey{}, session))
	}
	s.admitOperator(w, r, state, next)
}

// admitForward passe d'abord la garde du mandataire, à chaque requête, cookie
// ou non (R-A2-17) : un cookie volé, présenté sans le mandataire ni son
// secret, n'ouvre rien, et meurt. Ensuite seulement, la session est relue et
// comparée à l'identité de l'en-tête ; une autre identité la tue, 401. Sans
// session vivante, la requête admise en ouvre une.
func (s *Server) admitForward(w http.ResponseWriter, r *http.Request, state auth.State, next http.HandlerFunc) {
	identity, proven := s.checkForward(w, r, state)
	if !proven {
		// checkForward a répondu ; il reste à tuer le cookie présenté.
		if err := s.auth.ClosePresentedSession(r.Context(), s.presentedSessionToken(r)); err != nil {
			s.logger.Error("operator session not closed after a refused proxy proof", "error", err)
		}
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), forwardedIdentityKey{}, identity))
	session, resumed, err := s.auth.ResumeForwardSession(r.Context(), state, s.presentedSessionToken(r), identity)
	if errors.Is(err, auth.ErrSessionIdentityChanged) {
		clearSessionCookies(w)
		s.writeForwardUnauthorized(w, r)
		return
	}
	if err != nil {
		s.apiInternalError(w, r, err)
		return
	}
	if !resumed {
		session, resumed, err = s.openForwardSession(w, r, state, identity)
		if s.failed(w, r, err, nil) {
			return
		}
	}
	if resumed {
		r = r.WithContext(context.WithValue(r.Context(), operatorSessionKey{}, session))
	}
	s.admitOperator(w, r, state, next)
}

// openForwardSession ouvre la session d'une requête admise par le mandataire
// et pose son cookie. En HTTP clair hors de la boucle locale, aucune ne
// s'ouvre (R-A2-4) : la garde du mandataire suffit à la requête.
func (s *Server) openForwardSession(w http.ResponseWriter, r *http.Request, state auth.State, identity string) (auth.Session, bool, error) {
	cookieName, canOpen := s.sessionCookieName(r)
	if !canOpen {
		return auth.Session{}, false, nil
	}
	opened, err := s.auth.OpenForwardSession(r.Context(), state, identity, sessionClientOf(r, s.clientAddress(r)))
	if err != nil {
		return auth.Session{}, false, err
	}
	setSessionCookie(w, cookieName, opened.Token)
	return opened.Session, true, nil
}

// operatorSessionKey porte, dans le contexte de la requête, la session native
// qui l'a admise.
type operatorSessionKey struct{}

func sessionFrom(ctx context.Context) (auth.Session, bool) {
	session, ok := ctx.Value(operatorSessionKey{}).(auth.Session)
	return session, ok
}

// Le refus d'une installation sans compte : le front montre l'écran de
// première configuration. Hors /api, le texte dit d'ouvrir l'interface.
func (s *Server) writeSetupRequired(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.writeAPIError(w, http.StatusUnauthorized, codeSetupRequired)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	catalog := s.catalogs.For(browserLanguage(r))
	http.Error(w, catalog.Get(codeSetupRequired), http.StatusUnauthorized)
}

// forwardedIdentityKey porte, dans le contexte de la requête, l'identité
// que le mandataire a transmise : /api/auth la rend à la barre latérale.
type forwardedIdentityKey struct{}

func identityFrom(ctx context.Context) string {
	identity, _ := ctx.Value(forwardedIdentityKey{}).(string)
	return identity
}

// checkForward ne croit l'en-tête d'identité que d'un mandataire déclaré :
// de n'importe où ailleurs, un conteneur voisin pourrait l'écrire lui-même.
// Quand un secret est configuré, il faut en plus que la requête le porte :
// l'adresse d'un pair de boucle locale est celle de tous les processus de la
// machine, pas la preuve de passer par le mandataire.
// Il répond lui-même quand il refuse : 401 si le mandataire n'a rien prouvé,
// 403 si l'identité prouvée n'est pas dans forward_users.
func (s *Server) checkForward(w http.ResponseWriter, r *http.Request, state auth.State) (string, bool) {
	if !s.trustsPeer(r) {
		s.logger.Warn("interface authentication refused: peer is not a trusted proxy", "peer", httpx.PeerHost(r), "path", r.URL.Path)
		s.writeForwardUnauthorized(w, r)
		return "", false
	}
	if !s.hasProxySecret(r) {
		// La valeur reçue ne se journalise pas : un secret presque juste
		// resterait lisible dans le journal.
		s.logger.Warn("interface authentication refused: proxy secret missing or wrong, the request did not go through the proxy", "header", brand.ProxySecretHeader, "peer", httpx.PeerHost(r), "path", r.URL.Path)
		s.writeForwardUnauthorized(w, r)
		return "", false
	}
	if len(r.Header.Values(state.Header)) > 1 {
		s.logger.Warn("interface authentication refused: identity header sent more than once, the proxy must overwrite it", "header", state.Header, "source", s.clientAddress(r), "path", r.URL.Path)
		s.writeForwardUnauthorized(w, r)
		return "", false
	}
	identity := s.trustedIdentity(r, state.Header)
	if identity == "" {
		s.logger.Warn("interface authentication refused: identity header missing", "header", state.Header, "source", s.clientAddress(r), "path", r.URL.Path)
		s.writeForwardUnauthorized(w, r)
		return "", false
	}
	// Après le pair, le secret et l'en-tête : une requête qui échoue à l'un
	// d'eux reste un 401, et ne dit pas quelles identités sont admises.
	if !s.admitsForwardUser(identity) {
		s.logger.Warn("interface authentication refused: identity not in forward_users", "identity", printable(identity, auth.MaxUsernameLength), "peer", httpx.PeerHost(r), "path", r.URL.Path)
		s.writeForwardForbidden(w, r, identity)
		return "", false
	}
	return identity, true
}

// forwardUserSet range la liste blanche pour la recherche. Une entrée vide
// reste dans l'ensemble : elle ne correspond à aucune identité (celle-ci est
// non vide quand on la compare), et la liste ne devient jamais « vide » par
// erreur, ce qui ouvrirait la porte à tous.
func forwardUserSet(users []string) map[string]bool {
	set := make(map[string]bool, len(users))
	for _, user := range users {
		set[user] = true
	}
	return set
}

// admitsForwardUser : sans liste, tout le monde ; avec une liste, seulement
// ses entrées, comparées telles quelles, casse comprise.
func (s *Server) admitsForwardUser(identity string) bool {
	return len(s.forwardUsers) == 0 || s.forwardUsers[identity]
}

// trustedIdentity rend l'identité posée par un mandataire de confiance, ou
// rien si la requête ne vient pas de l'un d'eux, n'en prouve pas le passage
// ou ne la porte pas. Le secret a fini de servir : il est ôté de la requête
// pour qu'aucun gestionnaire ne le voie.
func (s *Server) trustedIdentity(r *http.Request, header string) string {
	if !s.trustsPeer(r) || !s.hasProxySecret(r) {
		return ""
	}
	r.Header.Del(brand.ProxySecretHeader)
	// Plusieurs valeurs : le mandataire a ajouté la sienne au lieu
	// d'écraser, et la première peut venir du client.
	values := r.Header.Values(header)
	if len(values) != 1 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

// forwardSecretRequired dit si le mode forward manque de preuve : aucun
// secret n'est configuré alors qu'un préfixe de confiance couvre la boucle
// locale. Un pair non loopback (Traefik en conteneur, en /32) reste cru sur
// son adresse, comme avant.
func (s *Server) forwardSecretRequired() bool {
	return s.forwardSecret == "" && TrustsLoopback(s.trustedProxies)
}

// hasProxySecret dit si la requête porte exactement une fois le secret du
// mandataire. Sans secret configuré, il n'y a rien à prouver. Les valeurs
// passent par une empreinte pour que la comparaison, à temps constant, ne
// dise rien de la longueur du secret.
func (s *Server) hasProxySecret(r *http.Request) bool {
	if s.forwardSecret == "" {
		return true
	}
	values := r.Header.Values(brand.ProxySecretHeader)
	if len(values) != 1 {
		return false
	}
	received := sha256.Sum256([]byte(values[0]))
	expected := sha256.Sum256([]byte(s.forwardSecret))
	return subtle.ConstantTimeCompare(received[:], expected[:]) == 1
}

// Le refus du mode forward : c'est le SSO en amont qui authentifie.
func (s *Server) writeForwardUnauthorized(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.writeAPIError(w, http.StatusUnauthorized, codeUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	catalog := s.catalogs.For(browserLanguage(r))
	http.Error(w, catalog.Get("auth.forward_unauthorized"), http.StatusUnauthorized)
}

// Le refus d'une identité que le mandataire a authentifiée mais que la liste
// forward_users n'admet pas : 403, pas 401, le mandataire n'y peut rien. La
// page dit l'identité reçue : c'est le remède à une faute de casse dans la
// configuration.
func (s *Server) writeForwardForbidden(w http.ResponseWriter, r *http.Request, identity string) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.writeAPIError(w, http.StatusForbidden, codeForwardForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	catalog := s.catalogs.For(browserLanguage(r))
	http.Error(w, catalog.Format(forwardForbiddenPage, printable(identity, auth.MaxUsernameLength)), http.StatusForbidden)
}

// La langue du navigateur, faute de session : le français s'il le demande
// en premier, l'anglais sinon.
func browserLanguage(r *http.Request) lang.Code {
	preferred := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language")))
	if strings.HasPrefix(preferred, "fr") {
		return lang.French
	}
	return lang.English
}
