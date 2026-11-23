package server

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/server/servertest"
	"github.com/ldesfontaine/kagu/internal/edge/store/storetest"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/fact/auth/authtest"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/goldentest"
)

const (
	testUsername = "lucas"
	testPassword = "correct horse battery"
)

// enableNative passe le serveur en mode native, par le composant.
func (ts *testServer) enableNative(t *testing.T) {
	t.Helper()
	if _, err := ts.operator.EnableNative(context.Background(), auth.State{Mode: auth.ModeNone}, authtest.SetupCode(t, ts.operator), testUsername, testPassword); err != nil {
		t.Fatal(err)
	}
}

// rescue ramène la base à none sans passer par serve, comme une base
// restaurée d'avant la première configuration : aucun geste de Kagu ne le
// fait plus (R-A2-10). Les jetons d'API tirés sous le compte restent : c'est
// la seule façon d'en trouver à l'activation.
func (ts *testServer) rescue(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	current, err := ts.operator.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if swapped, err := ts.db.SaveAuthStateIf(ctx, current, auth.State{Mode: auth.ModeNone}, testNow); err != nil || !swapped {
		t.Fatalf("back to none: %v %v", swapped, err)
	}
}

// requireSetupRequired : le refus d'une installation sans compte, sans défi
// Basic qui ferait ouvrir au navigateur une fenêtre sans réponse possible.
func requireSetupRequired(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Code != http.StatusUnauthorized || errorCode(t, recorder) != codeSetupRequired {
		t.Fatalf("status %d %s, want 401 %s", recorder.Code, recorder.Body.String(), codeSetupRequired)
	}
	if got := recorder.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate %q on a first setup refusal", got)
	}
}

// callAs joue une requête comme le front. Avec un identifiant et un mot de
// passe, elle se connecte d'abord par le composant et porte le cookie de la
// session ouverte ; s'ils sont faux, elle n'en porte aucun. Sans, c'est un
// inconnu, même face au banc qui pose la session de l'opérateur.
func callAs(server *Server, method, path, username, password string) *httptest.ResponseRecorder {
	return callAsWithin(context.Background(), server, method, path, username, password)
}

// callAsWithin borne la requête : un flux ouvert (direct de la page de
// statut) ne rend la main qu'à la fin de son contexte.
func callAsWithin(ctx context.Context, server *Server, method, path, username, password string) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(ctx, method, path, nil)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set(anonymousHeader, "1")
	if username != "" || password != "" {
		signInRequest(server, request, username, password)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// signInRequest pose sur la requête le cookie d'une session ouverte avec ces
// identifiants, aucun s'ils sont refusés ; le banc n'y ajoute rien.
func signInRequest(server *Server, request *http.Request, username, password string) {
	request.Header.Set(anonymousHeader, "1")
	if token := signIn(server, username, password); token != "" {
		request.AddCookie(&http.Cookie{Name: brand.SessionCookie, Value: token})
	}
}

// signIn ouvre une session par le composant, sans passer par la route ni son
// limiteur, et rend son jeton ; rien si la connexion est refusée.
func signIn(server *Server, username, password string) string {
	ctx := context.Background()
	state, err := server.auth.State(ctx)
	if err != nil {
		return ""
	}
	opened, err := server.auth.Login(ctx, state, username, password, "", auth.SessionClient{})
	if err != nil {
		return ""
	}
	return opened.Token
}

// Un chemin concret pour chaque motif : les jokers deviennent « x ».
func concretePath(pattern string) string {
	pattern = strings.ReplaceAll(pattern, "{$}", "")
	parts := strings.Split(pattern, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") {
			parts[i] = "x"
		}
	}
	return strings.Join(parts, "/")
}

func concreteMethod(method string) string {
	if method == anyMethod {
		return http.MethodGet
	}
	return method
}

// Chaque route de l'arbre est jugée : sans session, celles de l'opérateur
// répondent 401, sans défi Basic, hors des routes d'avant la connexion ; les
// autres ne demandent jamais rien.
func TestAuthNative_GuardsEveryOperatorRouteAndLeavesTheOthersOpen(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	open := map[string]bool{}
	for _, route := range server.routes() {
		path := concretePath(route.pattern)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		recorder := callAsWithin(ctx, server.Server, concreteMethod(route.method), path, "", "")
		cancel()
		if got := recorder.Header().Get("WWW-Authenticate"); strings.HasPrefix(got, "Basic") {
			t.Errorf("%s %s: a Basic challenge %q", route.method, route.pattern, got)
		}
		if isOperatorRoute(route.pattern) {
			beforeSignIn := isBeforeSignInRoute(route.method, route.pattern)
			if !beforeSignIn && recorder.Code != http.StatusUnauthorized {
				t.Errorf("%s %s: status %d, want 401", route.method, route.pattern, recorder.Code)
			}
			if beforeSignIn && recorder.Code == http.StatusUnauthorized && errorCode(t, recorder) == codeUnauthorized {
				t.Errorf("%s %s: a route of the sign-in refused without a session", route.method, route.pattern)
			}
			continue
		}
		open[route.pattern] = true
	}
	checkOpenRoutes(t, open)
}

// La liste des ouvertes est une décision : la voici, entière, la même pour
// chaque mode.
var wantOpenRoutes = []string{
	"/agent/enroll", "/agent/stream", "/agent/signal", "/agent/logs/{request}", "/agent/parcels/{parcel}/{name}", "/agent/",
	// Le relais de restic : la preuve de la source, la session de la cible.
	"/agent/relay/rest/{target}/", "/agent/relay/body/{id}", "/agent/relay/response/{id}",
	"/ping/{token}", "/ping/{token}/start", "/ping/{token}/{code}",
	"/statut", "/statut/{$}", "/statut/{slug}", "/statut/{slug}/{$}",
	"/statut/{slug}/api/status", "/statut/{slug}/api/i18n", "/statut/{slug}/api/events", "/statut/",
}

func checkOpenRoutes(t *testing.T, open map[string]bool) {
	t.Helper()
	if len(open) != len(wantOpenRoutes) {
		t.Errorf("open routes %v, want %v", open, wantOpenRoutes)
	}
	for _, pattern := range wantOpenRoutes {
		if !open[pattern] {
			t.Errorf("%s should stay open", pattern)
		}
	}
	if open["/"] || open["/api/events"] || open["/api/containers/{id}/logs/stream"] {
		t.Error("the front, the live stream and the log stream must be guarded")
	}
}

func TestAuthNative_RightCredentialsPassAndWrongPasswordIs401(t *testing.T) {
	servertest.RequireFront(t)
	server := newFirstSetupServer(t)
	server.enableNative(t)
	if got := callAs(server.Server, http.MethodGet, "/api/counts", testUsername, testPassword); got.Code != http.StatusOK {
		t.Fatalf("right credentials: status %d", got.Code)
	}
	if got := callAs(server.Server, http.MethodGet, "/machines", testUsername, testPassword); got.Code != http.StatusOK {
		t.Fatalf("front with credentials: status %d", got.Code)
	}
	wrong := callAs(server.Server, http.MethodGet, "/api/counts", testUsername, "not the password")
	if wrong.Code != http.StatusUnauthorized || errorCode(t, wrong) != codeUnauthorized {
		t.Fatalf("wrong password: status %d %s", wrong.Code, wrong.Body.String())
	}
	if got := callAs(server.Server, http.MethodGet, "/api/counts", "someone", testPassword); got.Code != http.StatusUnauthorized {
		t.Fatalf("wrong username: status %d", got.Code)
	}
}

func TestAuthNative_StatusPageAndPingStayPublic(t *testing.T) {
	servertest.RequireFront(t)
	server := newFirstSetupServer(t)
	server.enableNative(t)
	storetest.PublishedProject(t, server.db, "statut")
	if got := callAs(server.Server, http.MethodGet, "/statut/statut", "", ""); got.Code != http.StatusOK {
		t.Fatalf("/statut/statut: status %d", got.Code)
	}
	if got := callAs(server.Server, http.MethodGet, "/statut/statut/api/status", "", ""); got.Code != http.StatusOK {
		t.Fatalf("/statut/statut/api/status: status %d", got.Code)
	}
	if got := callAs(server.Server, http.MethodGet, "/ping/hb_unknown", "", ""); got.Code != http.StatusNotFound {
		t.Fatalf("/ping: status %d, want the ping's own 404", got.Code)
	}
}

// La page de statut charge ses scripts, styles et icône par le fourre-tout
// de l'interface : ils restent lisibles sans session. Les pages de
// l'interface aussi (elles montrent la connexion) ; ses données, non.
func TestAuthNative_StatusPageAssetsStayPublic(t *testing.T) {
	servertest.RequireFront(t)
	server := newFirstSetupServer(t)
	server.enableNative(t)
	assets, err := fs.Glob(server.app, "assets/*")
	if err != nil || len(assets) == 0 {
		t.Fatalf("no compiled assets: %v", err)
	}
	for _, asset := range append(assets, "theme.js", "favicon.svg") {
		if got := callAs(server.Server, http.MethodGet, "/"+asset, "", ""); got.Code != http.StatusOK {
			t.Fatalf("/%s: status %d", asset, got.Code)
		}
	}
	for _, page := range []string{"/", "/machines"} {
		if got := callAs(server.Server, http.MethodGet, page, "", ""); got.Code != http.StatusOK {
			t.Fatalf("%s: status %d, want the page of the sign-in", page, got.Code)
		}
	}
	if got := callAs(server.Server, http.MethodGet, "/api/counts", "", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("/api/counts: status %d, want 401", got.Code)
	}
}

// Les échecs de connexion comptent par adresse : au-delà de la rafale, 429,
// même avec le bon mot de passe ; une autre adresse n'est pas touchée.
func TestLogin_FailuresAreRateLimitedPerAddress(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	for i := range authAttemptBurst {
		if got := callLogin(server.Server, "203.0.113.9:4000", testUsername, "guess"); got.Code != http.StatusUnauthorized || errorCode(t, got) != "auth.login_failed" {
			t.Fatalf("attempt %d: status %d %s", i+1, got.Code, got.Body.String())
		}
	}
	if got := callLogin(server.Server, "203.0.113.9:4000", testUsername, testPassword); got.Code != http.StatusTooManyRequests {
		t.Fatalf("after the burst: status %d, want 429", got.Code)
	}
	if got := callLogin(server.Server, "198.51.100.7:4000", testUsername, testPassword); got.Code != http.StatusOK {
		t.Fatalf("another address: status %d", got.Code)
	}
}

// Une session ne repasse ni par le hachage lent ni par la limite : les
// requêtes qui la portent ne comptent pas.
func TestAuthNative_ASessionDoesNotCountAgainstTheLimit(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	token := signIn(server.Server, testUsername, testPassword)
	for i := range authAttemptBurst * 3 {
		request := httptest.NewRequest(http.MethodGet, "/api/counts", nil)
		request.AddCookie(&http.Cookie{Name: brand.SessionCookie, Value: token})
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i+1, recorder.Code)
		}
	}
}

func TestAuthAPI_EnableAndChange(t *testing.T) {
	server := newFirstSetupServer(t)
	var state authResponse
	decodeAPI(t, callAPI(server.Server, http.MethodGet, "/api/auth", nil), &state)
	if state.Mode != "none" || state.Username != "" || state.PasswordMinLength != auth.MinPasswordLength {
		t.Fatalf("initial state %+v", state)
	}

	short := callSetupAPI(server.Server, authSetupRequest{SetupCode: authtest.SetupCode(t, server.operator), Username: testUsername, Password: "short"})
	if short.Code != http.StatusUnprocessableEntity || errorCode(t, short) != "auth.password_too_short" {
		t.Fatalf("short password: %d %s", short.Code, short.Body.String())
	}
	badName := callSetupAPI(server.Server, authSetupRequest{SetupCode: authtest.SetupCode(t, server.operator), Username: "a:b", Password: testPassword})
	if badName.Code != http.StatusUnprocessableEntity || errorCode(t, badName) != "auth.username_invalid" {
		t.Fatalf("bad username: %d %s", badName.Code, badName.Body.String())
	}

	enabled := callSetupAPI(server.Server, authSetupRequest{SetupCode: authtest.SetupCode(t, server.operator), Username: testUsername, Password: testPassword})
	if enabled.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", enabled.Code, enabled.Body.String())
	}
	if strings.Contains(enabled.Body.String(), "$2") || strings.Contains(enabled.Body.String(), testPassword) {
		t.Fatal("neither the hash nor the password leaves the process")
	}
	decodeAPI(t, enabled, &state)
	if state.Mode != "native" || state.Username != testUsername || state.EnabledAt == nil || !state.EnabledAt.Equal(testNow) || !state.SignedIn || state.Session == "" {
		t.Fatalf("enabled state %+v", state)
	}
	// Désormais l'API elle-même demande une session ; l'état d'accès reste
	// lisible, sans le compte.
	if got := callAPI(server.Server, http.MethodGet, "/api/counts", nil); got.Code != http.StatusUnauthorized {
		t.Fatalf("after enabling, anonymous read: %d", got.Code)
	}
	state = authResponse{}
	decodeAPI(t, callAPI(server.Server, http.MethodGet, "/api/auth", nil), &state)
	if state.Mode != "native" || state.SignedIn || state.Username != "" || state.EnabledAt != nil || state.Session != "" {
		t.Fatalf("anonymous auth state %+v", state)
	}

	const newPassword = "another long passphrase"
	changed := callSignedInJSON(server.Server, http.MethodPut, "/api/auth/password", `{"current":"`+testPassword+`","password":"`+newPassword+`"}`, testPassword)
	if changed.Code != http.StatusOK {
		t.Fatalf("change: %d %s", changed.Code, changed.Body.String())
	}
	// L'ancien mot de passe ne vaut plus rien.
	if got := callAs(server.Server, http.MethodGet, "/api/counts", testUsername, testPassword); got.Code != http.StatusUnauthorized {
		t.Fatalf("old password after change: %d", got.Code)
	}
	read := callAs(server.Server, http.MethodGet, "/api/auth", testUsername, newPassword)
	if read.Code != http.StatusOK {
		t.Fatalf("new password: %d", read.Code)
	}
	decodeAPI(t, read, &state)
	goldentest.Compare(t, filepath.Join("testdata", "auth.golden.json"), strings.Replace(read.Body.String(), state.Session, "<session>", 1))

	again := callSetupAPI(server.Server, authSetupRequest{Username: "x", Password: newPassword})
	if again.Code != http.StatusConflict || errorCode(t, again) != "auth.already_enabled" {
		t.Fatalf("enable twice: %d %s", again.Code, again.Body.String())
	}
}

// Activer l'authentification révoque tous les jetons d'API et dit combien.
// Changer le mot de passe, ou le refaire par root, ne révoque rien. Les
// jetons sont tirés sous le compte, puis la base revient à la première
// configuration : c'est là qu'une activation en trouve.
func TestAuthAPI_EnableRevokesEveryAPITokenAndPasswordChangeDoesNot(t *testing.T) {
	server := newTestServer(t)
	first := server.issueAPIToken(t, "lecteur")
	second := server.issueAPIToken(t, "script")
	server.rescue(t)

	enabled := callSetupAPI(server.Server, authSetupRequest{SetupCode: authtest.SetupCode(t, server.operator), Username: testUsername, Password: testPassword})
	if enabled.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", enabled.Code, enabled.Body.String())
	}
	var response authSetupResponse
	decodeAPI(t, enabled, &response)
	if response.Mode != "native" || response.APITokensRevoked != 2 {
		t.Fatalf("response %+v", response)
	}
	for _, bearer := range []string{first, second} {
		if got := callBearer(server.Server, "/api/counts", bearer); got.Code != http.StatusUnauthorized {
			t.Fatalf("a token survived the activation: %d", got.Code)
		}
	}

	// Un jeton créé après l'activation survit au changement de mot de
	// passe et à celui de root.
	created := callSignedInJSON(server.Server, http.MethodPost, "/api/settings/api-tokens", `{"name":"après"}`, testPassword)
	if created.Code != http.StatusCreated {
		t.Fatalf("create after: %d %s", created.Code, created.Body.String())
	}
	var after apiTokenCreated
	decodeAPI(t, created, &after)
	const newPassword = "another long passphrase"
	if got := callSignedInJSON(server.Server, http.MethodPut, "/api/auth/password", `{"current":"`+testPassword+`","password":"`+newPassword+`"}`, testPassword); got.Code != http.StatusOK {
		t.Fatalf("change: %d %s", got.Code, got.Body.String())
	}
	if got := callBearer(server.Server, "/api/counts", after.Token); got.Code != http.StatusOK {
		t.Fatalf("password change revoked a token: %d", got.Code)
	}
	if _, err := server.operator.ResetPassword(context.Background(), "a passphrase from root"); err != nil {
		t.Fatal(err)
	}
	if _, err := server.apiTokens.Verify(context.Background(), after.Token); err != nil {
		t.Fatalf("the reset revoked a token: %v", err)
	}
}

// Root refait le mot de passe par la socket : serve le suit à la requête
// suivante, sans redémarrer ; l'ancien mot de passe et les sessions ouvertes
// avant ne rouvrent rien (R-A2-2).
func TestAuthNative_ResetPasswordOnTheSocketTakesEffectWithoutRestart(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	before := signIn(server.Server, testUsername, testPassword)
	if got := callWithSession(server.Server, "/api/counts", before); got.Code != http.StatusOK {
		t.Fatalf("before: %d", got.Code)
	}
	if got := callControl(server, "POST", "/control/admin/reset-password", `{"password":"a brand new passphrase"}`, 0); got.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", got.Code, got.Body.String())
	}
	if got := callAs(server.Server, http.MethodGet, "/api/counts", testUsername, testPassword); got.Code != http.StatusUnauthorized {
		t.Fatalf("the old password reopened the door: %d", got.Code)
	}
	if got := callWithSession(server.Server, "/api/counts", before); got.Code != http.StatusUnauthorized {
		t.Fatalf("a session from before the reset reopened the door: %d", got.Code)
	}
	if got := callAs(server.Server, http.MethodGet, "/api/counts", testUsername, "a brand new passphrase"); got.Code != http.StatusOK {
		t.Fatalf("the new password: %d", got.Code)
	}
}

// callWithSession lit une route sous le cookie de session donné, sans rien
// d'autre.
func callWithSession(server *Server, path, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set(anonymousHeader, "1")
	request.AddCookie(&http.Cookie{Name: brand.SessionCookie, Value: token})
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// Sur la boucle locale en HTTP (le tunnel SSH), la connexion pose le cookie
// local ; le direct passe avec lui, comme le navigateur le renvoie de
// lui-même à la même origine.
func TestAuthNative_LiveStreamOpensWithTheSessionCookie(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	liveServer := httptest.NewServer(server.Server)
	t.Cleanup(liveServer.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, liveServer.URL+"/api/events", nil)
	anonymous, err := liveServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous stream: %d", anonymous.StatusCode)
	}
	login, _ := http.NewRequestWithContext(ctx, http.MethodPost, liveServer.URL+"/api/auth/login",
		strings.NewReader(`{"username":"`+testUsername+`","password":"`+testPassword+`"}`))
	login.Header.Set("Content-Type", "application/json")
	signedIn, err := liveServer.Client().Do(login)
	if err != nil {
		t.Fatal(err)
	}
	signedIn.Body.Close()
	var local *http.Cookie
	for _, cookie := range signedIn.Cookies() {
		if cookie.Name == brand.LocalSessionCookie && cookie.Value != "" {
			local = cookie
		}
	}
	if signedIn.StatusCode != http.StatusOK || local == nil {
		t.Fatalf("login on the loopback: %d %v", signedIn.StatusCode, signedIn.Header.Values("Set-Cookie"))
	}
	if local.Secure || !local.HttpOnly || local.SameSite != http.SameSiteStrictMode || local.Path != "/" {
		t.Fatalf("local cookie %+v", local)
	}
	request, _ = http.NewRequestWithContext(ctx, http.MethodGet, liveServer.URL+"/api/events", nil)
	request.AddCookie(&http.Cookie{Name: local.Name, Value: local.Value})
	response, err := liveServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream with the session: %d %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
}

// Les pairs des requêtes du mode forward : httptest donne 192.0.2.1, et le
// mandataire déclaré est son réseau ; l'autre est un conteneur voisin.
const (
	trustedPeer   = "192.0.2.1"
	untrustedPeer = "203.0.113.9"
)

// enableForward passe le serveur en mode forward derrière un mandataire
// déclaré, l'en-tête par défaut.
func (ts *testServer) enableForward(t *testing.T) {
	t.Helper()
	ts.trustedProxies = parsePrefixes(t, "192.0.2.0/24")
	if _, err := ts.operator.EnableForward(context.Background(), auth.State{Mode: auth.ModeNone}, authtest.SetupCode(t, ts.operator), auth.DefaultForwardHeader); err != nil {
		t.Fatal(err)
	}
}

// callForwarded joue une requête depuis peer, avec l'identité dans
// Remote-User quand elle n'est pas vide, comme le poserait Authelia.
func callForwarded(server *Server, method, path, peer, identity string) *httptest.ResponseRecorder {
	return callForwardedWithin(context.Background(), server, method, path, peer, identity)
}

func callForwardedWithin(ctx context.Context, server *Server, method, path, peer, identity string) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(ctx, method, path, nil)
	request.RemoteAddr = peer + ":4000"
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	if identity != "" {
		request.Header.Set(auth.DefaultForwardHeader, identity)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// callForwardedJSON : une écriture de l'API comme le front derrière le
// mandataire, avec un en-tête choisi.
func callForwardedJSON(server *Server, method, path, body, peer, header, identity string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = peer + ":4000"
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	if identity != "" {
		request.Header.Set(header, identity)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// Le jumeau du test native : depuis le mandataire mais sans identité, chaque
// route de l'opérateur répond 401 sans défi Basic ; les ouvertes répondent
// exactement ce qu'elles répondent sans authentification.
func TestAuthForward_GuardsEveryOperatorRouteAndLeavesTheOthersOpen(t *testing.T) {
	reference := newFirstSetupServer(t)
	server := newFirstSetupServer(t)
	server.enableForward(t)
	open := map[string]bool{}
	for _, route := range server.routes() {
		path := concretePath(route.pattern)
		method := concreteMethod(route.method)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		recorder := callForwardedWithin(ctx, server.Server, method, path, trustedPeer, "")
		cancel()
		if isOperatorRoute(route.pattern) {
			if recorder.Code != http.StatusUnauthorized {
				t.Errorf("%s %s: status %d, want 401", route.method, route.pattern, recorder.Code)
			}
			if got := recorder.Header().Get("WWW-Authenticate"); got != "" {
				t.Errorf("%s %s: forward mode must not challenge, got %q", route.method, route.pattern, got)
			}
			continue
		}
		open[route.pattern] = true
		ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
		unguarded := callForwardedWithin(ctx, reference.Server, method, path, trustedPeer, "")
		cancel()
		if recorder.Code != unguarded.Code {
			t.Errorf("%s %s: status %d in forward mode, %d without authentication", route.method, route.pattern, recorder.Code, unguarded.Code)
		}
	}
	checkOpenRoutes(t, open)
}

// Seul un mandataire déclaré qui porte l'identité passe : ni le mandataire
// sans identité, ni un conteneur voisin qui écrit l'en-tête lui-même.
func TestAuthForward_OnlyATrustedProxyWithTheIdentityPasses(t *testing.T) {
	servertest.RequireFront(t)
	server := newFirstSetupServer(t)
	server.enableForward(t)
	if got := callForwarded(server.Server, http.MethodGet, "/api/counts", trustedPeer, testUsername); got.Code != http.StatusOK {
		t.Fatalf("trusted proxy with identity: status %d", got.Code)
	}
	if got := callForwarded(server.Server, http.MethodGet, "/machines", trustedPeer, testUsername); got.Code != http.StatusOK {
		t.Fatalf("front through the proxy: status %d", got.Code)
	}
	missing := callForwarded(server.Server, http.MethodGet, "/api/counts", trustedPeer, "")
	if missing.Code != http.StatusUnauthorized || errorCode(t, missing) != codeUnauthorized {
		t.Fatalf("trusted proxy without identity: status %d %s", missing.Code, missing.Body.String())
	}
	if got := callForwarded(server.Server, http.MethodGet, "/api/counts", trustedPeer, "   "); got.Code != http.StatusUnauthorized {
		t.Fatalf("blank identity: status %d", got.Code)
	}
	forged := callForwarded(server.Server, http.MethodGet, "/api/counts", untrustedPeer, testUsername)
	if forged.Code != http.StatusUnauthorized || errorCode(t, forged) != codeUnauthorized {
		t.Fatalf("untrusted peer with identity: status %d %s", forged.Code, forged.Body.String())
	}
	if got := forged.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("no Basic challenge in forward mode, got %q", got)
	}
	// Basic ne rouvre rien : il n'y a pas de mot de passe en forward.
	if got := callAs(server.Server, http.MethodGet, "/api/counts", testUsername, testPassword); got.Code != http.StatusUnauthorized {
		t.Fatalf("basic credentials in forward mode: status %d", got.Code)
	}
	storetest.PublishedProject(t, server.db, "statut")
	if got := callForwarded(server.Server, http.MethodGet, "/statut/statut", untrustedPeer, ""); got.Code != http.StatusOK {
		t.Fatalf("/statut/statut stays public: %d", got.Code)
	}
	if got := callForwarded(server.Server, http.MethodGet, "/ping/hb_unknown", untrustedPeer, ""); got.Code != http.StatusNotFound {
		t.Fatalf("/ping: status %d, want the ping's own 404", got.Code)
	}
}

// Un mandataire qui ajoute l'identité au lieu d'écraser laisse passer celle
// du client en premier : deux valeurs, c'est un refus, dans les deux ordres.
func TestAuthForward_IdentityHeaderSentTwiceIsRefused(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableForward(t)
	for _, values := range [][]string{{"admin", testUsername}, {testUsername, testUsername}} {
		request := httptest.NewRequest(http.MethodGet, "/api/counts", nil)
		request.RemoteAddr = trustedPeer + ":4000"
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		for _, value := range values {
			request.Header.Add(auth.DefaultForwardHeader, value)
		}
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized || errorCode(t, recorder) != codeUnauthorized {
			t.Fatalf("identity %v: status %d %s", values, recorder.Code, recorder.Body.String())
		}
	}
}

// Le refus d'une page dit de passer par le mandataire, et comment root rend
// un compte si le SSO tombe, dans la langue du navigateur.
func TestAuthForward_RefusedPageSaysToGoThroughTheProxy(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableForward(t)
	cases := map[string]string{
		"fr-FR,fr;q=0.9": "Accès refusé : passez par le SSO. SSO en panne : sur la machine " + brand.ProductName + ", sudo " + brand.Command + " admin auth-mode native -username <nom> rend un compte.",
		"en-US,en;q=0.9": "Access denied: go through the SSO. SSO down: on the " + brand.ProductName + " machine, sudo " + brand.Command + " admin auth-mode native -username <name> brings back an account.",
	}
	for acceptLanguage, want := range cases {
		request := httptest.NewRequest(http.MethodGet, "/machines", nil)
		request.RemoteAddr = untrustedPeer + ":4000"
		request.Header.Set("Accept-Language", acceptLanguage)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%q: status %d, want 401", acceptLanguage, recorder.Code)
		}
		if got := strings.TrimSpace(recorder.Body.String()); got != want {
			t.Errorf("%q: body %q, want %q", acceptLanguage, got, want)
		}
	}
}

// Le garde-fou : on n'active forward que depuis une requête qui porte déjà
// l'identité d'un mandataire de confiance, sans quoi on s'enfermerait dehors.
func TestAuthAPI_EnableForwardRequiresTheIdentityFromATrustedProxy(t *testing.T) {
	server := newFirstSetupServer(t)
	server.trustedProxies = parsePrefixes(t, "192.0.2.0/24")
	const enable = "/api/auth/setup"
	const remoteUser = auth.DefaultForwardHeader

	missing := callForwardedJSON(server.Server, http.MethodPost, enable, `{"mode":"forward"}`, trustedPeer, remoteUser, "")
	if missing.Code != http.StatusUnprocessableEntity || errorCode(t, missing) != "auth.forward_header_missing" {
		t.Fatalf("without the header: %d %s", missing.Code, missing.Body.String())
	}
	forged := callForwardedJSON(server.Server, http.MethodPost, enable, `{"mode":"forward"}`, untrustedPeer, remoteUser, testUsername)
	if forged.Code != http.StatusUnprocessableEntity || errorCode(t, forged) != "auth.forward_header_missing" {
		t.Fatalf("from an untrusted peer: %d %s", forged.Code, forged.Body.String())
	}
	other := callForwardedJSON(server.Server, http.MethodPost, enable, `{"mode":"forward","header":"X-Forwarded-User"}`, trustedPeer, remoteUser, testUsername)
	if other.Code != http.StatusUnprocessableEntity || errorCode(t, other) != "auth.forward_header_missing" {
		t.Fatalf("carrying another header than the one asked: %d %s", other.Code, other.Body.String())
	}
	invalid := callForwardedJSON(server.Server, http.MethodPost, enable, `{"mode":"forward","header":"Remote User"}`, trustedPeer, remoteUser, testUsername)
	if invalid.Code != http.StatusUnprocessableEntity || errorCode(t, invalid) != "auth.header_invalid" {
		t.Fatalf("invalid header name: %d %s", invalid.Code, invalid.Body.String())
	}
	unknown := callForwardedJSON(server.Server, http.MethodPost, enable, `{"mode":"none"}`, trustedPeer, remoteUser, testUsername)
	if unknown.Code != http.StatusUnprocessableEntity || errorCode(t, unknown) != "auth.mode_invalid" {
		t.Fatalf("unknown mode: %d %s", unknown.Code, unknown.Body.String())
	}
	var state authResponse
	decodeAPI(t, callAPI(server.Server, http.MethodGet, "/api/auth", nil), &state)
	if state.Mode != "none" {
		t.Fatalf("a refused activation changed the mode: %+v", state)
	}

	forwardWithCode := `{"mode":"forward","setup_code":"` + authtest.SetupCode(t, server.operator) + `"}`
	enabled := callForwardedJSON(server.Server, http.MethodPost, enable, forwardWithCode, trustedPeer, remoteUser, testUsername)
	if enabled.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", enabled.Code, enabled.Body.String())
	}
	var response authSetupResponse
	decodeAPI(t, enabled, &response)
	if response.Mode != "forward" || response.Header != remoteUser || response.Username != testUsername ||
		response.EnabledAt == nil || !response.EnabledAt.Equal(testNow) {
		t.Fatalf("enabled %+v", response)
	}

	read := callForwarded(server.Server, http.MethodGet, "/api/auth", trustedPeer, "marie")
	if read.Code != http.StatusOK {
		t.Fatalf("read through the proxy: %d", read.Code)
	}
	decodeAPI(t, read, &state)
	if state.Mode != "forward" || state.Header != remoteUser || state.Username != "marie" {
		t.Fatalf("the identity of the current request is shown: %+v", state)
	}
	if got := callAPI(server.Server, http.MethodGet, "/api/auth", nil); got.Code != http.StatusUnauthorized {
		t.Fatalf("after enabling, a request without identity: %d", got.Code)
	}
	change := callForwardedJSON(server.Server, http.MethodPut, "/api/auth/password", `{"current":"`+testPassword+`","password":"another long passphrase"}`, trustedPeer, remoteUser, testUsername)
	if change.Code != http.StatusConflict || errorCode(t, change) != "auth.no_password" {
		t.Fatalf("change password in forward mode: %d %s", change.Code, change.Body.String())
	}
	again := callForwardedJSON(server.Server, http.MethodPost, enable, `{"mode":"forward"}`, trustedPeer, remoteUser, testUsername)
	if again.Code != http.StatusConflict || errorCode(t, again) != "auth.already_enabled" {
		t.Fatalf("enable twice: %d %s", again.Code, again.Body.String())
	}
}

// Un en-tête choisi remplace Remote-User, et l'activation révoque les
// jetons d'API comme en native : tirés sous le compte, laissés par une base
// revenue à none.
func TestAuthAPI_EnableForwardWithAnotherHeaderRevokesAPITokens(t *testing.T) {
	server := newTestServer(t)
	server.trustedProxies = parsePrefixes(t, "192.0.2.0/24")
	server.issueAPIToken(t, "lecteur")
	server.rescue(t)
	const header = "X-Forwarded-User"
	enabled := callForwardedJSON(server.Server, http.MethodPost, "/api/auth/setup", `{"mode":"forward","setup_code":"`+authtest.SetupCode(t, server.operator)+`","header":"`+header+`"}`, trustedPeer, header, testUsername)
	if enabled.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", enabled.Code, enabled.Body.String())
	}
	var response authSetupResponse
	decodeAPI(t, enabled, &response)
	if response.Header != header || response.APITokensRevoked != 1 {
		t.Fatalf("response %+v", response)
	}
	// Remote-User ne vaut plus rien : seul l'en-tête choisi porte l'identité.
	if got := callForwarded(server.Server, http.MethodGet, "/api/counts", trustedPeer, testUsername); got.Code != http.StatusUnauthorized {
		t.Fatalf("Remote-User with another header configured: %d", got.Code)
	}
	ok := callForwardedJSON(server.Server, http.MethodGet, "/api/counts", "", trustedPeer, header, testUsername)
	if ok.Code != http.StatusOK {
		t.Fatalf("the configured header: %d %s", ok.Code, ok.Body.String())
	}
}

// callSignedInJSON joue une écriture JSON du front, sous une session du compte
// de test ouverte avec ce mot de passe ; sans session si la connexion est
// refusée.
func callSignedInJSON(server *Server, method, path, body, password string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	signInRequest(server, request, testUsername, password)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}
