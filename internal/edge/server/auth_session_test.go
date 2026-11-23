package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
)

// loginFrom joue POST /api/auth/login avec le compte de test ; shape pose le
// pair, le schéma, les en-têtes ou les cookies de la requête.
func loginFrom(server *Server, password string, shape func(*http.Request)) *httptest.ResponseRecorder {
	body := `{"username":"` + testUsername + `","password":"` + password + `"}`
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(anonymousHeader, "1")
	shape(request)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

func overHTTPS(request *http.Request) {
	request.TLS = &tls.ConnectionState{}
}

func fromLoopback(request *http.Request) {
	request.RemoteAddr = "127.0.0.1:41000"
}

// cookieNamed rend le cookie posé par la réponse sous ce nom, avec une
// valeur ; nil sinon.
func cookieNamed(recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name && cookie.Value != "" {
			return cookie
		}
	}
	return nil
}

// readWith lit une route sous un cookie, depuis le pair donné.
func readWith(server *Server, path string, cookie *http.Cookie, peer string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set(anonymousHeader, "1")
	request.RemoteAddr = peer
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// countSessions compte les sessions en base.
func (ts *testServer) countSessions(t *testing.T) int {
	t.Helper()
	sessions, err := ts.db.ListSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(sessions)
}

// R-A2-1 : deux modes gardent l'interface, native et forward ; HTTP Basic
// n'existe plus, même avec le bon mot de passe.
func TestR_A2_1_BasicIsGoneNativeOrForward(t *testing.T) {
	if got := auth.Modes(); !slices.Equal(got, []auth.Mode{auth.ModeNone, auth.ModeNative, auth.ModeForward}) {
		t.Fatalf("modes %v", got)
	}
	server := newFirstSetupServer(t)
	server.enableNative(t)
	request := httptest.NewRequest(http.MethodGet, "/api/counts", nil)
	request.SetBasicAuth(testUsername, testPassword)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || recorder.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("Basic with the right password: %d, challenge %q", recorder.Code, recorder.Header().Get("WWW-Authenticate"))
	}
	signedIn := loginFrom(server.Server, testPassword, overHTTPS)
	if signedIn.Code != http.StatusOK || cookieNamed(signedIn, brand.SessionCookie) == nil {
		t.Fatalf("login: %d %s", signedIn.Code, signedIn.Body.String())
	}
}

// R-CNX-1 : un en-tête Authorization: Basic est ignoré : il n'ouvre rien seul,
// et ne gêne pas une session.
func TestR_CNX_1_ABasicHeaderIsIgnored(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	for _, route := range []string{"/api/counts", "/api/machines", "/api/auth/sessions", "/api/events"} {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		request := httptest.NewRequestWithContext(ctx, http.MethodGet, route, nil)
		request.SetBasicAuth(testUsername, testPassword)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		cancel()
		if recorder.Code != http.StatusUnauthorized || errorCode(t, recorder) != codeUnauthorized {
			t.Fatalf("%s with Basic: %d %s", route, recorder.Code, recorder.Body.String())
		}
	}
	token := signIn(server.Server, testUsername, testPassword)
	request := httptest.NewRequest(http.MethodGet, "/api/counts", nil)
	request.SetBasicAuth("someone", "anything")
	request.AddCookie(&http.Cookie{Name: brand.SessionCookie, Value: token})
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("a session with a wrong Basic header: %d", recorder.Code)
	}
}

// R-A2-2 : une session meurt après deux heures sans requête, à douze heures
// quoi qu'il arrive, et à la déconnexion.
func TestR_A2_2_ASessionDiesIdleAfterTwoHoursAndAtTwelve(t *testing.T) {
	newServer := func(t *testing.T) (*testServer, *time.Time) {
		server := newFirstSetupServer(t)
		now := testNow
		server.operator.SetClock(func() time.Time { return now })
		server.enableNative(t)
		return server, &now
	}

	t.Run("idle", func(t *testing.T) {
		server, now := newServer(t)
		cookie := &http.Cookie{Name: brand.SessionCookie, Value: signIn(server.Server, testUsername, testPassword)}
		*now = testNow.Add(time.Hour)
		if got := readWith(server.Server, "/api/counts", cookie, "192.0.2.1:1234"); got.Code != http.StatusOK {
			t.Fatalf("after an hour: %d", got.Code)
		}
		*now = testNow.Add(time.Hour + 2*time.Hour - time.Second)
		if got := readWith(server.Server, "/api/counts", cookie, "192.0.2.1:1234"); got.Code != http.StatusOK {
			t.Fatalf("just before two idle hours: %d", got.Code)
		}
		*now = now.Add(2 * time.Hour)
		if got := readWith(server.Server, "/api/counts", cookie, "192.0.2.1:1234"); got.Code != http.StatusUnauthorized {
			t.Fatalf("after two idle hours: %d", got.Code)
		}
		if server.countSessions(t) != 0 {
			t.Fatal("the idle session stays in the database")
		}
	})

	t.Run("twelve hours at most", func(t *testing.T) {
		server, now := newServer(t)
		cookie := &http.Cookie{Name: brand.SessionCookie, Value: signIn(server.Server, testUsername, testPassword)}
		for hour := 1; hour < 12; hour++ {
			*now = testNow.Add(time.Duration(hour) * time.Hour)
			if got := readWith(server.Server, "/api/counts", cookie, "192.0.2.1:1234"); got.Code != http.StatusOK {
				t.Fatalf("hour %d: %d", hour, got.Code)
			}
		}
		*now = testNow.Add(12 * time.Hour)
		if got := readWith(server.Server, "/api/counts", cookie, "192.0.2.1:1234"); got.Code != http.StatusUnauthorized {
			t.Fatalf("at twelve hours: %d", got.Code)
		}
	})

	t.Run("logout", func(t *testing.T) {
		server, _ := newServer(t)
		cookie := &http.Cookie{Name: brand.SessionCookie, Value: signIn(server.Server, testUsername, testPassword)}
		request := httptest.NewRequest(http.MethodPost, "/api/auth/logout", strings.NewReader(`{}`))
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(cookie)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("logout: %d %s", recorder.Code, recorder.Body.String())
		}
		for _, set := range recorder.Result().Cookies() {
			if set.Value != "" || set.MaxAge >= 0 {
				t.Fatalf("logout keeps a cookie %+v", set)
			}
		}
		if got := readWith(server.Server, "/api/counts", cookie, "192.0.2.1:1234"); got.Code != http.StatusUnauthorized {
			t.Fatalf("after the logout: %d", got.Code)
		}
	})
}

// R-A2-2 : la base ne garde que l'empreinte du jeton ; ni elle, ni le
// journal, ni la liste des sessions ne le rendent.
func TestR_A2_2_OnlyTheHashOfTheSessionIsStored(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	signedIn := loginFrom(server.Server, testPassword, overHTTPS)
	cookie := cookieNamed(signedIn, brand.SessionCookie)
	if cookie == nil || len(cookie.Value) != 64 {
		t.Fatalf("login: %d %v", signedIn.Code, cookie)
	}
	ctx := context.Background()
	if _, found, err := server.db.SessionByTokenHash(ctx, ident.HashToken(cookie.Value)); err != nil || !found {
		t.Fatalf("no session under the hash of the token: %v %v", found, err)
	}
	if _, found, err := server.db.SessionByTokenHash(ctx, cookie.Value); err != nil || found {
		t.Fatalf("the token itself is stored: %v %v", found, err)
	}
	sessions, err := server.db.ListSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	everything := fmt.Sprintf("%+v", sessions)
	listed := readWith(server.Server, "/api/auth/sessions", cookie, "192.0.2.1:1234")
	for where, text := range map[string]string{"database": everything, "logs": server.logs.String(), "list": listed.Body.String(), "login answer": signedIn.Body.String()} {
		if strings.Contains(text, cookie.Value) {
			t.Errorf("the %s holds the session token", where)
		}
	}
}

// R-A2-3, W-F1 : un cookie posé avant la connexion, par un autre serveur de la
// boucle locale ou par une session d'avant, n'ouvre rien après : la connexion
// tire toujours un jeton neuf et ferme la session présentée.
func TestR_A2_3_ACookieSetBeforeLoginOpensNothing(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)

	planted := &http.Cookie{Name: brand.LocalSessionCookie, Value: strings.Repeat("a", 64)}
	signedIn := loginFrom(server.Server, testPassword, func(request *http.Request) {
		fromLoopback(request)
		request.AddCookie(planted)
	})
	fresh := cookieNamed(signedIn, brand.LocalSessionCookie)
	if signedIn.Code != http.StatusOK || fresh == nil || fresh.Value == planted.Value {
		t.Fatalf("login with a planted cookie: %d %v", signedIn.Code, fresh)
	}
	if got := readWith(server.Server, "/api/counts", planted, "127.0.0.1:41000"); got.Code != http.StatusUnauthorized {
		t.Fatalf("the planted cookie opens: %d", got.Code)
	}

	// Une session d'avant, présentée à la connexion, est fermée ; la nouvelle
	// a un autre identifiant.
	var before authResponse
	decodeAPI(t, readWith(server.Server, "/api/auth", fresh, "127.0.0.1:41000"), &before)
	again := loginFrom(server.Server, testPassword, func(request *http.Request) {
		fromLoopback(request)
		request.AddCookie(fresh)
	})
	var after authResponse
	decodeAPI(t, again, &after)
	renewed := cookieNamed(again, brand.LocalSessionCookie)
	if again.Code != http.StatusOK || renewed == nil || renewed.Value == fresh.Value || after.Session == "" || after.Session == before.Session {
		t.Fatalf("second login: %d, session %q after %q", again.Code, after.Session, before.Session)
	}
	if got := readWith(server.Server, "/api/counts", fresh, "127.0.0.1:41000"); got.Code != http.StatusUnauthorized {
		t.Fatalf("the session presented at the login survives: %d", got.Code)
	}
	if server.countSessions(t) != 1 {
		t.Fatalf("%d sessions, want only the new one", server.countSessions(t))
	}
}

// R-A2-3 : le cookie local n'est accepté que d'un client de boucle locale :
// pair et adresse cliente, sans schéma transmis. Derrière un mandataire de
// confiance sur 127.0.0.1, tout client a un pair de boucle locale.
func TestR_A2_3_TheLocalCookieOnlyFromLoopback(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	server.trustedProxies = parsePrefixes(t, "127.0.0.1/32")
	local := &http.Cookie{Name: brand.LocalSessionCookie, Value: signIn(server.Server, testUsername, testPassword)}

	for _, peer := range []string{"127.0.0.1:41000", "[::1]:41000"} {
		if got := readWith(server.Server, "/api/counts", local, peer); got.Code != http.StatusOK {
			t.Fatalf("from %s: %d", peer, got.Code)
		}
	}
	refused := map[string]func(*http.Request){
		"a public peer":  func(request *http.Request) { request.RemoteAddr = "192.0.2.1:41000" },
		"a private peer": func(request *http.Request) { request.RemoteAddr = "10.0.0.5:41000" },
		"a proxied client": func(request *http.Request) {
			fromLoopback(request)
			request.Header.Set("X-Forwarded-For", "198.51.100.7")
		},
		"a proxied scheme": func(request *http.Request) { fromLoopback(request); request.Header.Set("X-Forwarded-Proto", "http") },
	}
	for name, shape := range refused {
		request := httptest.NewRequest(http.MethodGet, "/api/counts", nil)
		request.Header.Set(anonymousHeader, "1")
		request.AddCookie(local)
		shape(request)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("local cookie from %s: %d, want 401", name, recorder.Code)
		}
	}
}

// R-A2-4 : aucune session ne s'ouvre en HTTP clair hors de la boucle locale :
// ni la connexion ni la première configuration, qui n'use pas son code.
func TestR_A2_4_NoSessionOverClearHTTPFromAPublicAddress(t *testing.T) {
	server := newFirstSetupServer(t)
	code := issueOnSocket(t, server).Code
	clear := newAPIRequest(http.MethodPost, "/api/auth/setup", authSetupRequest{SetupCode: code, Username: testUsername, Password: testPassword})
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, clear)
	requireRefusal(t, recorder, http.StatusForbidden, codeHTTPSRequired)
	requireStillAwaitingSetup(t, server)
	if got := callSetupAPI(server.Server, authSetupRequest{SetupCode: code, Username: testUsername, Password: testPassword}); got.Code != http.StatusOK {
		t.Fatalf("the code was used by the refused setup: %d %s", got.Code, got.Body.String())
	}

	server.trustedProxies = parsePrefixes(t, "127.0.0.1/32")
	cases := map[string]func(*http.Request){
		"a public peer":          func(*http.Request) {},
		"a proxy that says http": func(request *http.Request) { fromLoopback(request); request.Header.Set("X-Forwarded-Proto", "http") },
		"a proxy for a public client": func(request *http.Request) {
			fromLoopback(request)
			request.Header.Set("X-Forwarded-For", "198.51.100.7")
		},
		"an untrusted peer that says https": func(request *http.Request) { request.Header.Set("X-Forwarded-Proto", "https") },
	}
	before := server.countSessions(t)
	for name, shape := range cases {
		got := loginFrom(server.Server, testPassword, shape)
		if got.Code != http.StatusForbidden || errorCode(t, got) != codeHTTPSRequired || len(got.Result().Cookies()) != 0 {
			t.Errorf("%s: %d %s, cookies %v", name, got.Code, got.Body.String(), got.Result().Cookies())
		}
	}
	if server.countSessions(t) != before {
		t.Fatal("a refused login opened a session")
	}
	proxied := loginFrom(server.Server, testPassword, func(request *http.Request) {
		fromLoopback(request)
		request.Header.Set("X-Forwarded-Proto", "https")
		request.Header.Set("X-Forwarded-For", "198.51.100.7")
	})
	if proxied.Code != http.StatusOK || cookieNamed(proxied, brand.SessionCookie) == nil {
		t.Fatalf("behind the proxy over HTTPS: %d %s", proxied.Code, proxied.Body.String())
	}
}

// R-CNX-5 : sur HTTPS, __Host-, Secure, HttpOnly, SameSite=Strict, Path=/,
// sans domaine ; sur la boucle locale en HTTP, le cookie local, sans Secure.
func TestR_CNX_5_TheSessionCookieNeedsHTTPSOrLoopback(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)

	secure := loginFrom(server.Server, testPassword, overHTTPS)
	cookie := cookieNamed(secure, brand.SessionCookie)
	if secure.Code != http.StatusOK || cookie == nil {
		t.Fatalf("over HTTPS: %d %v", secure.Code, secure.Result().Cookies())
	}
	if !strings.HasPrefix(cookie.Name, "__Host-") || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("HTTPS cookie %+v", cookie)
	}
	if cookieNamed(secure, brand.LocalSessionCookie) != nil {
		t.Fatal("HTTPS also set the local cookie")
	}

	local := loginFrom(server.Server, testPassword, fromLoopback)
	cookie = cookieNamed(local, brand.LocalSessionCookie)
	if local.Code != http.StatusOK || cookie == nil {
		t.Fatalf("on the loopback: %d %v", local.Code, local.Result().Cookies())
	}
	if cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("local cookie %+v", cookie)
	}
	if cookieNamed(local, brand.SessionCookie) != nil {
		t.Fatal("clear HTTP set the secure cookie")
	}
}

// R-A2-9 : changer le mot de passe ferme toutes les autres sessions ; celle
// qui l'a changé reste ouverte.
func TestR_A2_9_ChangingThePasswordClosesTheOtherSessions(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	kept := &http.Cookie{Name: brand.SessionCookie, Value: signIn(server.Server, testUsername, testPassword)}
	other := &http.Cookie{Name: brand.SessionCookie, Value: signIn(server.Server, testUsername, testPassword)}

	request := httptest.NewRequest(http.MethodPut, "/api/auth/password", strings.NewReader(changePasswordBody(testPassword, changedPassword)))
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(kept)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("change: %d %s", recorder.Code, recorder.Body.String())
	}
	if got := readWith(server.Server, "/api/counts", kept, "192.0.2.1:1234"); got.Code != http.StatusOK {
		t.Fatalf("the session that changed the password: %d", got.Code)
	}
	if got := readWith(server.Server, "/api/counts", other, "192.0.2.1:1234"); got.Code != http.StatusUnauthorized {
		t.Fatalf("another session survives the change: %d", got.Code)
	}
}

// Réglages › Connexion : la liste marque la session de la requête, une autre
// se ferme par son identifiant, « Fermer les autres » garde la sienne.
func TestAuthSessions_ListCloseAndCloseOthers(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	mine := &http.Cookie{Name: brand.SessionCookie, Value: signIn(server.Server, testUsername, testPassword)}
	signIn(server.Server, testUsername, testPassword)
	signIn(server.Server, testUsername, testPassword)

	var listed operatorSessionsResponse
	decodeAPI(t, readWith(server.Server, "/api/auth/sessions", mine, "192.0.2.1:1234"), &listed)
	if len(listed.Sessions) != 3 {
		t.Fatalf("listed %+v", listed)
	}
	var current, another string
	for _, session := range listed.Sessions {
		if session.Current {
			current = session.ID
		} else {
			another = session.ID
		}
	}
	if current == "" || another == "" {
		t.Fatalf("listed %+v", listed)
	}

	write := func(method, path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(mine)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		return recorder
	}
	if got := write(http.MethodDelete, "/api/auth/sessions/"+another); got.Code != http.StatusNoContent {
		t.Fatalf("close another: %d %s", got.Code, got.Body.String())
	}
	if got := write(http.MethodDelete, "/api/auth/sessions/"+another); got.Code != http.StatusNotFound {
		t.Fatalf("close it twice: %d", got.Code)
	}
	closed := write(http.MethodPost, "/api/auth/sessions/actions/close-others")
	var response closedSessionsResponse
	decodeAPI(t, closed, &response)
	if closed.Code != http.StatusOK || response.Closed != 1 {
		t.Fatalf("close others: %d %+v", closed.Code, response)
	}
	if server.countSessions(t) != 1 {
		t.Fatalf("%d sessions left", server.countSessions(t))
	}
	if got := readWith(server.Server, "/api/counts", mine, "192.0.2.1:1234"); got.Code != http.StatusOK {
		t.Fatalf("close others closed mine: %d", got.Code)
	}
	if got := write(http.MethodDelete, "/api/auth/sessions/"+current); got.Code != http.StatusNoContent || got.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatalf("close mine: %d", got.Code)
	}
	if got := readWith(server.Server, "/api/counts", mine, "192.0.2.1:1234"); got.Code != http.StatusUnauthorized {
		t.Fatalf("my closed session: %d", got.Code)
	}
}
