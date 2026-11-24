package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
	"github.com/ldesfontaine/kagu/internal/kit/wait/waittest"
)

// Les sessions du mode forward (R-A2-17, W-M5), les flux liés à leur session
// (R-A2-12) et la garde d'origine des flux de l'opérateur.

const containerPeer = "172.17.0.2"

// callProxiedOverHTTPS joue une lecture de l'API derrière le mandataire, en
// HTTPS, depuis peer, avec le cookie donné s'il n'est pas nil.
func callProxiedOverHTTPS(server *Server, peer, identity string, cookie *http.Cookie, secrets ...string) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/counts", nil)
	request.RemoteAddr = net.JoinHostPort(peer, "4000")
	overHTTPS(request)
	proxied(identity, secrets...)(request)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// openForwardSession : la première requête admise par le mandataire ouvre
// une session et pose son cookie.
func (ts *testServer) openForwardSession(t *testing.T, identity string) *http.Cookie {
	t.Helper()
	admitted := callProxiedOverHTTPS(ts.Server, loopbackPeer, identity, nil, proxySecret)
	cookie := cookieNamed(admitted, brand.SessionCookie)
	if admitted.Code != http.StatusOK || cookie == nil {
		t.Fatalf("first admitted request: %d, cookie %v", admitted.Code, cookie)
	}
	return cookie
}

// R-A2-17, W-M5 : un cookie valable n'ouvre rien sans la garde du mandataire
// (en-tête, secret, pair de trusted_proxies) ; il est refusé 401 et sa
// session supprimée. Un conteneur qui joint serve par docker0 avec un cookie
// volé n'entre pas.
func TestR_A2_17_ACookieWithoutTheProxyProofIsRefusedAndKilled(t *testing.T) {
	cases := map[string]func(*Server, *http.Cookie) *httptest.ResponseRecorder{
		"without the identity header": func(server *Server, cookie *http.Cookie) *httptest.ResponseRecorder {
			return callProxiedOverHTTPS(server, loopbackPeer, "", cookie, proxySecret)
		},
		"without the proxy secret": func(server *Server, cookie *http.Cookie) *httptest.ResponseRecorder {
			return callProxiedOverHTTPS(server, loopbackPeer, testUsername, cookie)
		},
		"with a wrong proxy secret": func(server *Server, cookie *http.Cookie) *httptest.ResponseRecorder {
			return callProxiedOverHTTPS(server, loopbackPeer, testUsername, cookie, wrongProxySecret)
		},
		"from a container, around the proxy": func(server *Server, cookie *http.Cookie) *httptest.ResponseRecorder {
			return callProxiedOverHTTPS(server, containerPeer, testUsername, cookie, proxySecret)
		},
		"the cookie alone": func(server *Server, cookie *http.Cookie) *httptest.ResponseRecorder {
			return callProxiedOverHTTPS(server, containerPeer, "", cookie)
		},
	}
	for name, refused := range cases {
		t.Run(name, func(t *testing.T) {
			server := newFirstSetupServer(t)
			server.enableForwardOnLoopback(t, proxySecret)
			cookie := server.openForwardSession(t, testUsername)

			// Avec la garde, le même cookie sert la même session.
			again := callProxiedOverHTTPS(server.Server, loopbackPeer, testUsername, cookie, proxySecret)
			if again.Code != http.StatusOK || cookieNamed(again, brand.SessionCookie) != nil || server.countSessions(t) != 1 {
				t.Fatalf("the session is not reused: %d, %d sessions", again.Code, server.countSessions(t))
			}

			got := refused(server.Server, cookie)
			if got.Code != http.StatusUnauthorized || errorCode(t, got) != codeUnauthorized {
				t.Fatalf("status %d %s, want 401", got.Code, got.Body.String())
			}
			if sessions := server.countSessions(t); sessions != 0 {
				t.Fatalf("%d sessions left, the presented one must be deleted", sessions)
			}
			if strings.Contains(server.logs.String(), cookie.Value) {
				t.Fatal("the logs hold the session token")
			}
			// Le cookie est mort : même avec la garde, il n'est pas repris, une
			// session neuve s'ouvre.
			reopened := callProxiedOverHTTPS(server.Server, loopbackPeer, testUsername, cookie, proxySecret)
			fresh := cookieNamed(reopened, brand.SessionCookie)
			if reopened.Code != http.StatusOK || fresh == nil || fresh.Value == cookie.Value {
				t.Fatalf("after the refusal: %d, cookie %v", reopened.Code, fresh)
			}
		})
	}
}

// R-A2-17 : la session est comparée à l'identité de l'en-tête ; une autre
// identité (le SSO a changé d'utilisateur) tue la session, 401, et le cookie
// est effacé. L'identité nouvelle, sans le cookie, ouvre la sienne.
func TestR_A2_17_AnotherIdentityKillsTheSession(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableForwardOnLoopback(t, proxySecret)
	cookie := server.openForwardSession(t, testUsername)

	got := callProxiedOverHTTPS(server.Server, loopbackPeer, "mallory", cookie, proxySecret)
	if got.Code != http.StatusUnauthorized || errorCode(t, got) != codeUnauthorized {
		t.Fatalf("status %d %s, want 401", got.Code, got.Body.String())
	}
	if sessions := server.countSessions(t); sessions != 0 {
		t.Fatalf("%d sessions left, want 0", sessions)
	}
	cleared := false
	for _, set := range got.Result().Cookies() {
		if set.Name == brand.SessionCookie && set.Value == "" && set.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("the refused cookie is not cleared")
	}
	if replayed := callProxiedOverHTTPS(server.Server, loopbackPeer, testUsername, cookie, proxySecret); cookieNamed(replayed, brand.SessionCookie) == nil {
		t.Fatal("the killed cookie was resumed for its first identity")
	}
	other := callProxiedOverHTTPS(server.Server, loopbackPeer, "mallory", nil, proxySecret)
	if other.Code != http.StatusOK || cookieNamed(other, brand.SessionCookie) == nil {
		t.Fatalf("the new identity without cookie: %d", other.Code)
	}
}

// En HTTP clair hors de la boucle locale, la garde du mandataire admet la
// requête, mais aucune session ne s'ouvre (R-A2-4).
func TestForwardSession_NoneOpensInClearHTTP(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableForward(t)
	got := callForwarded(server.Server, http.MethodGet, "/api/counts", trustedPeer, testUsername)
	if got.Code != http.StatusOK || len(got.Result().Cookies()) != 0 || server.countSessions(t) != 0 {
		t.Fatalf("status %d, cookies %v, %d sessions", got.Code, got.Result().Cookies(), server.countSessions(t))
	}
}

// --- Les flux liés à leur session ---

// openSessionStream ouvre un flux de l'opérateur ; le canal se ferme quand le
// serveur le termine.
func openSessionStream(t *testing.T, server *testServer, path string, shape func(*http.Request)) <-chan struct{} {
	t.Helper()
	next, _ := openLiveAs(t, server, path, shape)
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		for next() != "EOF" {
		}
	}()
	return ended
}

// requireEndsWithinASecond attend la fin du flux et juge sa durée depuis
// killedAt : le ping de quinze secondes ne compte pas.
func requireEndsWithinASecond(t *testing.T, ended <-chan struct{}, killedAt time.Time) {
	t.Helper()
	waittest.Until(t, "the stream to end with its session", func() bool {
		select {
		case <-ended:
			return true
		default:
			return false
		}
	})
	if elapsed := time.Since(killedAt); elapsed >= time.Second {
		t.Fatalf("the stream ended %v after its session, want less than a second", elapsed)
	}
}

func withCookie(cookie *http.Cookie) func(*http.Request) {
	return func(request *http.Request) { presentCookie(request, cookie) }
}

// sendWithCookie joue une écriture de l'API comme le front, sous cookie.
func sendWithCookie(server *Server, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(anonymousHeader, "1")
	presentCookie(request, cookie)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// R-A2-12 : un flux ouvert par une session se ferme dans la seconde qui suit
// sa mort, quelle qu'elle soit : déconnexion, fermeture depuis la liste, mot
// de passe changé, échéance, autre identité ou cookie sans la preuve du
// mandataire en forward ; le direct comme le journal d'un conteneur.
func TestR_A2_12_AStreamClosesWithinASecondOfItsSession(t *testing.T) {
	nativeStream := func(t *testing.T) (*testServer, *http.Cookie, <-chan struct{}) {
		server := newFirstSetupServer(t)
		server.enableNative(t)
		cookie := &http.Cookie{Name: brand.SessionCookie, Value: signIn(server.Server, testUsername, testPassword)}
		return server, cookie, openSessionStream(t, server, "/api/events", withCookie(cookie))
	}
	otherSession := func(server *testServer) *http.Cookie {
		return &http.Cookie{Name: brand.SessionCookie, Value: signIn(server.Server, testUsername, testPassword)}
	}

	t.Run("logout", func(t *testing.T) {
		server, cookie, ended := nativeStream(t)
		killedAt := time.Now()
		if got := sendWithCookie(server.Server, http.MethodPost, "/api/auth/logout", "", cookie); got.Code != http.StatusNoContent {
			t.Fatalf("logout: %d %s", got.Code, got.Body.String())
		}
		requireEndsWithinASecond(t, ended, killedAt)
	})
	t.Run("closed from the list", func(t *testing.T) {
		server, _, ended := nativeStream(t)
		sessions, err := server.db.ListSessions(context.Background())
		if err != nil || len(sessions) != 1 {
			t.Fatalf("sessions %v %v", sessions, err)
		}
		killedAt := time.Now()
		if got := sendWithCookie(server.Server, http.MethodDelete, "/api/auth/sessions/"+sessions[0].ID, "", otherSession(server)); got.Code != http.StatusNoContent {
			t.Fatalf("close: %d %s", got.Code, got.Body.String())
		}
		requireEndsWithinASecond(t, ended, killedAt)
	})
	t.Run("password changed elsewhere", func(t *testing.T) {
		server, _, ended := nativeStream(t)
		body := `{"current":"` + testPassword + `","password":"another long passphrase"}`
		killedAt := time.Now()
		if got := sendWithCookie(server.Server, http.MethodPut, "/api/auth/password", body, otherSession(server)); got.Code != http.StatusOK {
			t.Fatalf("password: %d %s", got.Code, got.Body.String())
		}
		requireEndsWithinASecond(t, ended, killedAt)
	})
	t.Run("deadline", func(t *testing.T) {
		server := newFirstSetupServer(t)
		server.enableNative(t)
		server.operator.SetClock(time.Now)
		// Une session à la fin de ses douze heures : la base garde des
		// secondes, la fin tombe entre 0,5 et 1,5 s d'ici.
		now := time.Now()
		endsAt := now.Add(1500 * time.Millisecond).Truncate(time.Second)
		session := auth.Session{ID: "deadline", Identity: testUsername, CreatedAt: endsAt.Add(-auth.SessionLifetime), SeenAt: now, ExpiresAt: endsAt, Cookie: auth.CookieHost}
		token := strings.Repeat("d", 64)
		if err := server.db.CreateSession(context.Background(), session, ident.HashToken(token)); err != nil {
			t.Fatal(err)
		}
		ended := openSessionStream(t, server, "/api/events", withCookie(&http.Cookie{Name: brand.SessionCookie, Value: token}))
		requireEndsWithinASecond(t, ended, endsAt)
		if sessions := server.countSessions(t); sessions != 0 {
			t.Fatalf("%d sessions left after the deadline", sessions)
		}
	})
	t.Run("another identity in forward", func(t *testing.T) {
		server := newFirstSetupServer(t)
		server.enableForwardOnLoopback(t, proxySecret)
		cookie := server.openForwardSession(t, testUsername)
		ended := openSessionStream(t, server, "/api/events", func(request *http.Request) {
			proxied(testUsername, proxySecret)(request)
			presentCookie(request, cookie)
		})
		killedAt := time.Now()
		if got := callProxiedOverHTTPS(server.Server, loopbackPeer, "mallory", cookie, proxySecret); got.Code != http.StatusUnauthorized {
			t.Fatalf("another identity: %d", got.Code)
		}
		requireEndsWithinASecond(t, ended, killedAt)
	})
	t.Run("a cookie without the proxy proof", func(t *testing.T) {
		server := newFirstSetupServer(t)
		server.enableForwardOnLoopback(t, proxySecret)
		cookie := server.openForwardSession(t, testUsername)
		ended := openSessionStream(t, server, "/api/events", func(request *http.Request) {
			proxied(testUsername, proxySecret)(request)
			presentCookie(request, cookie)
		})
		killedAt := time.Now()
		if got := callProxiedOverHTTPS(server.Server, containerPeer, "", cookie); got.Code != http.StatusUnauthorized {
			t.Fatalf("the cookie alone: %d", got.Code)
		}
		requireEndsWithinASecond(t, ended, killedAt)
	})
	t.Run("the logs of a container", func(t *testing.T) {
		server := newTestServer(t)
		enrolled, private := server.enroll(t, "vps-paris-1", remoteID)
		agent, _, _, stopAgent := openStream(t, server, enrolled.ID, private)
		defer agent.Body.Close()
		defer stopAgent()
		containerID := server.seedContainers(t)
		ended := openSessionStream(t, server, "/api/containers/"+containerID+"/logs/stream", func(*http.Request) {})
		killedAt := time.Now()
		if err := server.operator.CloseSession(context.Background(), testSessionID); err != nil {
			t.Fatal(err)
		}
		requireEndsWithinASecond(t, ended, killedAt)
	})
}

// Une session déjà morte à l'ouverture du flux : il ne s'ouvre pas, ou
// se ferme aussitôt ; il ne vit jamais sur une session effacée.
func TestR_A2_12_AStreamOfASessionDeletedMeanwhileEndsAtOnce(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	token := signIn(server.Server, testUsername, testPassword)
	sessions, err := server.db.ListSessions(context.Background())
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions %v %v", sessions, err)
	}
	// Effacée entre la reprise de la session (la garde) et l'inscription du
	// flux : WatchSession relit la base après s'être inscrit.
	request := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	request = request.WithContext(context.WithValue(request.Context(), operatorSessionKey{}, sessions[0]))
	if _, err := server.db.DeleteSession(context.Background(), sessions[0].ID); err != nil {
		t.Fatal(err)
	}
	bound, stop, err := server.bindStreamToSession(request)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	waittest.Until(t, "the stream of a deleted session to end", func() bool { return bound.Context().Err() != nil })
	if token == "" {
		t.Fatal("no session opened")
	}
}

// Au ping, le flux juge aussi sa session : une session effacée par un autre
// processus (la commande de secours) n'est vue que là.
func TestAuthorizationLapsed_JudgesTheSessionOfTheStream(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	signIn(server.Server, testUsername, testPassword)
	ctx := context.Background()
	state, err := server.operator.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := server.db.ListSessions(ctx)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions %v %v", sessions, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	request = request.WithContext(context.WithValue(context.WithValue(request.Context(), authorizingStateKey{}, state), operatorSessionKey{}, sessions[0]))
	if server.authorizationLapsed(request) {
		t.Fatal("a stream of a living session lapsed")
	}
	if _, err := server.db.DeleteSession(ctx, sessions[0].ID); err != nil {
		t.Fatal(err)
	}
	if !server.authorizationLapsed(request) {
		t.Fatal("a stream outlived its deleted session")
	}
}

// --- La garde d'origine des flux ---

// streamRequest joue un GET de flux sous la session du banc, borné : un flux
// admis ne rend la main qu'à la fin de son contexte.
func streamRequest(t *testing.T, server *Server, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// Un flux de l'opérateur exige Sec-Fetch-Site absent ou same-origin, et un
// Origin égal à public_url quand il est présent : 403 sinon, avant même
// l'accès. Le flux public de la page de statut n'est pas gardé.
func TestStreamOrigin_OnlyTheOperatorsOwnPageOpensItsStreams(t *testing.T) {
	server := newTestServer(t)
	server.publicURL = "https://kagu.example.org"
	refused := map[string]map[string]string{
		"cross-site":                        {"Sec-Fetch-Site": "cross-site"},
		"same-site":                         {"Sec-Fetch-Site": "same-site"},
		"typed address":                     {"Sec-Fetch-Site": "none"},
		"a foreign Origin":                  {"Origin": "https://evil.example.net"},
		"a foreign scheme":                  {"Origin": "http://kagu.example.org"},
		"same-origin from a foreign Origin": {"Sec-Fetch-Site": "same-origin", "Origin": "https://evil.example.net"},
	}
	for _, path := range []string{"/api/events", "/api/containers/x/logs/stream"} {
		for name, headers := range refused {
			if got := streamRequest(t, server.Server, path, headers); got.Code != http.StatusForbidden || errorCode(t, got) != codeOrigin {
				t.Errorf("%s, %s: status %d %s, want 403", path, name, got.Code, got.Body.String())
			}
		}
	}
	admitted := map[string]map[string]string{
		"nothing said":   {},
		"same-origin":    {"Sec-Fetch-Site": "same-origin"},
		"its own Origin": {"Sec-Fetch-Site": "same-origin", "Origin": "https://kagu.example.org"},
	}
	for name, headers := range admitted {
		if got := streamRequest(t, server.Server, "/api/events", headers); got.Code != http.StatusOK {
			t.Errorf("%s: status %d %s, want 200", name, got.Code, got.Body.String())
		}
	}
	public := streamRequest(t, server.Server, "/statut/statut/api/events", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example.net"})
	if public.Code == http.StatusForbidden {
		t.Fatalf("the public stream is guarded: %d %s", public.Code, public.Body.String())
	}
}

// Le refus d'origine tombe avant l'accès : en forward, une page d'un autre
// site n'ouvre aucune session.
func TestStreamOrigin_IsJudgedBeforeTheProxyGuard(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableForwardOnLoopback(t, proxySecret)
	request := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	request.RemoteAddr = net.JoinHostPort(loopbackPeer, "4000")
	overHTTPS(request)
	proxied(testUsername, proxySecret)(request)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || server.countSessions(t) != 0 || len(recorder.Result().Cookies()) != 0 {
		t.Fatalf("status %d, %d sessions, cookies %v", recorder.Code, server.countSessions(t), recorder.Result().Cookies())
	}
}
